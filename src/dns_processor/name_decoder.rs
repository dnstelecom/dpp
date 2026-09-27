/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use arrayvec::ArrayVec;
use std::collections::HashMap;

const POINTER_TAG: u8 = 0xc0;
const MAX_POINTER_OFFSET: usize = 0x3fff;
const DIRECT_SUFFIX_BYTES: usize = 64;
const DIRECT_POINTER_JUMPS: usize = 8;

#[derive(Clone, Copy, Debug)]
pub(super) struct ValidatedName {
    /// End of this segment's encoded labels and terminating pointer or root.
    wire_end: usize,
    pub(super) jumps: usize,
    pub(super) expanded_wire_len: usize,
    /// First label (or root), bypassing any leading pointer-only segments.
    first_label: usize,
}

struct PendingSegment {
    start: usize,
    wire_end: usize,
    label_bytes: usize,
}

impl PendingSegment {
    fn prepend(self, suffix: ValidatedName) -> ValidatedName {
        ValidatedName {
            wire_end: self.wire_end,
            jumps: suffix.jumps + 1,
            expanded_wire_len: self.label_bytes + suffix.expanded_wire_len,
            first_label: if self.label_bytes == 0 {
                suffix.first_label
            } else {
                self.start
            },
        }
    }
}

/// One immutable DNS message owns all cached validation results. Only referenced
/// suffixes are cached: ordinary flat RR lists do not grow the cache per record.
/// Small messages need no heap allocation; larger caches cover at most the 14-bit
/// pointer address space. No recursion is used, even when the jump limit is zero.
pub(super) struct DnsNameDecoder<'a> {
    data: &'a [u8],
    max_jumps: usize,
    cache: Option<DnsNameCache>,
    #[cfg(test)]
    visited: usize,
}

#[derive(Default)]
struct DnsNameCache {
    inline: ArrayVec<(usize, ValidatedName), 8>,
    overflow: Option<HashMap<usize, ValidatedName>>,
    pending: ArrayVec<PendingSegment, 8>,
    pending_overflow: Vec<PendingSegment>,
}

impl<'a> DnsNameDecoder<'a> {
    pub(super) fn new(data: &'a [u8], max_jumps: usize) -> Self {
        Self {
            data,
            max_jumps,
            cache: None,
            #[cfg(test)]
            visited: 0,
        }
    }

    fn cached(&self, start: usize) -> Option<ValidatedName> {
        let state = self.cache.as_ref()?;
        if let Some(cache) = &state.overflow {
            cache.get(&start).copied()
        } else {
            state
                .inline
                .iter()
                .find_map(|&(offset, name)| (offset == start).then_some(name))
        }
    }

    fn remember(&mut self, start: usize, name: ValidatedName) {
        debug_assert!(start <= MAX_POINTER_OFFSET);
        let state = self
            .cache
            .as_mut()
            .expect("an uncached pointer initialized the traversal state");
        if let Some(cache) = &mut state.overflow {
            cache.insert(start, name);
        } else if !state.inline.is_full() {
            state.inline.push((start, name));
        } else {
            let mut cache = HashMap::with_capacity(state.inline.len() * 2);
            cache.extend(state.inline.drain(..));
            cache.insert(start, name);
            state.overflow = Some(cache);
        }
    }

    fn check_jumps(&self, jumps: usize) -> Result<(), &'static str> {
        if self.max_jumps != 0 && jumps > self.max_jumps {
            Err("DNS compression jump limit exceeded")
        } else {
            Ok(())
        }
    }

    fn boundary_error(&self, end: usize, truncated: &'static str) -> &'static str {
        if end < self.data.len() {
            "DNS compression name overlaps its target"
        } else {
            truncated
        }
    }

    #[inline]
    pub(super) fn read(&mut self, cursor: &mut usize) -> Result<ValidatedName, &'static str> {
        self.read_inner::<false>(cursor, |_| {})
    }

    #[inline]
    pub(super) fn read_with_labels(
        &mut self,
        cursor: &mut usize,
        visit: impl FnMut(&[u8]),
    ) -> Result<ValidatedName, &'static str> {
        self.read_inner::<true>(cursor, visit)
    }

    #[inline(always)]
    fn read_inner<const VISIT: bool>(
        &mut self,
        cursor: &mut usize,
        mut visit: impl FnMut(&[u8]),
    ) -> Result<ValidatedName, &'static str> {
        let start = *cursor;
        let mut segment_start = start;
        let mut segment_end = self.data.len();
        let mut jumps = 0;

        let mut suffix = 'segments: loop {
            let mut position = segment_start;
            loop {
                #[cfg(test)]
                {
                    self.visited += 1;
                }
                let length = *self
                    .data
                    .get(..segment_end)
                    .and_then(|segment| segment.get(position))
                    .ok_or_else(|| self.boundary_error(segment_end, "DNS name truncated"))?;
                match length {
                    0 => {
                        break 'segments ValidatedName {
                            wire_end: position + 1,
                            jumps: 0,
                            expanded_wire_len: position - segment_start + 1,
                            first_label: segment_start,
                        };
                    }
                    _ if length & POINTER_TAG == POINTER_TAG => {
                        let next = *self
                            .data
                            .get(..segment_end)
                            .and_then(|segment| segment.get(position + 1))
                            .ok_or_else(|| {
                                self.boundary_error(
                                    segment_end,
                                    "DNS compression pointer truncated",
                                )
                            })?;
                        let target = (usize::from(length & 0x3f) << 8) | usize::from(next);
                        if target >= segment_start {
                            return Err("DNS compression pointer is not prior to name");
                        }
                        jumps += 1;
                        self.check_jumps(jumps)?;
                        let segment = PendingSegment {
                            start: segment_start,
                            wire_end: position + 2,
                            label_bytes: position - segment_start,
                        };
                        if let Some(cached) = self.cached(target) {
                            // The cached suffix was validated in a possibly wider range.
                            // Its first segment must still end BEFORE this name begins.
                            if cached.wire_end > segment_start {
                                return Err("DNS compression name overlaps its target");
                            }
                            self.check_jumps(jumps + cached.jumps)?;
                            if VISIT {
                                for label in self.labels(cached) {
                                    visit(label);
                                }
                            }
                            break 'segments segment.prepend(cached);
                        }
                        let state = self.cache.get_or_insert_with(DnsNameCache::default);
                        if jumps == 1 {
                            state.pending.clear();
                            state.pending_overflow.clear();
                        }
                        if state.pending.is_full() {
                            state.pending_overflow.push(segment);
                        } else {
                            state.pending.push(segment);
                        }
                        segment_end = segment_start;
                        segment_start = target;
                        continue 'segments;
                    }
                    _ if length & POINTER_TAG != 0 => return Err("Unsupported DNS label encoding"),
                    _ => {
                        let end = position + 1 + usize::from(length);
                        let label = self
                            .data
                            .get(..segment_end)
                            .and_then(|segment| segment.get(position + 1..end))
                            .ok_or_else(|| {
                                self.boundary_error(segment_end, "DNS label truncated")
                            })?;
                        if VISIT {
                            visit(label);
                        }
                        position = end;
                    }
                }
            }
        };

        // Publish only fully validated suffixes. Failed or partial names cannot
        // poison later reads, including the semantic fallback in the same message.
        if segment_start == start {
            *cursor = suffix.wire_end;
            return Ok(suffix);
        }
        self.remember(segment_start, suffix);
        while let Some(segment) = {
            let state = self
                .cache
                .as_mut()
                .expect("a traversed suffix has pending segments");
            state.pending_overflow.pop().or_else(|| state.pending.pop())
        } {
            let offset = segment.start;
            suffix = segment.prepend(suffix);
            if offset != start {
                self.remember(offset, suffix);
            }
        }
        *cursor = suffix.wire_end;
        Ok(suffix)
    }

    #[inline(always)]
    pub(super) fn skip(&mut self, cursor: &mut usize) -> Result<bool, &'static str> {
        let start = *cursor;
        let mut position = start;
        let mut resume = None;
        let mut segment_start = start;
        let mut segment_end = self.data.len();
        let direct_limit = if self.max_jumps == 0 {
            DIRECT_POINTER_JUMPS
        } else {
            self.max_jumps.min(DIRECT_POINTER_JUMPS)
        };
        let mut jumps = 0;
        loop {
            let length = *self
                .data
                .get(..segment_end)
                .and_then(|segment| segment.get(position))
                .ok_or_else(|| self.boundary_error(segment_end, "DNS name truncated"))?;
            match length {
                0 => {
                    *cursor = resume.unwrap_or(position + 1);
                    // OPT requires a literal root, never an expanded root.
                    return Ok(resume.is_none() && position == start);
                }
                _ if length & POINTER_TAG == POINTER_TAG => {
                    if jumps == direct_limit {
                        // Cheap short walks avoid cache bookkeeping. The full
                        // walker enforces smaller configured limits and caches
                        // longer chains, counting every cached transition.
                        return self.skip_cached(cursor);
                    }
                    let next = *self
                        .data
                        .get(..segment_end)
                        .and_then(|segment| segment.get(position + 1))
                        .ok_or_else(|| {
                            self.boundary_error(segment_end, "DNS compression pointer truncated")
                        })?;
                    let target = (usize::from(length & 0x3f) << 8) | usize::from(next);
                    if target >= segment_start {
                        return Err("DNS compression pointer is not prior to name");
                    }
                    jumps += 1;
                    if resume.is_none() {
                        resume = Some(position + 2);
                    }
                    segment_end = segment_start;
                    segment_start = target;
                    position = target;
                }
                _ if length & POINTER_TAG != 0 => return Err("Unsupported DNS label encoding"),
                _ => {
                    let end = position + 1 + usize::from(length);
                    if resume.is_some() && end - segment_start > DIRECT_SUFFIX_BYTES {
                        // Bound repeated literal-label work too, including RR
                        // owner names whose expanded size is not materialized.
                        return self.skip_cached(cursor);
                    }
                    self.data
                        .get(..segment_end)
                        .and_then(|segment| segment.get(position + 1..end))
                        .ok_or_else(|| self.boundary_error(segment_end, "DNS label truncated"))?;
                    position = end;
                }
            }
        }
    }

    #[inline(never)]
    fn skip_cached(&mut self, cursor: &mut usize) -> Result<bool, &'static str> {
        self.read(cursor)?;
        Ok(false)
    }

    pub(super) fn labels(&self, name: ValidatedName) -> NameLabels<'_, 'a> {
        NameLabels {
            decoder: self,
            position: name.first_label,
        }
    }
}

#[cfg(test)]
#[path = "name_decoder_tests.rs"]
mod tests;

/// Materialization visits only label-bearing segments. Pointer-only chains have
/// already been validated and reduced to their first label by `read`.
pub(super) struct NameLabels<'decoder, 'data> {
    decoder: &'decoder DnsNameDecoder<'data>,
    position: usize,
}

impl<'data> Iterator for NameLabels<'_, 'data> {
    type Item = &'data [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let data = self.decoder.data;
            let length = data[self.position];
            if length == 0 {
                return None;
            }
            if length & POINTER_TAG == POINTER_TAG {
                let target =
                    (usize::from(length & 0x3f) << 8) | usize::from(data[self.position + 1]);
                self.position = self
                    .decoder
                    .cached(target)
                    .expect("every followed pointer target has been validated")
                    .first_label;
            } else {
                let start = self.position + 1;
                self.position = start + usize::from(length);
                return Some(&data[start..self.position]);
            }
        }
    }
}
