/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use super::*;

fn append_pointer(data: &mut Vec<u8>, target: usize) -> usize {
    assert!(target <= MAX_POINTER_OFFSET);
    let start = data.len();
    data.extend_from_slice(&(0xc000 | target as u16).to_be_bytes());
    start
}

fn pointer_chain(depth: usize) -> (Vec<u8>, Vec<usize>) {
    let mut data = vec![0];
    let mut offsets = vec![0];
    for _ in 0..depth {
        let next = append_pointer(&mut data, *offsets.last().unwrap());
        offsets.push(next);
    }
    (data, offsets)
}

#[test]
fn cache_hit_still_rejects_a_suffix_overlapping_its_pointer() {
    let mut data = vec![4, b'a', b'b', 0xc0, 0, 0];
    let warm = append_pointer(&mut data, 0);
    let mut decoder = DnsNameDecoder::new(&data, 0);
    let mut cursor = warm;
    decoder.read(&mut cursor).unwrap();
    assert_eq!(decoder.cached(0).unwrap().wire_end, 6);

    let mut overlapping = 3;
    assert!(decoder.read(&mut overlapping).is_err());
    assert_eq!(overlapping, 3);
}

#[test]
fn cached_suffix_depth_counts_toward_the_limit() {
    let (data, offsets) = pointer_chain(33);
    let mut decoder = DnsNameDecoder::new(&data, 32);
    for (depth, &offset) in offsets.iter().take(33).enumerate() {
        let mut cursor = offset;
        let name = decoder.read(&mut cursor).unwrap();
        assert_eq!(name.jumps, depth);
        assert_eq!(cursor, offset + if depth == 0 { 1 } else { 2 });
    }
    assert_eq!(decoder.cached(offsets[31]).unwrap().jumps, 31);
    assert!(decoder.cached(offsets[32]).is_none());

    for _ in 0..2 {
        let mut cursor = offsets[33];
        assert_eq!(
            decoder.read(&mut cursor).unwrap_err(),
            "DNS compression jump limit exceeded"
        );
        assert_eq!(cursor, offsets[33]);
        assert!(decoder.cached(offsets[32]).is_none());
    }
    // A failed traversal must not leave pending segments attached to the next name.
    assert_eq!(decoder.read(&mut 0).unwrap().jumps, 0);
}

#[test]
fn unlimited_mode_accepts_the_maximum_backward_pointer_chain() {
    let (data, offsets) = pointer_chain(8193);
    assert_eq!(offsets[8192], MAX_POINTER_OFFSET);
    let mut decoder = DnsNameDecoder::new(&data, 0);
    let mut cursor = offsets[8193];
    let name = decoder.read(&mut cursor).unwrap();
    assert_eq!(name.jumps, 8193);
    assert_eq!(name.expanded_wire_len, 1);
    assert_eq!(cursor, data.len());
    assert_eq!(decoder.labels(name).count(), 0);
}

#[test]
fn materialization_preserves_labels_across_cached_pointer_only_segments() {
    let mut data = b"\x03CoM\0".to_vec();
    let mut target = 0;
    for _ in 0..9 {
        target = append_pointer(&mut data, target);
    }
    let example = data.len();
    data.extend_from_slice(b"\x07ExAmPlE");
    append_pointer(&mut data, target);
    target = example;
    for _ in 0..9 {
        target = append_pointer(&mut data, target);
    }
    let www = data.len();
    data.extend_from_slice(b"\x03WwW");
    append_pointer(&mut data, target);

    let mut decoder = DnsNameDecoder::new(&data, 32);
    for start in [target, www, example, www] {
        let mut cursor = start;
        let name = decoder.read(&mut cursor).unwrap();
        let labels: Vec<_> = decoder.labels(name).collect();
        if start == www {
            assert_eq!(labels, vec![&b"WwW"[..], &b"ExAmPlE"[..], &b"CoM"[..]]);
            assert_eq!(name.expanded_wire_len, 17);
            assert_eq!(name.jumps, 20);
        } else {
            assert_eq!(labels, vec![&b"ExAmPlE"[..], &b"CoM"[..]]);
        }
    }
}

#[test]
fn short_chains_and_repeated_flat_names_use_only_inline_storage() {
    let (data, offsets) = pointer_chain(8);
    let mut decoder = DnsNameDecoder::new(&data, 32);
    let mut cursor = offsets[8];
    decoder.read(&mut cursor).unwrap();
    assert!(decoder.cache.as_ref().unwrap().overflow.is_none());
    assert_eq!(
        decoder.cache.as_ref().unwrap().pending_overflow.capacity(),
        0
    );
    assert!(decoder.cache.as_ref().unwrap().pending.is_empty());

    let mut flat = b"\x07example\x03com\0".to_vec();
    let mut owners = Vec::new();
    for _ in 0..2000 {
        owners.push(append_pointer(&mut flat, 0));
    }
    let mut decoder = DnsNameDecoder::new(&flat, 32);
    for mut owner in owners {
        decoder.skip(&mut owner).unwrap();
    }
    assert!(decoder.cache.is_none());
}

#[test]
fn cached_suffixes_are_local_to_their_message() {
    let valid = [1, b'a', 0, 0xc0, 0];
    let invalid = [3, b'a', b'b', 0xc0, 0];
    let mut first = DnsNameDecoder::new(&valid, 0);
    let name = first.read(&mut 3).unwrap();
    assert_eq!(first.labels(name).collect::<Vec<_>>(), vec![&b"a"[..]]);
    assert!(first.cached(0).is_some());

    let mut second = DnsNameDecoder::new(&invalid, 0);
    assert!(second.cached(0).is_none());
    assert!(second.read(&mut 3).is_err());
    assert!(second.cached(0).is_none());
}

#[test]
fn repeated_deep_names_require_linear_validation_work() {
    let (mut data, offsets) = pointer_chain(1000);
    let mut repeated = Vec::new();
    for _ in 0..4000 {
        repeated.push(append_pointer(&mut data, offsets[1000]));
    }
    let mut decoder = DnsNameDecoder::new(&data, 0);
    for (index, &offset) in repeated.iter().enumerate() {
        let before = decoder.visited;
        let mut cursor = offset;
        let name = decoder.read(&mut cursor).unwrap();
        assert_eq!(name.jumps, 1001);
        assert_eq!(name.expanded_wire_len, 1);
        if index > 0 {
            assert_eq!(decoder.visited - before, 1);
        }
    }
    assert_eq!(decoder.visited, 1001 + repeated.len());
}

#[test]
fn compressed_root_does_not_become_a_literal_root_on_cache_hit() {
    let data = [0, 0xc0, 0, 0xc0, 0];
    let mut decoder = DnsNameDecoder::new(&data, 32);
    assert!(decoder.skip(&mut 0).unwrap());
    assert!(!decoder.skip(&mut 1).unwrap());
    decoder.read(&mut 1).unwrap();
    assert!(decoder.cached(0).is_some());
    assert!(!decoder.skip(&mut 3).unwrap());
}

#[test]
fn shallow_skip_fallback_enforces_the_second_jump_limit() {
    let (data, offsets) = pointer_chain(2);
    for warm_cache in [false, true] {
        let mut decoder = DnsNameDecoder::new(&data, 1);
        if warm_cache {
            let mut cursor = offsets[1];
            decoder.read(&mut cursor).unwrap();
        }
        let mut one_jump = offsets[1];
        assert!(!decoder.skip(&mut one_jump).unwrap());
        assert_eq!(one_jump, offsets[1] + 2);

        let mut two_jumps = offsets[2];
        assert_eq!(
            decoder.skip(&mut two_jumps).unwrap_err(),
            "DNS compression jump limit exceeded"
        );
        assert_eq!(two_jumps, offsets[2]);
    }
}

#[test]
fn shallow_skip_reports_overlap_consistently_with_cold_and_warm_cache() {
    let mut data = vec![4, b'a', b'b', 0xc0, 0, 0];
    let warm = append_pointer(&mut data, 0);
    for warm_cache in [false, true] {
        let mut decoder = DnsNameDecoder::new(&data, 0);
        if warm_cache {
            let mut cursor = warm;
            decoder.read(&mut cursor).unwrap();
        }
        let mut overlap = 3;
        assert_eq!(
            decoder.skip(&mut overlap).unwrap_err(),
            "DNS compression name overlaps its target"
        );
        assert_eq!(overlap, 3);
    }
}

#[test]
fn shallow_skip_memoizes_long_literal_suffixes() {
    let mut data = Vec::new();
    for _ in 0..128 {
        data.extend_from_slice(b"\x01x");
    }
    data.push(0);
    let mut owners = Vec::new();
    for _ in 0..2000 {
        owners.push(append_pointer(&mut data, 0));
    }

    let mut decoder = DnsNameDecoder::new(&data, 1);
    for (index, &owner) in owners.iter().enumerate() {
        let before = decoder.visited;
        let mut cursor = owner;
        assert!(!decoder.skip(&mut cursor).unwrap());
        assert_eq!(cursor, owner + 2);
        assert_eq!(decoder.cached(0).unwrap().expanded_wire_len, 257);
        if index > 0 {
            assert_eq!(decoder.visited - before, 1);
        }
    }
    assert_eq!(decoder.cache.as_ref().unwrap().inline.len(), 1);
    assert!(decoder.cache.as_ref().unwrap().overflow.is_none());
}

#[test]
fn streamed_labels_match_materialization_with_cold_and_warm_suffixes() {
    let mut data = b"\x03CoM\0".to_vec();
    let mut target = 0;
    for _ in 0..10 {
        target = append_pointer(&mut data, target);
    }
    let example = data.len();
    data.extend_from_slice(b"\x07ExAmPlE");
    append_pointer(&mut data, target);
    let www = data.len();
    data.extend_from_slice(b"\x03WwW");
    append_pointer(&mut data, example);

    let mut decoder = DnsNameDecoder::new(&data, 32);
    for _ in 0..2 {
        let mut cursor = www;
        let mut visited_labels = Vec::new();
        let name = decoder
            .read_with_labels(&mut cursor, |label| visited_labels.push(label.to_vec()))
            .unwrap();
        assert_eq!(cursor, data.len());
        assert_eq!(name.jumps, 12);
        assert_eq!(name.expanded_wire_len, 17);
        assert_eq!(
            visited_labels,
            vec![b"WwW".to_vec(), b"ExAmPlE".to_vec(), b"CoM".to_vec()]
        );
        assert_eq!(
            decoder.labels(name).map(<[u8]>::to_vec).collect::<Vec<_>>(),
            visited_labels
        );
    }
}

#[test]
fn shallow_skip_switches_to_cached_validation_after_eight_jumps() {
    let (data, offsets) = pointer_chain(9);
    for (limit, accepts_ninth) in [(8, false), (9, true), (32, true), (0, true)] {
        let mut decoder = DnsNameDecoder::new(&data, limit);
        let mut eight_jumps = offsets[8];
        assert!(!decoder.skip(&mut eight_jumps).unwrap());
        assert_eq!(eight_jumps, offsets[8] + 2);
        assert!(decoder.cache.is_none());
        assert_eq!(decoder.visited, 0);

        for _ in 0..2 {
            let mut nine_jumps = offsets[9];
            assert_eq!(decoder.skip(&mut nine_jumps).is_ok(), accepts_ninth);
            assert_eq!(nine_jumps, offsets[9] + if accepts_ninth { 2 } else { 0 });
        }
        if accepts_ninth {
            assert_eq!(decoder.cached(offsets[8]).unwrap().jumps, 8);
        }
    }
}

#[test]
fn shallow_literal_threshold_keeps_short_suffixes_direct_and_caches_longer_ones() {
    for extra_label in [false, true] {
        let mut data = vec![63];
        data.extend_from_slice(&[b'x'; 63]);
        if extra_label {
            data.extend_from_slice(b"\x01y");
        }
        data.push(0);
        let owner = append_pointer(&mut data, 0);
        let mut decoder = DnsNameDecoder::new(&data, 1);
        for _ in 0..2 {
            let mut cursor = owner;
            assert!(!decoder.skip(&mut cursor).unwrap());
            assert_eq!(cursor, owner + 2);
            assert_eq!(decoder.cached(0).is_some(), extra_label);
        }
    }
}
