/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

#[derive(Clone, Debug)]
pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub(crate) fn next_f64(&mut self) -> f64 {
        let value = self.next_u64() >> 11;
        value as f64 * (1.0 / ((1_u64 << 53) as f64))
    }

    pub(crate) fn below(&mut self, upper: u64) -> u64 {
        debug_assert!(upper > 0);
        let zone = upper.wrapping_neg() % upper;
        loop {
            let candidate = self.next_u64();
            if candidate >= zone {
                return candidate % upper;
            }
        }
    }

    pub(crate) fn chance(&mut self, probability: f64) -> bool {
        self.next_f64() < probability
    }

    pub(crate) fn range_inclusive_u64(&mut self, start: u64, end: u64) -> u64 {
        if start == end {
            return start;
        }
        start + self.below(end - start + 1)
    }

    pub(crate) fn range_u16(&mut self, start: u16, end_inclusive: u16) -> u16 {
        self.range_inclusive_u64(start.into(), end_inclusive.into()) as u16
    }
}

pub(crate) fn pick_weighted<'a, T, F>(items: &'a [T], rng: &mut SplitMix64, weight: F) -> &'a T
where
    F: Fn(&T) -> u64,
{
    debug_assert!(!items.is_empty());
    let total_weight: u64 = items.iter().map(&weight).sum();
    debug_assert!(total_weight > 0);

    let mut needle = rng.below(total_weight);
    for item in items {
        let item_weight = weight(item);
        if needle < item_weight {
            return item;
        }
        needle -= item_weight;
    }

    items.last().expect("non-empty slice")
}
