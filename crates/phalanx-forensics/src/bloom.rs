// crates/phalanx-forensics/src/bloom.rs
//
// Probabilistic membership testing with fixed memory.
// Laboratory layer — pure logic, no IO, no tokio, no libp2p.

/// Fixed-memory probabilistic set.
///
/// Uses k=4 hash functions derived from SHA-256 slices. Designed to accept
/// `[u8; 32]` keys directly (e.g., `evidence_hash` from `WitnessEnvelope`),
/// extracting bit positions from the first 16 bytes without additional hashing.
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
}

impl BloomFilter {
    /// Create a new Bloom filter with the given number of addressable bits.
    /// Actual allocation is rounded up to the next multiple of 64.
    pub fn new(num_bits: usize) -> Self {
        let num_words = num_bits.div_ceil(64);
        Self {
            bits: vec![0u64; num_words],
            num_bits,
        }
    }

    /// Insert a SHA-256 hash into the filter.
    pub fn insert(&mut self, hash: &[u8; 32]) {
        for pos in self.positions(hash) {
            let word = pos / 64;
            let bit = pos % 64;
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Test whether a SHA-256 hash is probably in the filter.
    /// False positives are possible; false negatives are not.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.positions(hash).iter().all(|&pos| {
            let word = pos / 64;
            let bit = pos % 64;
            self.bits[word] & (1u64 << bit) != 0
        })
    }

    /// Reset all bits to zero.
    pub fn clear(&mut self) {
        self.bits.fill(0);
    }

    /// Derive k=4 bit positions from the first 16 bytes of a SHA-256 hash.
    /// Each 4-byte slice → u32 → mod num_bits.
    fn positions(&self, hash: &[u8; 32]) -> [usize; 4] {
        [
            u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) as usize % self.num_bits,
            u32::from_le_bytes([hash[4], hash[5], hash[6], hash[7]]) as usize % self.num_bits,
            u32::from_le_bytes([hash[8], hash[9], hash[10], hash[11]]) as usize % self.num_bits,
            u32::from_le_bytes([hash[12], hash[13], hash[14], hash[15]]) as usize % self.num_bits,
        ]
    }
}

/// Time-windowed Bloom filter using a rotating pair.
///
/// - **Check:** exists in `current` OR `previous` → seen recently.
/// - **Insert:** add to `current` only.
/// - **Rotate:** swap `current` → `previous`, clear new `current`.
///
/// The replay window is ~2× the rotation interval: an entry inserted
/// just before rotation survives in `previous` for one full interval.
pub struct RotatingBloomFilter {
    current: BloomFilter,
    previous: BloomFilter,
}

impl RotatingBloomFilter {
    /// Default capacity for replay-protection filters.
    ///
    /// At k=4 hash functions and 10K expected insertions per rotation,
    /// 1M bits yields a false-positive rate well under 1%.
    /// All production callers should use this constant rather than
    /// hardcoding the value, so tuning happens in one place.
    pub const DEFAULT_CAPACITY: usize = 1_000_000;

    pub fn new(num_bits: usize) -> Self {
        Self {
            current: BloomFilter::new(num_bits),
            previous: BloomFilter::new(num_bits),
        }
    }

    /// Insert a hash into the current generation.
    pub fn insert(&mut self, hash: &[u8; 32]) {
        self.current.insert(hash);
    }

    /// Test whether a hash was inserted in the current or previous generation.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.current.contains(hash) || self.previous.contains(hash)
    }

    /// Rotate generations: current becomes previous, new current is empty.
    pub fn rotate(&mut self) {
        std::mem::swap(&mut self.current, &mut self.previous);
        self.current.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, byte) in h.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8).wrapping_mul(31);
        }
        h
    }

    #[test]
    fn bloom_insert_then_contains() {
        let mut bf = BloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);
        let h = test_hash(42);
        assert!(!bf.contains(&h));
        bf.insert(&h);
        assert!(bf.contains(&h));
    }

    #[test]
    fn bloom_absent_item_not_found() {
        let mut bf = BloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);
        bf.insert(&test_hash(1));
        assert!(!bf.contains(&test_hash(2)));
    }

    #[test]
    fn bloom_clear_removes_all() {
        let mut bf = BloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);
        bf.insert(&test_hash(1));
        bf.clear();
        assert!(!bf.contains(&test_hash(1)));
    }

    #[test]
    fn rotating_survives_one_rotation() {
        let mut rbf = RotatingBloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);
        let h = test_hash(99);
        rbf.insert(&h);
        rbf.rotate();
        // Still in previous
        assert!(rbf.contains(&h));
    }

    #[test]
    fn rotating_gone_after_two_rotations() {
        let mut rbf = RotatingBloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);
        let h = test_hash(99);
        rbf.insert(&h);
        rbf.rotate();
        rbf.rotate();
        assert!(!rbf.contains(&h));
    }

    #[test]
    fn rotating_current_and_previous_both_checked() {
        let mut rbf = RotatingBloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);
        let h1 = test_hash(1);
        let h2 = test_hash(2);

        rbf.insert(&h1);
        rbf.rotate();
        rbf.insert(&h2);

        // h1 in previous, h2 in current — both found
        assert!(rbf.contains(&h1));
        assert!(rbf.contains(&h2));
    }

    #[test]
    fn false_positive_rate_under_one_percent() {
        let mut bf = BloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);

        // Insert 10K items
        for i in 0..10_000u16 {
            let mut h = [0u8; 32];
            h[0..2].copy_from_slice(&i.to_le_bytes());
            bf.insert(&h);
        }

        // Check 10K absent items (offset by 20K to avoid overlap)
        let mut false_positives = 0u32;
        for i in 20_000..30_000u16 {
            let mut h = [0u8; 32];
            h[0..2].copy_from_slice(&i.to_le_bytes());
            if bf.contains(&h) {
                false_positives += 1;
            }
        }

        let fpr = false_positives as f64 / 10_000.0;
        assert!(
            fpr < 0.01,
            "False positive rate {:.4} exceeds 1% threshold",
            fpr
        );
    }
}
