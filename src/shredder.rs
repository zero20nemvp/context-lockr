//! Shredder module: Distribute vocabulary across N key files
//!
//! Randomly distributes vocabulary entries across multiple key files.
//! All files are required to decode - no single file has complete vocabulary.

use crate::glossary::Vocabulary;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A single key shard containing part of the vocabulary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShard {
    /// Shard index (1-based)
    pub index: usize,
    /// Total number of shards
    pub total: usize,
    /// Chaff count (for reference)
    pub chaff_count: usize,
    /// Vocabulary entries (word -> ID)
    pub vocabulary: Vec<(String, u32)>,
    /// Integrity hash fragment
    pub integrity_fragment: String,
}

/// The shredder distributes vocabulary across N key files
#[derive(Debug)]
pub struct Shredder {
    /// Number of shards to create
    num_shards: usize,
}

impl Shredder {
    /// Create a new shredder with the specified number of shards
    pub fn new(num_shards: usize) -> Self {
        assert!(num_shards >= 1, "Must have at least 1 shard");
        Self { num_shards }
    }

    /// Shred vocabulary into key shards
    pub fn shred(&self, vocab: &Vocabulary) -> Vec<KeyShard> {
        self.shred_with_rng(vocab, &mut rand::thread_rng())
    }

    /// Shred with a specific RNG (for testing)
    pub fn shred_with_rng<R: Rng>(&self, vocab: &Vocabulary, rng: &mut R) -> Vec<KeyShard> {
        // Initialize empty shards
        let mut shards: Vec<KeyShard> = (0..self.num_shards)
            .map(|i| KeyShard {
                index: i + 1,
                total: self.num_shards,
                chaff_count: 0,
                vocabulary: Vec::new(),
                integrity_fragment: String::new(),
            })
            .collect();

        // Get all vocabulary entries and shuffle
        let mut entries: Vec<_> = vocab.mappings().iter()
            .map(|(w, id)| (w.clone(), *id))
            .collect();
        entries.shuffle(rng);

        // Distribute entries across shards
        for (i, entry) in entries.into_iter().enumerate() {
            let shard_idx = i % self.num_shards;
            shards[shard_idx].vocabulary.push(entry);
        }

        // Generate and distribute integrity hash
        let integrity_hash = self.generate_integrity_hash(&shards);
        self.distribute_integrity_hash(&mut shards, &integrity_hash);

        shards
    }

    /// Generate integrity hash from all shard data
    fn generate_integrity_hash(&self, shards: &[KeyShard]) -> String {
        let mut hasher = Sha256::new();

        for shard in shards {
            let mut sorted_vocab = shard.vocabulary.clone();
            sorted_vocab.sort_by(|a, b| a.0.cmp(&b.0));

            for (word, id) in sorted_vocab {
                hasher.update(word.as_bytes());
                hasher.update(id.to_le_bytes());
            }
        }

        hex::encode(hasher.finalize())
    }

    /// Distribute integrity hash across shards
    fn distribute_integrity_hash(&self, shards: &mut [KeyShard], hash: &str) {
        let chars: Vec<char> = hash.chars().collect();
        let chunk_size = (chars.len() + self.num_shards - 1) / self.num_shards;

        for (i, shard) in shards.iter_mut().enumerate() {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, chars.len());

            if start < chars.len() {
                shard.integrity_fragment = chars[start..end].iter().collect();
            }
        }
    }

    /// Verify integrity of shards
    pub fn verify_integrity(shards: &[KeyShard]) -> bool {
        if shards.is_empty() {
            return false;
        }

        let reconstructed: String = shards
            .iter()
            .map(|s| s.integrity_fragment.as_str())
            .collect();

        let shredder = Shredder::new(shards.len());
        let expected = shredder.generate_integrity_hash(shards);

        reconstructed == expected
    }

    /// Merge shards back into complete vocabulary
    pub fn merge(shards: &[KeyShard]) -> HashMap<String, u32> {
        let mut vocabulary = HashMap::new();

        for shard in shards {
            for (word, id) in &shard.vocabulary {
                vocabulary.insert(word.clone(), *id);
            }
        }

        vocabulary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vocab() -> Vocabulary {
        Vocabulary::from_text("Hello World! This is a test.", 5)
    }

    #[test]
    fn test_shredder_creates_correct_number_of_shards() {
        let vocab = create_test_vocab();

        for num_shards in [1, 2, 3, 5, 8] {
            let shredder = Shredder::new(num_shards);
            let shards = shredder.shred(&vocab);

            assert_eq!(shards.len(), num_shards);

            for (i, shard) in shards.iter().enumerate() {
                assert_eq!(shard.index, i + 1);
                assert_eq!(shard.total, num_shards);
            }
        }
    }

    #[test]
    fn test_shredder_distributes_all_entries() {
        let vocab = create_test_vocab();
        let shredder = Shredder::new(3);
        let shards = shredder.shred(&vocab);

        let total_entries: usize = shards.iter().map(|s| s.vocabulary.len()).sum();
        assert_eq!(total_entries, vocab.len());
    }

    #[test]
    fn test_shredder_merge_restores_all() {
        let vocab = create_test_vocab();
        let shredder = Shredder::new(3);
        let shards = shredder.shred(&vocab);

        let merged = Shredder::merge(&shards);
        assert_eq!(merged.len(), vocab.len());
    }

    #[test]
    fn test_shredder_integrity_verification() {
        let vocab = create_test_vocab();
        let shredder = Shredder::new(3);
        let shards = shredder.shred(&vocab);

        assert!(Shredder::verify_integrity(&shards));

        // Tampered shard should fail
        let mut tampered = shards.clone();
        tampered[0].vocabulary.push(("tampered".to_string(), 999999));
        assert!(!Shredder::verify_integrity(&tampered));
    }
}
