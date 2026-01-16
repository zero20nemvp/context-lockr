//! Glossary module: Simple word vocabulary with chaff
//!
//! Maps words to random IDs with chaff entries mixed in for obfuscation.

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Chaff words that look like code variable names
const CHAFF_WORDS: &[&str] = &[
    "process_stack", "buildResult", "request_state", "loadHash", "cacheMap",
    "handleElement", "setResult", "parseCache", "stack_type", "process_user",
    "renderData", "delete_user", "isValue", "map_count", "sync_request",
    "set_size", "data_error", "response_config", "do_result", "canHash",
    "can_array", "cache_set", "findBuffer", "array_set", "parse_list",
    "handleUser", "saveConfig", "process_value", "createToken", "doElement",
    "result_info", "renderToken", "check_map", "load_map", "init_queue",
    "checkItem", "has_buffer", "set_state", "state_error", "element_data",
    "saveBuffer", "array_type", "array_mode", "do_buffer", "handle_hash",
    "store_data", "getCache", "has_request", "init_element", "storeToken",
    "fetch_value", "update_user", "loadRequest", "load_request", "hasMap",
    "render_array", "execute_buffer", "get_set", "config_key", "build_value",
    "get_list", "handle_token", "init_map", "state_count", "stack_flag",
    "save_auth", "makeSession", "cacheStack", "sync_element", "cache_type",
    "save_user", "checkValue", "cache_key", "can_cache", "format_queue",
    "check_node", "buildToken", "fetchStack", "createQueue", "response_info",
    "result_flag", "request_info", "buffer_count", "hash_map", "delete_config",
    "result_status", "load_data", "createItem", "formatArray", "cache_data",
    "fetch_node", "config_status", "node_value", "cacheSession", "cache_list",
    "find_map", "setResult", "delete_queue", "config_map", "checkResponse",
    "set_result", "getToken", "parseData", "loadBuffer", "storeHash",
    "handleConfig", "buildArray", "fetchUser", "createNode", "processQueue",
];

/// Word vocabulary: maps words to random IDs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vocabulary {
    /// Word to ID mapping
    word_to_id: HashMap<String, u32>,
    /// ID to word mapping (for decoding)
    id_to_word: HashMap<u32, String>,
}

impl Vocabulary {
    /// Build vocabulary from text with chaff mixed in
    pub fn from_text(text: &str, chaff_ratio: usize) -> Self {
        Self::from_text_with_rng(text, chaff_ratio, &mut rand::thread_rng())
    }

    /// Build vocabulary from text with specific RNG (for testing)
    pub fn from_text_with_rng<R: Rng>(text: &str, chaff_ratio: usize, rng: &mut R) -> Self {
        let mut word_to_id = HashMap::new();
        let mut id_to_word = HashMap::new();

        // Tokenize text into words
        let words = Self::tokenize(text);
        let real_word_count = words.len();

        // Assign IDs to real words (starting from 1)
        let mut next_id = 1u32;
        for word in &words {
            if !word_to_id.contains_key(word) {
                word_to_id.insert(word.clone(), next_id);
                id_to_word.insert(next_id, word.clone());
                next_id += 1;
            }
        }

        // Add chaff entries
        let chaff_count = real_word_count * chaff_ratio;
        let mut available_chaff: Vec<&str> = CHAFF_WORDS.to_vec();
        available_chaff.shuffle(rng);

        for chaff_word in available_chaff.into_iter().take(chaff_count) {
            if !word_to_id.contains_key(chaff_word) {
                // Random ID in a large range (to look realistic)
                let chaff_id = rng.gen_range(1000..100000u32);
                if !id_to_word.contains_key(&chaff_id) {
                    word_to_id.insert(chaff_word.to_string(), chaff_id);
                    id_to_word.insert(chaff_id, chaff_word.to_string());
                }
            }
        }

        Self { word_to_id, id_to_word }
    }

    /// Get the ID for a word
    pub fn get_id(&self, word: &str) -> Option<u32> {
        self.word_to_id.get(word).copied()
    }

    /// Get the word for an ID
    pub fn get_word(&self, id: u32) -> Option<&String> {
        self.id_to_word.get(&id)
    }

    /// Get number of entries (real + chaff)
    pub fn len(&self) -> usize {
        self.word_to_id.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.word_to_id.is_empty()
    }

    /// Get all word-to-ID mappings
    pub fn mappings(&self) -> &HashMap<String, u32> {
        &self.word_to_id
    }

    /// Tokenize text into words and whitespace runs
    fn tokenize(text: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_whitespace = false;

        for ch in text.chars() {
            let is_ws = ch.is_whitespace();

            if is_ws != in_whitespace && !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }

            current.push(ch);
            in_whitespace = is_ws;
        }

        if !current.is_empty() {
            tokens.push(current);
        }

        tokens
    }

    /// Get tokens for encoding text
    pub fn encode(&self, text: &str) -> Vec<u32> {
        let words = Self::tokenize(text);
        words.iter()
            .filter_map(|w| self.get_id(w))
            .collect()
    }
}

impl Default for Vocabulary {
    fn default() -> Self {
        Self {
            word_to_id: HashMap::new(),
            id_to_word: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vocabulary_from_text() {
        let vocab = Vocabulary::from_text("Hello World", 0);

        assert!(vocab.get_id("Hello").is_some());
        assert!(vocab.get_id(" ").is_some());
        assert!(vocab.get_id("World").is_some());
    }

    #[test]
    fn test_vocabulary_with_chaff() {
        let vocab = Vocabulary::from_text("Hello World", 5);

        // Should have real words + chaff
        assert!(vocab.len() > 3); // More than just "Hello", " ", "World"
    }

    #[test]
    fn test_vocabulary_encode() {
        let vocab = Vocabulary::from_text("Hello World", 0);
        let tokens = vocab.encode("Hello World");

        assert_eq!(tokens.len(), 3); // "Hello", " ", "World"
    }
}
