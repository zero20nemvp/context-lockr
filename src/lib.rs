//! context-lockr: LLM-native content protection
//!
//! A tool that transforms text into a format that:
//! - Humans cannot easily reverse (vocabulary mixed with chaff)
//! - LLMs can decode when key file is in context
//!
//! ## How it works
//!
//! 1. **Vocabulary**: Build word→ID mappings from the content
//! 2. **Chaff**: Mix in fake code-like words to obfuscate
//! 3. **Shred**: Optionally distribute across N key files
//! 4. **Encode**: Convert text to token IDs

pub mod glossary;
pub mod shredder;

pub use glossary::Vocabulary;
pub use shredder::{KeyShard, Shredder};
