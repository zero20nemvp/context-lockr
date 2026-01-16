//! Standalone decoder binary for context-lockr
//!
//! Minimal binary that decodes .locked files to stdout.
//! Designed to be bundled with plugins for on-demand decoding.
//!
//! Usage:
//!   decode <file.locked> [--plugin <name>]
//!
//! Key lookup:
//!   1. $CONTEXT_LOCKR_KEY_PATH (if set)
//!   2. ~/.config/context-lockr/keys/<plugin>/lock.key

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

/// Key shard structure (subset of full KeyShard for minimal deps)
#[derive(serde::Deserialize)]
struct KeyShard {
    vocabulary: Vec<(String, u32)>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: decode <file.locked> [--plugin <name>]");
        process::exit(1);
    }

    let file_path = PathBuf::from(&args[1]);

    // Parse --plugin argument
    let plugin_name = if args.len() >= 4 && args[2] == "--plugin" {
        args[3].clone()
    } else {
        // Derive from parent directory
        file_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("default")
            .to_string()
    };

    // Resolve key path
    let key_path = resolve_key_path(&plugin_name)?;

    // Load and parse key file
    let key_content = fs::read_to_string(&key_path)
        .map_err(|e| format!("Failed to read key file {:?}: {}", key_path, e))?;

    // Parse key file (skip protocol header, find YAML)
    let yaml_start = key_content
        .find("index:")
        .ok_or("Invalid key file format: no 'index:' found")?;
    let yaml_content = &key_content[yaml_start..];

    let shard: KeyShard = serde_yaml::from_str(yaml_content)
        .map_err(|e| format!("Failed to parse key file: {}", e))?;

    // Build vocabulary (ID -> word)
    let mut id_to_word: HashMap<u32, String> = HashMap::new();
    for (word, id) in &shard.vocabulary {
        id_to_word.insert(*id, word.clone());
    }

    // Read locked file
    let locked_content = fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read locked file {:?}: {}", file_path, e))?;

    // Find the token content (after "--- BEGIN INTEGRITY-PROTECTED CONTENT ---")
    let marker = "--- BEGIN INTEGRITY-PROTECTED CONTENT ---";
    let tokens_start = locked_content
        .find(marker)
        .map(|i| i + marker.len())
        .unwrap_or(0);

    let tokens_str = locked_content[tokens_start..].trim();

    // Decode tokens
    let mut decoded = String::new();
    for token_str in tokens_str.split_whitespace() {
        if let Ok(id) = token_str.parse::<u32>() {
            if let Some(word) = id_to_word.get(&id) {
                decoded.push_str(word);
            } else {
                // Unknown token - might be chaff or from another shard
                decoded.push_str(&format!("[?{}]", id));
            }
        }
    }

    // Output to stdout
    print!("{}", decoded);

    Ok(())
}

/// Resolve key path for a plugin
/// Priority: $CONTEXT_LOCKR_KEY_PATH > ~/.config/context-lockr/keys/<plugin>/lock.key
fn resolve_key_path(plugin_name: &str) -> Result<PathBuf, String> {
    // Check environment variable first
    if let Ok(env_path) = env::var("CONTEXT_LOCKR_KEY_PATH") {
        let path = PathBuf::from(&env_path);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "CONTEXT_LOCKR_KEY_PATH is set but file does not exist: {:?}",
            path
        ));
    }

    // Fall back to default location
    let config_dir = dirs::config_dir().ok_or("Could not determine config directory")?;
    let key_path = config_dir
        .join("context-lockr")
        .join("keys")
        .join(plugin_name)
        .join("lock.key");

    if key_path.exists() {
        Ok(key_path)
    } else {
        Err(format!(
            "Key not found for plugin '{}'. Expected at: {:?}\n\
             Or set CONTEXT_LOCKR_KEY_PATH environment variable.",
            plugin_name, key_path
        ))
    }
}
