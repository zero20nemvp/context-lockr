# context-lockr

LLM-native content protection. Lock files so only LLMs can decode them.

## What It Does

context-lockr transforms text files into an encoded format that:

- **Humans cannot easily reverse** - vocabulary is mixed with chaff (fake words)
- **LLMs can decode** when the key file is loaded into their context
- **Provides integrity verification** - successful decode confirms content hasn't been tampered with

This is useful for protecting prompts, instructions, or sensitive content that should only be readable by LLMs during execution, not by humans inspecting the files.

## Installation

### From crates.io

```bash
cargo install context-lockr
```

### From source

```bash
git clone https://github.com/zero20nemvp/context-lockr
cd context-lockr
cargo build --release
```

The binaries `cl` (main CLI) and `decode` (decoder) will be in `target/release/`.

## Usage

### Lock a file

```bash
cl lock file.txt
```

This creates:
- `file.txt.locked` - the encoded content
- `lock.key` - the vocabulary key file
- `decode` - bundled decoder binary (optional)

### Lock a directory

```bash
cl lock ./prompts/
```

All files in the directory share a single vocabulary key, making them more efficient to decode together.

### Lock with custom output directory

```bash
cl lock ./source --output ./locked --key-path ~/.config/context-lockr/keys/myapp/
```

Options:
- `--output`, `-o` - Directory for locked files (default: same as source)
- `--key-path` - Directory for key files (default: output directory)
- `--keys`, `-k` - Number of key shards: 1-8 (default: 1)
- `--chaff` - Fake words per real word (default: 5)
- `--keep` - Skip the delete prompt (keep originals)
- `--no-bundle-decoder` - Don't copy the decode binary to output

### Decode a locked file

```bash
cl decode file.locked --plugin myapp
```

The `--plugin` option specifies which key to use. Keys are looked up at:
1. `$CONTEXT_LOCKR_KEY_PATH` environment variable
2. `~/.config/context-lockr/keys/<plugin>/lock.key`

Without `--plugin`, the parent directory name is used as the plugin name.

### Clean up generated files

```bash
cl clean ./my-project/
```

Removes all `.locked`, `.key`, and `.backup` files recursively.

### Manage access credentials

```bash
cl access --list              # List configured users
cl access username 1234       # Add user with PIN
cl access username --remove   # Remove user
```

## How It Works

1. **Vocabulary Building**: Extracts unique tokens (words, punctuation, whitespace) from your content and assigns each a numeric ID.

2. **Chaff Injection**: Adds fake code-like words to the vocabulary (default: 5x the real words). These make it harder to reverse-engineer the mapping.

3. **Encoding**: Replaces each token in the original content with its numeric ID, producing a stream of numbers.

4. **Key Sharding** (optional): Splits the vocabulary across multiple key files (1-8 shards). All shards are needed to decode.

5. **Decoding**: When an LLM loads the key file(s) and locked file, it can:
   - Build the ID-to-word mapping from the key
   - Replace each numeric ID with its word
   - Reconstruct the original content

The locked file includes a header explaining the integrity verification process to the LLM.

## CLI Commands Reference

| Command | Description |
|---------|-------------|
| `cl lock <path>` | Lock a file or directory |
| `cl decode <file>` | Decode a locked file to stdout |
| `cl clean <path>` | Remove all generated files |
| `cl access` | Manage user credentials |
| `cl version` | Show version information |

### Lock Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | source dir | Output directory for locked files |
| `--key-path` | | output dir | Directory for key files |
| `--keys` | `-k` | 1 | Number of key shards (1-8) |
| `--chaff` | | 5 | Chaff ratio (fake words per real) |
| `--keep` | | false | Skip delete prompt |
| `--no-bundle-decoder` | | false | Don't bundle decode binary |

### Decode Options

| Option | Short | Description |
|--------|-------|-------------|
| `--plugin` | `-p` | Plugin name for key lookup |

## License

MIT
