# codr
Client for OneDrive in Rust - A Rust Command line tool for interacting with OneDrive.

## Example commands

```sh
# Help commands
cargo run -p codr -- -h
cargo run -p codr -- get -h
cargo run -p codr -- get drive-items -h
cargo run -p codr -- get drive-item-children -h
cargo run -p codr -- create sharing-links -h

# Example commands
cargo run -p codr -- -c config.yaml get drive-items path/to/folder
cargo run -p codr -- -c config.yaml get drive-item-children path/to/folder
cargo run -p codr -- -c config.yaml create sharing-links path/to/folder/file embed
```

## Notes
This is my first Rust project so use with caution...
