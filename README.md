# codr
Client for OneDrive in Rust - A Rust Command line tool for interacting with OneDrive.

## Example commands

```sh
# Help commands
cargo run -p codr -- -h
cargo run -p codr -- get -h
cargo run -p codr -- get drive-item -h
cargo run -p codr -- get drive-item-children -h
cargo run -p codr -- create sharing-links -h

# Example commands
cargo run -p codr -- -c config.yaml get drive-item path/to/folder
cargo run -p codr -- -c config.yaml get drive-item-children path/to/folder
cargo run -p codr -- -c config.yaml create sharing-links path/to/folder/file embed
```

## Notes
> [!WARNING]
> This is my first Rust project so use with caution...

### Potential issues that might arise

#### Firewall rules
If you're unable to access https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration

Then there might be firewall rules that is blocking access.

You can verify with the following command:

```sh
python3 -c "import requests; print(requests.get('https://login.microsoftonline.com/').status_code)"
```

See the following thread for ideas on resolving: https://learn.microsoft.com/en-us/answers/questions/408919/connection-reset-error-trying-to-request-azure-acc

In my case, I needed to turn back my VPN on.
