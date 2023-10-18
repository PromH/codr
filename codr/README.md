# `codr`

**C**lient for **O**ne**D**rive in **R**ust or (`codr`) - A Rust Command line tool for interacting with OneDrive.

## Usage

`codr` is a simple client that requires your own Microsoft OAuth2 credentials (see [here](https://docs.microsoft.com/azure/active-directory/develop/quickstart-register-app) for official instructions.) in order to function properly.

Once the credentials have been obtained, they can then be supplied to `codr` through a variety of means (see the [Example Commands](#example-commands)).

### Installing

```sh
# Via Cargo
cargo install codr
```

### How to obtain Microsoft OAuth2 Credentials

The following steps outline how these credentials can be obtained.

* Register a `Web` application with:
    - A `Redirect URI` of `http://localhost:<REDIRECT_PORT><REDIRECT_ENDPOINT>`
        - <REDIRECT_PORT> defaults to `8080`
        - <REDIRECT_ENDPOINT> defaults to `/redirect`
    - The supported account type: Accounts in any organizational directory and personal Microsoft accounts
* In the left menu select `Overview`. Copy the `Application (client) ID` as the **MSGRAPH_CLIENT_ID**.
* In the left menu select `Certificates & secrets` and add a new client secret. Copy the secret value
  as **MSGRAPH_CLIENT_SECRET**.
* In the left menu select `API permissions` and add a permission then select `Microsoft Graph` and
  `Delegated permissions`. Now add the `Files.Read` permission (and other permissions as necessary).

### Example Commands

```sh
# Help commands
codr -h
codr get -h
codr get drive-item -h
codr get drive-item-children -h
codr create sharing-links -h

# Example commands (using command options)
codr -i my-msgraph-client-id -s my-msgraph-client-secret get drive-item path/to/folder
codr -i my-msgraph-client-id -s my-msgraph-client-secret get drive-item-children path/to/folder
codr -i my-msgraph-client-id -s my-msgraph-client-secret create sharing-links path/to/folder/file embed

# Example commands (using config.yaml file)
codr -c config.yaml get drive-item path/to/folder
codr -c config.yaml get drive-item-children path/to/folder
codr -c config.yaml create sharing-links path/to/folder/file embed

# Example commands (using environment variable)
MSGRAPH_CLIENT_ID=my-msgraph-client-id
MSGRAPH_CLIENT_SECRET=my-msgraph-client-secret
codr get drive-item path/to/folder
codr get drive-item-children path/to/folder
codr create sharing-links path/to/folder/file embed
```

#### Example Config File Contents

```yaml
msgraph_client_id: insert-client-id-here
msgraph_client_secret: insert-client-secret-here
```

## Notes
> [!WARNING]
> This is my first Rust project so use with caution...
