# `onedrive`

A package for interacting with OneDrive.

## Usage

In order to use this package, your own Microsoft OAuth2 credentials (see [here](https://docs.microsoft.com/azure/active-directory/develop/quickstart-register-app) for official instructions.) will need to be provided, in order to function properly.

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

### Example Usage

#### Obtaining an MSGraph Token

```rs
use onedrive::{GraphTokenObtainer, TokenObtainer};
use std::env;
use std::time::SystemTime;

fn setup_logger(log_level: log::LevelFilter) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {} {}:{}] {}",
                humantime::format_rfc3339_seconds(SystemTime::now()),
                record.level(),
                record.target(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stdout())
        .chain(fern::log_file("output.log")?)
        .apply()?;
    Ok(())
}

fn main() {
    setup_logger(log::LevelFilter::Info).unwrap();

    let token_obtainer = GraphTokenObtainer {
        client_id: env::var("MSGRAPH_CLIENT_ID")
            .expect("Missing the MSGRAPH_CLIENT_ID environment variable."),
        client_secret: env::var("MSGRAPH_CLIENT_SECRET")
            .expect("Missing the MSGRAPH_CLIENT_SECRET environment variable."),
        access_scopes: vec![
            "https://graph.microsoft.com/Files.Read".to_string(),
            "https://graph.microsoft.com/User.Read".to_string(),
            "https://graph.microsoft.com/Files.Read.All".to_string(),
        ],
        auto_open_auth_url: true,
        redirect_endpoint: Some("/redirect".to_string()),
        redirect_port: Some(8080),
    };

    // This token can then be used to start interacting with MSGraph
    println!(
        "Token={:?}",
        token_obtainer.get_token().unwrap().access_token()
    )
}
```

#### Interacting with OneDrive

Please examine the source code in [`codr`](https://github.com/PromH/codr) to see how that's using the package to interact with OneDrive.

## What uses this package?

This package was developed to aid [`codr`](https://github.com/PromH/codr) with interacting with OneDrive.

## Notes
> [!WARNING]
> This is my first Rust project so use with caution...
