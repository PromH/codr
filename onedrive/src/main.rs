use onedrive::{GraphTokenObtainer, TokenObtainer, GENERATE_MS_OAUTH2_CREDENTIALS_INSTRUCTIONS};
use std::env;
use std::time::SystemTime;

/// Sets up the logger for the application
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

    println!("{}", GENERATE_MS_OAUTH2_CREDENTIALS_INSTRUCTIONS);

    // Setting up our struct that will obtain the msgraph token
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

    // Actually getting the token and printing it out
    println!(
        "Token={:?}",
        token_obtainer.get_token().unwrap().access_token()
    )
}
