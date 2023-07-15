use clap::{ Parser, Subcommand };
use serde_derive::{Serialize, Deserialize};
use std::env;
use onedrive::{ GraphTokenObtainer, TokenObtainer };
use std::time::SystemTime;

use onedrive;

// Constants
const DEFAULT_CONFIG_FILE_PATH: &str = "config.yaml";

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

/// A CLI tool for interacting with OneDrive
#[derive(Parser, Debug)]
#[command(name = "codr")]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
struct Cli {
    #[command(subcommand)]
    /// The command to run
    command: SubCommand,
    #[arg(short = 'l', long, value_name = "LOG_LEVEL")]
    /// <Optional> The log level of the application (defaults to `Info`)
    log_level: Option<log::LevelFilter>,
    #[arg(short = 'i', long, value_name = "MSGRAPH_CLIENT_ID")]
    /// <Optional> The Microsoft Graph Application Client ID 
    /// 
    /// (Will look at using the `MSGRAPH_CLIENT_ID` environment variable if empty)
    client_id: Option<String>,
    #[arg(short = 's', long, value_name = "MSGRAPH_CLIENT_SECRET")]
    /// <Optional> The Microsoft Graph Application Client Secret 
    /// 
    /// (Will look at using the `MSGRAPH_CLIENT_SECRET` environment variable if empty)
    client_secret: Option<String>,
    #[arg(short = 'c', long, value_name = "CONFIG_FILE")]
    /// <Optional> The path to the YAML file that contains values for `MSGRAPH_CLIENT_ID` and `MSGRAPH_CLIENT_SECRET`
    config_file: Option<String>,
}

/// Subcommands
#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Gets the requested object
    Get {
        #[command(subcommand)]
        /// Object to request from
        object: GetSubCommand,
    },
}

/// `get` Subcommands
#[derive(Subcommand, Debug)]
enum GetSubCommand {
    ///
    DriveItems {
        /// The system path to the driveitem (e.g. `Documents/folder/my_file_or_folder`)
        path: String,
    },
    ///
    SharingLinks {
        /// The system path to the driveitem (e.g. `Documents/folder/my_file_or_folder`)
        path: String,
    },
}

/// Configuration file struct
#[derive(Serialize, Deserialize)]
struct Config {
    msgraph_client_id: String,
    msgraph_client_secret: String,
}

/// `MyConfig` implements `Default`
impl ::std::default::Default for Config {
    fn default() -> Self { Self { msgraph_client_id: String::new(), msgraph_client_secret: String::new() } }
}

fn main() {
    // Argument handling
    let args = Cli::parse();
    let log_level = args.log_level.unwrap_or(log::LevelFilter::Info);
    let mut client_id: String = args.client_id.unwrap_or_default();
    let mut client_secret: String = args.client_secret.unwrap_or_default();
    let config_file_path: String = args.config_file.unwrap_or(String::from(DEFAULT_CONFIG_FILE_PATH));

    // Loading configuration file
    let cfg: Config = confy::load_path(config_file_path).unwrap_or_default();
    if client_id == String::new() {
        client_id = cfg.msgraph_client_id;
    }
    if client_secret == String::new() {
        client_secret = cfg.msgraph_client_secret;
    }

    // Using environment variables - if nothing found
    if client_id == String::new() {
        client_id = env::var("MSGRAPH_CLIENT_ID")
            .expect("Missing the MSGRAPH_CLIENT_ID environment variable.");
    }
    if client_secret == String::new() {
        client_secret = env::var("MSGRAPH_CLIENT_SECRET")
            .expect("Missing the MSGRAPH_CLIENT_SECRET environment variable.");
    }

    // Logger Setup
    setup_logger(log_level).unwrap();

    // Token Obtainer
    let token_obtainer = GraphTokenObtainer {
        client_id: client_id,
        client_secret: client_secret,
        access_scopes: vec![
            "https://graph.microsoft.com/Files.Read".to_string(),
            "https://graph.microsoft.com/User.Read".to_string(),
            "https://graph.microsoft.com/Files.Read.All".to_string()
        ],
        auto_open_auth_url: true,
        redirect_endpoint: Some("/redirect".to_string()),
        redirect_port: Some(8080),
    };

    // Processing commands
    match args.command {
        // Get
        SubCommand::Get { object } => {
            match object {
                GetSubCommand::DriveItems { path } => {
                    println!("asdf");
                },
                GetSubCommand::SharingLinks { path } => {
                    println!("1234");
                },
            }
        },
    }
    // let access_token = token_obtainer.get_token().unwrap().access_token();
}
