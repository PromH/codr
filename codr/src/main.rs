use clap::{Parser, Subcommand};
use onedrive::{
    CreateLinkRequest, GraphTokenObtainer, HttpClient, OneDriveClient, OneDriver, SharingLinkScope,
    SharingLinkType, TokenObtainer,
};
use reqwest::blocking;
use serde_derive::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::env;
use std::str::FromStr;
use std::time::SystemTime;

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

#[derive(Parser, Debug)]
#[command(name = "codr")]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
/// A CLI tool for interacting with OneDrive
/// but requires your own Microsoft OAuth2 Credentials (Application/Client ID and the Client Secret)
/// that contain the appropriate permissions to work with.
/// See here for instructions:  https://docs.microsoft.com/azure/active-directory/develop/quickstart-register-app
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

#[derive(Subcommand, Debug)]
/// Subcommands
enum SubCommand {
    /// Gets the requested object
    Get {
        #[command(subcommand)]
        /// Object to request from
        object: GetSubCommand,
    },
    /// Creates the requested object
    Create {
        #[command(subcommand)]
        /// Object to request from
        object: CreateSubCommand,
    },
}

#[derive(Subcommand, Deserialize, Serialize, Debug)]
/// `get` Subcommands
enum GetSubCommand {
    ///
    DriveItem {
        /// The system path to the driveitem (e.g. `Documents/folder/my_file_or_folder`)
        path: String,
    },
    ///
    DriveItemChildren {
        /// The system path to the driveitem that contains DriveItems as children (e.g. `Documents/folder/my_folder`)
        path: String,
    },
}

#[derive(Subcommand, Deserialize, Serialize, Debug)]
/// `create` Subcommands
enum CreateSubCommand {
    ///
    SharingLinks {
        /// The system path to the driveitem (e.g. `Documents/folder/my_file_or_folder`)
        path: String,
        #[serde(rename = "type")]
        /// The type of sharing link to create. Either view, edit, or embed.
        the_type: String,
        /// <Optional> The scope of link to create. Either anonymous or organization.
        scope: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
/// Configuration file struct
struct Config {
    msgraph_client_id: String,
    msgraph_client_secret: String,
}

/// `MyConfig` implements `Default`
impl ::std::default::Default for Config {
    fn default() -> Self {
        Self {
            msgraph_client_id: String::new(),
            msgraph_client_secret: String::new(),
        }
    }
}

fn main() {
    // Argument handling
    let args = Cli::parse();
    let log_level = args.log_level.unwrap_or(log::LevelFilter::Info);
    let mut client_id: String = args.client_id.unwrap_or_default();
    let mut client_secret: String = args.client_secret.unwrap_or_default();
    let config_file_path: String = args
        .config_file
        .unwrap_or_else(|| String::from(DEFAULT_CONFIG_FILE_PATH));

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
        client_id,
        client_secret,
        access_scopes: vec![
            "https://graph.microsoft.com/Files.Read".to_string(),
            "https://graph.microsoft.com/User.Read".to_string(),
            "https://graph.microsoft.com/Files.Read.All".to_string(),
            "https://graph.microsoft.com/Files.ReadWrite".to_string(),
            "https://graph.microsoft.com/Files.ReadWrite.All".to_string(),
            "https://graph.microsoft.com/Sites.ReadWrite.All".to_string(),
        ],
        auto_open_auth_url: true,
        redirect_endpoint: Some("/redirect".to_string()),
        redirect_port: Some(8080),
    };

    // Client
    let access_token = token_obtainer.get_token().unwrap().access_token();
    let http_client = HttpClient {
        client: blocking::Client::new(),
    };
    let client = OneDriveClient {
        access_token,
        http_handler: Box::new(http_client.borrow()),
        drive_id: None,
        group_id: None,
        site_id: None,
    };

    // Processing commands
    match args.command {
        // Get
        SubCommand::Get { object } => match object {
            GetSubCommand::DriveItem { path } => {
                let drive_item = client.get_drive_item(path.clone());
                match drive_item {
                    Ok(res) => println!("{:#?}", res),
                    Err(err) => panic!("Unable to get drive item from {} - {:?}", path, err),
                }
            }
            GetSubCommand::DriveItemChildren { path } => {
                let collection = client.get_drive_item_children(path.clone());
                match collection {
                    Ok(res) => println!("{:#?}", res),
                    Err(err) => panic!("Unable to get drive item from {} - {:?}", path, err),
                }
            }
        },
        // Create
        SubCommand::Create { object } => match object {
            CreateSubCommand::SharingLinks {
                path,
                the_type,
                scope,
            } => {
                let type_to_use = match SharingLinkType::from_str(the_type.as_str()) {
                    Ok(res) => res,
                    Err(_) => panic!("Invalid type provided for sharing links: {}", the_type),
                };
                let scope_to_use =
                    scope.map(
                        |the_scope| match SharingLinkScope::from_str(the_scope.as_str()) {
                            Ok(res) => res,
                            Err(_) => {
                                panic!("Invalid scope provided for sharing links: {}", the_scope)
                            }
                        },
                    );
                let link_request = CreateLinkRequest {
                    the_type: type_to_use,
                    scope: scope_to_use,
                };
                let links = client.create_sharing_links(path, link_request);
                println!("{:#?}", links.unwrap());
            }
        },
    }
}
