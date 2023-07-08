//!
//! Code contained in the library is based on the oauth2-rs example for Microsoft Graph.
//! Link to example: https://github.com/ramosbugs/oauth2-rs/blob/main/examples/msgraph.rs
//! 

use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthType,
    AuthUrl,
    AuthorizationCode,
    ClientId,
    ClientSecret,
    CsrfToken,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    TokenUrl,
    TokenResponse,
};

use std::io::{ BufRead, BufReader, Write };
use std::net::TcpListener;
use url::Url;

// Constants
pub const GENERATE_MS_OAUTH2_CREDENTIALS_INSTRUCTIONS: &str = r#"
    Showcases the Microsoft Graph OAuth2 process for requesting access to Microsoft services using PKCE.
    Before running it, you'll need to generate your own Microsoft OAuth2 credentials. See
    https://docs.microsoft.com/azure/active-directory/develop/quickstart-register-app
    * Register a `Web` application with:
        - A `Redirect URI` of `http://localhost:<REDIRECT_PORT><REDIRECT_ENDPOINT>`
            - <REDIRECT_PORT> defaults to `8080`
            - <REDIRECT_ENDPOINT> defaults to `/redirect`
        - The supported account type: Accounts in any organizational directory and personal Microsoft accounts
    * In the left menu select `Overview`. Copy the `Application (client) ID` as the MSGRAPH_CLIENT_ID.
    * In the left menu select `Certificates & secrets` and add a new client secret. Copy the secret value
      as MSGRAPH_CLIENT_SECRET.
    * In the left menu select `API permissions` and add a permission. Select Microsoft Graph and
      `Delegated permissions`. Add the `Files.Read` permission (and other permissions as necessary).
"#; 
pub const API_BASE_URL: &str = "https://api.onedrive.com/v1.0/";
const AUTH_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const DEFAULT_BIND_PORT: u16 = 8080;
const DEFAULT_REDIRECT_ENDPOINT: &str = "/redirect";

// Structs and Traits
/// Custom Token Struct
pub struct Token {
    access_token: String,
}
impl Token {
    /// Returns a clone of the `access_token` attribute.
    pub fn access_token(&self) -> String {
        self.access_token.clone()
    }
}

/// Token Error Struct
#[derive(Debug)]
pub struct TokenError(String);

/// Trait for obtaining a token
pub trait TokenObtainer {
    /// Gets the Token
    fn get_token(&self) -> Result<Token, TokenError>;
}

/// Struct that implements TokenObtainer to get a token from Microsoft Graph
pub struct GraphTokenObtainer {
    /// The application ID (client ID) assigned by Microsoft's Azure app registration portal.
    pub client_id: String,
    /// A client secret (application password), a certificate, or a federated identity credential.
    pub client_secret: String,
    /// A vector of permissions that the application requires. See here: https://learn.microsoft.com/en-us/azure/active-directory/develop/permissions-consent-overview?WT.mc_id=Portal-Microsoft_AAD_RegisteredApps
    pub access_scopes: Vec<String>,
    // If true, automatically opens the generated authorization URL.
    pub auto_open_auth_url: bool, 
    /// Optional port to use for the local redirect server that gets started up.
    pub redirect_port: Option<u16>,
    /// Optional url path to use for handling incoming redirect requests (e.g. `/redirect`).
    pub redirect_endpoint: Option<String>,
}

impl TokenObtainer for GraphTokenObtainer {
    fn get_token(&self) -> Result<Token, TokenError> {
        let graph_client_id = ClientId::new(self.client_id.clone());
        let graph_client_secret = ClientSecret::new(self.client_secret.clone());
        let auth_url = AuthUrl::new(AUTH_URL.to_string()).expect(
            "Invalid authorization endpoint URL"
        );
        let token_url = TokenUrl::new(TOKEN_URL.to_string()).expect("Invalid token endpoint URL");

        // Redirect URL
        let redirect_port = match &self.redirect_port {
            Some(port) => { *port },
            None => { DEFAULT_BIND_PORT },
        };
        let redirect_endpoint = match &self.redirect_endpoint {
            Some(endpoint) => { endpoint.clone() },
            None => { DEFAULT_REDIRECT_ENDPOINT.to_string() },
        };
        let redirect_url = format!("http://{}:{}{}", "localhost", redirect_port, redirect_endpoint);
        log::debug!("redirect_url={:?}", redirect_url);

        // Set up the config for the Microsoft Graph OAuth2 process.
        let client = BasicClient::new(
            graph_client_id,
            Some(graph_client_secret),
            auth_url,
            Some(token_url)
        )
            // Microsoft Graph requires client_id and client_secret in URL rather than
            // using Basic authentication.
            .set_auth_type(AuthType::RequestBody)
            .set_redirect_uri(
                RedirectUrl::new(redirect_url.clone()).expect("Invalid redirect URL")
            );

        // Microsoft Graph supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
        // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the authorization URL to which we'll redirect the user.
        let mut auth_request = client.authorize_url(CsrfToken::new_random);
        for scope_string in self.access_scopes.iter() {
            auth_request = auth_request.add_scope(Scope::new(scope_string.to_string()));
        }
        let (authorize_url, csrf_state) = auth_request
            .set_pkce_challenge(pkce_code_challenge)
            .url();
    
        if self.auto_open_auth_url {
            println!("Opening the following URL:\n{}\n", authorize_url.to_string());
            open::that(authorize_url.to_string()).unwrap();
        } else {
            println!("Open this URL in your browser:\n{}\n", authorize_url.to_string());
        }

        // A very naive implementation of the redirect server.
        let listener = TcpListener::bind(
            format!("{}:{}", "127.0.0.1", redirect_port)
        ).unwrap();
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let code;
                let state;
                {
                    let mut reader = BufReader::new(&stream);

                    let mut request_line = String::new();
                    reader.read_line(&mut request_line).unwrap();

                    let redirect_endpoint = request_line.split_whitespace().nth(1).unwrap();
                    let url = Url::parse(
                        &("http://localhost".to_string() + redirect_endpoint)
                    ).unwrap();

                    let code_pair = url
                        .query_pairs()
                        .find(|pair| {
                            let &(ref key, _) = pair;
                            key == "code"
                        })
                        .unwrap();

                    let (_, value) = code_pair;
                    code = AuthorizationCode::new(value.into_owned());

                    let state_pair = url
                        .query_pairs()
                        .find(|pair| {
                            let &(ref key, _) = pair;
                            key == "state"
                        })
                        .unwrap();

                    let (_, value) = state_pair;
                    state = CsrfToken::new(value.into_owned());
                }

                let message = "Go back to your terminal :)";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    message.len(),
                    message
                );
                stream.write_all(response.as_bytes()).unwrap();

                log::debug!("MS Graph returned the following code:\n{}\n", code.secret());
                log::debug!(
                    "MS Graph returned the following state:\n{} (expected `{}`)\n",
                    state.secret(),
                    csrf_state.secret()
                );

                // Exchange the code with a token.
                let token = client
                    .exchange_code(code)
                    // Send the PKCE code verifier in the token request
                    .set_pkce_verifier(pkce_code_verifier)
                    .request(http_client);

                log::debug!("MS Graph returned the following token:\n{:?}\n", token);

                // The server will terminate itself after collecting the first code.
                return match token {
                    Ok(token_resp) =>
                        Ok(Token { access_token: token_resp.access_token().secret().to_string() }),
                    Err(_err) => Err(TokenError("Failed to obtain token ".to_string())),
                };
            }
        }
        Err(TokenError("Failed to obtain token".to_string()))
    }
}
