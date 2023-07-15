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

/// Represents an identity of an *actor*.
/// For example, an actor can be a user, device or application.
pub struct Identity {
    /// The identity's display name.
    pub display_name: String,
    /// Unique identifier for the identity.
    pub id: String,
}

/// A keyed collection of Identity resources.
/// It is used to represent a set of identities associated with various events for an item, such as
/// *created by* or *last modified by*.
pub struct IdentitySet {
    /// Optional. The application associated with this action.
    pub application: Option<Identity>,
    /// Optional. The device associated with this action.
    pub device: Option<Identity>,
    /// Optional. The group associated with this action.
    pub group: Option<Identity>,
    /// Optional. The user associated with this action.
    pub user: Option<Identity>,
}

/// Struct that groups the various identifiers for an item stored in a SharePoint site or OneDrive for Business.
pub struct SharePointIds {
    /// The unique identifier (guid) for the item's list in SharePoint.
    pub list_id: String,
    /// An integer identifier for the item within the containing list.
    pub list_item_id: String,
    /// The unique identifier (guid) for the item within OneDrive for Business or a SharePoint site.
    pub list_item_unique_id: String,
    /// The unique identifier (guid) for the item's site collection (SPSite).
    pub site_id: String,
    /// The SharePoint URL for the site that contains the item.
    pub site_url: String,
    /// The unique identifier (guid) for the tenancy.
    pub tenant_id: String,
    /// The unique identifier (guid) for the item's site (SPWeb).
    pub web_id: String,
}

/// Provides information necessary to address a DriveItem via the API.
pub struct ItemReference {
    /// Identifier of the drive instance that contains the item.
    pub drive_id: String,
    /// Identifies the type of drive. See drive resource for values.
    pub drive_type: String,
    /// Identifier of the item in the drive.
    pub id: String,
    /// Identifier of the list.
    pub list_id: String,
    /// The name of the item being referenced.
    pub name: String,
    /// Path that can be used to navigate to the item.
    pub path: String,
    /// Identifier for a shared resource that can be accessed via the Shares API.
    pub share_id: String,
    /// Identifiers useful for SharePoint REST compatibility.
    pub sharepoint_ids: SharePointIds,
    /// Identifier of the site.
    pub site_id: String,
}

/// An abstract resource that contains a common set of properties shared among several other resource types.
pub struct BaseItem {
    /// The unique identifier of the drive.
    pub id: String,
    /// Identity of the user, device, or application which created the item.
    pub created_by: IdentitySet,
    /// Date and time of item creation (ISO 8601 UTC).
    pub created_date_time: String,
    /// Provides a user-visible description of the item.
    pub description: String,
    /// ETag for the item.
    pub e_tag: String,
    /// Identity of the user, device, and application which last modified the item.
    pub last_modified_by: String,
    /// Date and time the item was last modified.
    pub last_modified_date_time: String,
    /// The name of the item.
    pub name: String,
    /// Parent information, if the item has a parent.
    pub parent_reference: ItemReference,
    /// URL that displays the resource in the browser.
    pub web_url: String,
}

/// Struct that groups audio related properties on an item.
pub struct Audio {
    /// The title of the album for this audio file.
    pub album: String,
    /// The artist named on the album for the audio file.
    pub album_artist: String,
    /// The performing artist for the audio file.
    pub artist: String,
    /// Bitrate expressed in kbps.
    pub bitrate: i64,
    /// The name of the composer of the audio file.
    pub composers: String,
    /// Copyright information for the audio file.
    pub copyright: String,
    /// The number of the disc this audio file came from.
    pub disc: i16,
    /// The total number of discs in this album.
    pub disc_count: i16,
    /// Duration of the audio file, expressed in milliseconds
    pub duration: i64,
    /// The genre of this audio file.
    pub genre: String,
    /// Indicates if the file is protected with digital rights management.
    pub has_drm: bool,
    /// Indicates if the file is encoded with a variable bitrate.
    pub is_variable_bitrate: bool,
    /// The title of the audio file.
    pub title: String,
    /// The number of the track on the original disc for this audio file.
    pub track: i32,
    /// The total number of tracks on the original disc for this audio file.
    pub track_count: i32,
    /// The year the audio file was recorded.
    pub year: i32,
}

/// Struct that indicates that the item has been deleted.
pub struct Deleted {
    /// Represents the state of the deleted item.
    pub state: String,
}

/// Struct that groups available hashes into a single structure for an item.
pub struct Hashes {
    /// (Hex string). SHA1 hash for the contents of the file (if available).
    pub sha1_hash: String,
    /// (Hex string). The CRC32 value of the file in little endian (if available).
    pub crc32_hash: String,
    /// (Base64 string). A proprietary hash of the file that can be used to determine if the contents of the file have changed (if available).
    pub quick_xor_hash: String,
}

/// Struct that groups file-related data items.
pub struct File {
    /// Hashes of the file's binary content, if available.
    pub hashes: Hashes,
    /// The MIME type for the file.
    /// This is determined by logic on the server and might not be the value provided when the file was uploaded.
    pub mime_type: String,
    /// Flag indicating if the item is still being processed to extract metadata
    pub processing_metadata: bool,
}

/// Struct that contains properties that are reported by the device's local file system for the local version of the item.
pub struct FileSystemInfo {
    /// The UTC date and time the file was created on a client.
    pub created_date_time: String,
    /// The UTC date and time the file was last accessed. Available for the recent file list only.
    pub last_accessed_date_time: String,
    /// The UTC date and time the file was last modified on a client.
    pub last_modified_date_time: String,
}

/// Struct that provides or sets recommendations on the user-experience of a folder.
pub struct FolderView {
    /// The method by which the folder should be sorted.
    pub sort_by: String,
    /// If true, indicates that items should be sorted in descending order. Otherwise, items should be sorted ascending.
    pub sort_order: String,
    /// The type of view that should be used to represent the folder.
    pub view_type: String,
}

/// Struct that groups folder-related data on an item.
pub struct Folder {
    /// Number of children contained immediately within this container.
    pub child_count: i32,
    /// A collection of properties defining the recommended view for the folder.
    pub view: FolderView,
}

/// Struct that groups image-related properties.
pub struct Image {
    /// Optional. Height of the image, in pixels.
    pub height: Option<i32>,
    /// Optional. Width of the image, in pixels.
    pub width: Option<i32>,
}

/// Struct that provides geographic coordinates and elevation of a location based on metadata contained within the file.
pub struct GeoCoordinates {
    /// Optional. The altitude (height), in feet, above sea level for the item.
    pub altitude: Option<f64>,
    /// Optional. The latitude, in decimal, for the item.
    pub latitude: Option<f64>,
    /// Optional. The longitude, in decimal, for the item.
    pub longitude: Option<f64>,
}

/// Struct that indicates the presence of malware.
/// The presence (non-null) of the resource indicates that item contains malware.
/// A null (or missing) value indicates that the item is clean.
///
/// **Note:** The resource is currently empty based on the API spec.
pub struct Malware {}

/// Indicates that a DriveItem is the top level item in a "package" or a collection of items that should be treated as a
/// collection instead of individual items.
pub struct Package {
    /// A string indicating the type of package.
    pub package_type: String,
}

/// Struct that provides photo and camera properties, for example, EXIF metadata, on a drive item.
pub struct Photo {
    /// Represents the date and time the photo was taken.
    pub taken_date_time: String,
    /// Camera manufacturer.
    pub camera_make: String,
    /// Camera model.
    pub camera_model: String,
    /// The F-stop value from the camera.
    pub f_number: f64,
    /// The denominator for the exposure time fraction from the camera.
    pub exposure_denominator: f64,
    /// The numerator for the exposure time fraction from the camera.
    pub exposure_numerator: f64,
    /// The focal length from the camera.
    pub focal_length: f64,
    /// The ISO value from the camera.
    pub iso: i32,
}

/// Struct that provides details on the published status of a drive item version or drive item resource.
pub struct PublicationFacet {
    /// The state of publication for this document. Either published or checkout.
    pub level: String,
    /// The unique identifier for the version that is visible to the current caller.
    pub version_id: String,
}

/// Struct that indicates a DriveItem has been shared with others.
/// The resource includes information about how the item is shared.
pub struct Shared {
    /// The identity of the owner of the shared item.
    pub owner: IdentitySet,
    /// Indicates the scope of how the item is shared: anonymous, organization, or users.
    pub scope: String,
    /// The identity of the user who shared the item.
    pub shared_by: IdentitySet,
    /// The UTC date and time when the item was shared.
    pub shared_date_time: String,
}

/// Struct that groups special folder-related data items into a single structure.
pub struct SpecialFolder {
    /// The unique identifier for this item in the /drive/special collection
    pub name: String,
}

/// Struct that indicates that a drive item references an item that exists in another drive.
/// This resource provides the unique IDs of the source drive and target item.
pub struct RemoteItem {
    /// The unique identifier of the drive.
    pub id: String,
    /// Identity of the user, device, or application which created the remote item.
    pub created_by: IdentitySet,
    /// Date and time of remote item creation (ISO 8601 UTC).
    pub created_date_time: String,
    /// File metadata, if the remote item is a file.
    pub file: Option<File>,
    /// File system information on client.
    pub file_system_info: Option<FileSystemInfo>,
    /// Folder metadata, if the remote item is a folder.
    pub folder: Option<Folder>,
    /// Identity of the user, device, and application which last modified the remote item.
    pub last_modified_by: String,
    /// Date and time the remote item was last modified.
    pub last_modified_date_time: String,
    /// The name of the remote item.
    pub name: String,
    /// If present, indicates that this remote item is a package instead of a folder or file.
    /// Packages are treated like files in some contexts and folders in others.
    pub package: Option<Package>,
    /// Parent information, if the remote item has a parent.
    pub parent_reference: ItemReference,
    /// Indicates that the remote item has been shared with others and provides information about the shared state of the remote item.
    pub shared: Option<Shared>,
    /// Identifiers useful for SharePoint REST compatibility.
    pub sharepoint_ids: SharePointIds,
    /// Size of the remote item in bytes.
    pub size: i64,
    /// If the current remote item is also available as a special folder, this facet is returned.
    pub special_folder: Option<SpecialFolder>,
    /// WebDAV compatible URL for the remote item.
    pub web_dav_url: Option<String>,
    /// URL that displays the resource in the browser.
    pub web_url: String,
}

/// Struct that indicates that an object is the top-most one in its hierarchy.
/// The presence (non-null) of the facet value indicates that the object is the root.
/// A null (or missing) value indicates the object is not the root.
pub struct Root {}

/// Struct that indicates than an item is the response to a search query.
pub struct SearchResult {
    /// A callback URL that can be used to record telemetry information.
    /// The application should issue a GET on this URL if the user interacts with this item to improve the quality of results.
    pub on_click_telemetry_url: String,
}

/// Struct that groups video-related data items into a single structure.
pub struct Video {
    /// Number of audio bits per sample.
    pub audio_bits_per_sample: i32,
    /// Number of audio channels.
    pub audio_channels: i32,
    /// Name of the audio format (AAC, MP3, etc.).
    pub audio_format: String,
    /// Number of audio samples per second.
    pub audio_samples_per_second: i32,
    /// Bit rate of the video in bits per second.
    pub bitrate: i32,
    /// Duration of the file in milliseconds.
    pub duration: i64,
    /// Four character code" name of the video format.
    pub four_cc: String,
    /// Frame rate of the video.
    pub frame_rate: f64,
    /// Height of the video, in pixels.
    pub height: i32,
    /// Width of the video, in pixels.
    pub width: i32,
}

/// Represents a file, folder, or other item stored in a drive, in OneDrive.
///
/// **Note**: This struct is partially implemented.
///
/// Missing the following properties:
/// - content
pub struct DriveItem {
    /// Common properties
    pub base_item: BaseItem,
    /// Audio metadata, if the item is an audio file.
    pub audio: Option<Audio>,
    /// An eTag for the content of the item.
    /// This eTag is not changed if only the metadata is changed.
    /// **Note** This property is not returned if the item is a folder.
    pub c_tag: String,
    /// Information about the deleted state of the item.
    pub deleted: Option<Deleted>,
    /// File metadata, if the item is a file.
    pub file: Option<File>,
    /// File system information on client.
    pub file_system_info: Option<FileSystemInfo>,
    /// Folder metadata, if the item is a folder.
    pub folder: Option<Folder>,
    /// Image metadata, if the item is an image.
    pub image: Option<Image>,
    /// Location metadata, if the item has location data.
    pub location: Option<GeoCoordinates>,
    /// Malware metadata, if the item was detected to contain malware.
    pub malware: Option<Malware>,
    /// If present, indicates that this item is a package instead of a folder or file.
    /// Packages are treated like files in some contexts and folders in others.
    pub package: Option<Package>,
    /// Photo metadata, if the item is a photo.
    pub photo: Option<Photo>,
    /// Provides information about the published or checked-out state of an item, in locations that support such actions.
    /// This property is not returned by default.
    pub publication: Option<PublicationFacet>,
    /// Remote item data, if the item is shared from a drive other than the one being accessed.
    pub remote_item: Option<RemoteItem>,
    /// If this property is non-null, it indicates that the driveItem is the top-most driveItem in the drive.
    pub root: Option<Root>,
    /// Search metadata, if the item is from a search result.
    pub search_result: Option<SearchResult>,
    /// Indicates that the item has been shared with others and provides information about the shared state of the item.
    pub shared: Option<Shared>,
    /// Size of the item in bytes.
    pub size: i64,
    /// If the current item is also available as a special folder, this facet is returned.
    pub special_folder: Option<SpecialFolder>,
    /// Video metadata, if the item is a video.
    pub video: Option<Video>,
    /// WebDAV compatible URL for the item.
    pub web_dav_url: Option<String>,
}

/// OneDrive Error Struct
#[derive(Debug)]
pub struct OneDriveError(String);

/// Trait that describe OneDrive related operations that can be performed
pub trait OneDriver {
    /// Gets the drive items from a path based on the provided item path
    fn get_drive_item(&self, item_path: String) -> Result<DriveItem, OneDriveError>;
    /// Gets the children of a drive item
    fn list_children_of_driveitem(&self, item_path: String) -> Result<DriveItem, OneDriveError>;
    /// Gets the sharing links from drive items based on the provided item path
    fn get_sharing_links(&self, item_path: String) -> Result<DriveItem, OneDriveError>;
}

/// Struct that provides a client that is able to perform OneDrive related operations
pub struct Client {
    /// The ID of the drive resource representing the user's OneDrive
    pub drive_id: Option<String>,
    /// The ID of the SharePoint site
    pub site_id: Option<String>,
    /// The ID of the group that is used to manage resources
    pub group_id: Option<String>,
    /// The access token that is required to make HTTP requests to the OneDrive API
    pub access_token: String,
}
