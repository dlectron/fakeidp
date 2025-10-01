use actix_4_jwt_auth::{Oidc, OidcConfig};
use actix_cors::Cors;
use actix_files as fs;
use actix_web::{middleware, web, App, HttpServer};
use biscuit::jws::Secret;
use clap::Parser;
use std::process::Command;

mod auth;
mod checks;
mod discovery;
mod errors;
mod token;
mod userinfo;

//AppState object is initialized for the App and passed with every request that has a parameter with the AppState as type.
pub struct AppState {
    rsa_key_pair: biscuit::jws::Secret,
    exposed_host: String,
}

impl AppState {
    pub fn new(rsa_keys: Secret, exposed_host: String) -> Self {
        Self {
            rsa_key_pair: rsa_keys.clone(),
            exposed_host: exposed_host.clone(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Location of the RSA DER keypair as a file
    keyfile: Option<String>,
    // default value "./keys/private_key.der"
    /// Sets the port to listen to
    #[arg(short = 'p', long, default_value = "8080")]
    bind_port: u16,
    //default value 8080
    /// Sets the host or IP number to bind to
    #[arg(short = 'b', long, default_value = "0.0.0.0")]
    bind_host: String,
    // Default value 0.0.0.0
    /// Full base URL of the host the service is found, like https://accounts.google.com
    #[arg(short = 'e', long, default_value = "http://localhost:8080")]
    exposed_host: String,
    // Default value http://localhost:8080
    /// Folder for the static files to serve
    #[arg(short = 'f', long, default_value = "./static")]
    folder: String,
    // default value './static'
}

/*
Profiling: http://carol-nichols.com/2015/12/09/rust-profiling-on-osx-cpu-time/
*/
#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let bind = format!("{}:{}", args.bind_host, args.bind_port);

    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    let default_keyfile = "./keys/private_key.der".to_string();
    let keyfile_to_use = &args.keyfile.unwrap_or_else(|| default_keyfile);
    let rsa_keys = Secret::rsa_keypair_from_file(keyfile_to_use).expect("Cannot read RSA keypair");

    let jwk_set = discovery::create_jwk_set(rsa_keys.clone());

    let oidc = Oidc::new(OidcConfig::Jwks(jwk_set)).await.unwrap();

    let mut user = String::from_utf8(Command::new("whoami").output().unwrap().stdout).unwrap();
    user.pop();
    println!("FakeIdP endpoint bound to {} as user {}!", bind, user);
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_header()
            .allow_any_method()
            .allow_any_origin();

        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(web::Data::new(web::JsonConfig::default().limit(4096)))
            .app_data(web::Data::new(AppState::new(
                rsa_keys.clone(),
                args.exposed_host.clone(),
            )))
            .app_data(oidc.clone())
            .service(web::resource("/auth/login").route(web::post().to(auth::login)))
            .service(web::resource("/auth").route(web::get().to(auth::auth)))
            .service(web::resource("/token").route(web::post().to(token::create_token)))
            .service(web::resource("/userinfo").route(web::get().to(userinfo::user_info)))
            .service(
                web::resource("/.well-known/openid-configuration")
                    .route(web::get().to(discovery::openid_configuration)),
            )
            .service(web::resource("/keys").route(web::get().to(discovery::keys)))
            .service(web::resource("/health").route(web::get().to(checks::check)))
            .service(fs::Files::new("/static", args.folder.as_str()).show_files_listing())
    })
    .shutdown_timeout(5)
    .bind(bind)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create_appstate() {
        let exposed_host = "http://localhost:8080".to_string();
        let rsa_keys = Secret::rsa_keypair_from_file("./keys/private_key.der")
            .expect("Cannot read RSA keypair");
        let _app_state = AppState::new(rsa_keys, exposed_host);
    }
}
