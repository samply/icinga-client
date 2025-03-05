use std::{fmt::Display, path::PathBuf};

use base64::Engine;
use reqwest::{Certificate, Identity, Proxy, header};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Deserialize)]
pub struct IcingaConfig {
    icinga_url: String,
    ca_certificates: Option<PathBuf>,
    username: Option<String>,
    password: Option<String>,
    client_cert: Option<PathBuf>,
    client_cert_pass: Option<String>,
}

#[derive(Default, Debug, Clone, Copy, Serialize)]
pub enum IcingaType {
    Host,
    #[default]
    Service,
}

#[derive(Serialize_repr, Deserialize_repr, Default, Debug, Clone, Copy)]
#[repr(u8)]
pub enum IcingaServiceState {
    Ok = 0,
    Warning = 1,
    Critical = 2,
    #[default]
    Unknown = 3,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[repr(u8)]
pub enum IcingaHostState {
    Up = 0,
    Down = 1,
}

#[derive(Debug, Clone, Deserialize)]
struct IcingaReturn {
    results: Vec<IcingaResult>,
}

#[derive(Debug, Clone, Deserialize)]
struct IcingaResult {
    code: u32,
    status: String,
}

type Seconds = usize;
type Timestamp = u64;

#[derive(Default, Debug, Clone, Serialize)]
pub struct IcingaProcessResult {
    #[serde(rename = "type")]
    i_type: IcingaType,
    exit_status: IcingaServiceState,
    plugin_output: String,
    // Performance Data
    check_command: Option<Vec<String>>,
    check_source: Option<String>,
    execution_start: Option<Timestamp>,
    execution_end: Option<Timestamp>,
    ttl: Option<Seconds>,
    filter: String,
}

#[derive(Debug, Clone)]
enum IcingaError {
    SiteStatusNotify(String),
    HostMonitorNotify(String),
}
impl std::error::Error for IcingaError {}
impl Display for IcingaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SiteStatusNotify(err) => f.write_fmt(format_args!(
                "Error notifying site status to icinga: {}",
                err
            )),
            Self::HostMonitorNotify(err) => f.write_fmt(format_args!(
                "Error notifying host monitor status to icinga: {}",
                err
            )),
        }
    }
}

pub async fn report_to_icinga(
    config: &IcingaConfig,
    client: &reqwest::Client,
    result: &IcingaProcessResult,
) -> Result<(), eyre::Error> {
    println!("==REQ=> {}", serde_json::to_string(&result).unwrap());
    let res = client
        .post(format!(
            "{}/v1/actions/process-check-result",
            config.icinga_url
        ))
        .json(&result)
        .send()
        .await?;
    if res.status().is_success() {
        println!("<=RESP= {}", res.text().await?);
        Ok(())
    } else {
        Err(eyre::Report::new(IcingaError::HostMonitorNotify(format!(
            "Something went wrong while notifying icinga host monitor: {:?} - {}",
            res.status(),
            res.text().await?
        ))))
    }
}

pub fn reqwest_client_builder(config: &IcingaConfig) -> eyre::Result<reqwest::Client> {
    let tls_ca_certificates = load_certificates_from_dir(config.ca_certificates.clone())?;
    let client_cert = load_certificate_from_path(&config.client_cert, &config.client_cert_pass)?;

    let version = String::from(env!("CARGO_PKG_VERSION"));
    let user_agent = format!("ManagePKI/{}", version);
    let mut client = reqwest::Client::builder()
        .tcp_nodelay(true)
        .user_agent(user_agent);
    // Set client cert auth
    if let Some(cert) = client_cert {
        client = client.identity(cert);
    };
    let mut headers = header::HeaderMap::new();
    // Set headers for basic auth
    if let Some(username) = &config.username {
        let secret = format!(
            "{}:{}",
            username,
            config
                .password
                .clone()
                .expect("Icinga Username but no password given.")
        );
        let secret = base64::engine::general_purpose::STANDARD.encode(secret);
        let mut secret = header::HeaderValue::from_str(&format!("Basic {}", secret))?;
        secret.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, secret);
    }
    // Set Accept header
    let accept = header::HeaderValue::from_str("application/json")?;
    headers.insert(header::ACCEPT, accept);
    client = client.default_headers(headers);
    // Add trusted CA certs
    for cert in tls_ca_certificates {
        client = client.add_root_certificate(cert.to_owned());
    }
    // Pare proxy and no_proxy configuration
    let mut proxies: Vec<Proxy> = Vec::new();
    let no_proxy = reqwest::NoProxy::from_env();
    for var in ["http_proxy", "https_proxy", "all_proxy", "no_proxy"] {
        for (k, v) in std::env::vars().filter(|(k, _)| k.to_lowercase() == var) {
            unsafe { std::env::set_var(k.to_uppercase(), v.clone()) };
            match k.as_str() {
                "http_proxy" => proxies.push(Proxy::http(v)?.no_proxy(no_proxy.clone())),
                "https_proxy" => proxies.push(Proxy::https(v)?.no_proxy(no_proxy.clone())),
                "all_proxy" => proxies.push(Proxy::all(v)?.no_proxy(no_proxy.clone())),
                _ => (),
            };
        }
    }
    Ok(client.build()?)
}

fn load_certificates_from_dir(ca_dir: Option<PathBuf>) -> eyre::Result<Vec<Certificate>> {
    let mut result = Vec::new();
    if let Some(ca_dir) = ca_dir {
        for file in ca_dir.read_dir()? {
            //.map_err(|e| SamplyBeamError::ConfigurationFailed(format!("Unable to read from TLS CA directory {}: {}", ca_dir.to_string_lossy(), e)))
            let path = file?.path();
            let content = std::fs::read(&path)?;
            let cert = Certificate::from_pem(&content);
            if let Err(_e) = cert {
                continue;
            }
            result.push(cert.unwrap());
        }
    }
    Ok(result)
}

fn load_certificate_from_path(
    cert_file: &Option<PathBuf>,
    cert_pass: &Option<String>,
) -> eyre::Result<Option<Identity>> {
    match cert_file {
        Some(cert_file) => {
            let content = std::fs::read(cert_file)?;
            Ok(Some(Identity::from_pkcs12_der(
                &content,
                &cert_pass.clone().unwrap_or(String::new()),
            )?))
        }
        None => Ok(None),
    }
}
