use std::{fmt::Display, fs, path::PathBuf};

use base64::Engine;
use reqwest::{Certificate, Identity, Proxy, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IcingaConfig {
    icinga_url: String,
    ca_certificates: Option<PathBuf>,
    username: Option<String>,
    password: Option<String>,
    client_cert: Option<PathBuf>,
    client_cert_pass: Option<String>,
    max_days: i32,
    host_monitoring_name: String,
    broker_id: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RunStats {
    pub start: Timestamp,
    pub end: Timestamp,
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

async fn report_to_icinga(
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
        println!("<=RESP= {:?}", res.json::<IcingaReturn>().await?);
        Ok(())
    } else {
        Err(eyre::Report::new(IcingaError::HostMonitorNotify(format!(
            "Something went wrong while notifying icinga host monitor: {:?} - {}",
            res.status(),
            res.text().await?
        ))))
    }
}

pub(crate) async fn send_site_status(
    site: &str,
    expiry: i32,
    config: &IcingaConfig,
    stats: RunStats,
    client: &reqwest::Client,
) -> eyre::Result<bool> {
    let level = match expiry {
        ..=0 => IcingaServiceState::Critical,
        1.. if (1..config.max_days).contains(&expiry) => IcingaServiceState::Warning,
        _ => IcingaServiceState::Ok,
    };
    let output = format!(
        "The Beam certificate of {} expires in {} days",
        site, expiry
    );
    let result = IcingaProcessResult {
        exit_status: level,
        plugin_output: output,
        check_source: Some("Whatever".into()),
        execution_start: Some(stats.start),
        execution_end: Some(stats.end),
        filter: format!(
            "host.address==\"{}.{}\" && service.name == \"beam-cert-expiration\"",
            site, config.broker_id
        ),
        ..Default::default()
    };

    println!(
        "==REQ=> {}",
        serde_json::to_string(&result).unwrap_or("Failed to serialize".into())
    );

    let res = client
        .post(format!(
            "{}/v1/actions/process-check-result",
            config.icinga_url
        ))
        .json(&result)
        .send()
        .await?;
    match res.status() {
        x if x.is_success() => {
            println!("<=RESP= {:?}", res.json::<IcingaReturn>().await?);
            Ok(true)
        }
        StatusCode::INTERNAL_SERVER_ERROR => {
            let body = res.json::<IcingaReturn>().await?;
            if body.results.is_empty() {
                // notify_icinga_host(true, vec![site], config, client).await?;
                return Ok(false);
            }
            Err(eyre::Report::new(IcingaError::SiteStatusNotify(format!(
                "Error 500 while notifying icinga for site {} - {:?}",
                site, body
            ))))
        }
        StatusCode::NOT_FOUND => {
            println!("<=RESP= Site {site} not found in Icinga.");
            Ok(false)
        }
        code => Err(eyre::Report::new(IcingaError::SiteStatusNotify(format!(
            "Unknown Error while notifying icinga for site {} - {:?} - {}",
            site,
            code,
            res.text().await?
        )))),
    }
}

pub(crate) async fn send_overall_status(
    missing_sites: &mut [String],
    error_sites: &mut [(String, eyre::Report)],
    config: &IcingaConfig,
    client: &reqwest::Client,
) -> eyre::Result<()> {
    let (level, output) = match (missing_sites.len(), error_sites.len()) {
        (0, 0) => (
            IcingaServiceState::Ok,
            "All hosts present in Icinga.".to_string(),
        ),
        (missing, 0) => (
            IcingaServiceState::Warning,
            format!(
                "{} hosts are missing in Icinga: {}",
                missing,
                missing_sites.join(",")
            ),
        ),
        (missing, errors) => (
            IcingaServiceState::Critical,
            format!(
                "{missing} hosts are missing. Also, error during reporting {errors} sites ({}); for example, reason for site 0: {}",
                error_sites
                    .iter()
                    .map(|pair| pair.0.clone())
                    .collect::<Vec<_>>()
                    .join(","),
                error_sites.get(0).unwrap().1
            ),
        ),
    };

    report_to_icinga(
        config,
        client,
        &IcingaProcessResult {
            exit_status: IcingaServiceState::Ok,
            plugin_output: "Check has executed successfully.".into(),
            filter: format!(
                "host.name==\"{}\" && service.name == \"beam-cert-monitor\"",
                config.host_monitoring_name
            ),
            ..Default::default()
        },
    )
    .await?;

    report_to_icinga(
        config,
        client,
        &IcingaProcessResult {
            exit_status: level,
            plugin_output: output,
            filter: format!(
                "host.name==\"{}\" && service.name == \"beam-cert-monitor-missinghosts\"",
                config.host_monitoring_name
            ),
            ..Default::default()
        },
    )
    .await?;

    Ok(())
}

pub(crate) fn reqwest_client_builder(config: &IcingaConfig) -> eyre::Result<reqwest::Client> {
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

pub fn load_certificates_from_dir(ca_dir: Option<PathBuf>) -> eyre::Result<Vec<Certificate>> {
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

pub fn load_certificate_from_path(
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
