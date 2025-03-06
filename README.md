# icinga-client

A Rust library for sending reports to Icinga 2.

## Usage

First you need to create an `IcingaConfig` struct. We recommend to follow the convention and parse the struct from a TOML file:

```rust
struct MyAppConfig {
    icinga_client: icinga_client::IcingaConfig,
}

let content = fs::read_to_string(file)?;
let config: MyAppConfig = toml::from_str(&content)?;
```

Example TOML file:

```toml
[icinga_client]
TODO
```

When you have a config struct you can create an `IcingaClient` and send reports:

```rust
let icinga_client = icinga_client::IcingaClient::new(config.icinga_client)?;

icinga_client
    .report_to_icinga(&icinga_client::IcingaProcessResult {
        exit_status: icinga_client::IcingaState::Service(icinga_client::IcingaServiceState::Warning),
        plugin_output: "The service is having a problem".into(),
        filter: "host.name==\"some-host\" && service.name==\"some-service\"".into(),
        ..Default::default()
    })
    .await?;
```

## Samply bridgehead report convention

To attach a status report to a specific bridgehead, set a filter for `host.address` to equal the beam proxy ID of the bridgehead:

```rust
icinga_client
    .report_to_icinga(&icinga_client::IcingaProcessResult {
        exit_status: icinga_client::IcingaState::Service(icinga_client::IcingaServiceState::Ok),
        plugin_output: "The bridgehead has a valid git token".into(),
        filter: format!(
            "host.address==\"{}.{}\" && service.name==\"git-token-rotation\"",
            site,
            broker_id
        ),
        ..Default::default()
    })
    .await?;
```