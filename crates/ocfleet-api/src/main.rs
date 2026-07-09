use clap::Parser;
use ocfleet_api::{ApiCli, ApiConfig, AppState, build_router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ocfleet_api=info,tower_http=warn".into()),
        )
        .init();

    let config = ApiConfig::from_cli(ApiCli::parse())?;
    let listen = config.listen;
    let state = AppState::from_config(config);
    state.validate_startup()?;

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "starting read-only ocfleet API");
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}
