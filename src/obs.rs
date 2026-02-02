// LOGGING 
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_observability() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false)) // Hides the module path for cleaner logs
        .with(EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into())
            .add_directive("phalanx=debug".parse().unwrap())) // Phalanx specific DEBUG logs
        .init();
}

