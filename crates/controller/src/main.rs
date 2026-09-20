#[tokio::main]
async fn main() -> Result<(), fuin_controller::controller::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    fuin_controller::controller::run().await
}
