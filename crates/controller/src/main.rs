#[tokio::main]
async fn main() -> Result<(), fuin_controller::controller::Error> {
    fuin_controller::controller::run().await
}
