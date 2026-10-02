//! Writes the wrapper fixture bundle to the path given by `--out`.
//!
//! Run before the TypeScript, Kotlin and Swift wrapper test suites: the
//! output is generated, not committed (see `.gitignore`). See
//! `test_fixtures::bundle` for the key contract.
//!
//! ```text
//! cargo run -p equs-test-fixtures --bin fixture_gen -- --out fixtures.generated.json
//! ```

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args()
        .skip_while(|a| a != "--out")
        .nth(1)
        .ok_or("usage: fixture_gen --out <path>")?;

    let bundle = test_fixtures::bundle::build().await?;
    std::fs::write(&out, serde_json::to_vec_pretty(&bundle)?)?;
    eprintln!("wrote {} fixtures to {out}", bundle.len());
    Ok(())
}
