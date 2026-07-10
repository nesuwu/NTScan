Write-Host "Running cargo fmt..." -ForegroundColor Cyan
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { Write-Error "Formatting check failed. Run 'cargo fmt' to fix it."; exit 1 }

Write-Host "Running cargo clippy..." -ForegroundColor Cyan
cargo clippy --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) { Write-Error "Clippy check failed. Fix the warnings above."; exit 1 }

Write-Host "Running cargo test..." -ForegroundColor Cyan
cargo test --all-targets --all-features
if ($LASTEXITCODE -ne 0) { Write-Error "Tests failed."; exit 1 }

Write-Host "Running cargo build..." -ForegroundColor Cyan
cargo build --all-targets --all-features
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed."; exit 1 }

Write-Host "All CI checks passed! You are ready to push." -ForegroundColor Green
