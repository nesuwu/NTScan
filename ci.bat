@echo off
echo Running cargo fmt...
cargo fmt --all -- --check
if %errorlevel% neq 0 (
    echo Formatting check failed. Run 'cargo fmt' to fix it.
    exit /b %errorlevel%
)

echo Running cargo clippy...
cargo clippy --all-targets --all-features -- -D warnings
if %errorlevel% neq 0 (
    echo Clippy check failed. Fix the warnings above.
    exit /b %errorlevel%
)

echo Running cargo test...
cargo test --all-targets --all-features
if %errorlevel% neq 0 (
    echo Tests failed.
    exit /b %errorlevel%
)

echo Running cargo build...
cargo build --all-targets --all-features
if %errorlevel% neq 0 (
    echo Build failed.
    exit /b %errorlevel%
)

echo All CI checks passed! You are ready to push.
