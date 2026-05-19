#!/usr/bin/env fish
# This script is written for Fish shell

# Exit immediately if any command fails
# (Alternative to Bash 'set -e')
# Note: Fish natively halts multi-command chains linked with 'and'
# or you can handle errors manually per block.

echo "Running cargo fmt..."
cargo fmt --all -- --check

echo "Running cargo clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Running cargo test..."
cargo test --all-targets --all-features

echo "Running cargo build..."
cargo build --all-targets --all-features

echo "All CI checks passed! You are ready to push."
