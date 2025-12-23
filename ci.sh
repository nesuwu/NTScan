#!/bin/sh
# This script is compatible with both Bash and Zsh
set -e

echo "Running cargo fmt..."
cargo fmt --all -- --check

echo "Running cargo clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Running cargo test..."
cargo test --all-targets --all-features

echo "Running cargo build..."
cargo build --all-targets --all-features

echo "All CI checks passed! You are ready to push."
