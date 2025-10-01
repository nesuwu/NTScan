mod args;
mod context;
mod model;
mod modes;
mod report;
mod scanner;
mod tui;

use anyhow::Result;

fn main() -> Result<()> {
    modes::run()
}
