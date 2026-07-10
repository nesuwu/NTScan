// clippy 1.95 false positive: fires on scanner's WIDE_BUF thread_local even
// though its initializer already uses `const { }`. The attribute can't sit
// on the macro invocation itself (unused_attributes), so it lives here.
#![allow(clippy::missing_const_for_thread_local)]

pub mod args;
pub mod cache;
pub mod context;
pub mod duplicates;
pub mod engine;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod model;
#[cfg(feature = "tui")]
pub mod modes;
pub mod report;
pub mod scanner;
pub mod settings;
#[cfg(feature = "tui")]
pub mod tui;
pub mod util;
