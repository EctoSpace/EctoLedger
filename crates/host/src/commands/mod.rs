//! CLI command handlers — extracted from `main.rs` for maintainability.
//!
//! Each submodule corresponds to one (or a small group of related) CLI subcommands.
//! The `main()` function dispatches to these handlers after performing shared
//! setup (database, migrations, chain verification, platform sandbox).

pub mod anchor;
pub mod audit;
pub mod orchestrate;
pub mod prove;
pub mod report;
pub mod serve;
