//! One module per accounts struct, each holding the handlers that struct serves,
//! so a reviewer reads an instruction's constraints and its logic together.
//!
//! The globs are load-bearing: `#[program]` resolves the `__client_accounts_*`
//! modules that `#[derive(Accounts)]` generates from the crate root.

pub mod restake;
pub mod stake;
pub mod withdraw;

pub use restake::*;
pub use stake::*;
pub use withdraw::*;
