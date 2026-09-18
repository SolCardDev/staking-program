#![deny(unsafe_code)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]

//! Escrow for SolCard SOLC staking.
//!
//! Each staker's tokens sit in their OWN vault: a program-created token account
//! at the `["vault", owner]` PDA for the compiled-in [`constants::SOLC_MINT`],
//! held under that owner's [`state::StakeAccount`] PDA at `["stake", owner]`,
//! which holds `{owner, amount, lock_start, lock_duration}`.
//!
//! Four instructions, no admin, no pause, no partial withdraw, no events.
//! Tiers, multipliers and rewards are computed off-chain from the PDA; the
//! chain enforces only custody and the lock.
//!
//! Solvency rests on one property: `amount` changes only alongside a
//! `transfer_checked` of the same value in the same direction, so a vault's
//! balance is never below its own owner's `amount`. No staker's balance can be
//! reached by another staker's withdrawal at all.

use anchor_lang::prelude::*;

// localnet/devnet reuse 2RAS…, whose keypair is exposed; it must never be the mainnet id.
#[cfg(feature = "mainnet")]
declare_id!("EefJuupWjZbyqbKt11b1nn11nT57N7goeLg7CBA5E3rZ");
#[cfg(not(feature = "mainnet"))]
declare_id!("2RASqhcgpvvkqbkH6z7W3RSSpsvSRt4WCPvmqkccso8g");

pub mod constants;
pub mod errors;
pub mod instructions;
pub mod state;

pub use instructions::*;

#[program]
pub mod solcard_staking {
    use super::*;

    /// Locks `amount` SOLC for `lock_duration` seconds, opening the caller's stake.
    ///
    /// Signer: `owner`, who also pays the stake account's rent.
    /// Enforces: one live stake per owner; `amount > 0`; `0 < lock_duration <= MAX_LOCK_DURATION`.
    /// Errors: `InvalidAmount`, `InvalidLockDuration`, `MathOverflow`.
    pub fn stake(ctx: Context<Stake>, amount: u64, lock_duration: i64) -> Result<()> {
        instructions::stake::stake_handler(ctx, amount, lock_duration)
    }

    /// Adds `amount` SOLC to the caller's stake, keeping the term.
    ///
    /// Signer: `owner`.
    /// Enforces: at least half the term still remaining; the unlock moves later, never earlier.
    /// Errors: `InvalidAmount`, `AddRequiresRelock`, `MathOverflow`.
    pub fn add_stake(ctx: Context<Restake>, amount: u64) -> Result<()> {
        instructions::restake::add_stake_handler(ctx, amount)
    }

    /// Restarts the caller's lock at now with a term no shorter than the current one.
    ///
    /// Signer: `owner`. Moves no tokens.
    /// Enforces: `0 < lock_duration <= MAX_LOCK_DURATION`; the term never shortens; the unlock moves strictly later.
    /// Errors: `InvalidLockDuration`, `LockDowngraded`, `NoopRelock`, `MathOverflow`.
    pub fn relock(ctx: Context<Restake>, lock_duration: i64) -> Result<()> {
        instructions::restake::relock_handler(ctx, lock_duration)
    }

    /// Pays the caller's whole vault back and closes the vault and the stake account.
    ///
    /// Signer: `owner`, who receives the tokens and both accounts' reclaimed rent.
    /// Enforces: `now >= lock_start + lock_duration`; the payout is the vault's full balance,
    /// which must be at least the recorded `amount`.
    /// Errors: `LockNotExpired`, `VaultUnderfunded`, `MathOverflow`.
    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        instructions::withdraw::withdraw_handler(ctx)
    }
}
