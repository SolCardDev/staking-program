use anchor_lang::prelude::*;

/// Program errors, surfaced on-chain as `Custom(6000 + discriminant)`.
///
/// Account substitution, a missing signer and a forged stored owner do not appear
/// here: those are rejected by Anchor's own constraint errors before a handler runs.
#[error_code]
pub enum StakingError {
    /// `stake` or `add_stake` was called with `amount == 0`.
    #[msg("Stake amount must be greater than zero")]
    InvalidAmount,
    /// `lock_duration` is not in `1..=MAX_LOCK_DURATION`.
    #[msg("Lock duration must be positive and within the allowed maximum")]
    InvalidLockDuration,
    /// A checked operation on a timestamp or an amount left the representable range.
    #[msg("Arithmetic overflow")]
    MathOverflow,
    /// `withdraw` before `lock_start + lock_duration`, including after a backward clock correction.
    #[msg("Lock period has not yet expired")]
    LockNotExpired,
    /// `relock` was given a term shorter than the current one.
    #[msg("Relock cannot shorten the lock term")]
    LockDowngraded,
    /// `relock` would not move the unlock later, so it would only shorten the served lock.
    #[msg("Relock must move the unlock time later")]
    NoopRelock,
    /// `add_stake` on a stake with less than half its term remaining, matured ones included.
    #[msg("Add requires at least half the lock term to remain; relock first")]
    AddRequiresRelock,
    /// `withdraw` found the owner's vault holding less than the recorded `amount`.
    #[msg("Vault holds less than the recorded stake amount")]
    VaultUnderfunded,
}
