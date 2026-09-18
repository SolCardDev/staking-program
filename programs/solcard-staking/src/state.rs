use anchor_lang::prelude::*;

/// One active stake per user. PDA: `[STAKE_SEED, owner]`, created by `stake` and
/// closed by `withdraw`; a user with no live stake has no account.
///
/// Layout is frozen: there is no version field and no migration path, so a change
/// here means a new program id. Nothing derivable off-chain from these five
/// fields belongs in it.
///
/// Invariants across the account's life: `amount > 0`; `0 < lock_duration <=
/// MAX_LOCK_DURATION`; `lock_start + lock_duration` is representable in `i64`;
/// `lock_start <= now` at every write; and that sum, the unlock, never moves
/// earlier except under a backward clock correction via `relock`.
#[account]
#[derive(InitSpace)]
pub struct StakeAccount {
    /// The staker. Bound by the PDA seeds and re-checked via has_one on add_stake, relock and withdraw.
    pub owner: Pubkey,
    /// Staked SOLC amount in base units. Paid out in full, and only in full.
    pub amount: u64,
    /// Unix timestamp (seconds): amount-weighted start of the current term, moved
    /// by `add_stake` and `relock`, so it is not the first-stake date.
    pub lock_start: i64,
    /// Lock length in seconds. Withdrawable at lock_start + lock_duration.
    pub lock_duration: i64,
    /// Stored bump for the stake PDA, so later instructions do not re-derive it.
    pub bump: u8,
}
