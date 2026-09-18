use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};

use crate::constants::{MAX_LOCK_DURATION, SOLC_MINT, STAKE_SEED, VAULT_SEED};
use crate::errors::StakingError;
use crate::state::StakeAccount;

/// Accounts for [`add_stake_handler`] and [`relock_handler`], which share one struct so that
/// "add and extend" is a single transaction.
///
/// Both handlers only ever move tokens IN and never shorten a lock, so the
/// struct grants no capability `stake` does not already grant. `relock` moves no
/// tokens but still requires `owner_token_account` and `vault`; a user whose SOLC
/// ATA is closed must recreate it before relocking.
#[derive(Accounts)]
pub struct Restake<'info> {
    /// Signs the transfer and the state change. Pays no rent: the account exists.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The one staked mint, fixed at compile time per cluster.
    #[account(address = SOLC_MINT)]
    pub mint: Account<'info, Mint>,

    /// The owner's live stake. `has_one` re-checks the stored owner independently
    /// of the seeds, so a forged `owner` field is rejected on its own.
    #[account(
        mut,
        has_one = owner,
        seeds = [STAKE_SEED, owner.key().as_ref()],
        bump = stake_account.bump,
    )]
    pub stake_account: Account<'info, StakeAccount>,

    /// Source of an [`add_stake_handler`] transfer; unused by [`relock_handler`].
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = owner,
    )]
    pub owner_token_account: Account<'info, TokenAccount>,

    /// The owner's vault, opened by `stake`. Credited by [`add_stake_handler`];
    /// unused by [`relock_handler`].
    #[account(
        mut,
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = stake_account,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// Pinned to the classic SPL Token program, which excludes Token-2022 and its extensions.
    pub token_program: Program<'info, Token>,
}

/// Adds `amount` SOLC to the owner's stake without changing its term.
///
/// `lock_start` moves forward by the amount-weighted share of the elapsed time,
/// rounded up, so the unlock never moves earlier and the new tokens serve
/// `(A·remaining_old + a·lock_duration) / (A + a)` seconds. Allowed only while at
/// least half the term remains; otherwise [`relock_handler`] first.
///
/// Signer: `owner`.
/// Enforces: `amount > 0`; `remaining >= lock_duration / 2`; `lock_start` never
/// passes `now`; the unlock it writes is representable.
/// Errors: [`StakingError::InvalidAmount`], [`StakingError::AddRequiresRelock`],
/// [`StakingError::MathOverflow`].
pub fn add_stake_handler(ctx: Context<Restake>, amount: u64) -> Result<()> {
    require!(amount > 0, StakingError::InvalidAmount);

    let sa = &ctx.accounts.stake_account;
    let now = Clock::get()?.unix_timestamp;
    let old_unlock = sa
        .lock_start
        .checked_add(sa.lock_duration)
        .ok_or(StakingError::MathOverflow)?;
    // negative once matured, which the gate below rejects; only an i64 overflow errors here
    let remaining = old_unlock
        .checked_sub(now)
        .ok_or(StakingError::MathOverflow)?;
    // floor: an odd term rounds the gate toward requiring more remaining lock, not less
    #[allow(clippy::integer_division)]
    let half_term = sa.lock_duration / 2;
    require!(remaining >= half_term, StakingError::AddRequiresRelock);

    // clamped: a backward clock correction must not shift lock_start earlier
    let elapsed = u128::try_from(
        now.checked_sub(sa.lock_start)
            .ok_or(StakingError::MathOverflow)?
            .max(0),
    )
    .map_err(|_| StakingError::MathOverflow)?;
    // non-zero because amount > 0, which is what makes the div_ceil below infallible
    let total = u128::from(sa.amount)
        .checked_add(u128::from(amount))
        .ok_or(StakingError::MathOverflow)?;
    // (A + a) * remaining_new = A * remaining_old + a * lock_duration, rounded toward the later unlock
    let shift = elapsed
        .checked_mul(u128::from(amount))
        .ok_or(StakingError::MathOverflow)?
        .div_ceil(total);
    let new_amount = sa
        .amount
        .checked_add(amount)
        .ok_or(StakingError::MathOverflow)?;
    let new_lock_start = sa
        .lock_start
        .checked_add(i64::try_from(shift).map_err(|_| StakingError::MathOverflow)?)
        .ok_or(StakingError::MathOverflow)?;
    // withdraw recomputes this sum; leaving it unrepresentable would strand the stake forever
    new_lock_start
        .checked_add(sa.lock_duration)
        .ok_or(StakingError::MathOverflow)?;

    let cpi = CpiContext::new(
        ctx.accounts.token_program.key(),
        TransferChecked {
            from: ctx.accounts.owner_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
            authority: ctx.accounts.owner.to_account_info(),
        },
    );
    transfer_checked(cpi, amount, ctx.accounts.mint.decimals)?;

    let stake_account = &mut ctx.accounts.stake_account;
    stake_account.lock_start = new_lock_start;
    stake_account.amount = new_amount;
    Ok(())
}

/// Restarts the owner's lock at now with a term no shorter than the current one.
///
/// Moves no tokens and changes no balance. Allowed on a matured stake, where it
/// is a genuine fresh lock of the whole balance.
///
/// Signer: `owner`.
/// Enforces: `0 < lock_duration <= MAX_LOCK_DURATION`; the term never shortens;
/// the unlock moves strictly later.
/// Errors: [`StakingError::InvalidLockDuration`], [`StakingError::LockDowngraded`],
/// [`StakingError::NoopRelock`], [`StakingError::MathOverflow`].
pub fn relock_handler(ctx: Context<Restake>, lock_duration: i64) -> Result<()> {
    require!(
        lock_duration > 0 && lock_duration <= MAX_LOCK_DURATION,
        StakingError::InvalidLockDuration
    );
    let sa = &ctx.accounts.stake_account;
    require!(
        lock_duration >= sa.lock_duration,
        StakingError::LockDowngraded
    );

    let now = Clock::get()?.unix_timestamp;
    let old_unlock = sa
        .lock_start
        .checked_add(sa.lock_duration)
        .ok_or(StakingError::MathOverflow)?;
    let new_unlock = now
        .checked_add(lock_duration)
        .ok_or(StakingError::MathOverflow)?;
    require!(new_unlock > old_unlock, StakingError::NoopRelock);

    let stake_account = &mut ctx.accounts.stake_account;
    stake_account.lock_start = now;
    stake_account.lock_duration = lock_duration;
    Ok(())
}
