use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};

use crate::constants::{MAX_LOCK_DURATION, SOLC_MINT, STAKE_SEED, VAULT_SEED};
use crate::errors::StakingError;
use crate::state::StakeAccount;

/// Accounts for [`stake_handler`]. Opens the owner's single [`StakeAccount`] and the
/// vault that holds only their tokens.
///
/// No account is caller-chosen: `mint` is pinned by address, `owner_token_account`
/// by its ATA derivation, and both PDAs by their seeds. `init` is what makes a
/// second concurrent stake for one owner impossible.
#[derive(Accounts)]
pub struct Stake<'info> {
    /// Signs the transfer and pays the stake account's rent; receives it back on withdraw.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The one staked mint, fixed at compile time per cluster.
    #[account(address = SOLC_MINT)]
    pub mint: Account<'info, Mint>,

    /// The owner's stake, created here. `init` (never `init_if_needed`) rejects a
    /// second stake while one is live, so no existing position can be overwritten.
    #[account(
        init,
        payer = owner,
        space = 8 + StakeAccount::INIT_SPACE,
        seeds = [STAKE_SEED, owner.key().as_ref()],
        bump,
    )]
    pub stake_account: Account<'info, StakeAccount>,

    /// Source of the tokens. Pinned to the owner's ATA, so the owner cannot fund a
    /// stake from an account they merely hold a delegation on.
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = owner,
    )]
    pub owner_token_account: Account<'info, TokenAccount>,

    /// The owner's vault, created here and held under their own stake account. A
    /// plain PDA token account, not an ATA: anyone may create another wallet's
    /// ATA, and `init` on an existing account fails, so an ATA vault would let a
    /// stranger block this stake for the price of rent.
    #[account(
        init,
        payer = owner,
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = stake_account,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// Pinned to the classic SPL Token program, which excludes Token-2022 and its extensions.
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// Locks `amount` SOLC for `lock_duration` seconds, opening the owner's stake.
///
/// Signer: `owner`, who also pays the stake account's and the vault's rent.
/// Enforces: one live stake per owner (`init`); `amount > 0`;
/// `0 < lock_duration <= MAX_LOCK_DURATION`; the unlock it writes is representable.
/// Errors: [`StakingError::InvalidAmount`], [`StakingError::InvalidLockDuration`],
/// [`StakingError::MathOverflow`].
pub fn stake_handler(ctx: Context<Stake>, amount: u64, lock_duration: i64) -> Result<()> {
    require!(amount > 0, StakingError::InvalidAmount);
    require!(
        lock_duration > 0 && lock_duration <= MAX_LOCK_DURATION,
        StakingError::InvalidLockDuration
    );

    let now = Clock::get()?.unix_timestamp;
    // overflow guard only; unlock is recomputed as lock_start + lock_duration at withdraw
    now.checked_add(lock_duration)
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
    stake_account.owner = ctx.accounts.owner.key();
    stake_account.amount = amount;
    stake_account.lock_start = now;
    stake_account.lock_duration = lock_duration;
    stake_account.bump = ctx.bumps.stake_account;
    Ok(())
}
