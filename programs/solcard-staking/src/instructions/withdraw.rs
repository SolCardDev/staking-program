use anchor_lang::prelude::*;
use anchor_spl::token::{
    close_account, transfer_checked, CloseAccount, Mint, Token, TokenAccount, TransferChecked,
};

use crate::constants::{SOLC_MINT, STAKE_SEED, VAULT_SEED};
use crate::errors::StakingError;
use crate::state::StakeAccount;

/// Accounts for [`withdraw_handler`]. Drains the owner's vault, closes it, and closes
/// the stake.
///
/// `close = owner` runs after the handler returns: it drains the rent to `owner`,
/// zeroes the data and assigns the account to the system program, so the closed
/// account cannot be deserialized as a stake again even if someone refunds it.
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// Signs the withdrawal and receives the tokens and both accounts' reclaimed rent.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The one staked mint, fixed at compile time per cluster.
    #[account(address = SOLC_MINT)]
    pub mint: Account<'info, Mint>,

    /// The owner's live stake, closed here. `has_one` re-checks the stored owner
    /// independently of the seeds. It also signs the payout CPI, which is why the
    /// vault needs no separate authority.
    #[account(
        mut,
        close = owner,
        has_one = owner,
        seeds = [STAKE_SEED, owner.key().as_ref()],
        bump = stake_account.bump,
    )]
    pub stake_account: Account<'info, StakeAccount>,

    /// Destination. Pinned to the owner's ATA, so a withdrawal cannot be
    /// redirected to a third party's token account.
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = owner,
    )]
    pub owner_token_account: Account<'info, TokenAccount>,

    /// The owner's vault, emptied and closed here. Holding only this owner's
    /// tokens is what makes paying out its full balance safe.
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

/// Pays the owner's whole vault back and closes both the vault and the stake.
///
/// There is no partial withdraw. The payout is the vault's full balance rather
/// than the recorded `amount`: SPL `CloseAccount` refuses a non-empty account, so
/// paying `amount` and closing would let anyone brick a withdrawal by sending the
/// victim's vault one base unit. Anything donated to a vault is therefore paid to
/// that vault's owner.
///
/// Signer: `owner`, who receives the tokens and both accounts' reclaimed rent.
/// Enforces: `now >= lock_start + lock_duration`, recomputed here rather than
/// stored, so a backward clock correction denies the withdrawal instead of
/// mispaying it; and `vault balance >= amount`, which fails loudly rather than
/// paying out a short vault.
/// Errors: [`StakingError::LockNotExpired`], [`StakingError::VaultUnderfunded`],
/// [`StakingError::MathOverflow`].
pub fn withdraw_handler(ctx: Context<Withdraw>) -> Result<()> {
    let unlock = ctx
        .accounts
        .stake_account
        .lock_start
        .checked_add(ctx.accounts.stake_account.lock_duration)
        .ok_or(StakingError::MathOverflow)?;
    let now = Clock::get()?.unix_timestamp;
    require!(now >= unlock, StakingError::LockNotExpired);

    let payout = ctx.accounts.vault.amount;
    require!(
        payout >= ctx.accounts.stake_account.amount,
        StakingError::VaultUnderfunded
    );

    let owner_key = ctx.accounts.owner.key();
    let bump = ctx.accounts.stake_account.bump;
    let seeds: &[&[u8]] = &[STAKE_SEED, owner_key.as_ref(), &[bump]];
    let signer: &[&[&[u8]]] = &[seeds];

    let cpi = CpiContext::new_with_signer(
        ctx.accounts.token_program.key(),
        TransferChecked {
            from: ctx.accounts.vault.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.owner_token_account.to_account_info(),
            authority: ctx.accounts.stake_account.to_account_info(),
        },
        signer,
    );
    transfer_checked(cpi, payout, ctx.accounts.mint.decimals)?;

    // must follow the transfer: CloseAccount rejects a non-zero balance
    let cpi = CpiContext::new_with_signer(
        ctx.accounts.token_program.key(),
        CloseAccount {
            account: ctx.accounts.vault.to_account_info(),
            destination: ctx.accounts.owner.to_account_info(),
            authority: ctx.accounts.stake_account.to_account_info(),
        },
        signer,
    );
    close_account(cpi)?;
    Ok(())
}
