//! Happy-path lifecycle: the ported `stake.test.ts` and `withdraw.test.ts`.
//!
//! The exploit suites live in exploits*.rs. Those assert what the program
//! REFUSES; this asserts that the thing they are protecting actually works,
//! which is what stops a suite from passing because everything reverts.

mod common;

use common::{assert_ix_custom_with_log, send, setup, try_send, GENESIS_TS};
use solana_signer::Signer;

const ONE_SOLC: u64 = 1_000_000_000;

#[test]
fn stake_locks_solc_and_records_the_stake() {
    let mut ctx = setup();
    let (owner, ata) = ctx.actor(10 * ONE_SOLC);

    let ix = ctx.stake_ix(&owner.pubkey(), &ata, 3 * ONE_SOLC, 60);
    send(&mut ctx.svm, &[ix], &[&owner]);

    let stake = ctx.stake_account(&owner.pubkey()).expect("stake account should exist");
    assert_eq!(stake.owner, owner.pubkey());
    assert_eq!(stake.amount, 3 * ONE_SOLC);
    assert_eq!(stake.lock_start, GENESIS_TS);
    assert_eq!(stake.lock_duration, 60);

    // The tokens moved into the owner's own vault rather than merely being recorded.
    assert_eq!(ctx.vault_balance(&owner.pubkey()), 3 * ONE_SOLC);
    assert_eq!(ctx.token_balance(&ata), 7 * ONE_SOLC);
}

#[test]
fn withdraw_is_rejected_before_the_lock_expires() {
    let mut ctx = setup();
    let (owner, ata) = ctx.actor(10 * ONE_SOLC);
    let ix = ctx.stake_ix(&owner.pubkey(), &ata, 3 * ONE_SOLC, 60);
    send(&mut ctx.svm, &[ix], &[&owner]);

    ctx.warp(59);
    let ix = ctx.withdraw_ix(&owner.pubkey(), &owner.pubkey(), &ata);
    let err = try_send(&mut ctx.svm, &[ix], &[&owner]).expect_err("one second early must fail");
    assert_ix_custom_with_log(&err, 0, 6003, "LockNotExpired");

    // Nothing moved.
    assert_eq!(ctx.vault_balance(&owner.pubkey()), 3 * ONE_SOLC);
    assert!(ctx.stake_account(&owner.pubkey()).is_some(), "stake must survive a failed withdraw");
}

#[test]
fn withdraw_after_the_lock_returns_funds_and_closes_the_account() {
    let mut ctx = setup();
    let (owner, ata) = ctx.actor(10 * ONE_SOLC);
    let ix = ctx.stake_ix(&owner.pubkey(), &ata, 3 * ONE_SOLC, 60);
    send(&mut ctx.svm, &[ix], &[&owner]);

    ctx.warp(60);
    let ix = ctx.withdraw_ix(&owner.pubkey(), &owner.pubkey(), &ata);
    send(&mut ctx.svm, &[ix], &[&owner]);

    assert_eq!(ctx.token_balance(&ata), 10 * ONE_SOLC, "principal returned in full");
    assert!(
        ctx.svm.get_account(&ctx.vault_pda(&owner.pubkey())).is_none_or(|a| a.lamports == 0),
        "vault should be closed, not merely drained"
    );
    assert!(ctx.stake_account(&owner.pubkey()).is_none(), "stake account should be closed");
}
