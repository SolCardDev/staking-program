//! `add_stake` and `relock`: a stake can only be upgraded. `add_stake` keeps the
//! term, moves `lock_start` forward by the amount-weighted elapsed time (rounded
//! up) and needs half the term left; `relock` restarts the lock with a term that
//! never shrinks.

mod common;

use common::*;

use anchor_lang::prelude::{Clock, Pubkey};
use anchor_lang::solana_program::program_pack::Pack;
use anchor_lang::{InstructionData, ToAccountMetas};
use anchor_spl::token::spl_token;
use litesvm::types::FailedTransactionMetadata;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solcard_staking::constants::MAX_LOCK_DURATION;

const ONE_SOLC: u64 = 1_000_000;
const LOCK: i64 = 100;
const STAKED: u64 = 3 * ONE_SOLC;
const FUNDED: u64 = 10 * ONE_SOLC;
const DAY: i64 = 24 * 60 * 60;

const INVALID_AMOUNT: u32 = 6000;
const INVALID_LOCK_DURATION: u32 = 6001;
const MATH_OVERFLOW: u32 = 6002;
const LOCK_NOT_EXPIRED: u32 = 6003;
const LOCK_DOWNGRADED: u32 = 6004;
const NOOP_RELOCK: u32 = 6005;
const ADD_REQUIRES_RELOCK: u32 = 6006;

struct Actor {
    kp: Keypair,
    ata: Pubkey,
}

impl Actor {
    fn pk(&self) -> Pubkey {
        self.kp.pubkey()
    }
}

fn make_actor(ctx: &mut Ctx, funded: u64) -> Actor {
    let (kp, ata) = ctx.actor(funded);
    Actor { kp, ata }
}

/// Full `Restake` account map, so a test can substitute exactly one account.
struct RestakeAccounts {
    owner: Pubkey,
    mint: Pubkey,
    stake_account: Pubkey,
    owner_token_account: Pubkey,
    vault: Pubkey,
    token_program: Pubkey,
}

impl RestakeAccounts {
    fn new(ctx: &Ctx, owner: &Actor) -> Self {
        Self {
            owner: owner.pk(),
            mint: ctx.mint,
            stake_account: ctx.stake_pda(&owner.pk()),
            owner_token_account: owner.ata,
            vault: ctx.vault_pda(&owner.pk()),
            token_program: spl_token::ID,
        }
    }

    fn metas(&self) -> Vec<AccountMeta> {
        solcard_staking::accounts::Restake {
            owner: self.owner,
            mint: self.mint,
            stake_account: self.stake_account,
            owner_token_account: self.owner_token_account,
            vault: self.vault,
            token_program: self.token_program,
        }
        .to_account_metas(None)
    }

    fn add_stake(&self, amount: u64) -> Instruction {
        Instruction {
            program_id: solcard_staking::ID,
            accounts: self.metas(),
            data: solcard_staking::instruction::AddStake { amount }.data(),
        }
    }

    fn relock(&self, lock_duration: i64) -> Instruction {
        Instruction {
            program_id: solcard_staking::ID,
            accounts: self.metas(),
            data: solcard_staking::instruction::Relock { lock_duration }.data(),
        }
    }
}

fn stake(ctx: &mut Ctx, actor: &Actor, amount: u64, lock: i64) {
    fresh_blockhash(ctx);
    let ix = ctx.stake_ix(&actor.pk(), &actor.ata, amount, lock);
    send(&mut ctx.svm, &[ix], &[&actor.kp]);
}

fn add_stake(ctx: &mut Ctx, actor: &Actor, amount: u64) {
    fresh_blockhash(ctx);
    let ix = ctx.add_stake_ix(&actor.pk(), &actor.ata, amount);
    send(&mut ctx.svm, &[ix], &[&actor.kp]);
}

fn relock(ctx: &mut Ctx, actor: &Actor, lock: i64) {
    fresh_blockhash(ctx);
    let ix = ctx.relock_ix(&actor.pk(), &actor.ata, lock);
    send(&mut ctx.svm, &[ix], &[&actor.kp]);
}

fn withdraw(ctx: &mut Ctx, actor: &Actor) {
    fresh_blockhash(ctx);
    let ix = ctx.withdraw_ix(&actor.pk(), &actor.pk(), &actor.ata);
    send(&mut ctx.svm, &[ix], &[&actor.kp]);
}

fn try_signed(ctx: &mut Ctx, actor: &Actor, ix: Instruction) -> FailedTransactionMetadata {
    fresh_blockhash(ctx);
    try_send(&mut ctx.svm, &[ix], &[&actor.kp]).expect_err("must be rejected")
}

fn try_add_stake(ctx: &mut Ctx, actor: &Actor, amount: u64) -> FailedTransactionMetadata {
    let ix = ctx.add_stake_ix(&actor.pk(), &actor.ata, amount);
    try_signed(ctx, actor, ix)
}

fn try_relock(ctx: &mut Ctx, actor: &Actor, lock: i64) -> FailedTransactionMetadata {
    let ix = ctx.relock_ix(&actor.pk(), &actor.ata, lock);
    try_signed(ctx, actor, ix)
}

fn try_withdraw(ctx: &mut Ctx, actor: &Actor) -> FailedTransactionMetadata {
    let ix = ctx.withdraw_ix(&actor.pk(), &actor.pk(), &actor.ata);
    try_signed(ctx, actor, ix)
}

fn now(ctx: &Ctx) -> i64 {
    ctx.svm.get_sysvar::<Clock>().unix_timestamp
}

fn set_clock(ctx: &mut Ctx, ts: i64) {
    let mut clock = ctx.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = ts;
    ctx.svm.set_sysvar(&clock);
}

/// ceil(max(elapsed, 0) * added / (staked + added)), computed independently of the program.
fn oracle_shift(elapsed: i64, staked: u64, added: u64) -> i64 {
    let numerator = elapsed.max(0) as u128 * added as u128;
    let denominator = staked as u128 + added as u128;
    ((numerator + denominator - 1) / denominator) as i64
}

/// Stake state plus the owner and vault balances, compared whole before/after a rejection.
#[derive(Debug, PartialEq)]
struct Snapshot {
    stake: Option<(Pubkey, u64, i64, i64, u8)>,
    owner_balance: u64,
    vault_balance: u64,
}

fn snapshot(ctx: &Ctx, actor: &Actor) -> Snapshot {
    Snapshot {
        stake: ctx
            .stake_account(&actor.pk())
            .map(|s| (s.owner, s.amount, s.lock_start, s.lock_duration, s.bump)),
        owner_balance: ctx.token_balance(&actor.ata),
        vault_balance: ctx.vault_balance(&actor.pk()),
    }
}

fn set_token_balance(ctx: &mut Ctx, account: &Pubkey, amount: u64) {
    let mut raw = ctx.svm.get_account(account).expect("token account must exist");
    let mut state = spl_token::state::Account::unpack(&raw.data).unwrap();
    state.amount = amount;
    spl_token::state::Account::pack(state, &mut raw.data).unwrap();
    ctx.svm.set_account(*account, raw).unwrap();
}

fn create_rogue_mint(ctx: &mut Ctx) -> Pubkey {
    let rogue = Keypair::new();
    let payer = ctx.payer.insecure_clone();
    let rent = ctx.svm.minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN);
    send(
        &mut ctx.svm,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &rogue.pubkey(),
                rent,
                spl_token::state::Mint::LEN as u64,
                &spl_token::ID,
            ),
            spl_token::instruction::initialize_mint2(&spl_token::ID, &rogue.pubkey(), &payer.pubkey(), None, SOLC_DECIMALS)
                .unwrap(),
        ],
        &[&payer, &rogue],
    );
    rogue.pubkey()
}

/// (amount, lock_start, lock_duration)
fn state(ctx: &Ctx, actor: &Actor) -> (u64, i64, i64) {
    let s = ctx.stake_account(&actor.pk()).expect("stake must exist");
    assert_eq!(s.owner, actor.pk());
    (s.amount, s.lock_start, s.lock_duration)
}

mod add_stake {
    use super::*;

    #[test]
    fn shifts_lock_start_by_the_amount_weighted_elapsed_time_and_keeps_the_term() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(40);

        add_stake(&mut ctx, &user, ONE_SOLC);

        // 40s elapsed, 1 of 4 SOLC is new: lock_start moves 10s.
        assert_eq!(state(&ctx, &user), (4 * ONE_SOLC, GENESIS_TS + 10, LOCK));
        assert_eq!(ctx.vault_balance(&user.pk()), 4 * ONE_SOLC);
        assert_eq!(ctx.token_balance(&user.ata), FUNDED - 4 * ONE_SOLC);
    }

    #[test]
    fn matches_a_u128_ceiling_oracle_at_the_extremes() {
        const E15: u64 = 1_000_000_000_000_000;
        const HALF_MAX_LOCK: i64 = MAX_LOCK_DURATION / 2;
        let half = u64::MAX / 2;
        let cases: [(u64, u64, i64, i64); 9] = [
            (E15, 1, HALF_MAX_LOCK, 1),
            (1, E15, HALF_MAX_LOCK, HALF_MAX_LOCK),
            (E15, 1, 1, 1),
            (1, E15, 0, 0),
            (E15, E15, 0, 0),
            (E15, E15, HALF_MAX_LOCK, 31_536_000),
            (half, half, HALF_MAX_LOCK, 31_536_000),
            (7, 3, 1_000, 300),
            (3, 7, 999, 700),
        ];
        for (staked, added, elapsed, expected) in cases {
            assert_eq!(oracle_shift(elapsed, staked, added), expected, "oracle for {staked}+{added} after {elapsed}s");

            let mut ctx = setup();
            let user = make_actor(&mut ctx, staked + added);
            stake(&mut ctx, &user, staked, MAX_LOCK_DURATION);
            ctx.warp(elapsed);
            add_stake(&mut ctx, &user, added);

            assert_eq!(
                state(&ctx, &user),
                (staked + added, GENESIS_TS + expected, MAX_LOCK_DURATION),
                "{staked}+{added} after {elapsed}s"
            );
            assert_eq!(ctx.vault_balance(&user.pk()), staked + added);
        }
    }

    #[test]
    fn lock_start_never_decreases_never_passes_now_and_the_unlock_never_moves_earlier() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, u64::MAX / 2);
        let term = 1_000_000;
        stake(&mut ctx, &user, 1_000, term);

        let steps: [(i64, u64); 9] = [
            (0, 1),
            (10, 5),
            (500, 1_000_000),
            (3, 1),
            (-50, 7),
            (2_000, 999),
            (1, u32::MAX as u64),
            (100_000, 1),
            (7, 1_000_000_000_000),
        ];
        for (warp, added) in steps {
            let (amount, lock_start, term) = state(&ctx, &user);
            ctx.warp(warp);
            let t = now(&ctx);
            add_stake(&mut ctx, &user, added);

            let (new_amount, new_lock_start, new_term) = state(&ctx, &user);
            assert_eq!(new_amount, amount + added);
            assert_eq!(new_term, term);
            assert_eq!(new_lock_start, lock_start + oracle_shift(t - lock_start, amount, added));
            assert!(new_lock_start >= lock_start, "lock_start moved back at step {warp}/{added}");
            if t >= lock_start {
                assert!(new_lock_start <= t, "lock_start passed now at step {warp}/{added}");
            } else {
                assert_eq!(new_lock_start, lock_start);
            }
            assert!(new_lock_start + new_term >= lock_start + term);
            assert_eq!(ctx.vault_balance(&user.pk()), new_amount);
        }
    }

    #[test]
    fn a_clock_behind_lock_start_adds_without_shifting() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        set_clock(&mut ctx, GENESIS_TS - 30);

        add_stake(&mut ctx, &user, ONE_SOLC);

        assert_eq!(state(&ctx, &user), (4 * ONE_SOLC, GENESIS_TS, LOCK));
    }

    #[test]
    fn withdraw_fails_before_the_shifted_unlock_and_returns_the_total_after() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(40);
        add_stake(&mut ctx, &user, ONE_SOLC);

        for ts in [GENESIS_TS + LOCK, GENESIS_TS + 10 + LOCK - 1] {
            set_clock(&mut ctx, ts);
            let before = snapshot(&ctx, &user);
            let err = try_withdraw(&mut ctx, &user);
            assert_ix_custom_with_log(&err, 0, LOCK_NOT_EXPIRED, "LockNotExpired");
            assert_eq!(snapshot(&ctx, &user), before);
        }

        set_clock(&mut ctx, GENESIS_TS + 10 + LOCK);
        withdraw(&mut ctx, &user);
        assert_eq!(ctx.token_balance(&user.ata), FUNDED);
        assert_eq!(ctx.vault_balance(&user.pk()), 0);
        assert!(ctx.stake_account(&user.pk()).is_none());
    }

    #[test]
    fn a_top_up_split_into_3000_parts_never_unlocks_earlier_than_a_single_add() {
        let cases: [(u64, u64, i64, i64); 3] = [
            (1_000_000, 1_000, 100_000, 40_000),
            (7, 1, 1_000_000, 499_999),
            (ONE_SOLC, 12_345, MAX_LOCK_DURATION, MAX_LOCK_DURATION / 2),
        ];
        for (staked, part, term, elapsed) in cases {
            let total = part * 3_000;
            let run = |split: bool| -> (u64, i64, i64) {
                let mut ctx = setup();
                let user = make_actor(&mut ctx, staked + total);
                stake(&mut ctx, &user, staked, term);
                ctx.warp(elapsed);
                if split {
                    for _ in 0..3_000 {
                        add_stake(&mut ctx, &user, part);
                    }
                } else {
                    add_stake(&mut ctx, &user, total);
                }
                assert_eq!(ctx.vault_balance(&user.pk()), staked + total);
                state(&ctx, &user)
            };
            let single = run(false);
            let split = run(true);

            assert_eq!((single.0, single.2), (split.0, split.2));
            assert!(
                split.1 >= single.1,
                "{staked} + 3000x{part} after {elapsed}s: split lock_start {} earlier than single {}",
                split.1,
                single.1
            );
        }
    }

    #[test]
    fn the_half_term_guard_boundary() {
        for (term, elapsed, ok) in [(100, 50, true), (100, 51, false), (101, 51, true), (101, 52, false)] {
            let mut ctx = setup();
            let user = make_actor(&mut ctx, FUNDED);
            stake(&mut ctx, &user, STAKED, term);
            ctx.warp(elapsed);
            let before = snapshot(&ctx, &user);

            if ok {
                add_stake(&mut ctx, &user, ONE_SOLC);
                assert_eq!(state(&ctx, &user).0, STAKED + ONE_SOLC, "term {term} elapsed {elapsed}");
            } else {
                let err = try_add_stake(&mut ctx, &user, ONE_SOLC);
                assert_ix_custom_with_log(&err, 0, ADD_REQUIRES_RELOCK, "AddRequiresRelock");
                assert_eq!(snapshot(&ctx, &user), before, "term {term} elapsed {elapsed}");
            }
        }
    }

    #[test]
    fn a_matured_stake_rejects_any_add() {
        for elapsed in [LOCK, LOCK + 1, 100 * LOCK] {
            for added in [1, 99 * ONE_SOLC] {
                let mut ctx = setup();
                let user = make_actor(&mut ctx, 100 * ONE_SOLC);
                stake(&mut ctx, &user, ONE_SOLC, LOCK);
                ctx.warp(elapsed);
                let before = snapshot(&ctx, &user);

                let err = try_add_stake(&mut ctx, &user, added);

                assert_ix_custom_with_log(&err, 0, ADD_REQUIRES_RELOCK, "AddRequiresRelock");
                assert_eq!(snapshot(&ctx, &user), before);
            }
        }
    }

    #[test]
    fn a_long_matured_stake_cannot_be_revived_by_a_large_add() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, 1_000_000 * ONE_SOLC);
        stake(&mut ctx, &user, ONE_SOLC, 180 * DAY);
        ctx.warp(365 * DAY);
        let before = snapshot(&ctx, &user);

        // Unguarded, this shift lands lock_start ~32s before now: a fresh 180-day term on a stake that matured 185 days ago.
        assert!(GENESIS_TS + oracle_shift(365 * DAY, ONE_SOLC, 999_999 * ONE_SOLC) + 180 * DAY > now(&ctx) + 179 * DAY);
        let err = try_add_stake(&mut ctx, &user, 999_999 * ONE_SOLC);
        assert_ix_custom_with_log(&err, 0, ADD_REQUIRES_RELOCK, "AddRequiresRelock");
        assert_eq!(snapshot(&ctx, &user), before);

        withdraw(&mut ctx, &user);
        assert_eq!(ctx.token_balance(&user.ata), 1_000_000 * ONE_SOLC);
    }

    #[test]
    fn daily_dust_adds_cannot_hold_the_remaining_lock_below_half_the_term() {
        let mut ctx = setup();
        let term = 30 * DAY;
        let user = make_actor(&mut ctx, 10_000 * ONE_SOLC);
        stake(&mut ctx, &user, 1_000 * ONE_SOLC, term);

        let mut first_rejection = None;
        for day in 1..=60 {
            ctx.warp(DAY);
            if ctx.stake_account(&user.pk()).is_none() {
                break;
            }
            let (_, lock_start, _) = state(&ctx, &user);
            let remaining = lock_start + term - now(&ctx);
            fresh_blockhash(&mut ctx);
            let ix = ctx.add_stake_ix(&user.pk(), &user.ata, 1);
            match try_send(&mut ctx.svm, &[ix], &[&user.kp]) {
                Ok(_) => {
                    assert!(remaining >= term / 2, "day {day}: add accepted with {remaining}s left");
                    assert!(first_rejection.is_none(), "day {day}: add accepted after a rejection");
                    let (_, new_start, _) = state(&ctx, &user);
                    assert!(new_start + term - now(&ctx) >= term / 2, "day {day}: add left less than half the term");
                }
                Err(err) => {
                    assert_ix_custom_with_log(&err, 0, ADD_REQUIRES_RELOCK, "AddRequiresRelock");
                    assert!(remaining < term / 2, "day {day}: rejected with {remaining}s left");
                    first_rejection.get_or_insert(day);
                }
            }
        }

        let first_rejection = first_rejection.expect("dust adds must eventually be refused");
        assert!(first_rejection <= 16, "dust adds kept the stake open until day {first_rejection}");
        let (_, lock_start, _) = state(&ctx, &user);
        set_clock(&mut ctx, lock_start + term);
        withdraw(&mut ctx, &user);
        assert_eq!(ctx.token_balance(&user.ata), 10_000 * ONE_SOLC);
    }

    #[test]
    fn a_whale_on_the_last_day_must_relock_before_adding() {
        let mut ctx = setup();
        let whale = make_actor(&mut ctx, 1_010_000 * ONE_SOLC);
        stake(&mut ctx, &whale, 10_000 * ONE_SOLC, 365 * DAY);
        ctx.warp(364 * DAY);
        let before = snapshot(&ctx, &whale);

        let err = try_add_stake(&mut ctx, &whale, 1_000_000 * ONE_SOLC);
        assert_ix_custom_with_log(&err, 0, ADD_REQUIRES_RELOCK, "AddRequiresRelock");
        assert_eq!(snapshot(&ctx, &whale), before);

        let accounts = RestakeAccounts::new(&ctx, &whale);
        fresh_blockhash(&mut ctx);
        send(&mut ctx.svm, &[accounts.relock(365 * DAY), accounts.add_stake(1_000_000 * ONE_SOLC)], &[&whale.kp]);

        assert_eq!(state(&ctx, &whale), (1_010_000 * ONE_SOLC, GENESIS_TS + 364 * DAY, 365 * DAY));
    }
}

mod add_stake_rejections {
    use super::*;

    fn staked_user() -> (Ctx, Actor, Snapshot) {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(40);
        let before = snapshot(&ctx, &user);
        (ctx, user, before)
    }

    #[test]
    fn rejects_a_zero_amount() {
        let (mut ctx, user, before) = staked_user();
        let err = try_add_stake(&mut ctx, &user, 0);
        assert_ix_custom_with_log(&err, 0, INVALID_AMOUNT, "InvalidAmount");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_more_than_the_owner_holds() {
        let (mut ctx, user, before) = staked_user();
        let err = try_add_stake(&mut ctx, &user, FUNDED - STAKED + 1);
        assert_ix_custom_with_log(&err, 0, 1, "insufficient funds");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_an_owner_meta_downgraded_to_non_signer() {
        let (mut ctx, victim, before) = staked_user();
        let attacker = make_actor(&mut ctx, FUNDED);

        let mut ix = RestakeAccounts::new(&ctx, &victim).add_stake(ONE_SOLC);
        let owner_meta = ix.accounts.iter_mut().find(|m| m.pubkey == victim.pk()).unwrap();
        assert!(owner_meta.is_signer);
        owner_meta.is_signer = false;
        let err = try_signed(&mut ctx, &attacker, ix);

        assert_ix_custom_with_log(&err, 0, 3010, "AccountNotSigner");
        assert_eq!(snapshot(&ctx, &victim), before);
    }

    #[test]
    fn rejects_a_signer_pointing_at_another_users_stake_pda() {
        let (mut ctx, victim, victim_before) = staked_user();
        let attacker = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &attacker, STAKED, LOCK);
        let attacker_before = snapshot(&ctx, &attacker);

        let mut accounts = RestakeAccounts::new(&ctx, &attacker);
        accounts.stake_account = ctx.stake_pda(&victim.pk());
        let err = try_signed(&mut ctx, &attacker, accounts.add_stake(ONE_SOLC));

        assert_ix_custom_with_log(&err, 0, 2006, "ConstraintSeeds");
        assert_eq!(snapshot(&ctx, &victim).stake, victim_before.stake);
        assert_eq!(snapshot(&ctx, &attacker), attacker_before);
    }

    #[test]
    fn rejects_a_foreign_mint() {
        let (mut ctx, user, before) = staked_user();
        let rogue = create_rogue_mint(&mut ctx);

        let mut accounts = RestakeAccounts::new(&ctx, &user);
        accounts.mint = rogue;
        let err = try_signed(&mut ctx, &user, accounts.add_stake(ONE_SOLC));

        assert_ix_custom_with_log(&err, 0, 2012, "ConstraintAddress");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_a_foreign_vault() {
        let (mut ctx, user, before) = staked_user();
        let attacker = make_actor(&mut ctx, FUNDED);

        let mut accounts = RestakeAccounts::new(&ctx, &user);
        accounts.vault = attacker.ata;
        let err = try_signed(&mut ctx, &user, accounts.add_stake(ONE_SOLC));

        assert_ix_custom_with_log(&err, 0, 2006, "ConstraintSeeds");
        assert_eq!(snapshot(&ctx, &user), before);
        assert_eq!(ctx.token_balance(&attacker.ata), FUNDED);
    }

    #[test]
    fn rejects_the_owner_ata_posing_as_the_vault() {
        let (mut ctx, user, before) = staked_user();

        // A self-transfer is an SPL no-op, so this would credit `amount` with nothing deposited.
        let mut accounts = RestakeAccounts::new(&ctx, &user);
        accounts.vault = user.ata;
        let err = try_signed(&mut ctx, &user, accounts.add_stake(ONE_SOLC));

        assert_ix_custom_with_log(&err, 0, 2040, "ConstraintDuplicateMutableAccount");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_a_substituted_token_program() {
        let (mut ctx, user, before) = staked_user();

        let mut accounts = RestakeAccounts::new(&ctx, &user);
        accounts.token_program = anchor_spl::token_2022::ID;
        let err = try_signed(&mut ctx, &user, accounts.add_stake(ONE_SOLC));

        assert_ix_custom_with_log(&err, 0, 3008, "InvalidProgramId");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_an_amount_overflow() {
        let mut ctx = setup();
        let whale = make_actor(&mut ctx, u64::MAX - 1000);
        stake(&mut ctx, &whale, u64::MAX - 1000, LOCK);
        ctx.warp(10);
        set_token_balance(&mut ctx, &whale.ata, 1001);
        let before = snapshot(&ctx, &whale);

        let err = try_add_stake(&mut ctx, &whale, 1001);

        assert_ix_custom_with_log(&err, 0, MATH_OVERFLOW, "MathOverflow");
        assert_eq!(snapshot(&ctx, &whale), before);

        add_stake(&mut ctx, &whale, 1000);
        // ceil(10s * 1000 / u64::MAX) = 1
        assert_eq!(state(&ctx, &whale), (u64::MAX, GENESIS_TS + 1, LOCK));
    }

    #[test]
    fn rejects_an_add_with_no_stake_account() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        let before = snapshot(&ctx, &user);

        let err = try_add_stake(&mut ctx, &user, ONE_SOLC);

        assert_ix_custom_with_log(&err, 0, 3012, "AccountNotInitialized");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_an_add_after_the_stake_was_withdrawn() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(LOCK);
        withdraw(&mut ctx, &user);
        let before = snapshot(&ctx, &user);

        let err = try_add_stake(&mut ctx, &user, ONE_SOLC);

        assert_ix_custom_with_log(&err, 0, 3012, "AccountNotInitialized");
        assert_eq!(snapshot(&ctx, &user), before);
    }
}

mod relock {
    use super::*;

    #[test]
    fn lengthens_the_term_and_restarts_the_lock_without_moving_tokens() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(40);

        relock(&mut ctx, &user, 2 * LOCK);

        assert_eq!(state(&ctx, &user), (STAKED, GENESIS_TS + 40, 2 * LOCK));
        assert_eq!(ctx.vault_balance(&user.pk()), STAKED);
        assert_eq!(ctx.token_balance(&user.ata), FUNDED - STAKED);
    }

    #[test]
    fn the_same_term_restarts_once_time_has_passed() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(1);

        relock(&mut ctx, &user, LOCK);

        assert_eq!(state(&ctx, &user), (STAKED, GENESIS_TS + 1, LOCK));
    }

    #[test]
    fn relocks_a_matured_stake() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(500);

        relock(&mut ctx, &user, LOCK);

        assert_eq!(state(&ctx, &user), (STAKED, GENESIS_TS + 500, LOCK));
        let before = snapshot(&ctx, &user);
        let err = try_withdraw(&mut ctx, &user);
        assert_ix_custom_with_log(&err, 0, LOCK_NOT_EXPIRED, "LockNotExpired");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn accepts_the_maximum_lock() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);

        relock(&mut ctx, &user, MAX_LOCK_DURATION);

        assert_eq!(state(&ctx, &user), (STAKED, GENESIS_TS, MAX_LOCK_DURATION));
    }

    #[test]
    fn withdraw_waits_for_the_new_unlock_then_returns_everything() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(90);
        relock(&mut ctx, &user, LOCK);

        for ts in [GENESIS_TS + LOCK, GENESIS_TS + 90 + LOCK - 1] {
            set_clock(&mut ctx, ts);
            let before = snapshot(&ctx, &user);
            let err = try_withdraw(&mut ctx, &user);
            assert_ix_custom_with_log(&err, 0, LOCK_NOT_EXPIRED, "LockNotExpired");
            assert_eq!(snapshot(&ctx, &user), before);
        }

        set_clock(&mut ctx, GENESIS_TS + 90 + LOCK);
        withdraw(&mut ctx, &user);
        assert_eq!(ctx.token_balance(&user.ata), FUNDED);
        assert_eq!(ctx.vault_balance(&user.pk()), 0);
    }
}

mod relock_rejections {
    use super::*;

    fn staked_user(elapsed: i64) -> (Ctx, Actor, Snapshot) {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(elapsed);
        let before = snapshot(&ctx, &user);
        (ctx, user, before)
    }

    #[test]
    fn rejects_a_shorter_term() {
        let (mut ctx, user, before) = staked_user(0);
        let err = try_relock(&mut ctx, &user, LOCK - 1);
        assert_ix_custom_with_log(&err, 0, LOCK_DOWNGRADED, "LockDowngraded");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_a_shorter_term_even_when_it_would_push_the_unlock_later() {
        // 20s remain; a 50s term unlocks 30s later than today, but the term itself shrinks.
        let (mut ctx, user, before) = staked_user(80);
        let err = try_relock(&mut ctx, &user, 50);
        assert_ix_custom_with_log(&err, 0, LOCK_DOWNGRADED, "LockDowngraded");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_a_shorter_term_on_a_matured_stake() {
        let (mut ctx, user, before) = staked_user(1_000);
        let err = try_relock(&mut ctx, &user, 50);
        assert_ix_custom_with_log(&err, 0, LOCK_DOWNGRADED, "LockDowngraded");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_the_same_term_in_the_same_second() {
        let (mut ctx, user, before) = staked_user(0);
        let err = try_relock(&mut ctx, &user, LOCK);
        assert_ix_custom_with_log(&err, 0, NOOP_RELOCK, "NoopRelock");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_an_unlock_that_does_not_move_later_under_a_clock_that_went_backwards() {
        let (mut ctx, user, before) = staked_user(0);
        set_clock(&mut ctx, GENESIS_TS - 10);

        for lock in [LOCK, LOCK + 9, LOCK + 10] {
            let err = try_relock(&mut ctx, &user, lock);
            assert_ix_custom_with_log(&err, 0, NOOP_RELOCK, "NoopRelock");
            assert_eq!(snapshot(&ctx, &user), before);
        }

        relock(&mut ctx, &user, LOCK + 11);
        assert_eq!(state(&ctx, &user), (STAKED, GENESIS_TS - 10, LOCK + 11));
    }

    #[test]
    fn rejects_a_zero_negative_and_over_maximum_lock() {
        let (mut ctx, user, before) = staked_user(40);
        for lock in [0, -1, MAX_LOCK_DURATION + 1] {
            let err = try_relock(&mut ctx, &user, lock);
            assert_ix_custom_with_log(&err, 0, INVALID_LOCK_DURATION, "InvalidLockDuration");
            assert_eq!(snapshot(&ctx, &user), before);
        }
    }

    #[test]
    fn rejects_an_unlock_overflow() {
        let (mut ctx, user, before) = staked_user(0);
        set_clock(&mut ctx, i64::MAX - LOCK + 1);
        let err = try_relock(&mut ctx, &user, LOCK);
        assert_ix_custom_with_log(&err, 0, MATH_OVERFLOW, "MathOverflow");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_an_owner_meta_downgraded_to_non_signer() {
        let (mut ctx, victim, before) = staked_user(40);
        let attacker = make_actor(&mut ctx, FUNDED);

        let mut ix = RestakeAccounts::new(&ctx, &victim).relock(MAX_LOCK_DURATION);
        let owner_meta = ix.accounts.iter_mut().find(|m| m.pubkey == victim.pk()).unwrap();
        owner_meta.is_signer = false;
        let err = try_signed(&mut ctx, &attacker, ix);

        assert_ix_custom_with_log(&err, 0, 3010, "AccountNotSigner");
        assert_eq!(snapshot(&ctx, &victim), before);
    }

    #[test]
    fn rejects_a_signer_pointing_at_another_users_stake_pda() {
        let (mut ctx, victim, before) = staked_user(40);
        let attacker = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &attacker, STAKED, LOCK);

        let mut accounts = RestakeAccounts::new(&ctx, &attacker);
        accounts.stake_account = ctx.stake_pda(&victim.pk());
        let err = try_signed(&mut ctx, &attacker, accounts.relock(MAX_LOCK_DURATION));

        assert_ix_custom_with_log(&err, 0, 2006, "ConstraintSeeds");
        assert_eq!(snapshot(&ctx, &victim).stake, before.stake);
    }

    #[test]
    fn rejects_a_foreign_mint() {
        let (mut ctx, user, before) = staked_user(40);
        let rogue = create_rogue_mint(&mut ctx);

        let mut accounts = RestakeAccounts::new(&ctx, &user);
        accounts.mint = rogue;
        let err = try_signed(&mut ctx, &user, accounts.relock(2 * LOCK));

        assert_ix_custom_with_log(&err, 0, 2012, "ConstraintAddress");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_a_foreign_vault() {
        let (mut ctx, user, before) = staked_user(40);
        let attacker = make_actor(&mut ctx, FUNDED);

        let mut accounts = RestakeAccounts::new(&ctx, &user);
        accounts.vault = attacker.ata;
        let err = try_signed(&mut ctx, &user, accounts.relock(2 * LOCK));

        assert_ix_custom_with_log(&err, 0, 2006, "ConstraintSeeds");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_the_owner_ata_posing_as_the_vault() {
        let (mut ctx, user, before) = staked_user(40);

        let mut accounts = RestakeAccounts::new(&ctx, &user);
        accounts.vault = user.ata;
        let err = try_signed(&mut ctx, &user, accounts.relock(2 * LOCK));

        assert_ix_custom_with_log(&err, 0, 2040, "ConstraintDuplicateMutableAccount");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_a_substituted_token_program() {
        let (mut ctx, user, before) = staked_user(40);

        let mut accounts = RestakeAccounts::new(&ctx, &user);
        accounts.token_program = anchor_spl::token_2022::ID;
        let err = try_signed(&mut ctx, &user, accounts.relock(2 * LOCK));

        assert_ix_custom_with_log(&err, 0, 3008, "InvalidProgramId");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_a_relock_after_the_stake_was_withdrawn() {
        let (mut ctx, user, _) = staked_user(LOCK);
        withdraw(&mut ctx, &user);
        let before = snapshot(&ctx, &user);

        let err = try_relock(&mut ctx, &user, 2 * LOCK);

        assert_ix_custom_with_log(&err, 0, 3012, "AccountNotInitialized");
        assert_eq!(snapshot(&ctx, &user), before);
    }

    #[test]
    fn rejects_a_relock_with_no_stake_account() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        let before = snapshot(&ctx, &user);

        let err = try_relock(&mut ctx, &user, LOCK);

        assert_ix_custom_with_log(&err, 0, 3012, "AccountNotInitialized");
        assert_eq!(snapshot(&ctx, &user), before);
    }
}

mod combined {
    use super::*;

    #[test]
    fn add_and_extend_in_the_first_half_is_order_independent() {
        let run = |add_first: bool| -> (u64, i64, i64, u64) {
            let mut ctx = setup();
            let user = make_actor(&mut ctx, FUNDED);
            stake(&mut ctx, &user, STAKED, LOCK);
            ctx.warp(40);
            let accounts = RestakeAccounts::new(&ctx, &user);
            let (add, extend) = (accounts.add_stake(2 * ONE_SOLC), accounts.relock(3 * LOCK));
            let ixs = if add_first { [add, extend] } else { [extend, add] };
            send(&mut ctx.svm, &ixs, &[&user.kp]);
            let (amount, lock_start, term) = state(&ctx, &user);
            (amount, lock_start, term, ctx.vault_balance(&user.pk()))
        };

        let add_then_extend = run(true);
        let extend_then_add = run(false);

        assert_eq!(add_then_extend, extend_then_add);
        assert_eq!(add_then_extend, (5 * ONE_SOLC, GENESIS_TS + 40, 3 * LOCK, 5 * ONE_SOLC));
    }

    #[test]
    fn in_the_second_half_relock_must_come_before_the_add() {
        let mut ctx = setup();
        let user = make_actor(&mut ctx, FUNDED);
        stake(&mut ctx, &user, STAKED, LOCK);
        ctx.warp(60);
        let accounts = RestakeAccounts::new(&ctx, &user);
        let before = snapshot(&ctx, &user);

        fresh_blockhash(&mut ctx);
        let err = try_send(&mut ctx.svm, &[accounts.add_stake(2 * ONE_SOLC), accounts.relock(LOCK)], &[&user.kp])
            .expect_err("add first must fail in the second half");
        assert_ix_custom_with_log(&err, 0, ADD_REQUIRES_RELOCK, "AddRequiresRelock");
        assert_eq!(snapshot(&ctx, &user), before);

        fresh_blockhash(&mut ctx);
        send(&mut ctx.svm, &[accounts.relock(LOCK), accounts.add_stake(2 * ONE_SOLC)], &[&user.kp]);
        assert_eq!(state(&ctx, &user), (5 * ONE_SOLC, GENESIS_TS + 60, LOCK));
        assert_eq!(ctx.vault_balance(&user.pk()), 5 * ONE_SOLC);
    }

    #[test]
    fn every_vault_equals_its_own_stake_across_two_interleaved_users() {
        let mut ctx = setup();
        let a = make_actor(&mut ctx, FUNDED);
        let b = make_actor(&mut ctx, FUNDED);
        let check = |ctx: &Ctx| {
            let mut sum = 0u64;
            for x in [&a, &b] {
                let stored = ctx.stake_account(&x.pk()).map(|s| s.amount).unwrap_or(0);
                assert_eq!(ctx.vault_balance(&x.pk()), stored, "vault of {} drifted", x.pk());
                sum += stored;
            }
            assert_eq!(ctx.token_balance(&a.ata) + ctx.token_balance(&b.ata) + sum, 2 * FUNDED);
        };

        stake(&mut ctx, &a, ONE_SOLC, LOCK);
        check(&ctx);
        stake(&mut ctx, &b, 2 * ONE_SOLC, 2 * LOCK);
        check(&ctx);
        ctx.warp(30);
        add_stake(&mut ctx, &a, 3 * ONE_SOLC);
        check(&ctx);
        relock(&mut ctx, &b, 3 * LOCK);
        check(&ctx);
        ctx.warp(2 * LOCK);
        withdraw(&mut ctx, &a);
        check(&ctx);
        relock(&mut ctx, &b, 3 * LOCK);
        add_stake(&mut ctx, &b, 1);
        check(&ctx);
        stake(&mut ctx, &a, 5 * ONE_SOLC, LOCK);
        check(&ctx);
        add_stake(&mut ctx, &a, ONE_SOLC);
        check(&ctx);
        ctx.warp(1);
        relock(&mut ctx, &a, LOCK);
        check(&ctx);
        ctx.warp(4 * LOCK);
        withdraw(&mut ctx, &b);
        check(&ctx);
        withdraw(&mut ctx, &a);
        check(&ctx);

        assert_eq!(ctx.vault_balance(&a.pk()), 0);
        assert_eq!(ctx.vault_balance(&b.pk()), 0);
        assert_eq!(ctx.token_balance(&a.ata), FUNDED);
        assert_eq!(ctx.token_balance(&b.ata), FUNDED);
    }
}
