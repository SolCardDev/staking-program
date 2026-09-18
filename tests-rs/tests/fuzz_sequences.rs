//! Stateful property fuzzing over randomized `stake` / `add_stake` / `relock` /
//! `withdraw` sequences, multiple actors, and randomized clock jumps.
//!
//! Every operation is predicted by a reference model before it is submitted, so
//! the suite asserts the exact outcome — success, or a specific `Custom(code)`
//! together with the log line naming the program that raised it — the exact
//! resulting account state, and that a rejected operation moved nothing. A
//! divergence either way is a finding: an operation the model expects to fail
//! that succeeds is an exploit, one it expects to succeed that fails is a
//! griefing or availability bug.
//!
//! On top of model equality the money invariants are asserted independently of
//! the model, so a bug mirrored into both still fails:
//!
//! 1. each owner's vault balance == their own live `StakeAccount.amount`, and
//!    total supply is conserved.
//! 2. a withdraw pays exactly what the account was funded with, never more.
//! 3. `lock_start + lock_duration` never moves earlier, `amount` and
//!    `lock_duration` never shrink, for the life of an account.
//! 4. the tranche inequality `amount · remaining ≥ Σ aᵢ · (L − (now − tᵢ))`:
//!    no interleaving beats honest fresh stakes of the same tokens. Both sides
//!    decay by `amount · Δt` as the clock moves, each `add_stake` raises the
//!    left by at least what it raises the right, and `relock` collapses the
//!    tranches into the fresh stake it is equivalent to — so it composes over
//!    any sequence.
//! 5. arithmetic: every rejection is a named error, never a panic.
//!
//! Generation is state-aware: amounts, lock durations and clock targets are
//! drawn from tables built around the acting account's own `(lock_start,
//! lock_duration)`, because the boundaries that matter — the `/2` truncation,
//! `div_ceil` residues, the unlock instant ± 1 s — are unreachable by uniform
//! random draws.

mod common;

use common::*;

use anchor_lang::prelude::{Clock, Pubkey};
use anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas};
use anchor_spl::token::spl_token;
use litesvm::types::FailedTransactionMetadata;
use proptest::prelude::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solcard_staking::constants::{MAX_LOCK_DURATION, STAKE_SEED};
use solcard_staking::state::StakeAccount;

const ONE_SOLC: u64 = 1_000_000;
const DAY: i64 = 24 * 60 * 60;
const FUNDED: u64 = 1_000 * ONE_SOLC;
const ACTORS: usize = 3;
/// Upper bound on generated clocks: far past any lock the program accepts, and
/// far short of the i64 corner where `add_stake` stops being safe.
const CLOCK_MAX: i64 = GENESIS_TS + 1_000 * 365 * DAY;

// Program errors.
const INVALID_AMOUNT: u32 = 6000;
const INVALID_LOCK_DURATION: u32 = 6001;
const MATH_OVERFLOW: u32 = 6002;
const LOCK_NOT_EXPIRED: u32 = 6003;
const LOCK_DOWNGRADED: u32 = 6004;
const NOOP_RELOCK: u32 = 6005;
const ADD_REQUIRES_RELOCK: u32 = 6006;

// Anchor framework errors.
const CONSTRAINT_HAS_ONE: u32 = 2001;
const CONSTRAINT_SEEDS: u32 = 2006;
const ACCOUNT_NOT_INITIALIZED: u32 = 3012;

// spl-token / system program.
const TOKEN_INSUFFICIENT_FUNDS: u32 = 1;
const ACCOUNT_ALREADY_IN_USE: u32 = 0;

/// Every code the suite pins, with the log needle proving which program raised
/// it. `Custom(0)` and `Custom(1)` are ambiguous across programs, so the needle
/// is what makes the assertion mean something.
fn needle(code: u32) -> &'static str {
    match code {
        INVALID_AMOUNT => "Error Code: InvalidAmount.",
        INVALID_LOCK_DURATION => "Error Code: InvalidLockDuration.",
        MATH_OVERFLOW => "Error Code: MathOverflow.",
        LOCK_NOT_EXPIRED => "Error Code: LockNotExpired.",
        LOCK_DOWNGRADED => "Error Code: LockDowngraded.",
        NOOP_RELOCK => "Error Code: NoopRelock.",
        ADD_REQUIRES_RELOCK => "Error Code: AddRequiresRelock.",
        CONSTRAINT_HAS_ONE => "Error Code: ConstraintHasOne.",
        CONSTRAINT_SEEDS => "Error Code: ConstraintSeeds.",
        ACCOUNT_NOT_INITIALIZED => "Error Code: AccountNotInitialized.",
        TOKEN_INSUFFICIENT_FUNDS => "Error: insufficient funds",
        ACCOUNT_ALREADY_IN_USE => "already in use",
        other => panic!("no log needle pinned for Custom({other})"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Ok,
    Custom(u32),
}

fn outcome_label(o: Outcome) -> String {
    match o {
        Outcome::Ok => "ok".to_string(),
        Outcome::Custom(c) => c.to_string(),
    }
}

fn op_label(op: Op) -> &'static str {
    match op {
        Op::Stake { .. } => "stake",
        Op::Add { .. } => "add",
        Op::Relock { .. } => "relock",
        Op::Withdraw { .. } => "withdraw",
        Op::SetClock { .. } => "clock",
        Op::CrossWithdraw { .. } | Op::CrossAdd { .. } | Op::CrossRelock { .. } => "cross",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Live {
    amount: u64,
    lock_start: i64,
    lock_duration: i64,
}

impl Live {
    fn unlock(&self) -> Option<i64> {
        self.lock_start.checked_add(self.lock_duration)
    }
}

/// ceil(max(elapsed, 0) · added / (staked + added)), in u128 so the intermediate
/// product cannot wrap. Independent of the program's expression of the same rule.
fn shift_oracle(elapsed: i64, staked: u64, added: u64) -> u128 {
    let e = elapsed.max(0) as u128;
    let total = staked as u128 + added as u128;
    let numerator = e * added as u128;
    numerator.div_ceil(total)
}

#[derive(Clone, Debug, Default)]
struct ActorModel {
    live: Option<Live>,
    /// Tokens moved into the vault by the CURRENT account instance.
    instance_deposited: u64,
    /// `(amount, deposited_at)` per deposit into the current instance.
    tranches: Vec<(u64, i64)>,
    deposited_lifetime: u128,
    withdrawn_lifetime: u128,
    /// Watermarks for the current instance, for the monotonicity invariant.
    max_unlock: i64,
    max_amount: u64,
    max_duration: i64,
}

impl ActorModel {
    fn open(&mut self, live: Live, now: i64) {
        self.live = Some(live);
        self.instance_deposited = live.amount;
        self.tranches = vec![(live.amount, now)];
        self.deposited_lifetime += live.amount as u128;
        self.max_unlock = live.unlock().expect("a fresh stake cannot overflow");
        self.max_amount = live.amount;
        self.max_duration = live.lock_duration;
    }

    fn close(&mut self) {
        let paid = self.live.take().expect("close of an absent stake").amount;
        self.withdrawn_lifetime += paid as u128;
        self.instance_deposited = 0;
        self.tranches.clear();
        self.max_unlock = 0;
        self.max_amount = 0;
        self.max_duration = 0;
    }

    fn observe(&mut self) {
        let live = self.live.expect("observe of an absent stake");
        self.max_unlock = self.max_unlock.max(live.unlock().expect("live unlock must fit"));
        self.max_amount = self.max_amount.max(live.amount);
        self.max_duration = self.max_duration.max(live.lock_duration);
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Stake { who: usize, amount: u64, lock: i64 },
    Add { who: usize, amount: u64 },
    Relock { who: usize, lock: i64 },
    Withdraw { who: usize },
    SetClock { to: i64 },
    /// `who` signs but the instruction is pointed at `victim`'s stake PDA.
    CrossWithdraw { who: usize, victim: usize },
    CrossAdd { who: usize, victim: usize, amount: u64 },
    CrossRelock { who: usize, victim: usize, lock: i64 },
}

struct Actor {
    kp: Keypair,
    ata: Pubkey,
}

#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    balances: Vec<u64>,
    vaults: Vec<u64>,
    stakes: Vec<Option<(Pubkey, u64, i64, i64, u8)>>,
}

struct World {
    ctx: Ctx,
    actors: Vec<Actor>,
    model: Vec<ActorModel>,
    minted: u64,
    /// Reproduction trace: printed verbatim on any failure.
    trace: Vec<String>,
    /// `"<op>:<code>"` for every outcome reached, so a coverage test can prove
    /// the generator is not passing vacuously.
    seen: std::collections::BTreeSet<String>,
}

fn restake_metas(
    ctx: &Ctx,
    owner: &Pubkey,
    ata: &Pubkey,
    stake_account: Pubkey,
    vault: Pubkey,
) -> Vec<AccountMeta> {
    solcard_staking::accounts::Restake {
        owner: *owner,
        mint: ctx.mint,
        stake_account,
        owner_token_account: *ata,
        vault,
        token_program: spl_token::ID,
    }
    .to_account_metas(None)
}

impl World {
    fn new() -> Self {
        let mut ctx = setup();
        let mut actors = Vec::new();
        for _ in 0..ACTORS {
            let (kp, ata) = ctx.actor(FUNDED);
            actors.push(Actor { kp, ata });
        }
        World {
            ctx,
            actors,
            model: vec![ActorModel::default(); ACTORS],
            minted: FUNDED * ACTORS as u64,
            trace: vec![format!("// {ACTORS} actors, {FUNDED} base units each, clock at {GENESIS_TS}")],
            seen: std::collections::BTreeSet::new(),
        }
    }

    fn now(&self) -> i64 {
        self.ctx.svm.get_sysvar::<Clock>().unix_timestamp
    }

    fn balance(&self, who: usize) -> u64 {
        self.ctx.token_balance(&self.actors[who].ata)
    }

    fn vault(&self, who: usize) -> u64 {
        self.ctx.vault_balance(&self.actors[who].kp.pubkey())
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            balances: (0..ACTORS).map(|i| self.balance(i)).collect(),
            vaults: (0..ACTORS).map(|i| self.vault(i)).collect(),
            stakes: (0..ACTORS)
                .map(|i| {
                    self.ctx
                        .stake_account(&self.actors[i].kp.pubkey())
                        .map(|s| (s.owner, s.amount, s.lock_start, s.lock_duration, s.bump))
                })
                .collect(),
        }
    }

    #[track_caller]
    fn fail(&self, what: &str) -> ! {
        panic!("{what}\n\nreproduction:\n{}\n", self.trace.join("\n"));
    }

    // ------------------------------------------------------------------
    // Prediction
    // ------------------------------------------------------------------

    /// The outcome and, on success, the exact post-state.
    fn predict(&self, op: Op) -> (Outcome, Option<Live>) {
        let now = self.now();
        match op {
            Op::Stake { who, amount, lock } => {
                if self.model[who].live.is_some() {
                    return (Outcome::Custom(ACCOUNT_ALREADY_IN_USE), None);
                }
                if amount == 0 {
                    return (Outcome::Custom(INVALID_AMOUNT), None);
                }
                if lock <= 0 || lock > MAX_LOCK_DURATION {
                    return (Outcome::Custom(INVALID_LOCK_DURATION), None);
                }
                if now.checked_add(lock).is_none() {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                }
                if amount > self.balance(who) {
                    return (Outcome::Custom(TOKEN_INSUFFICIENT_FUNDS), None);
                }
                (Outcome::Ok, Some(Live { amount, lock_start: now, lock_duration: lock }))
            }
            Op::Add { who, amount } => {
                let Some(live) = self.model[who].live else {
                    return (Outcome::Custom(ACCOUNT_NOT_INITIALIZED), None);
                };
                if amount == 0 {
                    return (Outcome::Custom(INVALID_AMOUNT), None);
                }
                let Some(old_unlock) = live.unlock() else {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                };
                let Some(remaining) = old_unlock.checked_sub(now) else {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                };
                if remaining < live.lock_duration / 2 {
                    return (Outcome::Custom(ADD_REQUIRES_RELOCK), None);
                }
                let Some(elapsed) = now.checked_sub(live.lock_start) else {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                };
                let shift = shift_oracle(elapsed, live.amount, amount);
                let Some(new_amount) = live.amount.checked_add(amount) else {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                };
                let shift_i64 = match i64::try_from(shift) {
                    Ok(v) => v,
                    Err(_) => return (Outcome::Custom(MATH_OVERFLOW), None),
                };
                let Some(new_start) = live.lock_start.checked_add(shift_i64) else {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                };
                if new_start.checked_add(live.lock_duration).is_none() {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                }
                if amount > self.balance(who) {
                    return (Outcome::Custom(TOKEN_INSUFFICIENT_FUNDS), None);
                }
                (
                    Outcome::Ok,
                    Some(Live { amount: new_amount, lock_start: new_start, lock_duration: live.lock_duration }),
                )
            }
            Op::Relock { who, lock } => {
                let Some(live) = self.model[who].live else {
                    return (Outcome::Custom(ACCOUNT_NOT_INITIALIZED), None);
                };
                if lock <= 0 || lock > MAX_LOCK_DURATION {
                    return (Outcome::Custom(INVALID_LOCK_DURATION), None);
                }
                if lock < live.lock_duration {
                    return (Outcome::Custom(LOCK_DOWNGRADED), None);
                }
                let Some(old_unlock) = live.unlock() else {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                };
                let Some(new_unlock) = now.checked_add(lock) else {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                };
                if new_unlock <= old_unlock {
                    return (Outcome::Custom(NOOP_RELOCK), None);
                }
                (Outcome::Ok, Some(Live { amount: live.amount, lock_start: now, lock_duration: lock }))
            }
            Op::Withdraw { who } => {
                let Some(live) = self.model[who].live else {
                    return (Outcome::Custom(ACCOUNT_NOT_INITIALIZED), None);
                };
                let Some(unlock) = live.unlock() else {
                    return (Outcome::Custom(MATH_OVERFLOW), None);
                };
                if now < unlock {
                    return (Outcome::Custom(LOCK_NOT_EXPIRED), None);
                }
                (Outcome::Ok, None)
            }
            Op::SetClock { .. } => (Outcome::Ok, None),
            Op::CrossWithdraw { .. } | Op::CrossAdd { .. } | Op::CrossRelock { .. } => {
                (Outcome::Custom(CONSTRAINT_SEEDS), None)
            }
        }
    }

    fn instruction(&self, op: Op) -> Option<(Instruction, usize)> {
        let ctx = &self.ctx;
        Some(match op {
            Op::Stake { who, amount, lock } => (
                ctx.stake_ix(&self.actors[who].kp.pubkey(), &self.actors[who].ata, amount, lock),
                who,
            ),
            Op::Add { who, amount } => {
                (ctx.add_stake_ix(&self.actors[who].kp.pubkey(), &self.actors[who].ata, amount), who)
            }
            Op::Relock { who, lock } => {
                (ctx.relock_ix(&self.actors[who].kp.pubkey(), &self.actors[who].ata, lock), who)
            }
            Op::Withdraw { who } => {
                let pk = self.actors[who].kp.pubkey();
                (ctx.withdraw_ix(&pk, &pk, &self.actors[who].ata), who)
            }
            Op::SetClock { .. } => return None,
            Op::CrossWithdraw { who, victim } => (
                ctx.withdraw_ix(
                    &self.actors[who].kp.pubkey(),
                    &self.actors[victim].kp.pubkey(),
                    &self.actors[who].ata,
                ),
                who,
            ),
            Op::CrossAdd { who, victim, amount } => (
                Instruction {
                    program_id: solcard_staking::ID,
                    accounts: restake_metas(
                        ctx,
                        &self.actors[who].kp.pubkey(),
                        &self.actors[who].ata,
                        ctx.stake_pda(&self.actors[victim].kp.pubkey()),
                        ctx.vault_pda(&self.actors[victim].kp.pubkey()),
                    ),
                    data: solcard_staking::instruction::AddStake { amount }.data(),
                },
                who,
            ),
            Op::CrossRelock { who, victim, lock } => (
                Instruction {
                    program_id: solcard_staking::ID,
                    accounts: restake_metas(
                        ctx,
                        &self.actors[who].kp.pubkey(),
                        &self.actors[who].ata,
                        ctx.stake_pda(&self.actors[victim].kp.pubkey()),
                        ctx.vault_pda(&self.actors[victim].kp.pubkey()),
                    ),
                    data: solcard_staking::instruction::Relock { lock_duration: lock }.data(),
                },
                who,
            ),
        })
    }

    // ------------------------------------------------------------------
    // Execution
    // ------------------------------------------------------------------

    fn apply(&mut self, op: Op) {
        if let Op::SetClock { to } = op {
            self.trace.push(format!("set_clock({to});"));
            let mut clock = self.ctx.svm.get_sysvar::<Clock>();
            clock.unix_timestamp = to;
            self.ctx.svm.set_sysvar(&clock);
            self.check_invariants("after a clock move");
            return;
        }

        let now = self.now();
        self.trace.push(format!("// now = {now}\n{op:?};"));
        self.seen.insert(format!("{}:{}", op_label(op), outcome_label(self.predict(op).0)));
        let before = self.snapshot();
        let (expected, post) = self.predict(op);
        let (ix, signer) = self.instruction(op).expect("non-clock ops have an instruction");

        // LiteSVM drops a byte-identical transaction before the program runs.
        fresh_blockhash(&mut self.ctx);
        let kp = self.actors[signer].kp.insecure_clone();
        let result = try_send(&mut self.ctx.svm, &[ix], &[&kp]);

        match (&result, expected) {
            (Ok(_), Outcome::Ok) => {}
            (Err(err), Outcome::Custom(code)) => {
                let want = format!("InstructionError(0, Custom({code}))");
                if !err_text(err).contains(&want) {
                    self.fail(&format!(
                        "expected {want}, got {}\nlogs:\n{}",
                        err_text(err),
                        log_text(err)
                    ));
                }
                let n = needle(code);
                if !log_text(err).contains(n) {
                    self.fail(&format!("expected {n:?} in the logs of {want}, got:\n{}", log_text(err)));
                }
            }
            (Ok(_), Outcome::Custom(code)) => self.fail(&format!(
                "the model expected Custom({code}) ({}), but {op:?} SUCCEEDED",
                needle(code)
            )),
            (Err(err), Outcome::Ok) => self.fail(&format!(
                "the model expected success, but {op:?} was rejected with {}\nlogs:\n{}",
                err_text(err),
                log_text(err)
            )),
        }

        if let Err(err) = &result {
            let text = err_text(err);
            if text.contains("ProgramFailedToComplete") || log_text(err).contains("panicked") {
                self.fail(&format!("{op:?} panicked instead of returning an error: {text}\nlogs:\n{}", log_text(err)));
            }
            let after = self.snapshot();
            if after != before {
                self.fail(&format!("a rejected {op:?} changed state:\nbefore {before:?}\nafter  {after:?}"));
            }
            self.check_invariants("after a rejection");
            return;
        }

        match op {
            Op::Stake { who, amount, .. } => {
                let live = post.expect("a successful stake has a post-state");
                self.model[who].open(live, now);
                self.assert_owner_debited(who, &before, amount, "stake");
            }
            Op::Add { who, amount } => {
                let live = post.expect("a successful add has a post-state");
                let old = self.model[who].live.expect("add requires a live stake");
                self.assert_add_economics(who, old, live, amount, now);
                self.model[who].live = Some(live);
                self.model[who].instance_deposited += amount;
                self.model[who].tranches.push((amount, now));
                self.model[who].deposited_lifetime += amount as u128;
                self.model[who].observe();
                self.assert_owner_debited(who, &before, amount, "add_stake");
            }
            Op::Relock { who, .. } => {
                let live = post.expect("a successful relock has a post-state");
                self.model[who].live = Some(live);
                // relock is honest-equivalent to a fresh stake of the whole balance at `now`.
                self.model[who].tranches = vec![(live.amount, now)];
                self.model[who].observe();
                if self.balance(who) != before.balances[who] || self.vault(who) != before.vaults[who] {
                    self.fail("relock moved tokens");
                }
            }
            Op::Withdraw { who } => {
                let funded = self.model[who].instance_deposited;
                let paid = self.balance(who) - before.balances[who];
                if paid != funded {
                    self.fail(&format!(
                        "withdraw paid {paid} but the account was funded with {funded}"
                    ));
                }
                if before.vaults[who] - self.vault(who) != funded {
                    self.fail("the vault debit does not match the payout");
                }
                if self.ctx.svm.get_account(&self.ctx.vault_pda(&self.actors[who].kp.pubkey()))
                    .is_some_and(|a| a.lamports != 0)
                {
                    self.fail("withdraw left the vault behind");
                }
                if self.ctx.stake_account(&self.actors[who].kp.pubkey()).is_some() {
                    self.fail("withdraw left the stake account behind");
                }
                self.model[who].close();
            }
            Op::SetClock { .. } | Op::CrossWithdraw { .. } | Op::CrossAdd { .. } | Op::CrossRelock { .. } => {
                self.fail("a cross-account operation must never succeed")
            }
        }

        self.assert_chain_matches_model();
        self.check_invariants("after a successful operation");
    }

    fn assert_owner_debited(&self, who: usize, before: &Snapshot, amount: u64, what: &str) {
        if before.balances[who] - self.balance(who) != amount {
            self.fail(&format!("{what} did not debit the owner by exactly {amount}"));
        }
        if self.vault(who) - before.vaults[who] != amount {
            self.fail(&format!("{what} did not credit the vault by exactly {amount}"));
        }
    }

    /// Per-operation economics of `add_stake`, stated independently of the
    /// program's expression of the rule.
    fn assert_add_economics(&self, who: usize, old: Live, new: Live, added: u64, now: i64) {
        let l = old.lock_duration as i128;
        let r_old = old.unlock().expect("old unlock fits") as i128 - now as i128;
        let r_new = new.unlock().expect("new unlock fits") as i128 - now as i128;
        let a_old = old.amount as i128;
        let total = new.amount as i128;

        if new.lock_duration != old.lock_duration {
            self.fail("add_stake changed the term");
        }
        // Property 3: the unlock never moves earlier.
        if new.unlock().unwrap() < old.unlock().unwrap() {
            self.fail("add_stake moved the unlock earlier");
        }
        // Property 4, per operation: the weighted commitment never falls short
        // of honest. The upper bound holds only once the term has started —
        // under a clock behind `lock_start` the elapsed clamp makes `r_old`
        // exceed `L`, so the add is legitimately worth more than honest.
        let honest = a_old * r_old + added as i128 * l;
        if total * r_new < honest {
            self.fail(&format!(
                "add_stake under-locked: (A+a)·r_new = {} < A·r_old + a·L = {honest}",
                total * r_new
            ));
        }
        if now >= old.lock_start && total * r_new >= honest + total {
            self.fail(&format!(
                "add_stake over-locked by a whole second or more: {} ≥ {} + {total}",
                total * r_new,
                honest
            ));
        }
        if now < old.lock_start && r_new != r_old {
            self.fail("a clock behind lock_start must leave the unlock exactly where it was");
        }
        // The half-term gate must still hold after the add, or the marginal
        // tokens are counted at term L while being withdrawable sooner than L/2.
        if r_new < (l / 2) {
            self.fail(&format!("after add_stake remaining {r_new} < L/2 = {}", l / 2));
        }
        // Never worse for the user than a fresh stake of the same term.
        let fresh = now as i128 + l;
        let bound = (old.unlock().unwrap() as i128).max(fresh);
        if new.unlock().unwrap() as i128 > bound {
            self.fail("add_stake pushed the unlock past max(old_unlock, now + L)");
        }
        let _ = who;
    }

    fn assert_chain_matches_model(&self) {
        for (i, m) in self.model.iter().enumerate() {
            let owner = self.actors[i].kp.pubkey();
            let chain = self.ctx.stake_account(&owner);
            match (chain, m.live) {
                (None, None) => {}
                (Some(c), Some(l)) => {
                    let got = Live { amount: c.amount, lock_start: c.lock_start, lock_duration: c.lock_duration };
                    if got != l {
                        self.fail(&format!("actor {i}: chain {got:?} != model {l:?}"));
                    }
                    if c.owner != owner {
                        self.fail(&format!("actor {i}: stored owner {} != {owner}", c.owner));
                    }
                }
                (a, b) => self.fail(&format!("actor {i}: existence mismatch chain={:?} model={:?}", a.is_some(), b.is_some())),
            }
        }
    }

    fn check_invariants(&self, when: &str) {
        let now = self.now();

        // 1. per-actor solvency, then global conservation.
        let mut escrowed: u128 = 0;
        for i in 0..ACTORS {
            let vault = self.vault(i);
            let owed = self.model[i].live.map(|l| l.amount).unwrap_or(0);
            if vault != owed {
                self.fail(&format!("{when}: actor {i} vault {vault} != own amount {owed}"));
            }
            escrowed += vault as u128;
        }
        let held: u128 = (0..ACTORS).map(|i| self.balance(i) as u128).sum::<u128>() + escrowed;
        if held != self.minted as u128 {
            self.fail(&format!("{when}: supply drifted, {held} in circulation vs {} minted", self.minted));
        }

        for (i, m) in self.model.iter().enumerate() {
            // 2. never paid more than deposited.
            if m.withdrawn_lifetime > m.deposited_lifetime {
                self.fail(&format!(
                    "{when}: actor {i} withdrew {} against {} deposited",
                    m.withdrawn_lifetime, m.deposited_lifetime
                ));
            }
            let Some(live) = m.live else { continue };
            let unlock = match live.unlock() {
                Some(u) => u,
                None => self.fail(&format!("{when}: actor {i} holds an unlock that overflows i64")),
            };

            // 3. monotonicity over the life of the account.
            if unlock < m.max_unlock {
                self.fail(&format!("{when}: actor {i} unlock {unlock} < watermark {}", m.max_unlock));
            }
            if live.amount < m.max_amount {
                self.fail(&format!("{when}: actor {i} amount shrank to {}", live.amount));
            }
            if live.lock_duration < m.max_duration {
                self.fail(&format!("{when}: actor {i} term shrank to {}", live.lock_duration));
            }

            // 4. tranche inequality: no sequence beats honest fresh stakes.
            let remaining = unlock as i128 - now as i128;
            let lhs = live.amount as i128 * remaining;
            let rhs: i128 = m
                .tranches
                .iter()
                .map(|(a, t)| *a as i128 * (live.lock_duration as i128 - (now as i128 - *t as i128)))
                .sum();
            if lhs < rhs {
                self.fail(&format!(
                    "{when}: actor {i} commitment {lhs} < honest {rhs} (tranches {:?}, live {live:?}, now {now})",
                    m.tranches
                ));
            }
            let tranche_total: u128 = m.tranches.iter().map(|(a, _)| *a as u128).sum();
            if tranche_total != live.amount as u128 {
                self.fail(&format!("{when}: actor {i} tranches sum to {tranche_total}, amount is {}", live.amount));
            }
        }
    }

    /// Everyone still staked warps past their unlock and withdraws: the end
    /// state must return every base unit that entered the vault.
    fn drain(&mut self) {
        let horizon = self
            .model
            .iter()
            .filter_map(|m| m.live)
            .filter_map(|l| l.unlock())
            .max()
            .unwrap_or(GENESIS_TS);
        self.apply(Op::SetClock { to: horizon.saturating_add(1) });
        for who in 0..ACTORS {
            if self.model[who].live.is_some() {
                self.apply(Op::Withdraw { who });
            }
        }
        if (0..ACTORS).any(|i| self.vault(i) != 0) {
            self.fail("a vault is not empty after every stake was withdrawn");
        }
        for who in 0..ACTORS {
            let m = &self.model[who];
            if m.deposited_lifetime != m.withdrawn_lifetime {
                self.fail(&format!("actor {who} deposited {} but got back {}", m.deposited_lifetime, m.withdrawn_lifetime));
            }
            if self.balance(who) != FUNDED {
                self.fail(&format!("actor {who} ended with {} instead of {FUNDED}", self.balance(who)));
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct OpSeed {
    kind: u8,
    who: u8,
    amount: u8,
    lock: u8,
    clock: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Amounts and terms in 1..=8: the only way `div_ceil` residues and the
    /// `/2` truncation are hit often enough to matter.
    Small,
    /// Realistic magnitudes plus the u64/i64 extremes.
    Wide,
}

fn op_seed() -> impl Strategy<Value = OpSeed> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
        .prop_map(|(kind, who, amount, lock, clock)| OpSeed { kind, who, amount, lock, clock })
}

fn pick<T: Copy>(table: &[T], sel: u8) -> T {
    table[sel as usize % table.len()]
}

impl World {
    fn amounts(&self, who: usize, mode: Mode) -> Vec<u64> {
        let b = self.balance(who);
        let a = self.model[who].live.map_or(0, |l| l.amount);
        match mode {
            Mode::Small => vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, b, b.saturating_add(1)],
            Mode::Wide => vec![
                0,
                1,
                2,
                3,
                ONE_SOLC,
                7 * ONE_SOLC + 1,
                b / 3,
                b / 2,
                b,
                b.saturating_add(1),
                u64::MAX,
                u64::MAX - a,
                (u64::MAX - a).saturating_add(1),
                999_983,
            ],
        }
    }

    fn locks(&self, who: usize, mode: Mode) -> Vec<i64> {
        let l = self.model[who].live.map_or(0, |x| x.lock_duration);
        let mut t = match mode {
            Mode::Small => vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 11],
            Mode::Wide => vec![1, 2, 3, 100, 101, DAY, 30 * DAY, 365 * DAY, MAX_LOCK_DURATION - 1, MAX_LOCK_DURATION],
        };
        t.extend_from_slice(&[0, -1, MAX_LOCK_DURATION + 1, i64::MAX, l, l.saturating_sub(1), l.saturating_add(1)]);
        t
    }

    /// Clock targets anchored on the account's own boundaries: the `/2` gate
    /// edge, the unlock instant, and one second either side of both.
    fn clocks(&self, who: usize, mode: Mode) -> Vec<i64> {
        let now = self.now();
        // Clamped to a realistic horizon: Solana's `unix_timestamp` is wall
        // time, and a sequence that parks the clock at i64::MAX explores a state
        // the chain cannot be in. The i64 boundary is covered by the targeted
        // tests instead.
        let off = |base: i64, d: i64| base.saturating_add(d).clamp(1, CLOCK_MAX);
        let mut t = vec![now, off(now, 1), off(now, -1), GENESIS_TS, 1, CLOCK_MAX];
        match mode {
            Mode::Small => {
                t.extend_from_slice(&[off(now, 2), off(now, 3), off(now, 4), off(now, 5), off(now, 8), off(now, -2)])
            }
            Mode::Wide => t.extend_from_slice(&[
                off(now, DAY),
                off(now, 30 * DAY),
                off(now, 400 * DAY),
                off(now, 5 * 365 * DAY),
            ]),
        }
        if let Some(l) = self.model[who].live {
            let s = l.lock_start;
            let d = l.lock_duration;
            // last second at which `add_stake` passes the half-term gate
            let gate = s.saturating_add(d - d / 2);
            let unlock = s.saturating_add(d);
            t.extend_from_slice(&[
                s,
                off(s, 1),
                off(s, -1),
                off(gate, -1),
                gate,
                off(gate, 1),
                off(unlock, -1),
                unlock,
                off(unlock, 1),
            ]);
        }
        t
    }

    fn choose(&self, seed: OpSeed, mode: Mode) -> Op {
        let who = seed.who as usize % ACTORS;
        match seed.kind % 10 {
            0 | 1 => Op::Stake {
                who,
                amount: pick(&self.amounts(who, mode), seed.amount),
                lock: pick(&self.locks(who, mode), seed.lock),
            },
            2 | 3 | 4 => Op::Add { who, amount: pick(&self.amounts(who, mode), seed.amount) },
            5 | 6 => Op::Relock { who, lock: pick(&self.locks(who, mode), seed.lock) },
            7 => Op::Withdraw { who },
            8 => Op::SetClock { to: pick(&self.clocks(who, mode), seed.clock) },
            _ => {
                let victim = (who + 1 + seed.clock as usize % (ACTORS - 1)) % ACTORS;
                // A cross-account probe only means something against a live PDA.
                if self.model[victim].live.is_none() {
                    return Op::Withdraw { who };
                }
                match seed.lock % 3 {
                    0 => Op::CrossWithdraw { who, victim },
                    1 => Op::CrossAdd { who, victim, amount: pick(&self.amounts(who, mode), seed.amount) },
                    _ => Op::CrossRelock { who, victim, lock: pick(&self.locks(victim, mode), seed.lock) },
                }
            }
        }
    }
}

fn run_sequence(seeds: &[OpSeed], mode: Mode) {
    let mut world = World::new();
    for seed in seeds {
        let op = world.choose(*seed, mode);
        world.apply(op);
    }
    world.drain();
}

fn cases(default: u32) -> u32 {
    std::env::var("STAKING_FUZZ_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(256),
        max_shrink_iters: 2048,
        // Committed alongside the suite: a shrunk counterexample becomes a
        // permanent regression case instead of a seed nobody can reproduce.
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::Direct(
            "tests/fuzz_sequences.proptest-regressions",
        ))),
        ..ProptestConfig::default()
    })]

    /// Small amounts and terms: the mode that reaches the `/2` truncation and
    /// the `div_ceil` residues.
    #[test]
    fn small_domain_sequences_hold_every_money_invariant(
        seeds in prop::collection::vec(op_seed(), 1..48)
    ) {
        run_sequence(&seeds, Mode::Small);
    }

    /// Realistic magnitudes plus the u64/i64 extremes.
    #[test]
    fn wide_domain_sequences_hold_every_money_invariant(
        seeds in prop::collection::vec(op_seed(), 1..48)
    ) {
        run_sequence(&seeds, Mode::Wide);
    }
}

/// Deterministic boundary cases: the proptest runs are probabilistic, so these
/// pin the sequences a mutation of the gate, the rounding, the unlock check or
/// `has_one` must fail on.
mod targeted {
    use super::*;

    fn world() -> World {
        World::new()
    }

    /// Anti-vacuity gate. A sequence fuzzer that only ever reaches two or three
    /// outcomes proves nothing, and the failure mode is silent: the suite stays
    /// green while the generator stops reaching the interesting states. This
    /// drives the same generator from a fixed RNG and fails if any outcome the
    /// suite claims to cover went unvisited.
    #[test]
    fn the_generator_reaches_every_outcome_the_suite_claims_to_cover() {
        let mut seen = std::collections::BTreeSet::new();
        let mut rng: u64 = 0x5EED_1234_ABCD_0001;
        let mut next = || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (rng >> 33) as u8
        };
        for mode in [Mode::Small, Mode::Wide] {
            for _ in 0..40 {
                let mut w = World::new();
                for _ in 0..30 {
                    let seed = OpSeed {
                        kind: next(),
                        who: next(),
                        amount: next(),
                        lock: next(),
                        clock: next(),
                    };
                    let op = w.choose(seed, mode);
                    w.apply(op);
                }
                seen.append(&mut w.seen);
            }
        }

        let required = [
            "stake:ok",
            "stake:0",    // a second stake over a live account
            "stake:1",    // more than the wallet holds
            "stake:6000", // zero amount
            "stake:6001", // zero, negative or over-maximum term
            "add:ok",
            "add:1",
            "add:6000",
            "add:6002", // the u64 sum overflows
            "add:6006", // past the half-term gate
            "add:3012", // no stake account
            "relock:ok",
            "relock:6001",
            "relock:6004", // a shorter term
            "relock:6005", // the unlock would not move later
            "relock:3012",
            "withdraw:ok",
            "withdraw:6003", // before the unlock
            "withdraw:3012",
            "cross:2006", // a signer aimed at another user's stake PDA
        ];
        let missing: Vec<_> = required.iter().filter(|r| !seen.contains(**r)).collect();
        assert!(missing.is_empty(), "the generator never reached {missing:?}\nreached: {seen:?}");
    }

    /// `div_ceil` vs plain division: A=3, a=1, elapsed=1 rounds 1/4 up to a
    /// whole second. Truncating would leave `lock_start` — and the unlock —
    /// where it was, handing the added token a free second at the full term.
    #[test]
    fn a_sub_second_weighted_shift_rounds_up_to_one_second() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 3, lock: 8 });
        let start = w.model[0].live.unwrap().lock_start;
        w.apply(Op::SetClock { to: start + 1 });
        w.apply(Op::Add { who: 0, amount: 1 });
        let live = w.model[0].live.unwrap();
        assert_eq!(live.lock_start, start + 1, "ceil(1·1/4) must be 1 second, not 0");
        assert_eq!(live.unlock().unwrap(), start + 9);
    }

    /// The same shape at exact divisibility: 2 tokens on 2 after 2 seconds is
    /// exactly 1 second, so rounding must not add a spurious extra.
    #[test]
    fn an_exactly_divisible_weighted_shift_adds_no_extra_second() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 2, lock: 8 });
        let start = w.model[0].live.unwrap().lock_start;
        w.apply(Op::SetClock { to: start + 2 });
        w.apply(Op::Add { who: 0, amount: 2 });
        assert_eq!(w.model[0].live.unwrap().lock_start, start + 1);
    }

    /// The half-term gate, both sides of the boundary, on an odd term where the
    /// truncation of `L / 2` decides the answer.
    #[test]
    fn the_half_term_gate_on_an_odd_term() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 100, lock: 7 });
        let start = w.model[0].live.unwrap().lock_start;
        // remaining = 3 == 7/2, the last second an add is allowed
        w.apply(Op::SetClock { to: start + 4 });
        w.apply(Op::Add { who: 0, amount: 1 });
        // one second later the gate must reject; predict() pins AddRequiresRelock
        let now = w.model[0].live.unwrap().lock_start + 7 - 3;
        w.apply(Op::SetClock { to: now + 1 });
        w.apply(Op::Add { who: 0, amount: 1 });
        assert!(w.model[0].live.is_some());
    }

    /// A matured stake cannot be revived by an add, however large.
    #[test]
    fn a_matured_stake_rejects_a_whale_add() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: ONE_SOLC, lock: 30 * DAY });
        let unlock = w.model[0].live.unwrap().unlock().unwrap();
        w.apply(Op::SetClock { to: unlock + 1 });
        w.apply(Op::Add { who: 0, amount: 500 * ONE_SOLC });
        assert_eq!(w.model[0].live.unwrap().amount, ONE_SOLC, "the add must not have landed");
    }

    /// Withdraw is rejected at `unlock - 1` and pays in full at `unlock`.
    #[test]
    fn withdraw_at_the_unlock_boundary_one_second_either_side() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 5 * ONE_SOLC, lock: DAY });
        let unlock = w.model[0].live.unwrap().unlock().unwrap();
        w.apply(Op::SetClock { to: unlock - 1 });
        w.apply(Op::Withdraw { who: 0 });
        assert!(w.model[0].live.is_some(), "a withdraw one second early must not pay");
        w.apply(Op::SetClock { to: unlock });
        w.apply(Op::Withdraw { who: 0 });
        assert!(w.model[0].live.is_none());
    }

    /// The whole point of the shift: a stake topped up mid-term is not
    /// withdrawable at the term's original unlock.
    #[test]
    fn a_top_up_pushes_the_unlock_past_the_original_one() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: ONE_SOLC, lock: 100 });
        let original = w.model[0].live.unwrap().unlock().unwrap();
        w.apply(Op::SetClock { to: original - 60 });
        w.apply(Op::Add { who: 0, amount: 9 * ONE_SOLC });
        w.apply(Op::SetClock { to: original });
        w.apply(Op::Withdraw { who: 0 });
        assert!(w.model[0].live.is_some(), "the top-up must have moved the unlock later");
        let unlock = w.model[0].live.unwrap().unlock().unwrap();
        w.apply(Op::SetClock { to: unlock });
        w.apply(Op::Withdraw { who: 0 });
        assert_eq!(w.balance(0), FUNDED);
    }

    /// Adding `u64::MAX - A` keeps the sum inside u64 (so the overflow guard
    /// passes) and fails on the balance instead; one more overflows first.
    #[test]
    fn the_u64_sum_boundary_separates_insufficient_funds_from_overflow() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: ONE_SOLC, lock: 100 });
        w.apply(Op::Add { who: 0, amount: u64::MAX - ONE_SOLC });
        w.apply(Op::Add { who: 0, amount: u64::MAX - ONE_SOLC + 1 });
        assert_eq!(w.model[0].live.unwrap().amount, ONE_SOLC);
    }

    /// A stake whose unlock would overflow i64 is refused rather than wrapping
    /// into the past.
    #[test]
    fn an_unlock_that_overflows_i64_is_refused_on_every_path() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: ONE_SOLC, lock: 100 });
        w.apply(Op::SetClock { to: i64::MAX - 1 });
        w.apply(Op::Relock { who: 0, lock: MAX_LOCK_DURATION });
        w.apply(Op::Stake { who: 1, amount: ONE_SOLC, lock: MAX_LOCK_DURATION });
        assert!(w.model[1].live.is_none());
        // the original stake is long past its unlock and still pays exactly once
        w.apply(Op::Withdraw { who: 0 });
        assert_eq!(w.balance(0), FUNDED);
    }

    /// Relock is a pure state change: it never moves a token, and it cannot
    /// shorten the term or leave the unlock where it was.
    #[test]
    fn relock_never_downgrades_and_never_moves_tokens() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 4 * ONE_SOLC, lock: DAY });
        w.apply(Op::Relock { who: 0, lock: DAY });
        assert_eq!(w.model[0].live.unwrap().lock_duration, DAY, "same second, same term: NoopRelock");
        w.apply(Op::Relock { who: 0, lock: DAY - 1 });
        assert_eq!(w.model[0].live.unwrap().lock_duration, DAY, "a shorter term is a downgrade");
        w.apply(Op::SetClock { to: w.now() + 1 });
        w.apply(Op::Relock { who: 0, lock: DAY });
        w.apply(Op::Relock { who: 0, lock: 30 * DAY });
        assert_eq!(w.balance(0), FUNDED - 4 * ONE_SOLC);
    }

    /// A signer aimed at someone else's stake PDA is rejected by the seeds
    /// constraint on all three paths, and nothing moves.
    #[test]
    fn a_signer_cannot_reach_another_users_stake_pda() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 10 * ONE_SOLC, lock: 10 });
        w.apply(Op::Stake { who: 1, amount: ONE_SOLC, lock: 10 });
        w.apply(Op::SetClock { to: w.now() + 100 });
        w.apply(Op::CrossWithdraw { who: 1, victim: 0 });
        w.apply(Op::CrossAdd { who: 1, victim: 0, amount: 1 });
        w.apply(Op::CrossRelock { who: 1, victim: 0, lock: 1_000 });
        assert_eq!(w.model[0].live.unwrap().amount, 10 * ONE_SOLC);
    }

    /// `has_one = owner`, independent of the seeds check: a stake PDA at the
    /// attacker's own seeds whose stored owner is somebody else must be refused
    /// on all three paths that read it. The seeds constraint passes here, so
    /// this is the only test that sees `has_one` do any work.
    #[test]
    fn a_forged_stored_owner_is_rejected_on_every_path() {
        let mut w = world();
        w.apply(Op::Stake { who: 1, amount: 10 * ONE_SOLC, lock: 10 });
        // The attacker stakes for real first: without a vault of their own the
        // instruction dies on a missing account and `has_one` is never reached.
        w.apply(Op::Stake { who: 0, amount: ONE_SOLC, lock: 10 });

        let attacker = w.actors[0].kp.pubkey();
        let victim = w.actors[1].kp.pubkey();
        let (pda, bump) = Pubkey::find_program_address(&[STAKE_SEED, attacker.as_ref()], &solcard_staking::ID);
        let forged = StakeAccount {
            owner: victim,
            amount: ONE_SOLC,
            lock_start: GENESIS_TS,
            lock_duration: 10,
            bump,
        };
        let mut data = Vec::new();
        forged.try_serialize(&mut data).expect("StakeAccount must serialise");
        let lamports = w.ctx.svm.minimum_balance_for_rent_exemption(data.len());
        w.ctx
            .svm
            .set_account(
                pda,
                RawAccount { lamports, data, owner: solcard_staking::ID, executable: false, rent_epoch: 0 },
            )
            .expect("set_account must succeed");

        let vault_before = w.ctx.vault_balance(&attacker);
        let held_before = w.balance(0);
        let mut clock = w.ctx.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = GENESIS_TS + 1_000;
        w.ctx.svm.set_sysvar(&clock);

        for (label, ix) in [
            ("withdraw", w.ctx.withdraw_ix(&attacker, &attacker, &w.actors[0].ata)),
            ("add_stake", w.ctx.add_stake_ix(&attacker, &w.actors[0].ata, 1)),
            ("relock", w.ctx.relock_ix(&attacker, &w.actors[0].ata, 100_000)),
        ] {
            fresh_blockhash(&mut w.ctx);
            let kp = w.actors[0].kp.insecure_clone();
            let err: FailedTransactionMetadata =
                try_send(&mut w.ctx.svm, &[ix], &[&kp]).expect_err(&format!("{label} on a forged owner must fail"));
            assert_ix_custom_with_log(&err, 0, CONSTRAINT_HAS_ONE, needle(CONSTRAINT_HAS_ONE));
        }

        assert_eq!(w.ctx.vault_balance(&attacker), vault_before, "the vault must be untouched");
        assert_eq!(w.ctx.vault_balance(&victim), 10 * ONE_SOLC, "the victim's vault must be untouched");
        assert_eq!(w.balance(0), held_before);
    }

    /// Regression, found by the sequence fuzzer. `add_stake` used to bounds-check
    /// `lock_start + shift` without re-checking `new_lock_start + lock_duration`,
    /// so an add could park the unlock past `i64::MAX`; `withdraw` recomputes that
    /// sum with `checked_add` and returned `MathOverflow` forever, stranding the
    /// tokens in the owner's vault. The add must now be rejected outright, leaving
    /// the stake untouched and still withdrawable at its original unlock.
    #[test]
    fn add_stake_rejects_an_add_that_would_push_the_unlock_past_i64_max() {
        let mut w = world();
        let owner = w.actors[0].kp.pubkey();
        let ata = w.actors[0].ata;
        let kp = w.actors[0].kp.insecure_clone();

        let mut clock = w.ctx.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = i64::MAX - 2;
        w.ctx.svm.set_sysvar(&clock);
        fresh_blockhash(&mut w.ctx);
        let ix = w.ctx.stake_ix(&owner, &ata, ONE_SOLC, 2);
        send(&mut w.ctx.svm, &[ix], &[&kp]);
        assert_eq!(w.ctx.stake_account(&owner).unwrap().lock_start, i64::MAX - 2);
        let held_before = w.balance(0);

        let mut clock = w.ctx.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = i64::MAX - 1;
        w.ctx.svm.set_sysvar(&clock);
        fresh_blockhash(&mut w.ctx);
        let ix = w.ctx.add_stake_ix(&owner, &ata, 9 * ONE_SOLC);
        let err = try_send(&mut w.ctx.svm, &[ix], &[&kp]).expect_err("the add must be rejected");
        assert_ix_custom_with_log(&err, 0, MATH_OVERFLOW, needle(MATH_OVERFLOW));

        let live = w.ctx.stake_account(&owner).unwrap();
        assert_eq!(live.lock_start, i64::MAX - 2, "the rejected add must not move lock_start");
        assert_eq!(live.amount, ONE_SOLC, "the rejected add must not credit the stake");
        assert_eq!(live.lock_start.checked_add(live.lock_duration), Some(i64::MAX));
        assert_eq!(w.ctx.vault_balance(&owner), ONE_SOLC, "no tokens moved");
        assert_eq!(w.balance(0), held_before);

        // and the stake is not bricked: it still pays out at its original unlock
        let mut clock = w.ctx.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = i64::MAX;
        w.ctx.svm.set_sysvar(&clock);
        fresh_blockhash(&mut w.ctx);
        let ix = w.ctx.withdraw_ix(&owner, &owner, &ata);
        send(&mut w.ctx.svm, &[ix], &[&kp]);
        assert_eq!(w.ctx.vault_balance(&owner), 0);
        assert!(w.ctx.stake_account(&owner).is_none(), "the stake account is closed");
    }

    /// The guard above is `checked_add`, not a margin: an add whose unlock lands
    /// exactly on `i64::MAX` is still representable and must go through. A
    /// same-second add shifts by zero, which is the only way to reach the ceiling.
    #[test]
    fn add_stake_accepts_an_unlock_landing_exactly_on_i64_max() {
        let mut w = world();
        let owner = w.actors[0].kp.pubkey();
        let ata = w.actors[0].ata;
        let kp = w.actors[0].kp.insecure_clone();

        let mut clock = w.ctx.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = i64::MAX - 2;
        w.ctx.svm.set_sysvar(&clock);
        fresh_blockhash(&mut w.ctx);
        let ix = w.ctx.stake_ix(&owner, &ata, ONE_SOLC, 2);
        send(&mut w.ctx.svm, &[ix], &[&kp]);

        fresh_blockhash(&mut w.ctx);
        let ix = w.ctx.add_stake_ix(&owner, &ata, 9 * ONE_SOLC);
        send(&mut w.ctx.svm, &[ix], &[&kp]);

        let live = w.ctx.stake_account(&owner).unwrap();
        assert_eq!(live.lock_start, i64::MAX - 2, "a same-second add shifts by zero");
        assert_eq!(live.amount, 10 * ONE_SOLC);
        assert_eq!(live.lock_start.checked_add(live.lock_duration), Some(i64::MAX));
        assert_eq!(w.ctx.vault_balance(&owner), 10 * ONE_SOLC);
    }

    /// Two users interleaved: the vault tracks the sum of live stakes through
    /// every step, and each is paid exactly what they put in.
    #[test]
    fn two_users_interleaved_settle_to_exactly_what_they_deposited() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 7 * ONE_SOLC, lock: 1_000 });
        w.apply(Op::SetClock { to: w.now() + 100 });
        w.apply(Op::Stake { who: 1, amount: 3 * ONE_SOLC, lock: 500 });
        w.apply(Op::Add { who: 0, amount: 2 * ONE_SOLC });
        w.apply(Op::SetClock { to: w.now() + 200 });
        w.apply(Op::Relock { who: 1, lock: 2_000 });
        w.apply(Op::Add { who: 1, amount: ONE_SOLC });
        w.apply(Op::SetClock { to: w.now() + 400 });
        w.apply(Op::Add { who: 0, amount: ONE_SOLC });
        w.drain();
    }

    /// A clock that steps backwards: `elapsed` clamps, the add lands without a
    /// shift, and no invariant moves.
    #[test]
    fn a_backwards_clock_adds_without_shifting_and_breaks_nothing() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 5 * ONE_SOLC, lock: 1_000 });
        let start = w.model[0].live.unwrap().lock_start;
        w.apply(Op::SetClock { to: start + 400 });
        w.apply(Op::Add { who: 0, amount: 5 * ONE_SOLC });
        let shifted = w.model[0].live.unwrap().lock_start;
        w.apply(Op::SetClock { to: start });
        w.apply(Op::Add { who: 0, amount: ONE_SOLC });
        assert_eq!(w.model[0].live.unwrap().lock_start, shifted, "a clock behind lock_start must not shift");
        w.drain();
    }

    /// Dust added every second cannot hold a full-term tier on a stake that is
    /// really about to mature: the gate stops it at the half-term line.
    #[test]
    fn perpetual_dust_adds_cannot_outrun_the_half_term_gate() {
        let mut w = world();
        w.apply(Op::Stake { who: 0, amount: 100 * ONE_SOLC, lock: 100 });
        let start = w.model[0].live.unwrap().lock_start;
        for step in 1..=60 {
            w.apply(Op::SetClock { to: start + step });
            w.apply(Op::Add { who: 0, amount: 1 });
        }
        let live = w.model[0].live.unwrap();
        let remaining = live.unlock().unwrap() - w.now();
        assert!(
            remaining >= live.lock_duration / 2,
            "dust adds left {remaining}s against a {}s term",
            live.lock_duration
        );
    }
}
