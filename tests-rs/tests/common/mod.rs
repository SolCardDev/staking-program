#![allow(dead_code, unused_imports)]
//
// Each test binary compiles this module separately and uses a different slice
// of it, so anything unused by one binary would warn there while being
// load-bearing in another.

//! Shared harness for the litesvm exploit suite.
//!
//! Replaces the TypeScript helpers. The TS suite could not run in CI at all:
//! litesvm's JS addon corrupts the heap on linux-x86-64 and aborts with a bare
//! std::bad_alloc (LiteSVM/litesvm#171), on every version tried, 0.3.3 through
//! 1.3.0. The Rust crate is the same VM without the napi layer in front of it.
//!
//! Instructions are built from the program's own `accounts` and `instruction`
//! types rather than from the IDL, so a change to an account struct breaks
//! these tests at compile time instead of at assertion time.
//!
//! The harness is cluster-agnostic: `SOLC_MINT` comes from the cargo feature the
//! test binary was built with, so the same suite runs against the localnet
//! artifact and the mainnet one. Both pinned mints have 6 decimals.

use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::program_option::COption;
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use anchor_spl::associated_token::spl_associated_token_account;
use anchor_spl::token::spl_token;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solcard_staking::constants::{SOLC_MINT, STAKE_SEED, VAULT_SEED};
use solcard_staking::state::StakeAccount;

/// Mainnet SOLC and the localnet/devnet test mint both have 6 decimals.
pub const SOLC_DECIMALS: u8 = 6;

/// LiteSVM boots at unix_timestamp 0. The suite warps to a fixed, realistic
/// epoch so `Clock::get()` yields a nonzero lock_start, and a fixed one rather
/// than "now" so clock-warp tests have a known base.
pub const GENESIS_TS: i64 = 1_700_000_000;

pub struct Ctx {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub mint: Pubkey,
}

fn manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The artifact under test. `anchor build` writes every feature variant to the
/// same `target/deploy/solcard_staking.so`, so a run against a non-default
/// variant points `SOLCARD_STAKING_SO` at its own copy of that build.
pub fn so_path() -> std::path::PathBuf {
    match std::env::var("SOLCARD_STAKING_SO") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => manifest_dir().join("../target/deploy/solcard_staking.so"),
    }
}

/// Writes the pinned SOLC mint at its compiled-in address, with `payer` as mint
/// authority so the suite can fund actors.
///
/// Set directly rather than created through the token program: the mint address
/// is a program constant, and for mainnet nobody holds the keypair that would
/// let `create_account` sign for it. Writing the account is also what makes the
/// decimals a property of the build rather than of a committed fixture.
pub fn write_mint(svm: &mut LiteSVM, mint_authority: &Pubkey, freeze_authority: Option<&Pubkey>) {
    let state = spl_token::state::Mint {
        mint_authority: COption::Some(*mint_authority),
        supply: 0,
        decimals: SOLC_DECIMALS,
        is_initialized: true,
        freeze_authority: freeze_authority.map_or(COption::None, |k| COption::Some(*k)),
    };
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint::pack(state, &mut data).expect("mint must pack");
    let lamports = svm.minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN);
    svm.set_account(
        SOLC_MINT,
        RawAccount { lamports, data, owner: spl_token::ID, executable: false, rent_epoch: 0 },
    )
    .expect("set_account must succeed");
}

/// Signs and submits, requiring success. Failure carries the program logs,
/// which is the thing worth reading when an assertion is really a broken setup.
pub fn send(svm: &mut LiteSVM, ixs: &[solana_instruction::Instruction], signers: &[&Keypair]) -> TransactionMetadata {
    match try_send(svm, ixs, signers) {
        Ok(meta) => meta,
        Err(err) => panic!("expected success, got {:?}\nlogs:\n{}", err.err, err.meta.logs.join("\n")),
    }
}

/// Submits without asserting, for the many tests whose subject IS the failure.
pub fn try_send(
    svm: &mut LiteSVM,
    ixs: &[solana_instruction::Instruction],
    signers: &[&Keypair],
) -> Result<TransactionMetadata, FailedTransactionMetadata> {
    let payer = signers[0].pubkey();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer), signers, svm.latest_blockhash());
    svm.send_transaction(tx)
}

/// Boots the VM with the program loaded, the SOLC mint written and the clock
/// warped. Vaults are per-owner and created by `stake` itself, so there is
/// nothing left for a fixture to bootstrap.
pub fn boot() -> Ctx {
    boot_inner(false)
}

/// `boot()` with the payer doubling as the mint's freeze authority.
///
/// `boot()` writes `None` there, which bakes in an assumption about a token that
/// has not been deployed yet. This exists to find out what the program does if
/// that assumption turns out to be wrong.
pub fn boot_with_freeze_authority() -> Ctx {
    boot_inner(true)
}

fn boot_inner(with_freeze_authority: bool) -> Ctx {
    let mut svm = LiteSVM::new();
    let so = so_path();
    svm.add_program_from_file(solcard_staking::ID, &so)
        .unwrap_or_else(|e| panic!("cannot load {} — run `anchor build` first: {e:?}", so.display()));

    let mut clock = svm.get_sysvar::<anchor_lang::prelude::Clock>();
    clock.unix_timestamp = GENESIS_TS;
    svm.set_sysvar(&clock);

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100 * 1_000_000_000).unwrap();

    let freeze_authority = with_freeze_authority.then(|| payer.pubkey());
    write_mint(&mut svm, &payer.pubkey(), freeze_authority.as_ref());

    Ctx { svm, payer, mint: SOLC_MINT }
}

/// `boot()` plus the guard that the artifact under test pins the mint this binary
/// expects — the starting point for every test that is not about that guard.
pub fn setup() -> Ctx {
    let ctx = boot();
    assert_artifact_pins_solc_mint(&ctx);
    ctx
}

/// `setup()` with the payer doubling as the mint's freeze authority.
pub fn setup_with_freeze_authority() -> Ctx {
    let ctx = boot_with_freeze_authority();
    assert_artifact_pins_solc_mint(&ctx);
    ctx
}

/// Simulates a zero-amount stake: past the mint `address` constraint it fails `InvalidAmount`, not `ConstraintAddress`.
fn assert_artifact_pins_solc_mint(ctx: &Ctx) {
    let payer = ctx.payer.insecure_clone();
    let ata = spl_associated_token_account::address::get_associated_token_address(&payer.pubkey(), &ctx.mint);
    let create = spl_associated_token_account::instruction::create_associated_token_account_idempotent(
        &payer.pubkey(),
        &payer.pubkey(),
        &ctx.mint,
        &spl_token::ID,
    );
    let probe = ctx.stake_ix(&payer.pubkey(), &ata, 0, 1);
    let tx = Transaction::new_signed_with_payer(&[create, probe], Some(&payer.pubkey()), &[&payer], ctx.svm.latest_blockhash());
    let err = ctx.svm.simulate_transaction(tx).expect_err("a zero-amount stake must fail");
    assert!(
        err_text(&err).contains("InstructionError(1, Custom(6000))"),
        "{} does not pin SOLC_MINT {SOLC_MINT}, which this test binary expects; rebuild it with the matching cargo feature.\n\
         probe got {}\nlogs:\n{}",
        so_path().display(),
        err_text(&err),
        log_text(&err),
    );
}

/// Advance LiteSVM's blockhash so a REPEATED, byte-identical transaction gets a
/// fresh signature.
///
/// Without this, a replayed instruction with the same accounts, args, signers
/// and blockhash produces the SAME signature, and LiteSVM rejects it as a
/// duplicate transaction BEFORE the program is ever entered. Any replay /
/// idempotency / revival assertion written without it passes vacuously — it
/// proves the SVM deduplicates, not that the program defends itself. The tell
/// is a rejection whose logs are empty, meaning no program executed.
pub fn fresh_blockhash(ctx: &mut Ctx) {
    ctx.svm.expire_blockhash();
}

// ----------------------------------------------------------------------
// Failure assertions.
//
// Always the exact `InstructionError(index, …)`, never a substring search for
// a bare number: a lamport count or compute-unit figure containing the same
// digits satisfies that, so the assertion can pass for the wrong reason. The
// index is what proves WHICH instruction failed, which is the whole point in a
// multi-instruction attack.
// ----------------------------------------------------------------------

pub fn err_text(err: &FailedTransactionMetadata) -> String {
    format!("{:?}", err.err)
}

pub fn log_text(err: &FailedTransactionMetadata) -> String {
    err.meta.logs.join("\n")
}

#[track_caller]
pub fn assert_ix_custom(err: &FailedTransactionMetadata, index: usize, code: u32) {
    let want = format!("InstructionError({index}, Custom({code}))");
    assert!(
        err_text(err).contains(&want),
        "expected {want}, got {}\nlogs:\n{}",
        err_text(err),
        log_text(err)
    );
}

/// For codes that are ambiguous across programs — `Custom(0)` is the system
/// program's AccountAlreadyInUse and spl-token's NotRentExempt — the log line
/// names which one actually fired.
#[track_caller]
pub fn assert_ix_custom_with_log(
    err: &FailedTransactionMetadata,
    index: usize,
    code: u32,
    needle: &str,
) {
    assert_ix_custom(err, index, code);
    assert!(
        log_text(err).contains(needle),
        "expected {needle:?} in the logs, got:\n{}",
        log_text(err)
    );
}

/// For runtime `InstructionError` variants that are not `Custom`, e.g.
/// `IllegalOwner` from the system program.
#[track_caller]
pub fn assert_ix_error(err: &FailedTransactionMetadata, index: usize, variant: &str) {
    let want = format!("InstructionError({index}, {variant})");
    assert!(
        err_text(err).contains(&want),
        "expected {want}, got {}\nlogs:\n{}",
        err_text(err),
        log_text(err)
    );
}

impl Ctx {
    /// Creates `owner`'s ATA and mints `amount` SOLC into it.
    pub fn fund(&mut self, owner: &Pubkey, amount: u64) -> Pubkey {
        let ata = spl_associated_token_account::address::get_associated_token_address(owner, &self.mint);
        let payer = self.payer.insecure_clone();
        send(
            &mut self.svm,
            &[
                spl_associated_token_account::instruction::create_associated_token_account(
                    &payer.pubkey(),
                    owner,
                    &self.mint,
                    &spl_token::ID,
                ),
                spl_token::instruction::mint_to(
                    &spl_token::ID,
                    &self.mint,
                    &ata,
                    &payer.pubkey(),
                    &[],
                    amount,
                )
                .unwrap(),
            ],
            &[&payer],
        );
        ata
    }

    /// Funds a brand-new wallet with SOL and `amount` SOLC.
    pub fn actor(&mut self, amount: u64) -> (Keypair, Pubkey) {
        let kp = Keypair::new();
        self.svm.airdrop(&kp.pubkey(), 10 * 1_000_000_000).unwrap();
        let ata = self.fund(&kp.pubkey(), amount);
        (kp, ata)
    }

    pub fn stake_pda(&self, owner: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[STAKE_SEED, owner.as_ref()], &solcard_staking::ID).0
    }

    /// The owner's vault: a plain PDA token account, NOT an ATA. Nothing outside
    /// the program can create it, which is the point of the derivation.
    pub fn vault_pda(&self, owner: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[VAULT_SEED, owner.as_ref()], &solcard_staking::ID).0
    }

    /// Balance of `owner`'s vault, or 0 once it has been closed.
    pub fn vault_balance(&self, owner: &Pubkey) -> u64 {
        self.token_balance(&self.vault_pda(owner))
    }

    /// SPL token balance, or 0 when the account does not exist.
    pub fn token_balance(&self, account: &Pubkey) -> u64 {
        self.svm
            .get_account(account)
            .filter(|a| !a.data.is_empty())
            .map(|a| spl_token::state::Account::unpack(&a.data).expect("not a token account").amount)
            .unwrap_or(0)
    }

    pub fn stake_account(&self, owner: &Pubkey) -> Option<StakeAccount> {
        let acct = self.svm.get_account(&self.stake_pda(owner))?;
        if acct.data.is_empty() {
            return None;
        }
        Some(StakeAccount::try_deserialize(&mut acct.data.as_slice()).expect("not a StakeAccount"))
    }

    /// Moves the clock forward, which is how every lock-expiry test works.
    pub fn warp(&mut self, seconds: i64) {
        let mut clock = self.svm.get_sysvar::<anchor_lang::prelude::Clock>();
        clock.unix_timestamp += seconds;
        self.svm.set_sysvar(&clock);
    }

    pub fn stake_ix(&self, owner: &Pubkey, owner_ata: &Pubkey, amount: u64, lock: i64) -> solana_instruction::Instruction {
        self.stake_ix_with_vault(owner, owner_ata, &self.vault_pda(owner), amount, lock)
    }

    /// `stake_ix` with the vault named explicitly, for substitution tests.
    pub fn stake_ix_with_vault(
        &self,
        owner: &Pubkey,
        owner_ata: &Pubkey,
        vault: &Pubkey,
        amount: u64,
        lock: i64,
    ) -> solana_instruction::Instruction {
        solana_instruction::Instruction {
            program_id: solcard_staking::ID,
            accounts: solcard_staking::accounts::Stake {
                owner: *owner,
                mint: self.mint,
                stake_account: self.stake_pda(owner),
                owner_token_account: *owner_ata,
                vault: *vault,
                token_program: spl_token::ID,
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: solcard_staking::instruction::Stake { amount, lock_duration: lock }.data(),
        }
    }

    pub fn restake_accounts(&self, owner: &Pubkey, owner_ata: &Pubkey) -> Vec<solana_instruction::AccountMeta> {
        self.restake_accounts_with_vault(owner, owner_ata, &self.vault_pda(owner))
    }

    pub fn restake_accounts_with_vault(
        &self,
        owner: &Pubkey,
        owner_ata: &Pubkey,
        vault: &Pubkey,
    ) -> Vec<solana_instruction::AccountMeta> {
        solcard_staking::accounts::Restake {
            owner: *owner,
            mint: self.mint,
            stake_account: self.stake_pda(owner),
            owner_token_account: *owner_ata,
            vault: *vault,
            token_program: spl_token::ID,
        }
        .to_account_metas(None)
    }

    pub fn add_stake_ix(&self, owner: &Pubkey, owner_ata: &Pubkey, amount: u64) -> solana_instruction::Instruction {
        solana_instruction::Instruction {
            program_id: solcard_staking::ID,
            accounts: self.restake_accounts(owner, owner_ata),
            data: solcard_staking::instruction::AddStake { amount }.data(),
        }
    }

    pub fn relock_ix(&self, owner: &Pubkey, owner_ata: &Pubkey, lock: i64) -> solana_instruction::Instruction {
        solana_instruction::Instruction {
            program_id: solcard_staking::ID,
            accounts: self.restake_accounts(owner, owner_ata),
            data: solcard_staking::instruction::Relock { lock_duration: lock }.data(),
        }
    }

    /// `stake_owner` is split out so authorization tests can point a signer at
    /// somebody else's stake PDA — the shape of the core exploit case. The vault
    /// defaults to that stake's own vault, i.e. the account holding the money the
    /// attack is after.
    pub fn withdraw_ix(
        &self,
        signer: &Pubkey,
        stake_owner: &Pubkey,
        owner_ata: &Pubkey,
    ) -> solana_instruction::Instruction {
        self.withdraw_ix_with_vault(signer, stake_owner, owner_ata, &self.vault_pda(stake_owner))
    }

    pub fn withdraw_ix_with_vault(
        &self,
        signer: &Pubkey,
        stake_owner: &Pubkey,
        owner_ata: &Pubkey,
        vault: &Pubkey,
    ) -> solana_instruction::Instruction {
        solana_instruction::Instruction {
            program_id: solcard_staking::ID,
            accounts: solcard_staking::accounts::Withdraw {
                owner: *signer,
                mint: self.mint,
                stake_account: self.stake_pda(stake_owner),
                owner_token_account: *owner_ata,
                vault: *vault,
                token_program: spl_token::ID,
            }
            .to_account_metas(None),
            data: solcard_staking::instruction::Withdraw {}.data(),
        }
    }
}

use anchor_lang::solana_program::program_pack::Pack as _;

/// Re-exported so the suites can construct/forge raw accounts and metas
/// without each file rediscovering which crate generation to depend on.
pub use solana_account::Account as RawAccount;
pub use solana_instruction::{AccountMeta, Instruction};
