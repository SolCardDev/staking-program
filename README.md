# solcard-staking

A Solana staking escrow for SOLC. It holds a staker's tokens for a chosen lock
period and releases them, in full, once that period expires. It does nothing
else: there is no reward accrual, no tier logic and no admin on-chain.

Tiers, multipliers and rewards are computed **off-chain** by SolCard's backend,
which reads the on-chain stake accounts. The chain enforces custody and the
lock; it is the source of truth for *what is staked and until when*, and for
nothing else.

**Status: not externally audited. Not deployed to mainnet.** See
[Audit status](#audit-status).

---

## Contents

| Path | What it is |
|---|---|
| `programs/solcard-staking/src/` | The program: four instructions, no admin, no events. |
| `tests-rs/` | The LiteSVM test suite — adversarial throughout, with fuzzed operation sequences. |
| `idl/solcard_staking.json` | Generated IDL, committed. |
| `docs/invariants.md` | Every property the program guarantees, each mapped to the test that proves it. |
| `docs/threat-model.md` | Assets, actors, trust boundaries, and the vulnerability classes considered. |
| `SECURITY.md` | How to report a vulnerability. |
| `LICENSE` | Apache License 2.0. |

Start with `docs/invariants.md` if you are reviewing the program: it is the
shortest complete statement of what is supposed to be true.

---

## What the program does

Each staker gets one `StakeAccount` PDA recording
`{owner, amount, lock_start, lock_duration}`, and **their own vault** — a token
account the program creates at `["vault", owner]` whose authority is that
staker's stake PDA. No balance is pooled; no staker's tokens are in an account
another staker's instruction can name.

```
                        ┌────────────────────────────────────┐
                        │  SOLC mint (pinned at compile time)│
                        │  classic SPL Token, 6 decimals     │
                        │  mint + freeze authority: null     │
                        └────────────────┬───────────────────┘
                                         │
                       both per staker, one each
 ┌──────────────────────────┐            │        ┌──────────────────────────────┐
 │ StakeAccount PDA         │            │        │ vault (plain PDA token acct) │
 │ seeds ["stake", owner]   │            └───────►│ seeds ["vault", owner]       │
 │                          │                     │ NOT an ATA — see below       │
 │  owner        : Pubkey   │   is the token      │                              │
 │  amount       : u64      │───authority of─────►│ holds ONLY this owner's SOLC │
 │  lock_start   : i64      │                     │                              │
 │  lock_duration: i64      │                     │                              │
 │  bump         : u8       │                     └──────────────────────────────┘
 └──────────────────────────┘                             ▲             │
        ▲            ▲                                    │ credit      │ debit + close
        │ init       │ mut                                │             ▼
   ┌────┴────────────┴────────────────────────────────────┴──────────────────────┐
   │  stake        opens BOTH accounts, moves tokens in                          │
   │  add_stake    adds to it, moves tokens in, keeps the term                   │
   │  relock       extends the term, moves no tokens                             │
   │  withdraw     pays the vault out in full, closes both, reclaims both rents  │
   └─────────────────────────────────────────────────────────────────────────────┘
                     every one of them requires the owner's signature
```

Solvency rests on a single property: **`amount` only ever changes alongside a
token transfer of the same size in the same direction**, so an owner's vault
balance is never below their own `amount`. `docs/invariants.md` states it
precisely; `tests-rs/tests/fuzz_sequences.rs` checks it for every actor after
every step of every generated operation sequence.

Two details are load-bearing rather than incidental:

- **The vault is a plain PDA token account, not an ATA of the stake account.**
  Anyone can create another wallet's ATA for the price of rent, and Anchor's
  `init` fails on an account that already exists — so an ATA vault would let a
  stranger permanently block a chosen victim's `stake`. Only the program can sign
  for `["vault", owner]`, and `init` adopts lamports somebody pre-sent there.
- **`withdraw` pays the vault's full balance, not the stored `amount`, and then
  closes it.** SPL `CloseAccount` refuses a non-empty account, so "pay `amount`,
  then close" would let anyone brick a victim's withdraw forever by sending their
  vault one base unit. The consequence is that a donation to a vault is paid to
  that vault's owner. A vault holding *less* than `amount` is rejected with
  `VaultUnderfunded` rather than paying out what is there.

## The four instructions

All four require `owner` to sign. No instruction accepts a caller-chosen
account: the mint is pinned by address, the owner's token account by its
associated-token-account derivation, and both PDAs by their seeds.

### `stake(amount: u64, lock_duration: i64)`

Creates the caller's stake account **and their vault**, and moves `amount` into
the vault.

| Constraint | Error |
|---|---|
| `amount > 0` | `InvalidAmount` |
| `0 < lock_duration <= 4 years` | `InvalidLockDuration` |
| `now + lock_duration` fits in `i64` | `MathOverflow` |
| No live stake for this owner (`init`, never `init_if_needed`) | System program `AccountAlreadyInUse` (`Custom(0)`) |

The owner pays both accounts' rent and gets all of it back on withdraw.

### `add_stake(amount: u64)`

Adds `amount` to a live stake **without changing `lock_duration`**. `lock_start`
moves forward by the amount-weighted share of the elapsed time, rounded up:

```
shift = ceil(elapsed × amount / (existing_amount + amount))
```

so that `(A + a) · remaining_new = A · remaining_old + a · lock_duration` — the
new tokens serve the weighted average of the remaining lock and a full term. The
rounding is always toward the *later* unlock, and `shift ≤ elapsed`, so
`lock_start` never passes `now` and the unlock never moves earlier.

| Constraint | Error |
|---|---|
| `amount > 0` | `InvalidAmount` |
| At least half the term still remaining | `AddRequiresRelock` |
| The resulting unlock fits in `i64` | `MathOverflow` |

The half-term gate is what stops a matured or nearly-matured stake being revived
by a small top-up. Its consequences are analysed in `docs/threat-model.md`
(§ "Economic residual in `add_stake`") — it bounds, but does not eliminate, the
advantage a top-up gets over an equivalent fresh stake.

### `relock(lock_duration: i64)`

Restarts the lock at `now` with a term no shorter than the current one. Moves no
tokens. Permitted on a matured stake, where it is a genuine fresh lock of the
whole balance.

| Constraint | Error |
|---|---|
| `0 < lock_duration <= 4 years` | `InvalidLockDuration` |
| `lock_duration >= current lock_duration` | `LockDowngraded` |
| The new unlock is strictly later than the old one | `NoopRelock` |

`add_stake` and `relock` share one accounts struct, so "add and extend" is a
single transaction. In the second half of a term the relock must come first.

### `withdraw()`

The staker gets everything back. `withdraw` pays the owner's whole vault balance
to their associated token account, closes both the vault and the stake account,
and returns both rents. The payout is the vault's live balance rather than the
stored `amount`; a vault holding less than `amount` is rejected with
`VaultUnderfunded` rather than paid out short.

| Constraint | Error |
|---|---|
| `now >= lock_start + lock_duration` | `LockNotExpired` |
| That sum fits in `i64` | `MathOverflow` |
| The vault holds at least the recorded `amount` | `VaultUnderfunded` |

There is no partial withdraw. The unlock time is recomputed from stored state on
every call rather than cached, so a backward clock correction denies the
withdrawal rather than mispaying it.

---

## Security model

### What the program guarantees

- **Only the owner can move their stake.** Every instruction requires the
  owner's signature, and the stake account is bound to the owner both by its PDA
  seeds and by an independent `has_one` check on the stored field.
- **No one can reach another staker's tokens, or withdraw earlier than their own
  unlock.** A withdrawal can only name the signer's own vault; the unlock is
  recomputed, not trusted.
- **A vault never owes more than it holds.** Recorded amounts only move together
  with matching token transfers, and a short vault reverts rather than paying out
  what is there.
- **A lock can only ever get longer.** No instruction shortens a term or moves
  an unlock earlier.
- **Exactly one mint.** It is compiled into the binary per cluster, and a
  mismatched build fails closed (`stake` rejects every mint) rather than
  accepting the wrong token.
- **Classic SPL Token only.** The token program is pinned, which excludes
  Token-2022 and every extension hazard that comes with it — transfer hooks,
  transfer fees, permanent delegates, default-frozen accounts.

### What it explicitly does not

- **There is no pause and no admin.** Nothing can stop a withdrawal, and nothing
  can stop a deposit. This is deliberate — an admin key that can halt the
  program is a key that can be stolen — but it means the only lever in an
  incident is a program upgrade.
- **The upgrade authority can replace the program and drain every vault.** This is
  the single largest risk in the system and no on-chain mechanism constrains it.
  At mainnet deploy the authority will be a Squads v4 2-of-2 multisig vault with
  a 3600-second timelock; until the authority is burned, it remains a trusted
  party. Verify it yourself rather than trusting this document — see
  [Verifying a deployment](#verifying-a-deployment).
- **Tier and reward logic is off-chain and is not part of this program.** The
  chain does not know what a tier is, and deliberately accepts **any** lock from
  one second to four years rather than an enum of the product's five tiers — so
  the tier table can change without a program upgrade. That is safe because the
  off-chain mapping rounds *down* to the tier a duration actually clears, never
  up. The consequence an auditor should note: the set of valid lock lengths is
  not enforced on chain, so "every live stake maps to a tier" is a backend
  property, not a guarantee of this program. See `docs/invariants.md` § I19 and
  `docs/threat-model.md` § T3. A bug in the off-chain multiplier cannot move a
  token, but this repository does not constrain it either.
- **Tokens sent to a vault become that staker's.** A vault is an ordinary token
  account; anyone can transfer into it. There is still no sweep and no rescue
  instruction, but `withdraw` pays the full balance, so a donation leaves with the
  one staker it was sent to. It is the donor's loss only and never a solvency
  risk. **Do not use a vault address as a deposit address.**
- **The account layout is frozen.** `StakeAccount` has no version field and
  there is no migration instruction. Changing the layout means deploying under a
  new program id.
- **No events.** The program emits no logs a consumer should depend on; state is
  read from the accounts.
- **Time is the validator clock.** Locks are enforced against
  `Clock::unix_timestamp`, which is a stake-weighted estimate, not a hardware
  clock. It can be corrected backwards. Locks here are measured in days to
  years, so the drift is immaterial — but a matured stake is not guaranteed to
  *stay* matured across a backward correction.

---

## Building

The toolchain is pinned and CI reads the pins rather than duplicating them:
anchor-cli **1.1.2** and solana-cli (agave) **2.2.19** from `Anchor.toml`'s
`[toolchain]` block, rustc **1.89.0** from `rust-toolchain.toml`. `Cargo.lock`
is committed for the SBF toolchain — do not run `cargo update`.

```bash
avm install 1.1.2 && avm use 1.1.2
anchor build                                              # localnet/devnet artifact
anchor build -- --no-default-features --features mainnet   # the only valid mainnet build
```

**Cargo features are additive.** `default = ["localnet"]` stays on unless you
disable it, so a mainnet build *must* pass `--no-default-features`. Combining
`mainnet` with `localnet` or `devnet` is a `compile_error!`, so this cannot pass
silently. A build with no cluster feature at all also fails, because `SOLC_MINT`
is then undefined.

Every variant is written to the same `target/deploy/solcard_staking.so`. Copy it
to a variant-named path before building another, or the second build silently
replaces the first.

### Addresses per cluster

| | mainnet | devnet / localnet |
|---|---|---|
| Program id | `EefJuupWjZbyqbKt11b1nn11nT57N7goeLg7CBA5E3rZ` | `2RASqhcgpvvkqbkH6z7W3RSSpsvSRt4WCPvmqkccso8g` |
| SOLC mint | `DLUNTKRQt7CrpqSX1naHUYoBznJ9pvMP65uCeWQgYnRK` | `4RrWLCNESAemwKDj9KjGnBkfyxKzWy8XGCBguzdqnyRb` |
| A staker's stake account | `["stake", owner]` under the program id | same derivation |
| A staker's vault | `["vault", owner]` under the program id | same derivation |

There is no global vault address to publish: both accounts are derived per
staker, so they differ per cluster only through the program id.

The devnet program id's keypair has been exposed and is treated as
compromised; it must never be used on mainnet, which is why `declare_id!` is
`cfg`-gated rather than configured.

## Running the tests

The suite is Rust + LiteSVM — no validator, no JavaScript.

```bash
anchor build
cargo test -p solcard-staking-litesvm-tests -- --test-threads=1
```

`--test-threads=1` is not a workaround; it makes a failure attributable to one
test rather than to whichever happened to run beside it.

To run the same suite against a specific artifact — which is how the mainnet
variant is tested — point `SOLCARD_STAKING_SO` at it:

```bash
anchor build -- --no-default-features --features mainnet
cp target/deploy/solcard_staking.so target/deploy/solcard_staking-mainnet.so
SOLCARD_STAKING_SO="$PWD/target/deploy/solcard_staking-mainnet.so" \
  cargo test -p solcard-staking-litesvm-tests --no-default-features --features mainnet -- --test-threads=1
```

The harness fails the boot with an explicit message if the `.so` it loads pins a
different `SOLC_MINT` than the test binary was compiled for, so the artifact and
the expectations cannot silently disagree.

CI builds and runs the full suite against **both** the localnet and the mainnet
artifact on every change, and asserts that a flagless build is not a mainnet one.

### Lints

```bash
cargo clippy -p solcard-staking -- -D warnings
cargo fmt --check
```

The program crate denies `unsafe_code` and, as errors:
`clippy::arithmetic_side_effects`, `expect_used`, `indexing_slicing`,
`integer_division`, `panic`, `todo`, `unimplemented`, `unreachable`,
`unwrap_used`. There is exactly one `#[allow]` in the program — on the
half-term division in `add_stake`, where flooring is intended and the comment
says so. Nothing in the program can panic or wrap: `overflow-checks = true` in
the release profile is a backstop, not the mechanism.

## Verifying a deployment

Nothing below trusts this repository's claims. Run it against the chain.

```bash
# 1. Who can upgrade the program, and when was it last deployed?
solana program show EefJuupWjZbyqbKt11b1nn11nT57N7goeLg7CBA5E3rZ

# 2. Is the mint what this program was built for, and can anyone freeze a vault?
spl-token display DLUNTKRQt7CrpqSX1naHUYoBznJ9pvMP65uCeWQgYnRK
#    expect: 6 decimals, mint authority and freeze authority both null

# 3. Is a staker solvent? Their vault's balance must be >= their stake's `amount`.
#    There is no single vault to check: derive both accounts from the owner and
#    compare, and a full sweep walks every stake account and the vault beside it.
spl-token balance --address $(solana find-program-derived-address \
  EefJuupWjZbyqbKt11b1nn11nT57N7goeLg7CBA5E3rZ string:vault pubkey:<OWNER>)
#    `amount` is the u64 at offset 40 (8 discriminator + 32 owner)
solana account $(solana find-program-derived-address \
  EefJuupWjZbyqbKt11b1nn11nT57N7goeLg7CBA5E3rZ string:stake pubkey:<OWNER>)
```

### Reproducing the binary

Use [`solana-verify`](https://github.com/solana-foundation/solana-verifiable-build)
(the current tool — `anchor build --verifiable` is the older path and is not what
feeds the explorer's verified badge). It builds in a pinned Docker image, so it
reproduces the same bytes on any host; a bare `anchor build` does not, because
the host toolchain differs.

```bash
solana-verify build --library-name solcard_staking -- --no-default-features --features mainnet
```

**`--no-default-features --features mainnet` is load-bearing.** The default
feature is `localnet`, which pins a different mint and therefore produces
different bytes. Omitting it silently verifies the wrong artifact.

No extra flags are needed beyond that: `programs/solcard-staking/Cargo.toml`
carries `[package.metadata.solana] tools-version = "v1.52"`, and the root
`Cargo.toml` pins the image with `[workspace.metadata.cli] solana = "3.0.1"`.
Without the first, `cargo build-sbf` takes the image default (platform-tools
v1.48/v1.51, cargo 1.84), which cannot parse the edition-2024 crates in
anchor-lang 1.1.2's dependency graph.

### Comparing against a deployment

```bash
solana-verify get-executable-hash target/deploy/solcard_staking.so
solana-verify get-program-hash -um EefJuupWjZbyqbKt11b1nn11nT57N7goeLg7CBA5E3rZ
```

The two must be equal.

> **This is not the same number as `sha256sum`.** `get-executable-hash` strips
> the trailing zero padding that the loader adds, so the two disagree by design.
> For the source in this commit (SolCard
> `89ead1116e9d2074331cdf8a2662fc50d7614dab`) the executable hash is
> `dbc962cb7b45169f826d325ddc4877162700a71ec1d91eff4bb721be34d79040` and the
> plain `sha256sum` of the same file is
> `1a47c9fb181bf1f787be034e893a47f8c474cdbbf3e709da5548b4c853af60fb`. Compare
> like with like, and recompute both after any source change — they are
> per-commit values, not constants.

Toolchain provenance for those hashes: `solana-verify` 0.5.1, image
`solanafoundation/solana-verifiable-build:3.0.1`, platform-tools v1.52. For that
commit the Docker build also reproduced our CI artifact byte for byte, which is
what makes the two build paths interchangeable — though that is an observation
about a commit, not a guarantee, so re-check it rather than assuming it.

Once the mirror is public and the program is deployed, verification can be
published on-chain with `solana-verify verify-from-repo`. A verified badge means
the deployed binary reproducibly matches published source. It does **not** mean
the source is safe, and it only means anything at all if the verification was
submitted by the program's upgrade authority.

**No verification has been published yet, because the program is not deployed to
mainnet.** Treat any future mainnet deployment as unverified until this section
names the deployed commit.

## Audit status

**This program has not been externally audited.** No third-party review has been
commissioned or completed, and no report exists to link. It is deployed to devnet
only and holds no real funds.

The review that *has* been done is internal: an adversarial test suite, the bulk
of it exploit attempts rather than happy paths; a fuzzed operation-sequence model
that checks the solvency and monotonicity invariants after every step; and
internal security review passes. `docs/invariants.md` records what those tests
actually prove, and `docs/threat-model.md` records what they do not.

This section will name the firm, the commit and the report when that changes.

## Reporting a vulnerability

See [SECURITY.md](./SECURITY.md). Please do not open a public issue for a
security report.

## Licence

Apache License 2.0 — see [LICENSE](./LICENSE). Copyright 2026 SolCard.
