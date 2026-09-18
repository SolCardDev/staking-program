# Threat model

What this program protects, from whom, and where it stops protecting you.
`invariants.md` says what is guaranteed and names the test for each; this
document says what is *not*, and why.

---

## Assets

| Asset | Where it lives | Worst case |
|---|---|---|
| Each staker's SOLC | **Their own vault** — a program-created token account at `["vault", owner]`, authority = their `StakeAccount` PDA | Loss for that staker |
| Each staker's position | Their `StakeAccount` PDA | Forged or altered state mispays that staker |
| Rent deposits | Lamports on each `StakeAccount` **and** each vault | Small per-user loss |
| The right to upgrade the program | Off-chain: a Squads v4 multisig | **Total loss for every staker at once** |

One vault per staker is the defining choice. Custody is partitioned: a bug in
the token path, a freeze, or an over-claim reaches one account, and no
instruction a staker can construct is even able to name another staker's vault.
The costs are real and are not hidden here — a second rent-exempt account per
staker (~0.00204 SOL, refunded on withdraw), one extra CPI on `withdraw`
(`CloseAccount`), and monitoring that must read N accounts rather than one.

The vault is a **plain PDA token account, not an ATA of the stake account**.
Anyone can create another wallet's ATA for the price of rent, and Anchor's
`init` fails on an account that already exists — so an ATA vault would let a
stranger permanently block a chosen victim's `stake`. Only the program can sign
for `["vault", owner]`, and `init` adopts lamports somebody pre-sent there.

`withdraw` pays the vault's **full balance**, not the recorded `amount`, then
closes it. SPL `CloseAccount` refuses a non-empty account, so "pay `amount`,
then close" would let anyone brick a victim's withdraw forever by sending their
vault one base unit. The consequence is that a donation to a vault is paid to
that vault's owner (T7).

## Actors

| Actor | Capability | Trusted? |
|---|---|---|
| A staker | Sign for their own wallet; call any instruction | No |
| Any third party | Submit any transaction; create/pre-fund accounts; donate to the vault | No |
| A validator | Choose transaction order; report the timestamp within consensus bounds | Bounded (see T5) |
| The SOLC mint authority | Mint; freeze token accounts | N/A on mainnet — both authorities are **null** |
| The upgrade authority | Replace the program entirely | **Yes — fully trusted** (T8) |
| SolCard's backend | Read the chain; compute tiers and rewards | Not trusted by the chain; cannot move a token |

The program treats every caller as hostile. It has no notion of an administrator
and no privileged account; there is nothing for a compromised operator key to
reach, because no such key exists on-chain.

## Trust boundaries

```
  UNTRUSTED                        │  ENFORCED ON-CHAIN        │  TRUSTED
  ─────────────────────────────────┼───────────────────────────┼─────────────────────
  Any wallet, any transaction,     │  signer + PDA seeds       │  Upgrade authority
  any account passed in, any       │  + has_one + address pin  │  (can replace all of
  amount, any lock duration        │  + ATA derivation         │   the middle column)
                                   │  + checked arithmetic     │
  ─────────────────────────────────┼───────────────────────────┤  SOLC mint authorities
  Backend tier/reward logic        │  (not consulted at all)   │  (null on mainnet)
  Web frontend                     │  (not consulted at all)   │
  ─────────────────────────────────┼───────────────────────────┤  Solana runtime,
  Clock (within consensus bounds)  │  >= comparison only       │  SPL Token program
```

Everything the program relies on in the left column is validated. The right
column is where the residual risk is, and T8 is the whole of it that matters.

---

## Vulnerability classes considered

Reviewed against the Sealevel Attacks taxonomy
(<https://github.com/coral-xyz/sealevel-attacks>), Neodyme's common-pitfalls
material (<https://neodyme.io/en/blog/solana_common_pitfalls/>), and Neodyme's
Token-2022 extension hazards (<https://neodyme.io/en/blog/token-2022/>). Each
row names how the class is closed; `invariants.md` names the test.

| # | Class | How it is closed | Invariant |
|---|---|---|---|
| 0 | Signer authorization | `Signer<'info>` on `owner` in all four instructions | I6 |
| 1 | Account data matching | `has_one = owner`, checked independently of the seeds | I6 |
| 2 | Owner checks | Typed `Account<'info, T>`; Anchor checks the program owner before deserializing | I15 |
| 3 | Type cosplay | Anchor's 8-byte discriminator; a foreign one is rejected | I15 |
| 4 | Re-initialization | `init`, never `init_if_needed`; `init-if-needed` feature not enabled | I14 |
| 5 | Arbitrary CPI | `Program<'info, Token>` pins the SPL Token program id | I16 |
| 6 | Duplicate mutable accounts | Source and destination substitutions rejected in both directions | I16 |
| 7 | Bump seed canonicalization | Canonical bump derived by Anchor on `init`, stored, then re-supplied via `bump = stake_account.bump` | I6 |
| 8 | PDA sharing | No PDA is shared between stakers. A stake PDA signs only inside `withdraw`, only to drain and close its own vault | I7 |
| 9 | Closing accounts / revival | Anchor `close = owner`: lamports drained, data zeroed, account assigned to the system program. Revival within one transaction and across transactions both rejected | I5, I14 |
| 10 | Sysvar address checking | No sysvar is passed as an account; `Clock::get()` is a syscall | — |
| — | Integer overflow / underflow | Explicit `checked_*`/`try_from` everywhere; `overflow-checks = true` as a backstop; `clippy::arithmetic_side_effects` denied | I18 |
| — | Rounding direction | `div_ceil`, always toward the later unlock | I11 |
| — | Token-2022 extensions (transfer hooks, transfer fees, permanent delegate, default-frozen, confidential transfers) | Excluded wholesale: the classic token program is pinned, and a Token-2022 mint is rejected even when its own program is supplied | I16 |
| — | Vault insolvency | `amount` only moves with a matching transfer; a vault short of `amount` reverts with `VaultUnderfunded` rather than paying what is there | I1, I4 |
| — | Clock manipulation | `>=` comparison only; unlock recomputed, never cached | I9, T5 |
| — | DoS via account state | Nobody can squat, block or grief another user's PDA | I8 |

Sec3's 2025 aggregate of 163 Solana audits (<https://sec3.dev/report>) puts
85.5% of high/critical findings in business logic, input validation and access
control rather than in the classic Sealevel classes. That is why the largest
part of the suite, and of the analysis below, is economic rather than structural.

---

## Residual risks

Ordered by what they cost if they come true.

### T8. The upgrade authority can drain the vault

**Severity: critical. Not mitigated on-chain; nothing in this repository
constrains it.**

Whoever holds the upgrade authority can deploy a `withdraw` that pays them
everything. This is the single largest risk in the system and it dwarfs every
other row here. The only mitigations are governance ones:

- The authority is a Squads v4 **2-of-2** multisig vault, not a single key, with
  a **3600-second timelock** on execution.
- The timelock is the only window in which a malicious upgrade can be stopped.
  Stakers cannot exit during it — they are lock-bound — so the window protects
  the operators' ability to react, not the users' ability to leave.
- Burning the authority would remove the risk entirely. It is **not** burned,
  because with no pause and no migration path, an upgrade is the only way to fix
  any bug at all. That trade is deliberate.

Verify the current authority with `solana program show <program-id>` rather than
trusting any document, including this one.

### T1. Economic residual in `add_stake`

**Severity: low, bounded, and it is the feature as designed.**

`add_stake` keeps `lock_duration` and moves `lock_start` forward by
`ceil(elapsed × a / (A + a))`. The added tokens therefore serve
`(A · remaining_old + a · lock_duration) / (A + a)` seconds — between
`remaining_old` and a full term — while the account reads `lock_duration` at its
full value.

If the off-chain multiplier is keyed on `lock_duration` (it is), a top-up made
in the first half of a term carries the full-term factor for as little as
`floor(lock_duration / 2)` of real lock.

The bound, and why it is acceptable:

- **Worst case is 2x, at the half-term boundary, for a top-up much smaller than
  the existing stake.** As `a → 0` the added tokens serve `remaining_old`, which
  the gate holds at `≥ lock_duration / 2`.
- **It shrinks to nothing as the top-up grows.** For `a ≫ A` the shift
  approaches `elapsed`, so the new tokens serve a genuine full term. A whale
  cannot free-ride.
- **It is self-funded.** The discount is paid for by an equal-or-larger honest
  position whose own unlock is pushed later by exactly the amount saved. Total
  capital-seconds are conserved — invariant I12, checked after every step of
  every fuzzed sequence.
- **It cannot revive a matured position.** The half-term gate rejects any add on
  a stake with less than half its term left, which is the attack that would
  otherwise matter: a matured max-tier position topped up by 1% every few days,
  holding the top tier forever on a few days of real lock.

Closing it completely means setting `shift = elapsed`, which makes every top-up
re-lock the whole base position for a full term. That was considered and rejected
on UX grounds: a staker adding a small amount would lose access to their whole
balance for a fresh full term. It is a product decision, not an open bug.

**If the off-chain tier logic ever changes to pay matured stakes, or to key the
factor on remaining time rather than term, this analysis must be redone.**

### T2. Elapsed time is not commitment

**Severity: low on-chain, high for a naive consumer.**

A matured stake stays open indefinitely — nothing sweeps or closes it. A
position opened with a one-second lock and left alone is, a year later,
indistinguishable in shape from a long-term stake while remaining withdrawable
in the next slot.

Any consumer computing tenure as `now − lock_start` credits a year of loyalty to
capital that was locked for one second. Read `lock_duration`, and check whether
the stake is still live. Asserted as intended behaviour in
`exploits_economics.rs::reachable_an_expired_stake_stays_open_forever_so_elapsed_time_is_not_commitment`.

### T3. The chain has no minimums and no whitelist

**Severity: low on-chain; it is where the off-chain gating has to be.**

Any amount above zero and any lock from one second to four years is accepted and
stored verbatim. The product's five lock tiers (7/30/90/180/365 days) exist only
off-chain; the program has no enum and no allowlist, so the tier table can be
retuned with a deploy instead of an upgrade ceremony under a 3600-second timelock.

**This is safe because the off-chain mapping rounds down**, not because arbitrary
durations are unreachable. The resolver picks the highest tier whose threshold the
duration actually clears, so a 45-day lock earns the 30-day factor and a 364-day
lock earns the 180-day factor; anything under the shortest tier earns nothing, and
an expired position matches no tier at all. A staker who picks an odd duration is
buying lock time they are not credited for. See `invariants.md` § I19 — and note
that the rounding is a **backend** property, so "every live stake maps to a tier"
is not something this program guarantees.

**That argument breaks** if the multiplier is ever keyed on remaining time rather
than `lock_duration`, or if a tier is added whose factor is not monotonically
increasing in duration — at which point "the tier below" stops being the
conservative answer. Either change requires redoing this section and § T1.

Eight wallets can become maximum-lock stakers for eight base units in total, and
capital can be recycled through unlimited wallets one second at a time. None of
this is an on-chain defect — it is the leanness contract — but a backend that
grants perks without its own minimum and Sybil handling will be farmed. All of
these behaviours are asserted as intended.

### T4. A freeze authority could strand individual stakers

**Severity: high if it were reachable; it is not, on mainnet.**

Every vault is an ordinary SPL token account. A non-null freeze authority on the
mint could freeze one, halting that staker's withdrawal with no recovery path in
the program. A freeze reaches one vault and therefore one staker, so this is
per-victim censorship rather than a halt of every withdrawal at once — a small
blast radius, but no remedy within it. Mainnet SOLC
(`DLUNTKRQt7CrpqSX1naHUYoBznJ9pvMP65uCeWQgYnRK`) has **both mint and freeze
authority null**, verifiable with `spl-token display`. Re-check it rather than
trusting this line. A frozen individual staker ATA strands that staker alone from
the other side.

### T5. Clock drift and backward correction

**Severity: low.**

Locks are enforced against `Clock::unix_timestamp`, a stake-weighted validator
estimate, not a hardware clock. The runtime bounds per-slot drift (up to ~25%
fast, ~150% slow) but does not guarantee strict monotonicity, so the value can
be corrected backwards.

Consequences, all of which fail safe:

- A matured stake is not guaranteed to *stay* matured; a backward correction
  re-locks it until the clock recovers. It denies a withdrawal rather than
  mispaying one.
- `relock` sets `lock_start = now`, so under a backward correction `lock_start`
  can decrease. The unlock cannot — `relock` requires it to move strictly later.
- `add_stake` clamps `elapsed` at zero, so a clock behind `lock_start` produces
  no shift rather than a negative one.

Locks here are days to years. Drift of seconds is immaterial to the product and
cannot be steered into a payout.

### T6. A delegate on a staker's own ATA

**Severity: low; it is outside the program's control.**

If a staker has approved a delegate on their SOLC associated token account, that
delegate takes the withdrawal the moment it lands. The program pins the
destination to the owner's ATA — it cannot pin what the owner has already
authorised on it. Asserted, not fixed, in
`exploits_accounts.rs::documents_that_a_delegate_takes_the_withdrawal_the_moment_it_lands`.

Relatedly: `withdraw` is unavailable while the owner's ATA is closed, and
recovers when it is recreated. Clients prepend an idempotent ATA create.

### T7. Tokens sent to a vault become that staker's property

**Severity: low; donor's loss only, never a solvency risk.**

Anyone can transfer SOLC into any vault. `withdraw` pays the full balance, so the
surplus goes to that vault's owner when they unwind — it is a gift to a stranger,
not a burn, and there is no sweep and no rescue instruction. Paying the balance
rather than the recorded `amount` is what stops a one-base-unit dust transfer
bricking a victim's withdraw, since SPL `CloseAccount` refuses a non-empty
account.

A donation cannot mispay anyone else: it is confined to the one vault it was sent
to, and `VaultUnderfunded` catches the opposite case.

**Do not publish a vault address as a deposit address.**

### T9. No verification has been published on-chain yet

**Severity: medium until resolved; the build itself is reproducible.**

The build *is* reproducible — `solana-verify build` produces the same bytes on
any host, and the README gives the exact command and the expected hashes. What
does not exist yet is a published on-chain verification, because the program is
not deployed to mainnet. Until one exists, a third party can reproduce the
binary but cannot confirm that it is what is running.

Note also that a verification only means anything if the upgrade authority
submitted it; anyone can publish a claim about any program.

### T10. `relock` requires a token account it never uses

**Severity: very low; an availability edge, not a loss.**

`add_stake` and `relock` share one accounts struct, so `relock` requires an
initialized `owner_token_account` and the owner's `vault` although it moves no
tokens. A
staker whose SOLC ATA is closed cannot extend their lock until they recreate it
— which requires acquiring some SOLC. Withdraw is unaffected (clients prepend an
idempotent ATA create there). Fixing it means a second accounts struct and an
IDL change, which is not worth an upgrade on its own.

### T11. `LockDowngraded` is not enforceable on a matured stake

**Severity: none; noted so a reviewer does not report it as a finding.**

`relock` refuses a term shorter than the current one. On a *matured* stake that
guard is cosmetic: the same wallet can `withdraw` and `stake` again with a
shorter term in a single transaction, landing a downgraded position at the same
PDA address. The guard is only meaningful while a stake is unmatured, which is
also the only place it is needed.

Because the stake account is closed and recreated with no on-chain marker of
continuity, **nothing should infer position history from the PDA address**. Read
live state.

---

## Out of scope

Not defects in this program, and not covered by anything above:

- The off-chain tier, multiplier and reward logic.
- The web frontend and any client library.
- The SOLC token's own economics, distribution or listing.
- Solana runtime and SPL Token program correctness.
- Wallet and key custody on the staker's side.
- Denial of service against RPC providers.
