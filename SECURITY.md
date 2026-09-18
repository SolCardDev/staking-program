# Security policy

This program is an escrow. Each staker's SOLC sits in **their own vault**, a
program-created token account at `["vault", owner]` held by that staker's stake
PDA — so an exploitable path in the token flow costs one staker, not all of them.
The upgrade authority is the exception and still reaches everything. We would
rather hear about a problem from you than from the chain.

---

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security report,
and do not disclose publicly before we have responded.**

**Email `security@solcard.cc`.** That is the primary channel and the one that
reaches us fastest. We do not publish a PGP key; if you need encryption, say so
in a first message with no details and we will arrange it.

**GitHub private vulnerability reporting** — the *Report a vulnerability* button
under this repository's **Security** tab — is also available, and is a
reasonable choice if you would rather the whole exchange stayed on GitHub.

Please include, as far as you have it:

- Which instruction and which accounts are involved.
- The concrete transaction sequence that reaches the problem — a failing test
  against `tests-rs/` is the single most useful thing you can send.
- What an attacker gains: tokens, someone else's position, or unearned state.
- The commit hash you looked at, and which cluster feature you built with.

## What to expect from us

| Stage | Target |
|---|---|
| Acknowledgement that a human has read it | 2 business days |
| Initial assessment and a severity we agree on | 5 business days |
| Status update while work is in progress | Every 7 days |
| Fix deployed, or a written explanation of why not | 90 days |

Fixing anything on-chain requires a multisig upgrade under a timelock, so a
deploy is slower than a patch. We will tell you the actual schedule rather than
letting the clock run silently.

We will credit you by name or handle when the fix is public, unless you ask us
not to.

## Safe harbour

If you act in good faith under this policy, we will treat your research as
authorised. Specifically, we will not pursue or support legal action against
you, and if a third party brings action we will make it known that your research
was authorised — provided you:

- Do not access, modify or exfiltrate data belonging to anyone but yourself.
- Take **only the minimum** needed to demonstrate the issue. Do not move funds
  you are not entitled to; a proof of concept on devnet or in a local validator
  is always sufficient and is what we want to see. **Do not test against
  mainnet.**
- Do not degrade the service for others — no denial of service, no spam, no
  social engineering of our staff, users or infrastructure providers.
- Report promptly, and give us a reasonable chance to fix the issue before
  disclosing it.

If you are unsure whether something crosses a line, ask first. We would rather
answer a question than argue afterwards.

This safe harbour covers this repository. It cannot bind third parties, and it
does not authorise anything unlawful.

---

## Scope

### In scope

- The on-chain program: everything under `programs/solcard-staking/src/`.
- The build and cluster-binding configuration insofar as it affects what is
  deployed — the `SOLC_MINT` pin, the `declare_id!` gating, the feature-additivity
  `compile_error!`.
- The committed IDL, where it misrepresents the program.
- Anything that breaks a property stated in [`docs/invariants.md`](./docs/invariants.md).

Findings we are most interested in, roughly by severity:

1. Any path by which a staker's vault holds less than their recorded `amount`,
   or by which one staker's funds pay another.
2. Any withdrawal before `lock_start + lock_duration`, or paid to an account
   other than the owner's.
3. Any way to act on a stake without the owner's signature.
4. Any way to move an unlock earlier, shorten a term, or reduce a recorded amount.
5. Any way to obtain a `(amount, lock_duration, unlock)` triple that was not
   paid for in locked capital, **beyond the bound already documented** in
   [`docs/threat-model.md`](./docs/threat-model.md) § T1.
6. Any account substitution, re-initialization or revival the constraints miss.
7. Arithmetic that wraps, panics or strands an account.

### Out of scope

These are known, documented and accepted. Reporting them is not a finding, but
if you think the *analysis* of one is wrong, that is very much a finding — say
which step is wrong.

- **The upgrade authority can replace the program and drain every vault.**
  `docs/threat-model.md` § T8. This is the design's central trusted party.
- **The economic residual in `add_stake`** — a first-half top-up carries the
  full-term tier for as little as half the term, bounded at 2x and self-funded.
  § T1. A demonstration that the bound is *wrong* is in scope.
- **Tokens sent directly to a vault become that vault owner's** and leave with
  their withdrawal. § T7.
- **The chain enforces no minimum stake, no lock whitelist and no Sybil
  resistance**; a matured stake stays open indefinitely. §§ T2, T3.
- **A delegate previously approved on a staker's own ATA** takes their
  withdrawal. § T6.
- **Clock drift and backward correction.** § T5.
- **`relock` requires an ATA it never uses.** § T10.
- **`LockDowngraded` is cosmetic on a matured stake.** § T11.
- Off-chain tier, multiplier and reward logic; the web frontend; wallet and key
  custody on the staker's side; RPC availability. Not in this repository.
- Solana runtime, SPL Token program and Anchor framework issues — report those
  upstream. If one of them breaks *this* program specifically, tell us too.
- Findings already listed in a published audit report, once one exists.
- Style, formatting, dependency versions with no demonstrated impact, and
  automated-scanner output with no exploit path.

## Rewards

**There is no formal bug bounty programme today.** Where a report turns out to
be a genuine, previously unknown vulnerability, a reward is discussed case by
case with the reporter, at SolCard's discretion.

We would rather say that than stay silent about it. But be clear on what it
means: there are no tiers, no amounts and no cap, and **nothing in this document
is an offer of payment** or an entitlement to one. Report because you want the
thing fixed; if a reward follows, we will talk to you about it directly.

We will credit you publicly whether or not anything else follows, unless you ask
us not to.

## Audit status

**This program has not been externally audited.** It is deployed to devnet only
and holds no real funds. `docs/invariants.md` records what the internal test
suite actually proves; `docs/threat-model.md` records what it does not.
