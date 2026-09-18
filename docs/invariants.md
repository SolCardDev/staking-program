# Invariants

Every property this program is supposed to guarantee, and the test that proves
it. A property with no test named against it is not a guarantee — it is a hope,
and it is listed in the last section as such.

Test paths are relative to `tests-rs/tests/`. The suite runs against both the
localnet and the mainnet build artifact on every change.

Four of these are also checked **after every step of every generated operation
sequence** by the model in `fuzz_sequences.rs` (`check_invariants`), rather than
only at the end of a hand-written scenario. Those are marked **[fuzzed]**.

---

## 1. Solvency

### I1. Every owner's vault balance is never below that owner's `amount`. **[fuzzed]**

The one property the whole design rests on. Each staker has their own vault at
`["vault", owner]`, held under their own stake PDA, and `amount` only ever
changes alongside a `transfer_checked` of the same value in the same direction,
so the two move together by construction. No staker's principal sits in an
account another staker's instruction is able to name.

| Proof | Test |
|---|---|
| Holds for every actor after every step of every generated sequence | `fuzz_sequences.rs::small_domain_sequences_hold_every_money_invariant`, `::wide_domain_sequences_hold_every_money_invariant` |
| Holds across 8 actors and every operation | `exploits_economics.rs::holds_every_vault_equals_its_own_stake_after_every_operation_with_8_actors` |
| Holds with two users interleaved | `add_stake_relock.rs::every_vault_equals_its_own_stake_across_two_interleaved_users`, `fuzz_sequences.rs::two_users_interleaved_settle_to_exactly_what_they_deposited` |
| The recorded amount equals the vault delta, from 1 unit to 1e18 | `exploits_economics.rs::stored_amount_always_equals_the_vault_delta_from_1_unit_to_1e18` |
| One vault survives the entire u64 supply | `exploits_economics.rs::a_single_vault_survives_the_entire_u64_supply_and_pays_it_back_in_full` |
| One staker's withdraw does not touch another's vault | `exploits.rs::keeps_every_staker_whole_across_interleaved_withdrawals` |

A vault's balance may be **above** its owner's `amount` — see I3.

### I2. Token supply never drifts. **[fuzzed]**

Tokens in circulation plus tokens in the vault always equals what was minted;
the program neither mints nor burns.

| Proof | Test |
|---|---|
| Checked after every generated step | `fuzz_sequences.rs::small_domain_sequences_hold_every_money_invariant` |
| A base unit round-trips with no rounding loss | `exploits_economics.rs::a_1_base_unit_stake_round_trips_with_no_rounding_loss` |
| Rent is exactly conserved across repeated cycles | `exploits_economics.rs::rent_is_exactly_conserved_across_repeated_stake_withdraw_cycles` |

### I3. A surplus in a vault is paid to that vault's owner.

Anyone may transfer into a vault. `withdraw` pays the vault's **full balance**,
not the recorded `amount`, and then closes the account — so a donation reaches
exactly one party, the staker whose vault it was sent to, and nothing is left
stranded.

Paying the full balance is load-bearing, not a convenience. SPL `CloseAccount`
refuses a non-empty account, so a "pay `amount`, then close" withdraw could be
bricked forever by sending the victim's vault one base unit.

| Proof | Test |
|---|---|
| A donation is paid to the owner, and the vault still closes | `exploits.rs::a_donation_to_a_vault_is_paid_to_that_vaults_owner`, `exploits_economics.rs::tokens_sent_to_a_vault_leave_with_that_vaults_owner` |
| One base unit of dust does not brick the withdraw | `exploits.rs::a_dust_donation_to_a_victims_vault_does_not_brick_their_withdraw` |

Sending SOLC to someone else's vault address is therefore a gift to that staker,
not a burn. See `threat-model.md` § T7.

### I4. An under-funded vault fails loudly instead of quietly shorting its owner.

Because `withdraw` pays the vault's full balance, a vault holding less than the
recorded `amount` would silently pay a staker less than they are owed. It is
rejected with `VaultUnderfunded` (6007) instead, and nothing moves.

| Proof | Test |
|---|---|
| Forged over-claim reverts whole | `exploits_forged_state.rs::fails_loudly_rather_than_partially_draining_when_a_stake_over_claims_the_vault` |
| One staker cannot reach a whale's principal | `exploits_economics.rs::a_1_unit_staker_cannot_reach_a_whales_principal_in_another_vault`, `exploits.rs::a_staker_cannot_reach_another_stakers_vault_at_all` |
| Interleaved withdrawals keep everyone whole | `exploits.rs::keeps_every_staker_whole_across_interleaved_withdrawals`, `exploits_accounts.rs::two_owners_withdrawing_in_one_transaction_each_get_their_own_principal` |

---

## 2. Custody

### I5. A withdrawal reaches only its own vault, and reaches it only once. **[fuzzed]**

Not "never more than `amount`": the payout is the vault's full balance, which a
donation can push above the recorded `amount` (I3). What no staker can do is take
a base unit out of anyone else's vault, or collect their own vault twice.

| Proof | Test |
|---|---|
| Lifetime withdrawn never exceeds lifetime deposited, every step | `fuzz_sequences.rs::small_domain_sequences_hold_every_money_invariant` |
| A staker cannot reach another staker's vault at all | `exploits.rs::a_staker_cannot_reach_another_stakers_vault_at_all`, `exploits_economics.rs::a_1_unit_staker_cannot_reach_a_whales_principal_in_another_vault` |
| No signer reaches another owner's PDA, after any generated sequence | `fuzz_sequences.rs::a_signer_cannot_reach_another_users_stake_pda` |
| No double withdraw in one transaction | `exploits_accounts.rs::cannot_withdraw_twice_in_one_transaction` |
| A closed account cannot be revived to withdraw twice | `exploits.rs::cannot_revive_a_closed_stake_account_to_double_withdraw`, `exploits_forged_state.rs::cannot_revive_a_closed_stake_account_within_a_single_transaction` |

### I6. Only the owner can touch their stake.

Bound twice over: by the PDA seeds `["stake", owner]` and by an independent
`has_one = owner` check on the stored field, so neither alone is load-bearing.

| Proof | Test |
|---|---|
| An attacker cannot withdraw a victim's stake | `exploits.rs::attacker_cannot_withdraw_a_victims_stake_by_pointing_at_the_victims_pda` |
| A signer cannot reach another user's PDA, on any path | `fuzz_sequences.rs::a_signer_cannot_reach_another_users_stake_pda`, `add_stake_relock.rs::rejects_a_signer_pointing_at_another_users_stake_pda` (add and relock) |
| `has_one` rejects a forged stored owner on its own | `exploits_forged_state.rs::has_one_rejects_a_mismatched_stored_owner_independently_of_the_seeds_check`, `fuzz_sequences.rs::a_forged_stored_owner_is_rejected_on_every_path` |
| A downgraded (non-signer) owner meta is rejected | `exploits.rs::withdraw_rejects_when_the_owner_meta_is_downgraded_to_non_signer`, `add_stake_relock.rs::rejects_an_owner_meta_downgraded_to_non_signer` (add and relock) |
| A withdrawal cannot be redirected to a third party | `exploits.rs::rejects_redirecting_a_withdrawal_to_a_non_owner_token_account` |
| Nobody can stake another user's tokens | `exploits_forged_state.rs::cannot_stake_another_users_tokens` |
| PDAs are disjoint per owner and use the canonical bump | `exploits.rs::derives_disjoint_pdas_per_owner`, `::stores_the_canonical_bump` |

### I7. Nobody can seize, delegate or close a staker's vault.

A vault's authority is that staker's own stake PDA, which signs only inside
`withdraw` and only to pay that staker and close the account.

| Proof | Test |
|---|---|
| No `set_authority` | `exploits_accounts.rs::nobody_can_seize_a_stakers_vault_via_set_authority` |
| No close, funded or empty | `exploits_accounts.rs::nobody_can_close_a_vault_funded_or_empty` |
| No delegate can be approved on it | `exploits_accounts.rs::nobody_can_approve_a_delegate_on_a_stakers_vault` |
| A delegate on some other ATA reaches nothing | `exploits_accounts.rs::a_delegate_on_one_ata_gains_no_authority_over_the_vault` |
| Another owner's vault PDA is rejected, on stake and on withdraw | `exploits.rs::rejects_a_stake_pointed_at_another_owners_vault_pda`, `::rejects_a_withdraw_pointed_at_another_owners_vault_pda`, `add_stake_relock.rs::rejects_a_foreign_vault` (add and relock) |

### I8. Nobody can squat or grief another user's stake PDA or vault.

Both accounts are program-created PDAs opened with `init`. Only the program can
sign for their addresses, so no third party can occupy either one; pre-funded
lamports are adopted by `init` and returned to the staker on close.

| Proof | Test |
|---|---|
| A victim cannot be locked out of their own PDA | `exploits_economics.rs::nobody_can_squat_a_victims_stake_pda_to_lock_them_out_for_4_years` |
| Pre-funding the stake PDA does not block the owner's stake | `exploits.rs::stake_still_succeeds_when_the_pda_was_pre_funded_by_an_attacker` |
| Pre-funding the **vault address** does not block it either, and the lamports come back to the staker | `exploits.rs::stake_still_succeeds_when_the_vault_address_was_pre_funded_by_an_attacker` |
| Squatting the stake account's **ATA** — the vault derivation this design deliberately rejected — is inert | `exploits.rs::an_ata_squatted_on_the_stake_account_does_not_block_stake` |
| Griefed lamports are claimable only by that PDA's owner | `exploits_economics.rs::lamports_griefed_onto_a_stake_pda_are_claimable_only_by_that_pdas_owner` |

---

## 3. The lock

### I9. No withdrawal before `lock_start + lock_duration`.

The unlock is recomputed from stored state on every call, never cached.

| Proof | Test |
|---|---|
| One second before the unlock is refused | `exploits.rs::rejects_a_withdraw_one_second_before_unlock`, `lifecycle.rs::withdraw_is_rejected_before_the_lock_expires` |
| Exactly at the boundary is allowed | `exploits.rs::allows_a_withdraw_exactly_at_the_unlock_boundary`, `fuzz_sequences.rs::withdraw_at_the_unlock_boundary_one_second_either_side` |
| Stake and withdraw in one transaction cannot bypass it | `exploits_accounts.rs::cannot_bypass_the_lock_by_staking_and_withdrawing_in_one_transaction` |
| A backward clock correction denies rather than mispays | `exploits_economics.rs::a_clock_that_moves_backward_past_the_unlock_relocks_the_funds_without_losing_them` |

### I10. `amount`, `lock_duration` and the unlock are monotone non-decreasing over an account's life. **[fuzzed]**

No instruction shrinks a balance, shortens a term, or moves an unlock earlier.
Watermarked and re-checked after every generated step.

| Proof | Test |
|---|---|
| Watermark check after every generated step | `fuzz_sequences.rs::small_domain_sequences_hold_every_money_invariant` |
| Stated directly for `add_stake` | `add_stake_relock.rs::lock_start_never_decreases_never_passes_now_and_the_unlock_never_moves_earlier` |
| A top-up always pushes the unlock past the original | `add_stake_relock.rs::a_top_up_pushes_the_unlock_past_the_original_one` (also in `fuzz_sequences.rs`) |
| `relock` never downgrades and never moves tokens | `fuzz_sequences.rs::relock_never_downgrades_and_never_moves_tokens`, `add_stake_relock.rs::lengthens_the_term_and_restarts_the_lock_without_moving_tokens` |
| A shorter term is refused, matured or not, even if it would push the unlock later | `add_stake_relock.rs::rejects_a_shorter_term`, `::rejects_a_shorter_term_even_when_it_would_push_the_unlock_later`, `::rejects_a_shorter_term_on_a_matured_stake` |
| A no-op relock is refused | `add_stake_relock.rs::rejects_the_same_term_in_the_same_second`, `::rejects_an_unlock_that_does_not_move_later_under_a_clock_that_went_backwards` |

**Exception, and it is a real one.** `relock` sets `lock_start = now`. Under a
backward clock correction `now` can be *earlier* than the stored `lock_start`,
so `lock_start` itself can decrease. The unlock cannot: `relock` requires
`new_unlock > old_unlock`. The invariant that holds is about the **unlock**, not
about `lock_start`.

| Proof | Test |
|---|---|
| A backward clock cannot produce an earlier unlock | `add_stake_relock.rs::rejects_an_unlock_that_does_not_move_later_under_a_clock_that_went_backwards` |
| An add under a backward clock does not shift at all | `add_stake_relock.rs::a_clock_behind_lock_start_adds_without_shifting`, `fuzz_sequences.rs::a_backwards_clock_adds_without_shifting_and_breaks_nothing` |

### I11. `add_stake` never lets added capital serve less lock than the weighted formula, and never rounds in the user's favour.

`shift = ceil(elapsed × a / (A + a))`, rounded up, so the unlock lands at or
after the exact weighted average — by less than one second across the position.

| Proof | Test |
|---|---|
| Matches a `u128` ceiling oracle at the extremes | `add_stake_relock.rs::matches_a_u128_ceiling_oracle_at_the_extremes` |
| The shift is amount-weighted and the term is unchanged | `add_stake_relock.rs::shifts_lock_start_by_the_amount_weighted_elapsed_time_and_keeps_the_term` |
| A sub-second shift rounds up to a whole second | `fuzz_sequences.rs::a_sub_second_weighted_shift_rounds_up_to_one_second` |
| An exactly divisible shift adds no extra second | `fuzz_sequences.rs::an_exactly_divisible_weighted_shift_adds_no_extra_second` |
| Splitting a top-up into 3000 parts never unlocks earlier than one add | `add_stake_relock.rs::a_top_up_split_into_3000_parts_never_unlocks_earlier_than_a_single_add` |
| Withdraw waits for the shifted unlock and then pays the total | `add_stake_relock.rs::withdraw_fails_before_the_shifted_unlock_and_returns_the_total_after` |

### I12. No operation sequence beats honest fresh stakes in capital-seconds. **[fuzzed]**

The strongest economic statement the suite makes. Each tranche of capital is
tracked with the time it entered; after every step, `amount × remaining` must be
at least the sum over tranches of `a × (lock_duration − age)`.

| Proof | Test |
|---|---|
| Checked after every generated step | `fuzz_sequences.rs::small_domain_sequences_hold_every_money_invariant`, `::wide_domain_sequences_hold_every_money_invariant` |
| The generator actually reaches every outcome claimed | `fuzz_sequences.rs::the_generator_reaches_every_outcome_the_suite_claims_to_cover` |

**This is an aggregate statement, not a per-token one.** It says total committed
capital-seconds never fall short. It does *not* say every token served the full
`lock_duration` — see `threat-model.md` § T1 for the residual and its bound.

### I13. The half-term gate cannot be outrun.

`add_stake` requires at least half the term remaining, so a matured or
nearly-matured stake cannot be revived by a top-up.

| Proof | Test |
|---|---|
| Boundary exactly | `add_stake_relock.rs::the_half_term_guard_boundary`, `fuzz_sequences.rs::the_half_term_gate_on_an_odd_term` |
| A matured stake rejects any add, dust or whale | `add_stake_relock.rs::a_matured_stake_rejects_any_add`, `::a_long_matured_stake_cannot_be_revived_by_a_large_add`, `fuzz_sequences.rs::a_matured_stake_rejects_a_whale_add` |
| Dust added every second cannot hold the remaining lock below half | `add_stake_relock.rs::daily_dust_adds_cannot_hold_the_remaining_lock_below_half_the_term`, `fuzz_sequences.rs::perpetual_dust_adds_cannot_outrun_the_half_term_gate` |
| A whale on the last day must relock first | `add_stake_relock.rs::a_whale_on_the_last_day_must_relock_before_adding` |
| Order: in the first half either order works; in the second half relock must come first | `add_stake_relock.rs::add_and_extend_in_the_first_half_is_order_independent`, `::in_the_second_half_relock_must_come_before_the_add` |

---

## 4. Account integrity

### I14. Exactly one live stake per owner; no re-initialization.

`init`, never `init_if_needed`.

| Proof | Test |
|---|---|
| A second stake while one is live is refused with no overwrite | `exploits.rs::refuses_a_second_stake_while_one_is_active_no_re_init_overwrite` |
| Not even twice in one transaction | `exploits_accounts.rs::cannot_stake_twice_for_the_same_owner_in_one_transaction` |
| A fresh stake after a completed withdraw is allowed and resets `lock_start` | `exploits.rs::allows_a_fresh_stake_after_a_completed_withdraw`, `exploits_economics.rs::re_staking_after_a_withdraw_resets_lock_start` |
| Withdraw-then-stake in one transaction stays conservative | `exploits_accounts.rs::withdraw_then_fresh_stake_in_one_transaction_stays_conservative` |

### I15. A forged or substituted stake account is rejected.

| Proof | Test |
|---|---|
| Owned by a different program | `exploits_forged_state.rs::rejects_a_stake_account_owned_by_a_different_program` |
| A foreign discriminator (type cosplay) | `exploits_forged_state.rs::rejects_a_stake_account_with_a_foreign_discriminator` |
| A system-owned account posing as the stake account | `exploits.rs::rejects_a_system_owned_account_posing_as_the_stake_account` |
| A faithfully re-encoded account still works (the harness is not vacuous) | `exploits_forged_state.rs::sanity_a_faithfully_re_encoded_stake_account_still_withdraws` |

### I16. The mint, the vault and the token program are all pinned.

| Proof | Test |
|---|---|
| A rogue or foreign mint, on both paths | `exploits.rs::rejects_a_rogue_mint`, `::rejects_a_rogue_mint_on_the_withdraw_path`, `add_stake_relock.rs::rejects_a_foreign_mint` (add and relock) |
| A Token-2022 mint, even with its matching token program | `exploits_accounts.rs::rejects_a_token_2022_mint_even_with_the_matching_token_program` |
| A substituted token program (arbitrary-CPI defence) | `exploits.rs::rejects_a_substituted_token_program_arbitrary_cpi_defence`, `add_stake_relock.rs::rejects_a_substituted_token_program` (add and relock) |
| A token account of a different mint as the source | `exploits_forged_state.rs::rejects_a_token_account_of_a_different_mint_as_the_source` |
| An attacker-controlled account posing as the vault | `exploits.rs::rejects_an_attacker_controlled_token_account_posing_as_the_vault` |
| An **off-PDA account genuinely owned by the stake account** posing as the vault — the substitution that passes the authority check and still loses | `exploits_accounts.rs::rejects_an_off_pda_token_account_owned_by_the_stake_account_posing_as_the_vault` |
| A non-ATA source account of the right mint | `exploits.rs::rejects_staking_from_a_non_ata_token_account_of_the_pinned_mint` |
| The owner's own ATA posing as the vault | `add_stake_relock.rs::rejects_the_owner_ata_posing_as_the_vault` (add and relock) |
| Duplicate mutable accounts, both directions | `exploits_accounts.rs::rejects_withdraw_with_owner_ata_as_both_source_and_destination`, `::rejects_withdraw_with_vault_as_both_source_and_destination` |
| A stake funded out of another staker's vault | `exploits_accounts.rs::rejects_a_stake_funded_out_of_another_stakers_vault` |
| An instruction the program does not implement is rejected, not silently dispatched | `exploits.rs::an_unimplemented_initialize_vault_instruction_is_rejected_as_unknown` |

### I17. The vault is opened by `stake` and closed by `withdraw`; its rent round-trips.

There is no bootstrap step and no operator involvement. `stake` creates the vault
with `init` (never `init_if_needed`), the owner pays its rent, and `withdraw`
returns that rent along with the tokens. A staker with no live stake has neither
a stake account nor a vault.

| Proof | Test |
|---|---|
| Withdraw closes the vault and refunds its rent | `exploits.rs::withdraw_closes_the_vault_and_refunds_its_rent_to_the_owner` |
| Rent is exactly conserved over five stake/withdraw cycles, for both accounts | `exploits_economics.rs::rent_is_exactly_conserved_across_repeated_stake_withdraw_cycles` |
| A closed vault is gone, not left holding dust | `exploits_economics.rs::tokens_sent_to_a_vault_leave_with_that_vaults_owner` |
| Re-staking opens a fresh vault | `exploits.rs::allows_a_fresh_stake_after_a_completed_withdraw`, `exploits_accounts.rs::withdraw_then_fresh_stake_in_one_transaction_stays_conservative` |

---

## 5. Arithmetic

### I18. Every arithmetic result is checked; nothing wraps and nothing panics.

`overflow-checks = true` is a backstop, not the mechanism: every operation on an
amount or a timestamp is an explicit `checked_*` or `try_from`. The crate denies
`clippy::arithmetic_side_effects`, `unwrap_used`, `expect_used`,
`indexing_slicing` and `panic`, which is what keeps it that way.

| Proof | Test |
|---|---|
| Input validation: zero amount, zero/negative/over-max lock | `exploits.rs::rejects_a_zero_amount`, `::rejects_a_zero_length_lock`, `::rejects_a_negative_lock`, `::rejects_a_lock_beyond_the_4_year_maximum`, `add_stake_relock.rs::rejects_a_zero_amount`, `::rejects_a_zero_negative_and_over_maximum_lock` |
| Exactly the maximum lock is accepted | `exploits.rs::accepts_a_lock_of_exactly_the_maximum`, `add_stake_relock.rs::accepts_the_maximum_lock` |
| `lock_start + lock_duration` overflow, on every path | `exploits.rs::catches_i64_overflow_on_lock_start_plus_lock_duration`, `exploits_forged_state.rs::catches_i64_overflow_of_lock_start_plus_lock_duration_on_the_withdraw_path`, `add_stake_relock.rs::rejects_an_unlock_overflow`, `fuzz_sequences.rs::an_unlock_that_overflows_i64_is_refused_on_every_path` |
| An add that would push the unlock past `i64::MAX` is refused, and the stake stays withdrawable | `fuzz_sequences.rs::add_stake_rejects_an_add_that_would_push_the_unlock_past_i64_max` |
| An unlock landing **exactly** on `i64::MAX` is still accepted (the guard is `checked_add`, not a margin) | `fuzz_sequences.rs::add_stake_accepts_an_unlock_landing_exactly_on_i64_max`, `exploits_economics.rs::a_stake_landing_exactly_on_the_i64_ceiling_still_unlocks` |
| `u64` amount overflow is distinguished from insufficient funds | `add_stake_relock.rs::rejects_an_amount_overflow`, `fuzz_sequences.rs::the_u64_sum_boundary_separates_insufficient_funds_from_overflow` |
| A `u64::MAX` stake beyond the balance creates no account at all | `exploits_economics.rs::a_u64_max_stake_beyond_the_balance_creates_no_stake_account_at_all`, `exploits.rs::rejects_staking_more_than_the_balance_without_creating_a_stake` |
| A negative unix timestamp is handled rather than assumed away | `exploits_economics.rs::a_negative_unix_timestamp_yields_a_negative_lock_start_handled_correctly` |

---

## 6. Deliberately true, and worth stating

These are not bugs. They are consequences of the design that a reviewer will
otherwise flag, so they are asserted as intended behaviour.

| Behaviour | Test |
|---|---|
| A 1-second lock is a valid stake and unwinds one second later | `exploits_economics.rs::reachable_a_1_second_lock_is_a_valid_stake_and_fully_unwinds_one_second_later` |
| Any duration in 1s–4y is stored verbatim; the chain has no whitelist or enum — see I19 | `exploits_economics.rs::reachable_any_lock_duration_in_1_to_4y_is_stored_verbatim_whitelist_or_not` |
| A matured stake stays open indefinitely, so elapsed time is **not** commitment | `exploits_economics.rs::reachable_an_expired_stake_stays_open_forever_so_elapsed_time_is_not_commitment` |
| 8 wallets can become max-lock stakers for 8 base units total; the chain has no minimum | `exploits_economics.rs::reachable_8_wallets_become_max_lock_stakers_for_8_base_units_total` |
| Capital can be recycled through unlimited wallets one second at a time | `exploits_economics.rs::capital_can_be_recycled_through_unlimited_wallets_one_second_at_a_time` |
| Every staker pays a second rent deposit (~0.00204 SOL) for their vault, refunded on withdraw | `exploits_economics.rs::rent_is_exactly_conserved_across_repeated_stake_withdraw_cycles` |
| A freeze authority on the mint could strand a staker's vault, and only that staker's; a frozen staker ATA does the same from the other side | `exploits_accounts.rs::a_frozen_vault_strands_only_its_own_staker`, `::freezing_one_stakers_ata_strands_that_staker_alone` |
| An existing delegate on a staker's ATA takes their withdrawal the moment it lands | `exploits_accounts.rs::documents_that_a_delegate_takes_the_withdrawal_the_moment_it_lands`, `::an_existing_delegate_on_the_stakers_ata_does_not_disturb_stake_or_withdraw` |
| Withdraw is unavailable while the owner's ATA is closed, and recovers when recreated | `exploits_economics.rs::withdraw_is_bricked_while_the_owners_ata_is_closed_and_recovers_when_recreated` |

### I19. A non-standard lock duration can never pay more than a standard one.

The product has five lock tiers (7, 30, 90, 180, 365 days). **None of them exist
in the program**, which accepts any duration from one second to four years and
stores it verbatim. Keeping the table off-chain means adding or retuning a tier
is a deploy rather than an upgrade ceremony under a 3600-second timelock.

That is safe only because the off-chain mapping **rounds down**: the resolver
picks the highest tier whose threshold the duration reaches, so a 45-day lock
earns the 30-day factor and a 364-day lock earns the 180-day factor. A duration
below the shortest tier earns nothing, and an expired position matches no tier at
all. The error is always in the protocol's favour.

| Proof | Test |
|---|---|
| The chain stores any duration in 1s–4y verbatim, with no whitelist | `exploits_economics.rs::reachable_any_lock_duration_in_1_to_4y_is_stored_verbatim_whitelist_or_not` |
| The bounds themselves are enforced | `exploits.rs::rejects_a_zero_length_lock`, `::rejects_a_negative_lock`, `::rejects_a_lock_beyond_the_4_year_maximum`, `::accepts_a_lock_of_exactly_the_maximum` |
| The mapping rounds **down** to the tier actually cleared | `staking-multiplier-calculator.spec.ts`, "rounds a non-whitelisted lock down to the tier it clears" — **in the backend repository, not this one** |

**Read the second half of that table carefully.** The rounding is a *backend*
property. This program guarantees only that it stores what it was given; it has
no opinion about tiers. See "What is **not** proven here" below.

The first five are why reward eligibility is gated off-chain. The chain accepts
any amount above zero and any lock from one second to four years; every minimum,
every whitelist and every tier lives in the backend. A consumer that infers
commitment from `now − lock_start` rather than from `lock_duration` will be
wrong.

---

## What is **not** proven here

Stated plainly, because the sections above are otherwise easy to over-read.

- **The upgrade authority is unconstrained.** Whoever holds it can replace
  `withdraw` and take the vault. No test can cover this; it is governance, not
  code. See `threat-model.md` § T8.
- **Off-chain tier and reward logic is out of scope.** Not in this repository,
  not tested here. A wrong multiplier cannot move a token but can misprice one.
- **"Every live stake maps to a tier" is NOT a program guarantee.** The set of
  valid lock lengths is not enforced on chain at all (I19). The chain bounds the
  duration and stores it; everything else — including the rounds-down property
  that makes an arbitrary duration harmless — lives in the backend and is proven
  by the backend's tests, not by anything here. An auditor should treat the tier
  mapping as an external dependency of the reward system, not of the escrow.
- **The clock is the validator clock.** Tests set it directly. They prove the
  program's *response* to a given timestamp, including backward movement; they
  prove nothing about what the network will actually report.
- **The deployed binary is not proven to be this source.** No verifiable build
  has been published. See the README's "Verifying a deployment".
- **`add_stake`'s residual advantage is bounded, not zero.** I12 is an aggregate
  capital-seconds statement. The per-token gap is analysed in `threat-model.md`
  § T1; no test asserts it is absent, because it is not.
