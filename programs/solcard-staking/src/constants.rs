use anchor_lang::prelude::*;

/// PDA seed for a user's stake account: [STAKE_SEED, owner].
pub const STAKE_SEED: &[u8] = b"stake";

/// PDA seed for a user's vault token account: [VAULT_SEED, owner].
pub const VAULT_SEED: &[u8] = b"vault";

/// Upper bound on a lock so `lock_start + lock_duration` cannot overflow i64
/// and to reject absurd locks. 4 years in seconds.
pub const MAX_LOCK_DURATION: i64 = 4 * 365 * 24 * 60 * 60;

/// The single staked mint (SOLC), pinned per cluster. Hard cutover: the program
/// accepts exactly this mint, never "any mint".
/// localnet + devnet share the devnet test mint: classic SPL Token, 6 decimals like mainnet.
#[cfg(any(feature = "localnet", feature = "devnet"))]
pub const SOLC_MINT: Pubkey = pubkey!("4RrWLCNESAemwKDj9KjGnBkfyxKzWy8XGCBguzdqnyRb");

/// Classic SPL Token, 6 decimals, mint + freeze authority both null (verified on mainnet).
#[cfg(feature = "mainnet")]
pub const SOLC_MINT: Pubkey = pubkey!("DLUNTKRQt7CrpqSX1naHUYoBznJ9pvMP65uCeWQgYnRK");

/// Cargo features are additive: `default = ["localnet"]` stays on unless disabled.
#[cfg(all(feature = "mainnet", any(feature = "localnet", feature = "devnet")))]
compile_error!(
    "A mainnet build must disable the default feature, or the test mint stays pinned \
     alongside it: anchor build -- --no-default-features --features mainnet"
);
