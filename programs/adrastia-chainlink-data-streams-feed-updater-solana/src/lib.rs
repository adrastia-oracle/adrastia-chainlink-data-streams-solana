use anchor_lang::prelude::*;
use adrastia_chainlink_data_streams_feed_solana as feed_prog;
use anchor_lang::solana_program::program::get_return_data;
use anchor_lang::AnchorDeserialize;

declare_id!("pPcrVUVrQULhX2sF3HjYi36wiKJGsuwpAny17VTTmpj");

#[program]
pub mod adrastia_chainlink_data_streams_feed_updater_solana {
    use super::*;

    /// Batch-verify-and-update reports on many feeds; allows per-item failure.
    ///
    /// Remaining accounts layout:
    ///   Globals (6 total, provided ONCE):
    ///     [0] feed_program                (adrastia feed program id)
    ///     [1] verifier_program_id         (Chainlink verifier program id)
    ///     [2] verifier_account            (Chainlink verifier account)
    ///     [3] access_controller           (Chainlink access controller)
    ///     [4] config                      (Adrastia global config PDA)
    ///     [5] user                        (must be a signer for the inner CPI)
    ///
    ///   Per item (3 each):
    ///     [6 + 3*i + 0] verifier_config_account (may differ per report)
    ///     [6 + 3*i + 1] feed PDA
    ///     [6 + 3*i + 2] history ring PDA
    pub fn batch_verify_and_update(ctx: Context<BatchVerifyAndUpdate>, items: Vec<UpdateItem>) -> Result<()> {
        let ra = ctx.remaining_accounts;
        require!(ra.len() == 6 + 3 * items.len(), ErrorCode::WrongRemainingAccountsLen);

        // Globals (all from remaining_accounts to keep a single lifetime)
        let feed_program_ai = ra[0].clone();
        let verifier_program_ai = ra[1].clone();
        let verifier_account_ai = ra[2].clone();
        let access_controller_ai = ra[3].clone();
        let config_ai = ra[4].clone();
        let user_ai = ra[5].clone();

        require!(user_ai.is_signer, ErrorCode::UserNotSigner);

        let user_key = user_ai.key();

        let now = Clock::get()?.unix_timestamp;

        // For PDA sanity checks
        let feed_program_key = feed_program_ai.key();

        let mut success_count = 0;

        for (i, item) in items.iter().enumerate() {
            let base = 6 + 3 * i;

            let verifier_config_ai = ra[base + 0].clone();
            let feed_ai = ra[base + 1].clone();
            let history_ring_ai = ra[base + 2].clone();

            let feed_key = feed_ai.key();

            // Verify the caller supplied the correct PDAs for this feed_id
            let (expected_feed, _) = Pubkey::find_program_address(&[b"feed", item.feed_id.as_ref()], &feed_program_key);
            let (expected_ring, _) = Pubkey::find_program_address(&[b"ring", item.feed_id.as_ref()], &feed_program_key);
            require_keys_eq!(feed_key, expected_feed, ErrorCode::AccountKeyMismatch);
            require_keys_eq!(history_ring_ai.key(), expected_ring, ErrorCode::AccountKeyMismatch);

            // --- Freshness check via CPI to latest_round_data ---
            // Build ReadFeed CPI accounts (only the feed account).
            let read_accounts = feed_prog::cpi::accounts::ReadFeed { feed: feed_ai.clone() };
            let read_ctx = CpiContext::new(feed_program_ai.clone(), read_accounts);

            let mut should_skip = false;

            match feed_prog::cpi::latest_round_data(read_ctx) {
                Ok(()) => {
                    if let Some((pid, data)) = get_return_data() {
                        if pid == feed_program_key {
                            if let Ok(latest) = feed_prog::LatestRoundData::try_from_slice(&data) {
                                let onchain_ts = latest.started_at;
                                if item.observations_timestamp <= onchain_ts {
                                    emit!(FeedUpdateSkipped {
                                        feed_id: item.feed_id,
                                        feed: feed_key,
                                        caller: user_key,
                                        stored_timestamp: onchain_ts,
                                        provided_timestamp: item.observations_timestamp,
                                        timestamp: now,
                                    });
                                    should_skip = true;
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    // If read fails, we just proceed (nothing to emit here unless you want a diagnostic event)
                }
            }

            if should_skip {
                continue;
            }

            // Build typed CPI accounts (all AccountInfo, no lifetime mix)
            let cpi_accounts = feed_prog::cpi::accounts::UpdateFromReport {
                verifier_program_id: verifier_program_ai.clone(),
                verifier_account: verifier_account_ai.clone(),
                access_controller: access_controller_ai.clone(),
                user: user_ai.clone(),
                verifier_config_account: verifier_config_ai,
                config: config_ai.clone(),
                feed: feed_ai,
                history_ring: history_ring_ai,
            };

            let cpi_ctx = CpiContext::new(feed_program_ai.clone(), cpi_accounts);

            match feed_prog::cpi::verify_and_update_report(cpi_ctx, item.feed_id, item.signed_report.clone()) {
                Ok(()) => {
                    emit!(FeedUpdatePerformed {
                        feed_id: item.feed_id,
                        feed: feed_key,
                        caller: user_key,
                        timestamp: now,
                    });

                    success_count += 1;
                }
                Err(e) => {
                    emit!(FeedUpdateFailed {
                        feed_id: item.feed_id,
                        feed: feed_key,
                        caller: user_key,
                        error_code: err_code(&e),
                        timestamp: now,
                    });
                }
            }
        }

        require_gt!(success_count, 0, ErrorCode::NoFeedsUpdated);

        Ok(())
    }
}

#[derive(Accounts)]
pub struct BatchVerifyAndUpdate<'info> {
    // nothing here; we use remaining_accounts only.

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UpdateItem {
    /// Target feed id (32 bytes)
    pub feed_id: [u8; 32],

    /// Observations timestamp coming from the off-chain signed report.
    /// Must be STRICTLY newer than on-chain to proceed with update.
    pub observations_timestamp: i64,

    /// The signed report bytes to forward if freshness check passes.
    pub signed_report: Vec<u8>,

    // no per-item pubkeys; verifier_config/feed/ring come via remaining_accounts
}

/// Emitted when a feed update is skipped because the provided report timestamp
/// is not strictly newer than the stored on-chain timestamp.
///
/// - `feed_id`: The feed ID (32 bytes).
/// - `feed`: The feed account (PDA) address.
/// - `stored_timestamp`: The on-chain observations timestamp (from `latest_round_data.started_at`).
/// - `provided_timestamp`: The observations timestamp carried by the provided report.
/// - `timestamp`: Wall-clock (cluster) time when this event was emitted.
#[event]
pub struct FeedUpdateSkipped {
    pub feed_id: [u8; 32],
    pub feed: Pubkey,
    pub caller: Pubkey,
    pub stored_timestamp: i64,
    pub provided_timestamp: i64,
    pub timestamp: i64,
}

/// Emitted when a feed update is performed successfully.
///
/// - `feed_id`: The feed ID (32 bytes).
/// - `feed`: The feed account (PDA) address.
/// - `timestamp`: Wall-clock (cluster) time when this event was emitted.
#[event]
pub struct FeedUpdatePerformed {
    pub feed_id: [u8; 32],
    pub feed: Pubkey,
    pub caller: Pubkey,
    pub timestamp: i64,
}

/// Emitted when a feed update fails during CPI to the feed program.
///
/// - `feed_id`: The feed ID (32 bytes).
/// - `feed`: The feed account (PDA) address.
/// - `error_code`: Stable numeric code derived from Anchor/Solana `ProgramError`.
/// - `timestamp`: Wall-clock (cluster) time when this event was emitted.
///
/// Note: Solana does not provide revert byte data like EVM; we log a stable u32.
#[event]
pub struct FeedUpdateFailed {
    pub feed_id: [u8; 32],
    pub feed: Pubkey,
    pub caller: Pubkey,
    pub error_code: u32,
    pub timestamp: i64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Wrong number of remaining accounts for batch")]
    WrongRemainingAccountsLen,
    #[msg("An account key did not match the expected key")]
    AccountKeyMismatch,
    #[msg("Provided user account is not a signer")]
    UserNotSigner,
    #[msg("No feeds were updated")]
    NoFeedsUpdated,
}

/// Map Anchor/ProgramError to a stable u32 code for logging
fn err_code(e: &anchor_lang::error::Error) -> u32 {
    use anchor_lang::error::Error as AErr;
    use anchor_lang::solana_program::program_error::ProgramError;

    match e {
        AErr::AnchorError(ae) => ae.error_code_number,
        AErr::ProgramError(pe) =>
            match &pe.program_error {
                ProgramError::Custom(0) => (u64::from(ProgramError::Custom(0)) >> 32) as u32,
                ProgramError::Custom(c) => *c,
                other => (u64::from(other.clone()) >> 32) as u32,
            }
    }
}
