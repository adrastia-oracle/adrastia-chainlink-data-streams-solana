use anchor_lang::{
    prelude::*,
    AnchorDeserialize,
    Discriminator,
    AccountDeserialize,
    solana_program::program::{ get_return_data, set_return_data },
};
use adrastia_chainlink_data_streams_feed_solana as feed_prog;
use num_derive::FromPrimitive;

declare_id!("pPcrVUVrQULhX2sF3HjYi36wiKJGsuwpAny17VTTmpj");

#[program]
pub mod adrastia_chainlink_data_streams_feed_updater_solana {
    use super::*;

    /// Batch-verify-and-update reports on many feeds; allows per-item failure. May revert.
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
        // Call into the try_ version
        try_batch_verify_and_update(ctx, items)?;

        // Inspect return data
        if let Some((pid, data)) = get_return_data() {
            if pid == crate::ID {
                // Decode                 let res = BatchUpdateAndVerifyResult::try_from_slice(&data).map_err(|_| error!(ErrorCode::DecodingError))?;

                let res = BatchUpdateAndVerifyResult::try_from_slice(&data).map_err(|_|
                    error!(ErrorCode::DecodingError)
                )?;

                if res.code != 0 {
                    // Try to map back into a known ErrorCode
                    if let Some(ec) = ErrorCode::from_anchor_code(res.code) {
                        return Err(error!(ec)); // bubbles up as proper Anchor error w/ name + code
                    } else {
                        // If it doesn't match a defined variant, bubble as raw custom error
                        return Err(ProgramError::Custom(res.code).into());
                    }
                }
            }
        }

        Ok(())
    }

    /// Batch-verify-and-update reports on many feeds; allows per-item failure. Makes a best-effort attempt to not
    /// revert (returns an error code if it does, or 0 upon success).
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
    pub fn try_batch_verify_and_update(ctx: Context<BatchVerifyAndUpdate>, items: Vec<UpdateItem>) -> Result<()> {
        let ra = ctx.remaining_accounts;

        // Safe indexing check: if mismatch, mark as error but don't revert
        if ra.len() != 6 + 3 * items.len() {
            set_result(u32::from(ErrorCode::WrongRemainingAccountsLen));
            return Ok(());
        }

        let feed_program_ai = ra[0].clone();
        let verifier_program_ai = ra[1].clone();
        let verifier_account_ai = ra[2].clone();
        let access_controller_ai = ra[3].clone();
        let config_ai = ra[4].clone();
        let user_ai = ra[5].clone();

        let feed_program_key = feed_program_ai.key();

        let (expected_cfg, _) = Pubkey::find_program_address(&[b"config"], &feed_program_key);
        if config_ai.key() != expected_cfg || config_ai.owner.key() != feed_program_key {
            set_result(u32::from(ErrorCode::AccountKeyMismatch));
            return Ok(());
        }

        if !user_ai.is_signer {
            set_result(u32::from(ErrorCode::UserNotSigner));
            return Ok(());
        }

        let user_key = user_ai.key();
        let now = match Clock::get() {
            Ok(c) => c.unix_timestamp,
            Err(_) => {
                set_result(u32::from(ErrorCode::ClockUnavailable));
                return Ok(());
            }
        };

        let mut success_count = 0;

        for (i, item) in items.iter().enumerate() {
            let base = 6 + 3 * i;
            let verifier_config_ai = ra[base + 0].clone();
            let feed_ai = ra[base + 1].clone();
            let history_ring_ai = ra[base + 2].clone();
            let feed_key = feed_ai.key();

            // PDA sanity check
            let (expected_feed, _) = Pubkey::find_program_address(&[b"feed", item.feed_id.as_ref()], &feed_program_key);
            let (expected_ring, _) = Pubkey::find_program_address(&[b"ring", item.feed_id.as_ref()], &feed_program_key);
            if
                feed_key != expected_feed ||
                feed_ai.owner.key() != feed_program_key ||
                history_ring_ai.key() != expected_ring ||
                history_ring_ai.owner.key() != feed_program_key
            {
                emit!(FeedUpdateFailed {
                    feed_id: item.feed_id,
                    feed: feed_key,
                    caller: user_key,
                    error_code: u32::from(ErrorCode::AccountKeyMismatch),
                    timestamp: now,
                });
                continue;
            }

            // Freshness check
            if let Some(onchain_ts) = read_feed_started_at(&feed_ai, &feed_program_key) {
                if item.observations_timestamp <= onchain_ts {
                    emit!(FeedUpdateSkipped {
                        feed_id: item.feed_id,
                        feed: feed_key,
                        caller: user_key,
                        stored_timestamp: onchain_ts,
                        provided_timestamp: item.observations_timestamp,
                        timestamp: now,
                    });
                    continue;
                }
            }

            // CPI
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

            clear_return_data();

            #[allow(unused_assignments)]
            let mut code_result = u32::from(ErrorCode::UnknownError); // default if something goes wrong

            match feed_prog::cpi::try_verify_and_update_report(cpi_ctx, item.feed_id, item.signed_report.clone()) {
                Ok(()) => {
                    if let Some((pid, data)) = get_return_data() {
                        if pid == feed_program_key {
                            if let Ok(res) = feed_prog::UpdateAndVerifyResult::try_from_slice(&data) {
                                code_result = res.code;
                            } else {
                                code_result = u32::from(ErrorCode::BadVerifyAndUpdateReturnData);
                            }
                        } else {
                            code_result = u32::from(ErrorCode::BadVerifyAndUpdateReturnData);
                        }
                    } else {
                        code_result = u32::from(ErrorCode::BadVerifyAndUpdateReturnData);
                    }
                }
                Err(e) => {
                    code_result = err_code(e);
                }
            }

            if code_result == 0 {
                emit!(FeedUpdatePerformed {
                    feed_id: item.feed_id,
                    feed: feed_key,
                    caller: user_key,
                    timestamp: now,
                });
                success_count += 1;
            } else {
                emit!(FeedUpdateFailed {
                    feed_id: item.feed_id,
                    feed: feed_key,
                    caller: user_key,
                    error_code: code_result,
                    timestamp: now,
                });
            }
        }

        // Final summary code in return data
        if success_count > 0 {
            set_result(0); // success
        } else {
            set_result(u32::from(ErrorCode::NoFeedsUpdated));
        }

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

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct BatchUpdateAndVerifyResult {
    pub code: u32, // 0 = OK, otherwise an ErrorCode discriminant
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
#[derive(FromPrimitive)]
pub enum ErrorCode {
    #[msg("Wrong number of remaining accounts for batch")]
    WrongRemainingAccountsLen,
    #[msg("An account key did not match the expected key")]
    AccountKeyMismatch,
    #[msg("Provided user account is not a signer")]
    UserNotSigner,
    #[msg("No feeds were updated")]
    NoFeedsUpdated,
    #[msg("Bad return data from feed during update")]
    BadVerifyAndUpdateReturnData,
    #[msg("Decoding error occurred")]
    DecodingError,
    #[msg("Unknown error occurred")]
    UnknownError,
    #[msg("Clock unavailable")]
    ClockUnavailable,
}

impl ErrorCode {
    /// Convert an Anchor error code to our ErrorCode. We assume that the default Anchor error base is 6000; if not,
    /// we need to adjust accordingly.
    pub fn from_anchor_code(code: u32) -> Option<Self> {
        // Anchor error codes always start at 6000
        num_traits::FromPrimitive::from_u32(code.saturating_sub(6000))
    }
}

/// Map Anchor/ProgramError to a stable u32 code for logging
fn err_code<E>(e: E) -> u32 where E: Into<anchor_lang::error::Error> {
    use anchor_lang::error::Error as AErr;
    use anchor_lang::solana_program::program_error::ProgramError;

    match e.into() {
        AErr::AnchorError(ae) => ae.error_code_number,
        AErr::ProgramError(pe) =>
            match &pe.program_error {
                // Keep Solana’s CUSTOM_ZERO convention stable
                ProgramError::Custom(0) => (u64::from(ProgramError::Custom(0)) >> 32) as u32,
                ProgramError::Custom(c) => *c,
                other => (u64::from(other.clone()) >> 32) as u32,
            }
    }
}

fn set_result(code: u32) {
    let res = BatchUpdateAndVerifyResult { code };
    if let Ok(bytes) = res.try_to_vec() {
        set_return_data(&bytes);
    } else {
        // As a fallback, set an empty payload (or a well-known sentinel)
        set_return_data(&[]);
    }
}

fn clear_return_data() {
    set_return_data(&[]);
}

fn read_feed_started_at(feed_ai: &AccountInfo, feed_program_key: &Pubkey) -> Option<i64> {
    // Only proceed if owned by the feed program
    if feed_ai.owner != feed_program_key {
        return None;
    }

    // Borrow data; bail on any error
    let data = feed_ai.try_borrow_data().ok()?;
    if data.len() < 8 {
        return None;
    }

    // Discriminator check
    if &data[..8] != feed_prog::Feed::DISCRIMINATOR {
        return None;
    }

    // Deserialize Feed (skip discriminator)
    let mut cursor: &[u8] = &data[8..];
    if let Ok(feed_acc) = feed_prog::Feed::try_deserialize(&mut cursor) {
        if feed_acc.last_round_id == 0 {
            // no report yet => behave like "no freshness info", i.e. don't skip
            None
        } else {
            Some(feed_acc.latest.observation_timestamp)
        }
    } else {
        None
    }
}
