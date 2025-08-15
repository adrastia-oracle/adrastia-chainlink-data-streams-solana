use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    program::{ get_return_data, invoke, set_return_data },
    program_error::ProgramError,
    pubkey,
};
use chainlink_solana_data_streams::VerifierInstructions;
use chainlink_data_streams_report::feed_id::ID as FeedId;
use chainlink_data_streams_report::report::{
    v2::ReportDataV2,
    v3::ReportDataV3,
    v4::ReportDataV4,
    v7::ReportDataV7,
    v8::ReportDataV8,
};
use num_traits::cast::ToPrimitive;

declare_id!("Et6bXECAiq9PH95uGwiAG4VyUUaD8JF4GZuCaduNBH9A");

// ⚠️ REPLACE BEFORE DEPLOY: only this signer can run `init_program_config` once.
pub const GLOBAL_BOOTSTRAP_ADMIN: Pubkey = pubkey!("634xiC5wufdbogSag2Q5koeRvJuUBQJ8vaU9j376oL2Q");

// ------------------------------------------------------------------------------------

pub const HISTORY_CAPACITY: usize = 128; // adjust as needed
pub const MAX_HOOK_TYPES: usize = 2; // PreUpdate, PostUpdate

#[program]
pub mod adrastia_chainlink_data_streams_feed_solana {
    use super::*;

    // ---------- One-time program bootstrap ----------
    // Stores global admin + verifier tuple.
    pub fn init_program_config(ctx: Context<InitProgramConfig>) -> Result<()> {
        require!(ctx.accounts.admin.key() == GLOBAL_BOOTSTRAP_ADMIN, ErrorCode::UnauthorizedAdmin);

        require!(ctx.accounts.verifier_program_id.executable, ErrorCode::BadVerifierProgram);
        require!(
            *ctx.accounts.verifier_account.owner == ctx.accounts.verifier_program_id.key(),
            ErrorCode::BadVerifierAccountOwner
        );

        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.verifier_program_id = ctx.accounts.verifier_program_id.key();
        cfg.verifier_account = ctx.accounts.verifier_account.key();
        cfg.access_controller = ctx.accounts.access_controller.key();
        Ok(())
    }

    // Rotate global admin later.
    pub fn set_global_admin(ctx: Context<SetGlobalAdmin>, new_admin: Pubkey) -> Result<()> {
        require!(ctx.accounts.current_admin.key() == ctx.accounts.config.admin, ErrorCode::GlobalAdminMismatch);
        require!(ctx.accounts.config.admin != new_admin, ErrorCode::GlobalAdminNotChanged);
        let old = ctx.accounts.config.admin;
        ctx.accounts.config.admin = new_admin;
        emit!(GlobalAdminChanged {
            old_admin: old,
            new_admin,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    // ---------- Init ----------
    pub fn init_feed(
        ctx: Context<InitFeed>,
        feed_id: [u8; 32],
        decimals: u8,
        description_ascii_32: [u8; 32],
        feed_admin: Pubkey // <- NEW: explicit feed admin
    ) -> Result<()> {
        // Only the current global admin (stored in ProgramConfig) can initialize feeds.
        require!(ctx.accounts.admin.key() == ctx.accounts.config.admin, ErrorCode::GlobalAdminMismatch);

        let f = &mut ctx.accounts.feed;
        f.feed_id = feed_id;
        f.decimals = decimals;
        f.description = description_ascii_32;
        f.admin = feed_admin; // <- set to explicit admin (can be any pubkey)
        f.paused = false;
        f.active_hook_types = 0;
        f.hooks = [Hook::default(); MAX_HOOK_TYPES];
        f.last_round_id = 0;
        f.latest = TruncatedReport::default();
        f.reentrancy_guard = false;

        emit!(FeedAdminChanged {
            feed_id,
            old_admin: Pubkey::default(),
            new_admin: feed_admin,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    pub fn init_history_ring(ctx: Context<InitHistoryRing>, feed_id: [u8; 32]) -> Result<()> {
        // Only the feed’s admin can run this (account is `init`, so it can't re-init anyway).
        require!(ctx.accounts.admin.key() == ctx.accounts.feed.admin, ErrorCode::FeedAdminMismatch);

        let mut ring = ctx.accounts.history_ring.load_init()?;
        ring.feed_id = feed_id;
        require!(HISTORY_CAPACITY > 0, ErrorCode::InvalidHistoryCapacity);
        ring.cap = HISTORY_CAPACITY as u32;
        ring.len = 0;
        ring.write_index = 0;
        ring.start_round_id = ctx.accounts.feed.last_round_id.saturating_add(1); // usually 1 on fresh feed
        Ok(())
    }

    // ---------- Admin ----------
    // NEW: only current feed admin can change to a new admin
    pub fn set_feed_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        let feed = &mut ctx.accounts.feed;
        require!(ctx.accounts.admin.key() == feed.admin, ErrorCode::FeedAdminMismatch);
        require!(new_admin != feed.admin, ErrorCode::FeedAdminNotChanged);
        let old = feed.admin;
        feed.admin = new_admin;
        emit!(FeedAdminChanged {
            feed_id: feed.feed_id,
            old_admin: old,
            new_admin,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        let feed = &mut ctx.accounts.feed;
        require!(ctx.accounts.admin.key() == feed.admin, ErrorCode::FeedAdminMismatch);
        require!(feed.paused != paused, ErrorCode::PauseStatusNotChanged);
        feed.paused = paused;
        emit!(PauseStatusChanged {
            caller: ctx.accounts.admin.key(),
            paused,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    pub fn set_hook_config(ctx: Context<AdminOnly>, hook_type: u8, cfg: Hook) -> Result<()> {
        let feed = &mut ctx.accounts.feed;
        require!(ctx.accounts.admin.key() == feed.admin, ErrorCode::FeedAdminMismatch);
        require!((hook_type as usize) < MAX_HOOK_TYPES, ErrorCode::InvalidHookType);
        if cfg.program == Pubkey::default() {
            require!(!cfg.allow_failure, ErrorCode::InvalidHookConfig);
        }
        let idx = hook_type as usize;
        let old = feed.hooks[idx];
        if old == cfg {
            return err!(ErrorCode::HookConfigUnchanged);
        }
        if cfg.program == Pubkey::default() {
            feed.active_hook_types &= !(1u16 << hook_type);
        } else {
            feed.active_hook_types |= 1u16 << hook_type;
        }
        feed.hooks[idx] = cfg;
        emit!(HookConfigUpdated {
            caller: ctx.accounts.admin.key(),
            hook_type,
            old_allow_failure: old.allow_failure,
            old_program: old.program,
            new_allow_failure: cfg.allow_failure,
            new_program: cfg.program,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    pub fn get_hook_config(ctx: Context<ReadFeed>, hook_type: u8) -> Result<()> {
        let feed = &ctx.accounts.feed;
        require!((hook_type as usize) < MAX_HOOK_TYPES, ErrorCode::InvalidHookType);
        let cfg = feed.hooks[hook_type as usize];
        let out = HookOut {
            allow_failure: cfg.allow_failure,
            program: cfg.program,
        };
        let data = out.try_to_vec().map_err(|_| error!(ErrorCode::InternalSer))?;
        set_return_data(&data);
        Ok(())
    }

    // ---------- Verify + Update ----------
    pub fn verify_and_update_report(
        ctx: Context<UpdateFromReport>,
        feed_id: [u8; 32],
        signed_report: Vec<u8>
    ) -> Result<()> {
        let feed = &mut ctx.accounts.feed;
        let cfg = &ctx.accounts.config;

        // Admin pause + tuple checks (now pinned against global config)
        require!(!feed.paused, ErrorCode::UpdatesPaused);
        require!(ctx.accounts.verifier_program_id.key() == cfg.verifier_program_id, ErrorCode::BadVerifierProgram);
        require!(ctx.accounts.verifier_account.key() == cfg.verifier_account, ErrorCode::BadVerifierAccount);
        require!(ctx.accounts.access_controller.key() == cfg.access_controller, ErrorCode::BadAccessController);
        require!(ctx.accounts.verifier_program_id.executable, ErrorCode::BadVerifierProgram);
        require!(*ctx.accounts.verifier_account.owner == cfg.verifier_program_id, ErrorCode::BadVerifierAccountOwner);

        // --- Reentrancy guard: set before any CPI out of this program ---
        require!(!feed.reentrancy_guard, ErrorCode::Reentrancy);
        feed.reentrancy_guard = true;

        // CPI to Verifier
        let ix: Instruction = VerifierInstructions::verify(
            &ctx.accounts.verifier_program_id.key(),
            &ctx.accounts.verifier_account.key(),
            &ctx.accounts.access_controller.key(),
            &ctx.accounts.user.key(),
            &ctx.accounts.verifier_config_account.key(), // external verifier config PDA
            signed_report
        );
        if
            let Err(_) = invoke(
                &ix,
                &[
                    ctx.accounts.verifier_account.to_account_info(),
                    ctx.accounts.access_controller.to_account_info(),
                    ctx.accounts.user.to_account_info(),
                    ctx.accounts.verifier_config_account.to_account_info(),
                ]
            )
        {
            return Err(error!(ErrorCode::VerifierCpiFailed));
        }

        // Return-data binding + decode (version-aware, based on Chainlink layout)
        let (pid, ret) = get_return_data().ok_or_else(|| error!(ErrorCode::BadVerifierReturnData))?;
        require!(pid == ctx.accounts.verifier_program_id.key(), ErrorCode::BadVerifierProgram);

        // feed_id is the first 32 bytes; version is the first 2 bytes of feed_id (big-endian)
        let (version, header_feed_id) = parse_header(&ret)?;
        require!(header_feed_id == feed_id, ErrorCode::FeedMismatch);
        require!(feed.feed_id == feed_id, ErrorCode::FeedMismatch);

        // Decode to normalized shape
        let report = decode_report_by_version(&ret, version)?;
        require!(report.feed_id == FeedId(feed_id), ErrorCode::FeedMismatch);

        let now = Clock::get()?.unix_timestamp;
        require!(report.observations_timestamp != 0, ErrorCode::InvalidReport);
        require!(now >= report.observations_timestamp, ErrorCode::ObservationInFuture);
        require!(now >= report.valid_from_timestamp, ErrorCode::ReportNotValidYet);

        let last = feed.latest;
        if last.round_id != 0 {
            require!(
                !(report.price_i128 == last.price && report.observations_timestamp == last.observation_timestamp),
                ErrorCode::DuplicateReport
            );
            require!(report.observations_timestamp > last.observation_timestamp, ErrorCode::StaleReport);
        }

        // New round id
        let new_round_id = feed.last_round_id.checked_add(1).ok_or(error!(ErrorCode::NumericalOverflow))?;

        // PRE-HOOK
        if is_hook_set(feed.active_hook_types, HookType::PreUpdate) {
            let hcfg = feed.hooks[HookType::PreUpdate as usize];
            if hcfg.program != Pubkey::default() {
                let payload = HookPayload {
                    feed_id,
                    round_id: new_round_id,
                    price: report.price_i128,
                    observation_timestamp: report.observations_timestamp,
                    storage_timestamp: now,
                };
                if let Err(e) = invoke_hook(hcfg.program, 0, &payload) {
                    if hcfg.allow_failure {
                        emit!(HookFailed {
                            hook_type: HookType::PreUpdate as u8,
                            program: hcfg.program,
                            reason_code: hook_error_code(e.into()),
                            timestamp: now,
                        });
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        // Append to ring (O(1))
        {
            let mut ring = ctx.accounts.history_ring.load_mut()?;
            require!(ring.feed_id == feed_id, ErrorCode::HistoryRingMismatch);
            let cap = ring.cap as u32;
            let len = ring.len;
            let w = ring.write_index;
            let idx = (w % cap) as usize;
            ring.records[idx] = RoundRecord {
                price: report.price_i128,
                observation_timestamp: report.observations_timestamp,
                storage_timestamp: now,
                round_id: new_round_id,
                _reserved: [0; 8],
            };
            ring.write_index = (w + 1) % cap;
            if len < cap {
                ring.len = len + 1;
                if len == 0 {
                    ring.start_round_id = new_round_id;
                }
            } else {
                ring.start_round_id = ring.start_round_id.checked_add(1).ok_or(error!(ErrorCode::NumericalOverflow))?;
            }
        }

        // Update latest in feed
        let rec = TruncatedReport {
            price: report.price_i128,
            observation_timestamp: report.observations_timestamp,
            storage_timestamp: now,
            round_id: new_round_id,
        };
        feed.last_round_id = new_round_id;
        feed.latest = rec;

        emit!(ReportUpdated {
            feed_id,
            updater: ctx.accounts.user.key(),
            round_id: new_round_id,
            price: rec.price,
            valid_from_timestamp: report.valid_from_timestamp,
            observations_timestamp: rec.observation_timestamp,
            timestamp: now,
        });

        // POST-HOOK
        if is_hook_set(feed.active_hook_types, HookType::PostUpdate) {
            let hcfg = feed.hooks[HookType::PostUpdate as usize];
            if hcfg.program != Pubkey::default() {
                let payload = HookPayload {
                    feed_id,
                    round_id: new_round_id,
                    price: rec.price,
                    observation_timestamp: rec.observation_timestamp,
                    storage_timestamp: now,
                };
                if let Err(e) = invoke_hook(hcfg.program, 1, &payload) {
                    if hcfg.allow_failure {
                        emit!(HookFailed {
                            hook_type: HookType::PostUpdate as u8,
                            program: hcfg.program,
                            reason_code: hook_error_code(e.into()),
                            timestamp: now,
                        });
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        // Clear reentrancy guard
        feed.reentrancy_guard = false;
        Ok(())
    }

    // ---------- Reads ----------
    pub fn latest_round_data(ctx: Context<ReadFeed>) -> Result<()> {
        let feed = &ctx.accounts.feed;
        require!(feed.last_round_id != 0, ErrorCode::MissingReport);
        let latest = feed.latest;
        let out = LatestRoundData {
            round_id: latest.round_id,
            answer: latest.price,
            started_at: latest.observation_timestamp,
            updated_at: latest.storage_timestamp,
            answered_in_round: latest.round_id,
        };
        let data = out.try_to_vec().map_err(|_| error!(ErrorCode::InternalSer))?;
        set_return_data(&data);
        Ok(())
    }

    pub fn get_round_data(ctx: Context<ReadRing>, feed_id: [u8; 32], round_id: u64) -> Result<()> {
        let feed = &ctx.accounts.feed;
        require!(feed.last_round_id != 0, ErrorCode::MissingReport);
        let ring = ctx.accounts.history_ring.load()?;
        require!(ring.feed_id == feed_id && feed.feed_id == feed_id, ErrorCode::HistoryRingMismatch);
        // bounds
        let len = ring.len as u64;
        require!(len > 0, ErrorCode::RoundNotFound);
        let start = ring.start_round_id;
        let end = start + len;
        require!(round_id >= start && round_id < end, ErrorCode::RoundNotFound);
        let cap = ring.cap as u64;
        let w = ring.write_index as u64;
        let start_index = (w + cap - (ring.len as u64)) % cap; // (w - len) mod cap
        let offset = round_id - start;
        let idx = ((start_index + offset) % cap) as usize;
        let r = ring.records[idx];
        let out = LatestRoundData {
            round_id: r.round_id,
            answer: r.price,
            started_at: r.observation_timestamp,
            updated_at: r.storage_timestamp,
            answered_in_round: r.round_id,
        };
        let data = out.try_to_vec().map_err(|_| error!(ErrorCode::InternalSer))?;
        set_return_data(&data);
        Ok(())
    }

    pub fn decimals(ctx: Context<ReadFeed>) -> Result<()> {
        let data = [ctx.accounts.feed.decimals];
        set_return_data(&data);
        Ok(())
    }
    pub fn description(ctx: Context<ReadFeed>) -> Result<()> {
        let data = ctx.accounts.feed.description;
        set_return_data(&data);
        Ok(())
    }
    pub fn feed_id(ctx: Context<ReadFeed>) -> Result<()> {
        let data = ctx.accounts.feed.feed_id;
        set_return_data(&data);
        Ok(())
    }
    pub fn paused(ctx: Context<ReadFeed>) -> Result<()> {
        let data = [if ctx.accounts.feed.paused { 1u8 } else { 0u8 }];
        set_return_data(&data);
        Ok(())
    }
    pub fn version(_ctx: Context<NoAccounts>) -> Result<()> {
        // version 1; encode as u16 little-endian
        set_return_data(&(1u16).to_le_bytes());
        Ok(())
    }
}

// ---------- Data & helpers ----------

#[account]
pub struct Feed {
    pub feed_id: [u8; 32],
    pub decimals: u8,
    pub description: [u8; 32],
    pub admin: Pubkey,
    pub paused: bool,
    pub active_hook_types: u16,
    pub hooks: [Hook; MAX_HOOK_TYPES],
    pub last_round_id: u64,
    pub latest: TruncatedReport,
    // Reentrancy guard (true while inside verify_and_update_report)
    pub reentrancy_guard: bool,
}
impl Feed {
    pub const SIZE: usize = 32 + 1 + 32 + 32 + 1 + 2 + Hook::SIZE * MAX_HOOK_TYPES + 8 + TruncatedReport::SIZE + 1;
}

#[derive(Clone, Copy)]
struct NormalizedReport {
    feed_id: FeedId,
    price_i128: i128,
    valid_from_timestamp: i64,
    observations_timestamp: i64,
}

#[account(zero_copy)]
#[repr(C)]
pub struct HistoryRing {
    pub feed_id: [u8; 32],
    pub start_round_id: u64,
    pub cap: u32,
    pub len: u32,
    pub write_index: u32,
    pub _pad: [u8; 12], // keep to 64 bytes header
    pub records: [RoundRecord; HISTORY_CAPACITY],
}

#[zero_copy]
#[repr(C)]
pub struct RoundRecord {
    pub price: i128,
    pub observation_timestamp: i64,
    pub storage_timestamp: i64,
    pub round_id: u64,
    pub _reserved: [u8; 8],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct TruncatedReport {
    pub price: i128,
    pub observation_timestamp: i64,
    pub storage_timestamp: i64,
    pub round_id: u64,
}
impl TruncatedReport {
    pub const SIZE: usize = 16 + 8 + 8 + 8;
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct LatestRoundData {
    pub round_id: u64,
    pub answer: i128,
    pub started_at: i64,
    pub updated_at: i64,
    pub answered_in_round: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hook {
    pub allow_failure: bool,
    pub program: Pubkey,
}
impl Hook {
    pub const SIZE: usize = 1 + 32;
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct HookOut {
    pub allow_failure: bool,
    pub program: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub enum HookType {
    PreUpdate = 0,
    PostUpdate = 1,
}
fn is_hook_set(bits: u16, t: HookType) -> bool {
    (bits & (1u16 << (t as u8))) != 0
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct HookPayload {
    pub feed_id: [u8; 32],
    pub round_id: u64,
    pub price: i128,
    pub observation_timestamp: i64,
    pub storage_timestamp: i64,
}

fn invoke_hook(program_id: Pubkey, disc: u8, payload: &HookPayload) -> Result<()> {
    let mut data = vec![disc];
    data.extend(payload.try_to_vec().map_err(|_| error!(ErrorCode::InternalSer))?);
    let ix = Instruction {
        program_id,
        accounts: vec![],
        data,
    };
    invoke(&ix, &[]).map_err(|e| e.into())
}
fn hook_error_code(e: ProgramError) -> u32 {
    match e {
        ProgramError::Custom(c) => c,
        ProgramError::InvalidInstructionData => 2,
        ProgramError::InvalidAccountData => 3,
        _ => 1,
    }
}

// Parse feed_id as the *first 32 bytes* and version from its first two bytes (big-endian).
fn parse_header(ret: &[u8]) -> Result<(u16, [u8; 32])> {
    require!(ret.len() >= 32, ErrorCode::InvalidReportData);
    let mut feed_id_bytes = [0u8; 32];
    feed_id_bytes.copy_from_slice(&ret[..32]);
    let version = u16::from_be_bytes([feed_id_bytes[0], feed_id_bytes[1]]);
    Ok((version, feed_id_bytes))
}

fn decode_report_by_version(ret: &[u8], version: u16) -> Result<NormalizedReport> {
    match version {
        8 => {
            let r = ReportDataV8::decode(ret).map_err(|_| error!(ErrorCode::InvalidV8Report))?;
            let price = r.mid_price.to_i128().ok_or(error!(ErrorCode::InvalidV8Report))?;
            Ok(NormalizedReport {
                feed_id: r.feed_id,
                price_i128: price,
                valid_from_timestamp: r.valid_from_timestamp as i64,
                observations_timestamp: r.observations_timestamp as i64,
            })
        }
        7 => {
            let r = ReportDataV7::decode(ret).map_err(|_| error!(ErrorCode::InvalidV7Report))?;
            let price = r.exchange_rate.to_i128().ok_or(error!(ErrorCode::InvalidV7Report))?;
            Ok(NormalizedReport {
                feed_id: r.feed_id,
                price_i128: price,
                valid_from_timestamp: r.valid_from_timestamp as i64,
                observations_timestamp: r.observations_timestamp as i64,
            })
        }
        4 => {
            let r = ReportDataV4::decode(ret).map_err(|_| error!(ErrorCode::InvalidV4Report))?;
            let price = r.price.to_i128().ok_or(error!(ErrorCode::InvalidV4Report))?;
            Ok(NormalizedReport {
                feed_id: r.feed_id,
                price_i128: price,
                valid_from_timestamp: r.valid_from_timestamp as i64,
                observations_timestamp: r.observations_timestamp as i64,
            })
        }
        3 => {
            let r = ReportDataV3::decode(ret).map_err(|_| error!(ErrorCode::InvalidV3Report))?;
            let price = r.benchmark_price.to_i128().ok_or(error!(ErrorCode::InvalidV3Report))?;
            Ok(NormalizedReport {
                feed_id: r.feed_id,
                price_i128: price,
                valid_from_timestamp: r.valid_from_timestamp as i64,
                observations_timestamp: r.observations_timestamp as i64,
            })
        }
        2 => {
            let r = ReportDataV2::decode(ret).map_err(|_| error!(ErrorCode::InvalidV2Report))?;
            let price = r.benchmark_price.to_i128().ok_or(error!(ErrorCode::InvalidV2Report))?;
            Ok(NormalizedReport {
                feed_id: r.feed_id,
                price_i128: price,
                valid_from_timestamp: r.valid_from_timestamp as i64,
                observations_timestamp: r.observations_timestamp as i64,
            })
        }
        _ => Err(error!(ErrorCode::InvalidReportVersion)),
    }
}

// ---------- Accounts ----------

#[account]
pub struct ProgramConfig {
    pub admin: Pubkey,
    pub verifier_program_id: Pubkey,
    pub verifier_account: Pubkey,
    pub access_controller: Pubkey,
}
impl ProgramConfig {
    pub const SIZE: usize = 32 + 32 + 32 + 32;
}

// No-accounts context (for version()).
#[derive(Accounts)]
pub struct NoAccounts {}

#[derive(Accounts)]
pub struct InitProgramConfig<'info> {
    #[account(init, payer = payer, space = 8 + ProgramConfig::SIZE, seeds = [b"config".as_ref()], bump)]
    pub config: Account<'info, ProgramConfig>,

    /// Must equal GLOBAL_BOOTSTRAP_ADMIN.
    pub admin: Signer<'info>,

    /// CHECK: verified executable at runtime
    pub verifier_program_id: AccountInfo<'info>,
    /// CHECK: owner checked at runtime
    pub verifier_account: AccountInfo<'info>,
    /// CHECK: optional invariant in handler
    pub access_controller: AccountInfo<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetGlobalAdmin<'info> {
    #[account(mut, seeds = [b"config".as_ref()], bump)]
    pub config: Account<'info, ProgramConfig>,

    /// Current global admin.
    pub current_admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(feed_id: [u8; 32])]
pub struct InitFeed<'info> {
    // Prove global admin
    #[account(seeds = [b"config".as_ref()], bump)]
    pub config: Account<'info, ProgramConfig>,

    #[account(init, payer = payer, space = 8 + Feed::SIZE, seeds = [b"feed".as_ref(), feed_id.as_ref()], bump)]
    pub feed: Account<'info, Feed>,

    pub admin: Signer<'info>, // must equal config.admin

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(feed_id: [u8; 32])]
pub struct InitHistoryRing<'info> {
    #[account(seeds = [b"feed".as_ref(), feed_id.as_ref()], bump)]
    pub feed: Account<'info, Feed>,

    // Anchor creates at full size (no realloc) owned by this program.
    #[account(
        init,
        payer = payer,
        space = 8 + core::mem::size_of::<HistoryRing>(),
        seeds = [b"ring".as_ref(), feed_id.as_ref()],
        bump
    )]
    pub history_ring: AccountLoader<'info, HistoryRing>,

    pub admin: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut)]
    pub feed: Account<'info, Feed>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReadFeed<'info> {
    #[account(seeds = [b"feed".as_ref(), feed.feed_id.as_ref()], bump)]
    pub feed: Account<'info, Feed>,
}

#[derive(Accounts)]
#[instruction(feed_id: [u8; 32])]
pub struct ReadRing<'info> {
    #[account(seeds = [b"feed".as_ref(), feed_id.as_ref()], bump)]
    pub feed: Account<'info, Feed>,
    #[account(seeds = [b"ring".as_ref(), feed_id.as_ref()], bump)]
    pub history_ring: AccountLoader<'info, HistoryRing>,
}

#[derive(Accounts)]
#[instruction(feed_id: [u8; 32])]
pub struct UpdateFromReport<'info> {
    /// CHECK: address/executable validated in handler
    pub verifier_program_id: AccountInfo<'info>,
    /// CHECK: validated in handler
    pub verifier_account: AccountInfo<'info>,
    /// CHECK: validated in handler
    pub access_controller: AccountInfo<'info>,
    pub user: Signer<'info>,
    /// CHECK: external verifier config PDA (passed through to CPI)
    pub verifier_config_account: UncheckedAccount<'info>,

    // Our global program config (stores the expected verifier tuple)
    #[account(seeds = [b"config".as_ref()], bump)]
    pub config: Account<'info, ProgramConfig>,

    #[account(mut, seeds = [b"feed".as_ref(), feed_id.as_ref()], bump)]
    pub feed: Account<'info, Feed>,
    #[account(mut, seeds = [b"ring".as_ref(), feed_id.as_ref()], bump)]
    pub history_ring: AccountLoader<'info, HistoryRing>,
}

// ---------- Events ----------

#[event]
pub struct GlobalAdminChanged {
    pub old_admin: Pubkey,
    pub new_admin: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct FeedAdminChanged {
    pub feed_id: [u8; 32],
    pub old_admin: Pubkey,
    pub new_admin: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct ReportUpdated {
    pub feed_id: [u8; 32],
    pub updater: Pubkey,
    pub round_id: u64,
    pub price: i128,
    pub valid_from_timestamp: i64,
    pub observations_timestamp: i64,
    pub timestamp: i64,
}

#[event]
pub struct PauseStatusChanged {
    pub caller: Pubkey,
    pub paused: bool,
    pub timestamp: i64,
}

#[event]
pub struct HookFailed {
    pub hook_type: u8,
    pub program: Pubkey,
    pub reason_code: u32,
    pub timestamp: i64,
}

#[event]
pub struct HookConfigUpdated {
    pub caller: Pubkey,
    pub hook_type: u8,
    pub old_allow_failure: bool,
    pub old_program: Pubkey,
    pub new_allow_failure: bool,
    pub new_program: Pubkey,
    pub timestamp: i64,
}

// ---------- Errors ----------

#[error_code]
pub enum ErrorCode {
    #[msg("No valid report data found")]
    NoReportData,
    #[msg("Invalid report data format")]
    InvalidReportData,
    #[msg("Report is not yet valid")]
    ReportNotValidYet,
    #[msg("Report observation time is in the future")]
    ObservationInFuture,
    #[msg("Duplicate report")]
    DuplicateReport,
    #[msg("Stale report")]
    StaleReport,
    #[msg("Invalid report")]
    InvalidReport,
    #[msg("Invalid report version")]
    InvalidReportVersion,
    #[msg("Missing report")]
    MissingReport,
    #[msg("Requested round not found")]
    RoundNotFound,
    #[msg("Numerical overflow")]
    NumericalOverflow,
    #[msg("Unauthorized admin")]
    UnauthorizedAdmin,
    #[msg("Updates are paused")]
    UpdatesPaused,
    #[msg("Pause status not changed")]
    PauseStatusNotChanged,
    #[msg("Invalid hook type")]
    InvalidHookType,
    #[msg("Invalid hook configuration")]
    InvalidHookConfig,
    #[msg("Hook configuration unchanged")]
    HookConfigUnchanged,
    #[msg("Feed mismatch")]
    FeedMismatch,
    #[msg("Bad verifier program id")]
    BadVerifierProgram,
    #[msg("Bad verifier account")]
    BadVerifierAccount,
    #[msg("Verifier account owner mismatch")]
    BadVerifierAccountOwner,
    #[msg("Bad access controller")]
    BadAccessController,
    #[msg("Internal serialization error")]
    InternalSer,
    #[msg("History ring/feed mismatch")]
    HistoryRingMismatch,
    #[msg("Global admin mismatch")]
    GlobalAdminMismatch,
    #[msg("Feed admin mismatch")]
    FeedAdminMismatch,
    #[msg("Verifier CPI failed")]
    VerifierCpiFailed,
    #[msg("Missing/invalid verifier return data")]
    BadVerifierReturnData,
    #[msg("Invalid V2 report data")]
    InvalidV2Report,
    #[msg("Invalid V3 report data")]
    InvalidV3Report,
    #[msg("Invalid V4 report data")]
    InvalidV4Report,
    #[msg("Invalid V7 report data")]
    InvalidV7Report,
    #[msg("Invalid V8 report data")]
    InvalidV8Report,
    #[msg("Reentrancy detected")]
    Reentrancy,
    #[msg("Invalid history capacity")]
    InvalidHistoryCapacity,
    #[msg("Global admin not changed")]
    GlobalAdminNotChanged,
    #[msg("Feed admin not changed")]
    FeedAdminNotChanged,
}
