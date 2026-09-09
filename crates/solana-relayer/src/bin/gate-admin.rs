//! `gate-admin` — the on-chain client for the Solana gate's governance
//! instructions.
//!
//! `scripts/testing/solana-onchain.sh` states the gap this fills: "driving
//! init/send/claim on-chain needs a client that…" — there wasn't one. The gate
//! could be built and deployed but never *configured*, so nothing downstream
//! (corridors, assets, the relayer) could be exercised against a real cluster.
//!
//! It lives in `solana-relayer` because that crate already carries the only
//! dependency set that can talk to Solana: `solana-client` pins `zeroize <1.4`,
//! which cannot coexist with alloy's `^1.5`, so no EVM-side crate can host it.
//!
//! Every subcommand is owner- or upgrade-authority-gated ON-CHAIN. This tool
//! only builds and signs transactions; it grants no authority of its own.
//!
//!   gate-admin --rpc <url> --keypair <path> --program <pubkey> <command>
//!
//!     init --chain-id N --threshold N --validator 0x.. [--validator 0x..]
//!          --bridge-domain <0x…32 bytes>
//!          [--max-validators N] [--max-corridors N] [--guardian <pubkey>]
//!     register-corridor --chain-id-to N
//!     register-asset --debridge-id 0x.. --mint <pubkey> --vault <pubkey>
//!     set-threshold --threshold N            (a DECREASE needs a matured schedule)
//!     set-validator --validator 0x.. --active <bool>
//!                                            (an ADDITION needs a matured schedule)
//!     schedule-governance (--add-validator 0x.. | --lower-threshold N | --action-id 0x..)
//!     cancel-governance   (--add-validator 0x.. | --lower-threshold N | --action-id 0x..)
//!     governance-status   (--add-validator 0x.. | --lower-threshold N | --action-id 0x..)
//!     send --debridge-id 0x.. --amount N --chain-id-to N --receiver 0x..
//!          --from-token-account <pubkey>
//!     cancel --debridge-id 0x.. --amount N --chain-id-from N --nonce N
//!            --receiver 0x.. --native-sender 0x.. --signature 0x.. [--signature 0x..]
//!     refund --submission-id 0x.. --debridge-id 0x.. --amount N --chain-id-to N
//!            --nonce N --receiver 0x.. --native-sender 0x..
//!            [--to-token-account <pubkey>]   (default: the account `send` debited,
//!                                             read from the ["sent", id] record)
//!            --signature 0x.. [--signature 0x..]
//!     digest --submission-id 0x.. — print the cancel/refund digests to sign
//!     show
//!
//! `cancel`/`refund` take signatures as INPUT rather than signing themselves:
//! they are validator attestations over domain-separated digests, and a tool that
//! could mint them would be a tool that could burn or claw back any transfer.
//! Use `digest` to get the bytes, sign them with the validator keys wherever
//! those live, and pass the results back.
//!
//! ## Governance timelock (audit round 4, H-2)
//!
//! Adding a validator or LOWERING the threshold grants signing power, so the
//! program makes it wait: `schedule-governance` first, then 48 h later the
//! `set-validator` / `set-threshold` call consumes the schedule (and must land
//! within the 7-day grace window or be re-scheduled). Removing a validator and
//! RAISING the threshold are instant. `set-validator`/`set-threshold` print the
//! action id they need, so a refused call tells you what to schedule.
//!
//! The program UPGRADE authority cannot be timelocked by the program itself:
//! put it behind a Squads / SPL-Governance timelock before any production use.

use std::str::FromStr;

use bridge_solana::instruction::{
    add_validator_action_id, lower_threshold_action_id, GateInstruction, GovernanceSchedule,
    InitArgs, GOVERNANCE_DELAY_SECS, GOVERNANCE_GRACE_SECS,
};
use borsh::BorshDeserialize as _;
use solana_relayer::gate::{
    decode_config_view, domain_id, hex20, hex32, ConfigTail, BPF_LOADER_UPGRADEABLE,
    CANCEL_PREFIX, REFUND_PREFIX, SPL_TOKEN,
};
use solana_relayer::target::refund_accounts;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Signer};
use solana_sdk::transaction::Transaction;

/// Parse a repeated `--signature 0x..` into 65-byte r||s||v arrays.
fn parse_sigs(args: &Args) -> anyhow::Result<Vec<Vec<u8>>> {
    let out: Vec<Vec<u8>> = args
        .all("--signature")
        .iter()
        .map(|s| {
            let h = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(h).map_err(|_| anyhow::anyhow!("signature {s:?} is not hex"))
        })
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(!out.is_empty(), "at least one --signature is required");
    for s in &out {
        anyhow::ensure!(s.len() == 65, "each signature must be 65 bytes, got {}", s.len());
    }
    Ok(out)
}

/// The governance action id a `schedule-governance` / `cancel-governance` /
/// `governance-status` call names: exactly one of `--add-validator 0x..`,
/// `--lower-threshold N` or a raw `--action-id 0x..`.
fn governance_action_id(args: &Args) -> anyhow::Result<[u8; 32]> {
    match (args.get("--add-validator"), args.get("--lower-threshold"), args.get("--action-id")) {
        (Some(v), None, None) => Ok(add_validator_action_id(&hex20(&v)?)),
        (None, Some(t), None) => Ok(lower_threshold_action_id(t.parse()?)),
        (None, None, Some(a)) => hex32(&a),
        _ => anyhow::bail!(
            "name exactly one action: --add-validator 0x.. | --lower-threshold N | --action-id 0x.."
        ),
    }
}

fn gov_pda(program_id: &Pubkey, action_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"gov", action_id], program_id).0
}

/// Minimal flag reader: `--name value`. Repeated flags collect.
struct Args(Vec<String>);
impl Args {
    fn get(&self, name: &str) -> Option<String> {
        self.0.iter().position(|a| a == name).and_then(|i| self.0.get(i + 1)).cloned()
    }
    fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == name)
            .filter_map(|(i, _)| self.0.get(i + 1).cloned())
            .collect()
    }
    fn req(&self, name: &str) -> anyhow::Result<String> {
        self.get(name).ok_or_else(|| anyhow::anyhow!("missing required flag {name}"))
    }
}

fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // The command is the first bare token that is NOT a flag's value. Skipping
    // only `--`-prefixed tokens is not enough: `--rpc https://…` would make the
    // URL look like the command.
    let cmd = argv
        .iter()
        .enumerate()
        .find(|(i, a)| {
            !a.starts_with("--") && !argv.get(i.wrapping_sub(1)).is_some_and(|p| p.starts_with("--"))
        })
        .map(|(_, a)| a.clone())
        .ok_or_else(|| anyhow::anyhow!("no command; see the header of this file"))?;
    let args = Args(argv);

    let rpc_url = args.req("--rpc")?;
    let program_id = Pubkey::from_str(&args.req("--program")?)?;
    let payer = read_keypair_file(args.req("--keypair")?)
        .map_err(|e| anyhow::anyhow!("reading keypair: {e}"))?;
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (config_pda, _) = Pubkey::find_program_address(&[b"config"], &program_id);
    let (vault_authority, _) = Pubkey::find_program_address(&[b"vault_authority"], &program_id);

    if cmd == "digest" {
        let id = hex32(&args.req("--submission-id")?)?;
        println!("submissionId : 0x{}", hex::encode(id));
        println!("cancelId     : 0x{}", hex::encode(domain_id(CANCEL_PREFIX, &id)));
        println!("refundId     : 0x{}", hex::encode(domain_id(REFUND_PREFIX, &id)));
        println!();
        println!("Validators sign the EIP-191 digest of the id above — the same");
        println!("`personal_sign` shape as the EVM side, so `cast wallet sign` works:");
        println!("  cast wallet sign --private-key <key> <cancelId|refundId>");
        return Ok(());
    }

    if cmd == "governance-status" {
        let action_id = governance_action_id(&args)?;
        let pda = gov_pda(&program_id, &action_id);
        println!("action id : 0x{}", hex::encode(action_id));
        println!("gov PDA   : {pda}");
        match rpc.get_account(&pda) {
            Ok(acct) if acct.owner == program_id && acct.data.len() >= 8 => {
                let sched = GovernanceSchedule::deserialize(&mut &acct.data[..])?;
                if sched.ready_at == 0 {
                    println!("status    : NOT SCHEDULED (consumed or cancelled)");
                } else {
                    let now = rpc
                        .get_account(&solana_sdk::sysvar::clock::id())
                        .ok()
                        .and_then(|a| solana_sdk::account::from_account::<solana_sdk::clock::Clock, _>(&a))
                        .map(|c| c.unix_timestamp);
                    println!("ready_at  : {} (unix, cluster clock)", sched.ready_at);
                    println!("expires   : {}", sched.ready_at + GOVERNANCE_GRACE_SECS);
                    match now {
                        Some(now) if now < sched.ready_at => {
                            println!("status    : SCHEDULED, matures in {}s", sched.ready_at - now)
                        }
                        Some(now) if now > sched.ready_at + GOVERNANCE_GRACE_SECS => {
                            println!("status    : EXPIRED — re-run schedule-governance")
                        }
                        Some(_) => println!("status    : READY — execute set-validator / set-threshold now"),
                        None => println!("status    : scheduled (could not read the cluster clock)"),
                    }
                }
            }
            _ => println!("status    : NOT SCHEDULED"),
        }
        return Ok(());
    }

    if cmd == "show" {
        println!("program        : {program_id}");
        println!("config PDA     : {config_pda}");
        println!("vault authority: {vault_authority}");
        match rpc.get_account(&config_pda) {
            Ok(acct) => {
                println!("config account : {} bytes, owner {}", acct.data.len(), acct.owner);
                // Deserialized through the ONE mirrored layout (`gate::ConfigView`),
                // never sliced at hardcoded offsets. An earlier version read
                // `validators` from byte 64 and silently reported zeros for
                // everything once `bridge_domain` was inserted ahead of `guardian`
                // — a diagnostic that lies is worse than none. Sharing the struct
                // with the runner means drift now breaks both loudly, together.
                let mut cursor: &[u8] = &acct.data;
                match decode_config_view(&mut cursor) {
                    Ok(c) => {
                        let guardian = Pubkey::new_from_array(c.guardian);
                        println!("  owner        : {}", Pubkey::new_from_array(c.owner));
                        println!("  bridge domain: 0x{}", hex::encode(c.bridge_domain));
                        println!(
                            "  guardian     : {}",
                            if guardian == Pubkey::default() {
                                "none".to_string()
                            } else {
                                guardian.to_string()
                            }
                        );
                        println!("  validators   : {}", c.validators.len());
                        for v in &c.validators {
                            println!("    0x{}", hex::encode(v));
                        }
                        println!("  threshold    : {}", c.threshold);
                        println!("  chain_id     : {}", c.chain_id);
                        println!("  paused       : {}", c.paused);
                        // The capacity/corridor tail continues from the same
                        // cursor. Only `show` reads it, so it stays out of the
                        // hot-path struct — and if it ever drifts, the fields
                        // above still print.
                        match <ConfigTail as borsh::BorshDeserialize>::deserialize(&mut cursor) {
                            Ok(t) => {
                                println!(
                                    "  capacity     : {} validators, {} corridors",
                                    t.max_validators, t.max_corridors
                                );
                                println!("  corridors    : {}", t.nonce_to.len());
                                for (chain, nonce) in &t.nonce_to {
                                    println!("    -> chain {chain}  next nonce {nonce}");
                                }
                            }
                            Err(e) => println!("  capacity/corridors UNREADABLE: {e}"),
                        }
                    }
                    Err(e) => println!("  UNREADABLE: {e} (layout drift between program and gate-admin?)"),
                }
            }
            Err(_) => println!("config account : NOT INITIALIZED (run `init`)"),
        }
        return Ok(());
    }

    let (ix_data, accounts) = match cmd.as_str() {
        "init" => {
            let validators: Vec<[u8; 20]> =
                args.all("--validator").iter().map(|v| hex20(v)).collect::<Result<_, _>>()?;
            anyhow::ensure!(!validators.is_empty(), "init needs at least one --validator");
            let threshold: u32 = args.req("--threshold")?.parse()?;
            let chain_id: u64 = args.req("--chain-id")?.parse()?;
            let max_validators: u32 =
                args.get("--max-validators").unwrap_or_else(|| "8".into()).parse()?;
            let max_corridors: u32 =
                args.get("--max-corridors").unwrap_or_else(|| "8".into()).parse()?;
            // Required, with no default: a defaulted domain shared by every
            // deployment would be the same as having none.
            let bridge_domain = hex32(&args.req("--bridge-domain")?)?;
            let guardian = match args.get("--guardian") {
                Some(g) => Pubkey::from_str(&g)?.to_bytes(),
                None => [0u8; 32],
            };

            let loader = Pubkey::from_str(BPF_LOADER_UPGRADEABLE)?;
            let (program_data, _) =
                Pubkey::find_program_address(&[program_id.as_ref()], &loader);

            (
                GateInstruction::Init(InitArgs {
                    bridge_domain,
                    validators,
                    threshold,
                    chain_id,
                    max_validators,
                    max_corridors,
                    guardian,
                })
                .to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                    AccountMeta::new_readonly(program_id, false),
                    AccountMeta::new_readonly(program_data, false),
                ],
            )
        }
        "register-corridor" => (
            GateInstruction::RegisterCorridor { chain_id_to: args.req("--chain-id-to")?.parse()? }
                .to_bytes(),
            vec![
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        ),
        "register-asset" => {
            let debridge_id = hex32(&args.req("--debridge-id")?)?;
            let mint = Pubkey::from_str(&args.req("--mint")?)?;
            let vault = Pubkey::from_str(&args.req("--vault")?)?;
            let (asset_pda, _) =
                Pubkey::find_program_address(&[b"asset", &debridge_id], &program_id);
            (
                GateInstruction::RegisterAsset { debridge_id }.to_bytes(),
                vec![
                    AccountMeta::new_readonly(config_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(asset_pda, false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new_readonly(vault, false),
                    AccountMeta::new_readonly(Pubkey::from_str(SPL_TOKEN)?, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                ],
            )
        }
        // A DECREASE consumes `["gov", lower_threshold_action_id(t)]`; an increase
        // ignores the extra account. Always attached, so the same command works
        // in both directions, and the action id is printed for the schedule step.
        "set-threshold" => {
            let threshold: u32 = args.req("--threshold")?.parse()?;
            let action_id = lower_threshold_action_id(threshold);
            println!("lowerThreshold action id: 0x{}", hex::encode(action_id));
            println!(
                "(a DECREASE needs `schedule-governance --lower-threshold {threshold}` {}h earlier; an increase is instant)",
                GOVERNANCE_DELAY_SECS / 3600
            );
            (
                GateInstruction::SetThreshold { threshold }.to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                ],
            )
        }
        // H-2 (round 4): queue a validator addition / threshold decrease.
        "schedule-governance" => {
            let action_id = governance_action_id(&args)?;
            println!("scheduling action 0x{}", hex::encode(action_id));
            println!(
                "matures {}h after this lands; execute within the following {}-day grace window",
                GOVERNANCE_DELAY_SECS / 3600,
                GOVERNANCE_GRACE_SECS / 86_400
            );
            (
                GateInstruction::ScheduleGovernance { action_id }.to_bytes(),
                vec![
                    AccountMeta::new_readonly(config_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                ],
            )
        }
        // Owner OR guardian.
        "cancel-governance" => {
            let action_id = governance_action_id(&args)?;
            println!("cancelling scheduled action 0x{}", hex::encode(action_id));
            (
                GateInstruction::CancelScheduledGovernance { action_id }.to_bytes(),
                vec![
                    AccountMeta::new_readonly(config_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                ],
            )
        }
        // Solana -> EVM. Locks the caller's SPL tokens into the registered vault
        // and emits the `Sent` event the relayer signs.
        //
        // The `["sent", submissionId]` record PDA has to be derived client-side,
        // which means recomputing the id exactly as the program does — same
        // fields, same order. `bridge_solana::hash` is the shared implementation
        // that Phase 3 locks against the Solidity fixtures, so this cannot drift
        // from either VM.
        "send" => {
            let debridge_id = hex32(&args.req("--debridge-id")?)?;
            let amount: u64 = args.req("--amount")?.parse()?;
            let chain_id_to: u64 = args.req("--chain-id-to")?.parse()?;
            let receiver = {
                let h = args.req("--receiver")?;
                let h = h.strip_prefix("0x").unwrap_or(&h).to_string();
                hex::decode(&h).map_err(|_| anyhow::anyhow!("--receiver is not hex"))?
            };
            anyhow::ensure!(
                receiver.len() == 20 || receiver.len() == 32,
                "receiver must be 20 bytes (EVM) or 32 (Solana), got {}",
                receiver.len()
            );
            let user_token = Pubkey::from_str(&args.req("--from-token-account")?)?;

            // chain_id and the per-corridor nonce come from the config; the
            // program uses exactly these to build the id.
            let cfg_acct = rpc.get_account(&config_pda)?;
            // Through the ONE mirrored layout (`gate::ConfigView` + `ConfigTail`),
            // never hand-sliced offsets — that is how `show` once reported zeros
            // after `bridge_domain` was inserted.
            let mut cursor: &[u8] = &cfg_acct.data;
            let view = decode_config_view(&mut cursor)?;
            let tail = ConfigTail::deserialize(&mut cursor)
                .map_err(|e| anyhow::anyhow!("config tail does not decode: {e}"))?;
            let bridge_domain = view.bridge_domain;
            let chain_id = view.chain_id;
            let nonce = tail
                .nonce_to
                .iter()
                .find(|(c, _)| *c == chain_id_to)
                .map(|(_, n)| *n)
                .ok_or_else(|| {
                    anyhow::anyhow!("corridor {chain_id_to} is not registered — run register-corridor")
                })?;

            // No auto-params here, so `native_sender` is NOT part of the hash —
            // it only enters via `keccak(nativeSender)` in the auto tail, exactly
            // as `BridgeHash.sol` defines it. Using the with-auto form here would
            // produce an id the gate never derives.
            let id = bridge_solana::hash::submission_id(
                &bridge_domain,
                &debridge_id,
                &bridge_solana::hash::amount_word(amount as u128),
                chain_id,
                chain_id_to,
                nonce,
                &receiver,
            );

            let (asset_pda, _) =
                Pubkey::find_program_address(&[b"asset", &debridge_id], &program_id);
            let (sent_pda, _) = Pubkey::find_program_address(&[b"sent", &id], &program_id);
            let asset_acct = rpc.get_account(&asset_pda)?;
            anyhow::ensure!(asset_acct.data.len() >= 96, "asset account is malformed");
            let vault = Pubkey::new_from_array(asset_acct.data[64..96].try_into()?);

            println!("submissionId : 0x{}", hex::encode(id));
            println!("nonce        : {nonce}  corridor {chain_id} -> {chain_id_to}");
            println!("vault        : {vault}");

            (
                GateInstruction::Send(bridge_solana::instruction::SendArgs {
                    debridge_id,
                    amount,
                    chain_id_to,
                    receiver,
                    auto: None,
                })
                .to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new_readonly(asset_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(user_token, false),
                    AccountMeta::new(vault, false),
                    AccountMeta::new_readonly(Pubkey::from_str(SPL_TOKEN)?, false),
                    AccountMeta::new(sent_pda, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                ],
            )
        }
        // M-2, DESTINATION side: burn the transfer so it can never be claimed.
        // Moves no funds; it only unlocks the source-side refund.
        "cancel" => {
            let a = bridge_solana::instruction::CancelArgs {
                debridge_id: hex32(&args.req("--debridge-id")?)?,
                amount: args.req("--amount")?.parse()?,
                chain_id_from: args.req("--chain-id-from")?.parse()?,
                nonce: args.req("--nonce")?.parse()?,
                receiver: hex::decode(
                    args.req("--receiver")?.strip_prefix("0x").unwrap_or(&args.req("--receiver")?),
                )?,
                auto: None,
                native_sender: hex::decode(
                    args.req("--native-sender")?
                        .strip_prefix("0x")
                        .unwrap_or(&args.req("--native-sender")?),
                )?,
                signatures: parse_sigs(&args)?,
            };
            let id = hex32(&args.req("--submission-id")?)?;
            let (executed, _) = Pubkey::find_program_address(&[b"executed", &id], &program_id);
            println!("burning {} (executed PDA {})", hex::encode(id), executed);
            (
                GateInstruction::Cancel(a).to_bytes(),
                vec![
                    AccountMeta::new_readonly(config_pda, false),
                    AccountMeta::new(executed, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                ],
            )
        }
        // M-2, SOURCE side: return the locked funds, but ONLY once the
        // destination burn is on-chain. The gate checks that itself.
        "refund" => {
            let debridge_id = hex32(&args.req("--debridge-id")?)?;
            let a = bridge_solana::instruction::RefundArgs {
                debridge_id,
                amount: args.req("--amount")?.parse()?,
                chain_id_to: args.req("--chain-id-to")?.parse()?,
                nonce: args.req("--nonce")?.parse()?,
                receiver: hex::decode(
                    args.req("--receiver")?.strip_prefix("0x").unwrap_or(&args.req("--receiver")?),
                )?,
                auto: None,
                native_sender: hex::decode(
                    args.req("--native-sender")?
                        .strip_prefix("0x")
                        .unwrap_or(&args.req("--native-sender")?),
                )?,
                signatures: parse_sigs(&args)?,
            };
            let id = hex32(&args.req("--submission-id")?)?;
            let (asset_pda, _) =
                Pubkey::find_program_address(&[b"asset", &debridge_id], &program_id);
            let (sent_pda, _) = Pubkey::find_program_address(&[b"sent", &id], &program_id);
            let (refunded_pda, _) =
                Pubkey::find_program_address(&[b"refunded", &id], &program_id);
            let asset_acct = rpc.get_account(&asset_pda)?;
            anyhow::ensure!(asset_acct.data.len() >= 96, "asset account is malformed");
            let vault = Pubkey::new_from_array(asset_acct.data[64..96].try_into()?);

            // The payout destination is the token account `send` debited, recorded
            // by the program in `["sent", id]` — so it can be read rather than
            // typed. An explicit `--to-token-account` still has to MATCH it, or the
            // program refuses; pass it only as a cross-check.
            let sent_acct = rpc
                .get_account(&sent_pda)
                .map_err(|_| anyhow::anyhow!("no [\"sent\", id] record: this gate never sent {}", hex::encode(id)))?;
            anyhow::ensure!(sent_acct.owner == program_id, "sent record is not program-owned");
            let record = bridge_solana::relayer::decode_sent_record(&sent_acct.data)
                .ok_or_else(|| anyhow::anyhow!("sent record does not decode (layout drift?)"))?;
            anyhow::ensure!(record.amount != 0, "sent record is zeroed: already refunded");
            let recorded_to = Pubkey::new_from_array(record.source_token);
            let to_token = match args.get("--to-token-account") {
                Some(t) => {
                    let t = Pubkey::from_str(&t)?;
                    anyhow::ensure!(t == recorded_to, "--to-token-account {t} != recorded {recorded_to}");
                    t
                }
                None => recorded_to,
            };
            println!("refunding {} : {} units from vault {vault} -> {to_token}", hex::encode(id), record.amount);
            println!("locked_at    : {} (cluster unix time)", record.locked_at);
            (
                GateInstruction::Refund(a).to_bytes(),
                refund_accounts(
                    config_pda,
                    asset_pda,
                    sent_pda,
                    refunded_pda,
                    payer.pubkey(),
                    vault,
                    to_token,
                    vault_authority,
                ),
            )
        }
        // An ADDITION consumes `["gov", add_validator_action_id(v)]`; a removal
        // is instant and ignores the extra account.
        "set-validator" => {
            let validator = hex20(&args.req("--validator")?)?;
            let active = args.get("--active").unwrap_or_else(|| "true".into()) == "true";
            let action_id = add_validator_action_id(&validator);
            println!("addValidator action id: 0x{}", hex::encode(action_id));
            if active {
                println!(
                    "(an ADDITION needs `schedule-governance --add-validator 0x{}` {}h earlier; removal is instant)",
                    hex::encode(validator),
                    GOVERNANCE_DELAY_SECS / 3600
                );
            }
            (
                GateInstruction::SetValidator { validator, active }.to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                ],
            )
        }
        other => anyhow::bail!("unknown command {other:?}"),
    };

    let ix = Instruction { program_id, accounts, data: ix_data };
    let blockhash = rpc.get_latest_blockhash()?;
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
    let sig = rpc.send_and_confirm_transaction(&tx)?;
    println!("{cmd} OK — tx {sig}");
    Ok(())
}
