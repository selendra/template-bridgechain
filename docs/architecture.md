# SelendraBridge Architecture

This document describes the system as implemented.
Every claim in it was checked against the source, and file and line references are given so you can check them again.
Where the code and this document disagree, the code is right and this document is a bug.

It replaced `BRIDGE_ARCHITECTURE.md`, which described a NestJS/TypeORM service that never existed in this repository and has been deleted.

---

## 1. What this is

An external-validator bridge, modeled on [deBridge's `DeBridgeGate`](https://github.com/debridge-finance/debridge-contracts-v1/tree/main/contracts/transfers).

The on-chain half is Solidity.
The off-chain half is Rust.
There is no TypeScript anywhere except the frontend.

The security model is a threshold multi-signature oracle.
A set of independent validators watch the source chain, each independently recomputes what it saw, and each signs only if its own computation matches the event.
A quorum of those signatures authorises a payout on the destination chain.
There is no fraud proof, no light client, and no optimistic window.
**If a threshold of validator keys is compromised, the bridge is compromised.**
Everything else in the design exists to make sure that is the *only* way to break it.

The asset model is lock and unlock, not mint and burn.
The destination gate holds pre-funded liquidity of a local ERC-20 registered against the incoming asset id.
A transfer moves value between two pools; it does not create tokens.

---

## 2. The one invariant that matters

Every transfer is identified by a `submissionId`, a keccak256 hash over its parameters.
The source contract computes it, and each validator independently recomputes it from the event log.
**A validator signs only when its own hash equals the one the contract emitted.**

That single equality check is what makes the validator an independent witness rather than a rubber stamp.
If the two implementations could ever disagree, the check would either block all traffic or, far worse, pass on parameters that differ from what the contract actually committed to.

So the hash is defined once in Solidity and reproduced in Rust, and the two are locked together by fixture-based tests that run on both sides:

- `contracts/src/BridgeHash.sol` is canonical.
- `contracts/test/GenFixtures.t.sol` generates `contracts/fixtures/submission_ids.json` from the Solidity.
- `crates/bridge-core/tests/equivalence.rs` and `crates/bridge-solana/tests/equivalence.rs` consume that file and assert byte equality.

This equivalence has been verified to hold: regenerating the fixtures from Solidity produces a byte-identical file, and the Rust suites pass against it.

Do not change `BridgeHash.sol` without regenerating the fixtures and running both test suites.

### 2.1 The preimages

All encoding is `abi.encodePacked`, chosen so alloy can reproduce it byte for byte off-chain.

**Asset id.**

```
debridgeId = keccak256(abi.encodePacked(nativeChainId, nativeToken))
```

A one-way hash of (origin chain, origin token address).
It travels in the message; the concrete local token address does not.
Each gate keeps its own `tokenOf[debridgeId] -> address` registry saying which local ERC-20 backs that asset on this chain.

Because keccak is not invertible, `Gate.Sent` also emits the concrete `token` address separately, since the refund relayer needs it to build a `refund()` call.

**Transfer id, without an execution payload.**

```
submissionId = keccak256(abi.encodePacked(
    SUBMISSION_PREFIX,   // uint256(1)
    debridgeId,
    chainIdFrom,
    chainIdTo,
    amount,
    receiver,            // dynamic bytes
    nonce
))
```

Note the field order: `chainIdFrom` and `chainIdTo` come *before* `amount`, which is not the order the arguments appear in any function signature.
Follow `BridgeHash.packedSubmission`, not intuition.

**Transfer id, with an execution payload.**
The seven-field packed base above, with five more fields appended before hashing:

```
submissionId = keccak256(abi.encodePacked(
    <the 7-field packed base>,
    autoParams.executionFee,
    autoParams.flags,
    keccak256(autoParams.fallbackAddress),
    keccak256(autoParams.data),
    keccak256(autoParams.nativeSender)
))
```

The three dynamic fields are hashed individually before being packed.
That is what keeps the concatenation unambiguous: without it, packed encoding of adjacent dynamic fields would admit collisions between different field splits.

**Refund-path digests.**

```
cancelId = keccak256(abi.encodePacked(CANCEL_PREFIX, submissionId))   // uint256(2)
refundId = keccak256(abi.encodePacked(REFUND_PREFIX, submissionId))   // uint256(3)
```

### 2.2 Why three prefixes

The prefixes are domain separators, and they are load-bearing.

A validator signature is just a signature over 32 bytes.
Without domain separation, the signature that authorises *paying out* a transfer would be a valid signature for *burning* it, and vice versa.
An attacker who collected a normal quorum of transfer signatures could replay them to cancel the transfer, then replay them again to refund it, and take the money twice.

Two things prevent that.
The prefix differs, and the preimage length differs: a cancel or refund preimage is 64 bytes, while a submission preimage is at least 224 bytes.
Crossing the domains would require a keccak256 preimage collision.

This is enforced on-chain and tested.
`contracts/test/Refund.t.sol` covers all four cross-domain replays by name:
`test_Cancel_RejectsReplayedTransferSignature`, `test_Cancel_RejectsReplayedRefundSignature`, `test_Refund_RejectsReplayedTransferSignature`, `test_Refund_RejectsReplayedCancelSignature`.
`crates/bridge-core/src/store.rs` tests the same property off-chain in `attestations_are_domain_separated`.

---

## 3. Contracts

All in `contracts/src/`, Solidity 0.8.24, built with `via_ir = true` and the optimizer on.

| Contract | Runtime size | Role |
| --- | --- | --- |
| `Gate.sol` | 5,983 B | The bridge. Deployed on every supported chain. |
| `SwapPool.sol` | 5,739 B | Same-chain swap, pegged pricing, reserve-capped. |
| `SwapRouter.sol` | 6,507 B | Composes swap and bridge into one cross-chain flow. |
| `BridgeHash.sol` | library | The canonical hashing. |
| `TestToken.sol` | test only | Mintable ERC-20 for local runs. |

### 3.1 Gate

One `Gate` per chain. It is both the source and the destination; the role depends on which function is called.

**State.**

| Mapping | Side | Meaning |
| --- | --- | --- |
| `nonceTo[chainIdTo]` | source | Monotonic per-corridor nonce. Makes each `submissionId` unique. |
| `sentBy[submissionId]` | source | Who locked the funds. Origin proof *and* authoritative refund recipient. Cleared on refund. |
| `refunded[submissionId]` | source | Refund replay guard. |
| `executed[submissionId]` | destination | Spent here. Set by **both** `claim` and `cancel`. |
| `cancelled[submissionId]` | destination | Distinguishes a burn from a delivery. |
| `tokenOf[debridgeId]` | destination | Asset registry: which local ERC-20 backs this asset id. Write-once. |
| `supportedChain[chainId]` | source | Destinations `send` accepts (M-3). Unlisted ⇒ `UnsupportedChain`; nothing is locked towards a chain with no gate. Instant and reversible; `claim`/`cancel`/`refund` never consult it. |
| `isSealed` | both | Ends the setup phase (H-1). Until `seal()`, the owner registers corridors instantly; after it, every new `setLocalToken` needs `scheduleGovernance(setLocalTokenActionId(id, token))` + `GOVERNANCE_DELAY`, so a stolen owner key cannot point a corridor at a worthless token and drain the pot. Irreversible. |

`send` additionally reverts `AmountTooWide` when the receiver is 32 bytes (a Solana account) and `amount > 2^64-1`: the Solana gate's claim and cancel carry a `u64`, so a wider transfer could be neither delivered nor refunded (H-3). The frontend mirrors the check.

Wiring order for every gate, before it is funded: `setSupportedChain` for each peer → `setLocalToken` for each inbound corridor → `seal()`. Both launchers do this and verify it.

The `executed` / `cancelled` split is a sharp edge worth internalising.
`executed` means "spent", not "delivered".
Any consumer that reads `executed` as proof of delivery must also check `cancelled`, or it will act on a payout that never happened.
`SwapRouter.finalize` gets this right at `SwapRouter.sol:227`, requiring `gate.executed(id) && !gate.cancelled(id)`.

**`send(token, amount, chainIdTo, receiver, autoParams)`** locks an ERC-20 and emits `Sent`.

The ordering inside `send` is deliberate and documented in the source.
The nonce is reserved, `sentBy` is written, and `Sent` is emitted **before** `safeTransferFrom` is called.
That is checks-effects-interactions: a token with a transfer hook that re-entered `send` would otherwise read the same nonce and emit a colliding `Sent`, desyncing the off-chain nonce sequence.
`Security.t.sol:test_Send_ReentrancyKeepsNoncesSequential` pins this.

**`claim(...)`** verifies a quorum, sets `executed`, then releases funds.
Effects before interactions again.

**`_verifySignatures(message, signatures)`** (`Gate.sol:524-542`) is the heart of the trust model:

```solidity
bytes32 digest = MessageHashUtils.toEthSignedMessageHash(message);
address last = address(0);
uint256 count = 0;
for (uint256 i = 0; i < signatures.length; i++) {
    address signer = ECDSA.recover(digest, signatures[i]);
    if (signer <= last) revert InvalidSignerOrder();   // strictly ascending
    if (isValidator[signer]) { count++; }
    last = signer;
}
if (count < threshold) revert NotEnoughSignatures(count, threshold);
```

Two things to note.
Signatures are EIP-191 (`eth_sign`) digests, not EIP-712.
And the **strictly ascending signer order is the deduplication mechanism**: it is what stops one validator's signature being submitted N times to fake a quorum.
Every caller must sort signatures by recovered signer address ascending.
`keeper::sorted_signatures` does this.

**Circuit breaker.**
`owner` or `guardian` may `pause`, halting `send` and `claim`.
Only `owner` may `unpause`.
The guardian is deliberately low-trust: it can stop the bridge but never start it and never move funds, so a compromised guardian causes a denial of service and nothing worse.

> **Operational note.** `DeployProd` (the `production` profile of `scripts/deploy-from-json.sh`) appoints the guardian and reverts if it is zero or equal to the owner. The `local` profile leaves it optional, which is one reason that profile is refused on any non-dev chain id.

### 3.2 SwapPool

A same-chain swap against a single stablecoin as the unit of account.
Not an AMM: prices are set by an oracle role, and each token's throughput is hard-capped by its own locked reserve.

`setPrice` enforces a per-update deviation cap (`maxPriceDeviationBps`) against the previous price.

> **Known gap.** The cap is per call, with no cooldown or time weighting. A compromised oracle key can walk the price arbitrarily far across repeated calls in a single block. See `report.md` M5.

`seedLiquidity` and `swap` both measure balance deltas across the transfer rather than trusting the requested amount, which is correct for fee-on-transfer tokens.

### 3.3 SwapRouter

Composes "swap on the source, bridge the stable, swap again on arrival" into one user flow.

`swapAndBridge` swaps the input token into the stable, then calls `gate.send`, encoding the destination intent (`finalToken`, `finalReceiver`, `finalMinOut`) into `autoParams.data`.
Because `autoParams` is folded into the `submissionId`, the destination intent is bound by the hash and cannot be altered in flight.

`finalize` is permissionless: anyone can complete the second leg for anyone else.
It requires `gate.executed(id) && !gate.cancelled(id)`, and is idempotent via its own `finalized[submissionId]` map.
If the destination swap cannot be satisfied, it falls back to delivering the stable rather than reverting.

---

## 4. Off-chain services

Nine crates. Two are excluded from the workspace, for different reasons. `crates/solana-gate` because its `solana-program` dependencies do not build for the host target; it is built with `cargo build-sbf`. `crates/solana-relayer` because `solana-client` pins `zeroize <1.4` while alloy needs `^1.5`; it is built with `docker/Dockerfile.relayer`.

| Crate | Kind | Responsibility |
| --- | --- | --- |
| `bridge-core` | lib | Canonical hashing, the signature store and **its trust boundary**, gate ABI bindings, allowlist. |
| `bridge-db` | lib | Postgres access via sqlx. Transaction history, refund lifecycle, allowlists. |
| `bridge-solana` | lib | Host-side reference model of the Solana gate, plus relayer log parsing. |
| `validator` | bin | Scan, recompute, sign, store. Also refund attestation. |
| `keeper` | bin | Collect a quorum, submit `claim` / `cancel` / `refund`. |
| `sig-store` | bin | HTTP signature store (axum). The shared bulletin board. |
| `indexer` | bin | Read-only chain observer. **Sole writer of `refund_status`.** |
| `graphql-api` | bin | Read API for the frontend. |
| `solana-relayer` | bin | The Solana leg's validator (and, with `[target]`, its keeper). Excluded from the workspace. |

### 4.1 Which processes are required for which features

This is not obvious from the code, and getting it wrong silently disables features rather than failing loudly.

| Feature | Requires |
| --- | --- |
| Basic transfer (send, claim) | `validator`, `keeper`, `sig-store` |
| Transaction history, stuck detection | plus `indexer`, Postgres |
| **Refunds** | plus `indexer` (it is the only writer of `refund_status`) |
| Frontend | plus `graphql-api` |

> **Operational note.** The `Dockerfile` now builds all five binaries and `docker-compose.yml` deploys all of them plus Postgres and the frontend, so the shipped stack advances refunds and serves the UI on its own. `report.md` H4 describes the earlier three-binary image, which no longer matches the tree.

### 4.2 validator

The validator is the only process that holds signing authority, and it is the only one whose output the Gate contract will accept. Everything it does is arranged so that it signs a transfer **only** if it saw that transfer itself, on a chain it reads over its own RPC, at a depth it chose.

One independent scan loop per configured source chain (`validator/src/main.rs:130`, `scan_source`). The loops are spawned into a `JoinSet` and isolated: a dead loop on one chain does not stop the others.

**Startup, per chain.** Connect through `provider::Failover` over the ordered `rpcs` list, with a `chainId` guard on every endpoint, then read `Gate.bridgeDomain()` **from the contract**, not from config (`main.rs:167`). That matters: every `submissionId` is recomputed under the domain, so a wrong one would make every id mismatch and the validator would silently sign nothing. Sourcing it from the gate removes that misconfiguration entirely at the cost of one call. Both steps retry rather than exit — a flaky RPC must not kill the loop.

**Per batch.** Fetch `Sent` logs over `[from_block, min(latest - block_confirmation, from_block + max_block_range - 1)]` (`main.rs:232`), and for each one (`main.rs:348`, `handle_log`):

1. Decode the event. Reject a `chainId`/`nonce` that exceeds `u64` — an aliasing cast would mis-key the nonce and break claim reconstruction — by **skipping**, not erroring, so one malformed log cannot wedge the batch.
2. Check the nonce is sequential for that **corridor** (`chain_from, chain_to`), not globally. Each source gate keeps its own `nonceTo[chainIdTo]`, so in a mesh two sources reaching one destination both count `0,1,2,…` independently. A gap (`MissedNonce`) or a replay (`DuplicatedNonce`) **pauses the scanner** rather than guessing.
3. **Independently recompute the `submissionId`** from the decoded fields under the gate's own `bridgeDomain`. On mismatch, refuse to sign and pause — the signal is a lying or broken RPC.
4. Check the token and corridor against the allowlist. A blocked transfer has its signature *withheld* but its **nonce consumed**: the transfer really did happen on-chain, so the sequence must stay intact, and withholding is already sufficient — it can never reach threshold.
5. Sign the EIP-191 digest over the raw 32-byte id and `upsert` to the store.
6. Record the nonce as accepted **only after** the sign-and-store succeeded.

**The two cursors advance together.** `handle_log` advances the per-corridor nonce cursor as each event is accepted, but the block cursor only advances once the whole batch is durably handled. So the loop snapshots the nonce cursors before the batch and rolls them back whenever the block cursor stays put (`main.rs:267-315`). Without that rollback, a failed batch would be rescanned with the nonces already consumed, and every event in it would look like a replay. Both cursors persist to `state_file`.

**Pausing is durable.** `Runtime.paused` and its reason are serialized (`validator/src/state.rs:32-38`), so a validator that stopped on a nonce anomaly comes back up *still paused* and logs why. Restarting is not a way to clear a safety stop; an operator must look and then `/resume`.

**Catch-up pacing.** `catchup_poll_interval_ms` (optional) is the delay used while the scanner is behind — i.e. when the last range was capped by `max_block_range` and confirmed history is still unread. It defaults to `poll_interval_ms`, deliberately: how fast a scanner *may* read is a property of the endpoint, not of the backlog. Reading back-to-back clears a fast chain's gap in minutes instead of hours, but on a shared rate-limited endpoint it starves every other consumer of the same key — the API's pool reads and the indexer included — which surfaces as 429s, not as slowness. Lower it only for an endpoint you know can take it.

**Fail-closed config.** `Config::load` refuses to start a source with `block_confirmation = 0` unless `allow_zero_confirmation = true`, because signing at the chain tip lets a source reorg erase a deposit *after* the keeper has released destination liquidity. `#[serde(deny_unknown_fields)]` on both structs means a typo in that opt-in is an error, not a silently-ignored no-op that leaves the buffer at 0.

An operator HTTP API (`validator/src/api.rs`) exposes `/status`, and `/pause`, `/resume`, `/rescan`, each optionally per chain.

### 4.3 validator refund attestation

A separate loop (`validator/src/refund.rs`) with its own safety rules, and the most carefully written code in the repository.

It polls the store for stuck candidates and decides **from on-chain facts alone**, never from what the database claims:

- It reads both chains at a **confirmed block, not the tip**. Reading `executed` at the tip would let a reorg make a claimed transfer look unclaimed, and the loop would then attest a cancel for a transfer that was actually paid.
- It refuses to vote on any corridor where it cannot read *both* ends. Attesting on a chain it cannot read would mean trusting the store's word for whether a transfer was delivered, which is precisely what an attacker would want.
- **A claimed transfer never earns a cancel or refund attestation, whatever the store says about timeouts.**
- A refund is never attested for a `submissionId` this gate never emitted.
- **The unclaimed timeout is established by this validator, not by the database.** The store only *nominates* candidates. Whether one is old enough is answered by reading `sentBy(id)` on the source gate at a block whose own timestamp is at least `timeout_secs` behind the chain head (`refund.rs:117` `aged_block`, `refund.rs:151` `was_sent_by_block`). `sentBy` is written by `send` in the same transaction that locks the funds, so a non-zero value at a historical height is the chain's own statement that the deposit already existed by then — an authenticated age check costing one `eth_call`, with no trust in a `created_at` column and no dependence on this node's wall clock.

That last rule is the one worth understanding. The timeout used to rest entirely on `refund_status = 'eligible'`, a column no validator verified. A wrong `created_at`, clock skew, a misconfigured sweep, or write access to Postgres would nominate healthy in-flight transfers, and every validator would attest cancels for them within one poll interval. `cancel` is irreversible and permanently forecloses the payout, so a database fault became a fleet-wide forced refund of everything in flight. The destination check never caught it: a transfer that is merely *in flight* has not been claimed yet either — that is exactly the window an early cancel steals.

The decision function (`decide`) is split out from the I/O specifically so these rules are unit-testable, and the tests are named after the attacks they block.

### 4.4 keeper

**The keeper decides nothing.** It holds a funded gas-payer key and no authority beyond it: it relays quorums the validators already formed, and every transaction it sends is re-verified on-chain by `Gate._verifySignatures` before anything moves. This is why running one is permissionless — a hostile keeper can waste its own gas, delay delivery, or pick which of several ready transfers goes first, but it cannot move funds that the validators did not already authorise.

**Loop topology.** One loop per `[[targets]]` chain (claims + cancels, on the destination) and one per `[[sources]]` chain (refunds, where the funds were locked). All are spawned into a `JoinSet` and isolated, so one bad chain does not stop delivery to the others; the process only exits when *every* loop has died. A chain listed as both a target and a source gets a startup warning: the two loops submit from one account and can briefly contend on its nonce under load (self-healing, but split the roles across processes or accounts for a busy bidirectional corridor).

**Per tick, per chain:**

1. `refresh_if_stale` re-reads `threshold`, `validatorCount` and validator membership from the gate every 60s (`GATE_REFRESH_INTERVAL`). These were once a startup snapshot, which meant an on-chain validator-set change needed a restart — and worse, a cached `true` for a since-removed validator lets the built signature array exceed the *current* `validatorCount`, which the Gate rejects outright.
2. Fetch the allowlist. **Fail-closed**: if the sig-store is unreachable, skip the tick rather than claim on a stale view.
3. For each record bound for this chain, filter its signatures through `member_signatures` — signatures from keys that are not in the gate's on-chain validator set are dropped *before* the quorum is counted. The record's raw `signatures` field is deliberately never forwarded to the calldata: it may hold well-formed signatures from any key at all, and passing those through is what makes a transfer permanently unclaimable.
4. **Cancels first**, before the transfer-threshold and allowlist gates, deliberately: those gates protect payouts, and a cancel is the opposite of a payout. Checking them first would strand precisely the transfers that most need refunding — an allowlist-rejected transfer never collects transfer signatures at all, so it would fail the threshold check, never reach the cancel branch, and its funds would stay locked forever.
5. Otherwise, if the surviving claim signatures reach `threshold`, re-check the allowlist (the second enforcement gate; validators are the first) and submit `claim()` with signatures sorted ascending by signer, as the Gate requires.

**Nonces.** The provider uses `with_simple_nonce_management()`, which fetches the pending nonce from the chain for every transaction, rather than alloy's default `CachedNonceManager`. The cached manager increments a local counter on *submission*; a send that reverts before broadcast leaves the counter ahead of the chain, and after a run of those the keeper wedges permanently, every subsequent transaction rejected as nonce-too-high.

**Receipts are checked.** `confirm` (`keeper/src/main.rs:427`) waits at most `RECEIPT_TIMEOUT` (120s) for the receipt and treats `!receipt.status()` as an error. A reverted claim reported as success would make the caller run `mark_claimed`, permanently excluding the transfer from the refund sweep — the transfer would be neither delivered nor refundable. A transaction that never confirms in the window errors instead of blocking the loop forever; the record is retried next tick, and each `try_*` re-reads on-chain state first, so a retry after the transaction actually landed is a no-op.

**Whose word counts for what.** The claim path calls `mark_claimed` because that record is advisory bookkeeping. The cancel and refund paths deliberately **discard their own transaction hashes** and let the indexer record the state from the observed on-chain `Cancelled`/`Refunded` event. The principle is in the source: the keeper's word is not authoritative for a state that gates the refund-candidate list, because a forged "refunded" would hide a stuck transfer from every relayer.

### 4.5 sig-store

An axum HTTP service, the shared bulletin board validators write to and keepers read from.
Postgres-backed, via `bridge-db`.

A validator does not have to use it.
`bridge_core::backend::StoreBackend` — shared by the validator, keeper and GraphQL API — picks its backing from config: `[store] url = ...` selects the HTTP sig-store, `[store] dir = ...` selects a local filesystem store, and it refuses to start if neither is set. Each service builds it with its own `SIG_STORE_*_TOKEN`, which is what bounds its authority server-side.
Single-validator local runs use the file path; a real deployment uses the HTTP path so multiple validators share one view.

**The same guards apply on both paths.**
`bridge-db` does not reimplement validation; it calls the exact functions from `bridge_core::store` (`canonical_submission_id`, `verify_signature`, `verify_token_binding`, `same_params`, `verify_attestation`, `is_valid_submission_id`) at `bridge-db/src/lib.rs:272-309` and `:447-460`.
This is the right structure: there is one definition of what a valid record is, and swapping the storage backend cannot weaken it.

Every route except `/health` requires a bearer token, and each route group demands the **narrowest scope that lets it work**:

| Scope | Token | Routes |
| --- | --- | --- |
| `Read` | any of the four | `GET /submissions`, `/submissions/:id`, `/refund-candidates`, `/history`, `/swaps`, `/allowed/*` |
| `Sign` | `SIG_STORE_VALIDATOR_TOKEN` | `POST /submissions`, `POST /submissions/:id/attestations` |
| `Relay` | `SIG_STORE_KEEPER_TOKEN` | `POST /submissions/:id/claimed` |
| `Admin` | `SIG_STORE_ADMIN_TOKEN` | allowlist mutations under `/allowed/` |

`SIG_STORE_READER_TOKEN` grants `Read` and nothing else; the GraphQL API — the most exposed component — gets that one, which is the whole point of the split. The legacy `SIG_STORE_TOKEN` still works and grants all four scopes to whoever holds it; the service logs a warning at startup when it is set.

The credential, not the Rust type, is what bounds a service. `StoreBackend` exposes every operation to every caller that compiles, and each service simply builds it with its own variable via `StoreBackend::remote_for_role`. A reader token calling `mark_claimed` gets a 401 regardless of what type-checked.

Routes: `/submissions` (post, list), `/submissions/:id`, `/submissions/:id/claimed`, `/submissions/:id/attestations`, `/refund-candidates`, `/history`, `/swaps`, and allowlist management under `/allowed/`.

There is deliberately **no write route** for the `cancelled`/`refunded` lifecycle. Those states gate the refund-candidate list, so they are set only by the indexer from observed on-chain events, never on a caller's word.

**The sig-store is untrusted infrastructure.**
It is a convenience for distribution, not a source of authority.
Its operator cannot forge a transfer, because the on-chain `_verifySignatures` counts only real validator signatures.
The guards in the next section are what make that true.

### 4.6 indexer

Read-only. Never signs, never sends a transaction.

Exists so every transfer is visible in the database, **including those with zero validator signatures**, which are invisible to the signature-store view by construction.

Observes `Gate.Sent`, `Gate.Claimed`, `SwapPool.Swapped`, `SwapRouter.SwapBridged`, `SwapRouter.Finalized` / `FinalizeFallback`, and runs the refund-eligibility sweep.

The cursor advances only when **every** relevant scan in the tick durably handled all of its logs; if any one fails, the cursor stays put and the range is reprocessed next tick. The one exception is a permanently-malformed event (e.g. a `chainId` exceeding `u64`), which is logged and skipped — otherwise the cursor could never move past it.

### 4.7 How the processes connect

**Validators never talk to each other.** There is no peer-to-peer layer, no gossip, and no consensus round between them. Coordination is hub-and-spoke through the sig-store:

```
machine A ─ validator val-1 ─┐         own RPCs, own key, own state file
machine B ─ validator val-2 ─┼──► sig-store ──► Postgres
machine C ─ validator val-3 ─┘         ▲   │
                                       │   └──► keeper ──► Gate.claim() on-chain
                              indexer ─┘            (once sigs ≥ threshold)
```

Each validator independently observes its source chains, recomputes the id, signs, and `POST`s to `/submissions`. The store merges signatures by signer (`ON CONFLICT (submission_id, signer) DO NOTHING`), so the order of arrival and the number of retries do not matter. The keeper polls `GET /submissions` and submits once a record carries `threshold` signatures **from keys in the gate's current validator set**. That is the entire coordination mechanism.

**The hub is a rendezvous point, not an authority.** Three layers make a compromised sig-store a liveness problem rather than a safety one:

1. `Db::upsert_signature` re-derives the id from the parameters and ecrecovers the signature server-side before storing anything (`bridge-db/src/lib.rs:412-420`), calling the same `bridge_core::store` functions the file backend uses.
2. Parameters are immutable after first insert — a re-`POST` with different fields is rejected as `ParamsConflict`.
3. `Gate._verifySignatures` counts only `isValidator[signer]` signatures, on-chain, at claim time.

So the store's operator can **censor** — withhold signatures, stall transfers — and the two-phase refund path exists to recover from exactly that. The operator cannot **forge**. This is why a central store is an acceptable design here, and why adding a P2P layer between validators would buy nothing.

**What running on separate machines actually requires.** Only the store URL and the credential change:

```toml
[store]
url = "https://sig-store.internal.example.com"   # instead of http://127.0.0.1:8080
```

with `SIG_STORE_VALIDATOR_TOKEN` exported on each validator host. See `operations.md` §5 for the network, credential and independence requirements that come with it — in particular that validators sharing one RPC provider are not independent observers, which makes the threshold decorative.

### 4.8 solana-relayer

The Solana leg's validator. A **separate binary and image**: `solana-client` pins `zeroize <1.4` and alloy needs `^1.5`, so it cannot share a binary — or a cargo workspace — with the EVM services. It shares only the secp256k1 signing key (the same key, so one validator set attests for both VMs) and the sig-store, which it reaches over HTTP with `SIG_STORE_VALIDATOR_TOKEN`.

It carries the same three safety rules as `scan_source`, translated:

- **finality** — reads at `finalized` only; `Config::load` refuses anything weaker without `allow_unfinalized`, for the same reason the EVM side refuses a zero `block_confirmation`.
- **never sign what you cannot reproduce** — recomputes the id under the `bridge_domain` read from the gate's `["config"]` PDA, plus an origin proof: the gate's `["sent", submissionId]` PDA is program state only `process_send` can write, which is what distinguishes "the gate locked these funds" from "someone printed a convincing log line".
- **the allowlist gates signing** — see below.

Differences from the EVM validator, all deliberate: one `[source]` rather than repeatable `[[sources]]`; the cursor is a transaction signature, not a block number; the refund attester runs unconditionally (the EVM validators cannot read Solana, so without it nobody votes on that corridor); there is no operator API; and `[signer]` has no encrypted-keystore option, only `private_key` / `private_key_env`.

**Where the allowlist is enforced, and why it has to be here.** The scanner originally signed every `Sent` it could authenticate and left the allowlist to the EVM keeper's pre-claim check. That made the control silently asymmetric. On an EVM→EVM corridor a de-listed token never reaches quorum, because each validator withholds. On Solana→EVM it reached quorum anyway — and `Gate.claim` is `external` with no access control and no notion of an off-chain list (`Gate.sol:524`; it checks validator signatures and `tokenOf[debridgeId] != 0`, nothing more), while the collected signatures are public, since the GraphQL API serves the raw 65 bytes so a user can self-claim. So anyone could complete a transfer the operator had just de-listed; the keeper's check only ever bound the keeper.

Not a fund-loss defect — the gate still releases only registered assets against a real quorum — but an operational kill-switch that did nothing in one direction, which is worse than none, because it is reached for during an incident. Withholding the signature is the only thing that actually stops the transfer, so `source.rs` now fetches the allowlist per tick and checks token and corridor before signing, failing closed (skip the tick, cursor untouched) if the fetch fails. A blocked transfer is skipped rather than errored, so the cursor still advances — the mirror of the EVM validator consuming a blocked transfer's nonce.

The `Allowlist` type is duplicated in `solana-relayer/src/store.rs` for the same unavoidable reason `SubmissionRecord` is, and its opt-in semantics are pinned by tests on both sides: an empty list allows everything, the first row flips that list to deny-by-default, and the two lists are independent.

---

## 5. The trust boundary

`crates/bridge-core/src/store.rs` is the single most security-critical file in the off-chain system.
Everything arriving at the store is treated as hostile, including input from other validators.

Read it before changing anything near it.

These guards are defined once and applied on **every** storage path.
The filesystem store calls them directly; `bridge-db` calls the same functions rather than reimplementing them.
Keep it that way.

| Guard | Function | Prevents |
| --- | --- | --- |
| Id and parameter binding | `canonical_submission_id` | A record whose claimed id does not hash from its own parameters. |
| Parameter immutability | `same_params` | Poisoning an existing record's fields on a later write. |
| Signature recovery | `verify_signature` | A signature that does not recover to its claimed signer. |
| Token binding | `verify_token_binding` | Substituting a more valuable asset. `token` is not covered by the `submissionId`, so it is recomputed against `debridgeId`. |
| Domain separation | `verify_attestation` | Replaying a transfer signature as a cancel or refund. |
| Path traversal | `is_valid_submission_id` | A crafted id escaping the store directory. |

Nine tests, each named after the attack it blocks:
`rejects_id_param_mismatch`, `rejects_param_poisoning_of_existing_record`, `rejects_forged_signature`, `rejects_token_not_matching_debridge_id`, `attestations_are_domain_separated`, `attestation_requires_an_existing_record`, `rejects_garbage_signature`, `happy_path_two_validators_merge_and_dedupe`.

> **Known gap.** `verify_signature` confirms the signature recovers to the claimed signer, but does **not** check that the signer is in the validator set. Anyone who can reach the store can inflate `signature_count` with well-formed signatures from arbitrary keys. This is not exploitable for fund loss, because the on-chain check counts only `isValidator[signer]`, but it makes the off-chain view of "how many validators signed" attacker-controlled. See `report.md` M3.

---

## 6. Transfer lifecycle

### 6.1 Happy path

```
SOURCE CHAIN                          OFF-CHAIN                      DESTINATION CHAIN

user: approve(gate, amount)
user: gate.send(...)
  nonce reserved
  sentBy[id] = msg.sender
  emit Sent(id, ...)      ─────────►  validator (xN)
  safeTransferFrom                      recompute id
                                        id == emitted? ──── no ──► refuse, log
                                        yes: check nonce sequence
                                             check allowlist
                                             sign EIP-191 digest
                                             POST to sig-store
                                                  │
                                                  ▼
                                              keeper polls
                                              sigs >= threshold?
                                              sort ascending
                                                  │
                                                  └──────────►  gate.claim(...)
                                                                  _verifySignatures
                                                                  executed[id] = true
                                                                  safeTransfer(to, amount)
                                                                  emit Claimed
                                                                       │
                                                indexer ◄──────────────┘
                                                  mark_claimed
```

### 6.2 Refund path

A transfer can strand: the destination gate may hold no liquidity for the asset, the corridor may be de-listed after funds were locked, or the destination chain may be down long enough that nobody claims.

The locked funds must be returnable.
But **a refund that merely waits out a timeout is a double-spend**: the transfer's validator signatures still exist, so a keeper can `claim()` on the destination in the same window the source pays the refund, releasing the same value twice.

The fix is to order the two legs and enforce that ordering **on-chain, not by any timing assumption**:

1. **`cancel()` on the destination** burns `executed[submissionId]`.
   From that moment `claim()` reverts with `AlreadyExecuted`.
   The destination can never pay out, permanently and verifiably.
   Moves no funds.
2. **Validators observe the resulting `Cancelled` event** at a confirmed block and only then sign the refund digest.
   This is an ordinary on-chain fact, attested exactly like a `Sent`.
3. **`refund()` on the source** returns the funds to `sentBy[submissionId]`.

If a keeper wins the race and claims first, step 1 reverts and no refund is ever authorised.
There is no interleaving that pays out twice.

`refund()` stands behind three independent guards:

- `sentBy[submissionId]` must be non-zero. This is the only proof this gate really sent this id, and it is also the payout address. For a plain transfer `nativeSender` is not folded into the hash, so a caller could name any address in calldata; **storage is authoritative, calldata is not trusted**.
- A validator threshold over `getRefundId(...)`, whose quorum only forms after `Cancelled` is observed.
- `keccak256(block.chainid, token)` must equal `debridgeId`, so a caller cannot name a different, more valuable asset held by the gate.

Twenty-three tests in `contracts/test/Refund.t.sol` cover this path.

---

## 7. Solana

Two separate things, and they have diverged.

`crates/bridge-solana` is a **host-side reference model** used for hash-equivalence tests and relayer log parsing. It models an asset registry and vault liquidity.

`crates/solana-gate` is the **deployable BPF program**. It is excluded from the workspace and absent from compose.

> **Do not deploy `solana-gate` as written.** It has no PDA or owner validation on the config account outside `process_init`, no asset registry, and no liquidity checks. Its `emit_sent` writes 64 bytes and discards the rest, so the emitted event does not contain what a validator needs, and its format is incompatible with the relayer's own parser. The reference model is the more correct of the two. See `report.md` L7 and L8.

Treat EVM to Solana as unfinished.

---

## 8. Configuration and secrets

Validators and keepers are configured by TOML (`validator/src/config.rs`, `keeper/src/config.rs`).
Examples live in `docker/configs/`.

Two things to know before running this anywhere real.

**`block_confirmation` is your reorg protection.**
It defaults to `0`, is not validated, and the config struct does not use `deny_unknown_fields`, so a typo'd safety key is silently ignored.
Set it explicitly per chain.

**Private keys are currently inline in the config TOMLs.**
The files in `docker/configs/` contain anvil's well-known development keys, which is fine for local runs.
`.dockerignore` now excludes them from the build context, but the pattern is still wrong: `SignerConfig` supports an encrypted keystore and an env var, and a real key should use one of those rather than the file.
See `docs/operations.md` for the key-custody options.

The sig-store takes one scoped bearer token per role (`SIG_STORE_{VALIDATOR,KEEPER,READER,ADMIN}_TOKEN`) and **fails closed** without them; both launchers generate random ones per run into `RUN_DIR/tokens.env`, alongside the random Postgres password (the container is bound to `127.0.0.1`).

**RPC urls are credentials.** The chain registry the GraphQL API serves carries two urls per chain: `rpc_url` (what the services dial; may embed a provider key) and `public_rpc_url` (keyless, what a browser may use). The API serves only the latter — `null` when unset, and the UI falls back to the wallet's provider — and registers gates (EVM and Solana, told apart by address form) and swap pools (`swap_pool`) from the registry file rather than from `--gate` / `--swap` argv, so a keyed url never sits on a command line. The generated compose stacks reference urls as `${RPC_<chain>}` from a gitignored `.env`.

---

## 9. Testing

| Suite | Command | Count |
| --- | --- | --- |
| Solidity | `forge test` (from `contracts/`) | 99 |
| Rust | `cargo test --workspace` | 40 |
| End-to-end | `scripts/testing/*.sh` | 29 scripts |

Solidity breakdown: `Swap` 27, `Refund` 23, `Security` 20, `SwapRouter` 9, `Claim` 8, `SolanaBridge` 6, `Send` 5, `GenFixtures` 1.

Requires Foundry, plus `forge install foundry-rs/forge-std@v1.9.4 OpenZeppelin/openzeppelin-contracts@v5.0.2` (`contracts/lib` is gitignored and vendored, not committed).

If you touch `BridgeHash.sol`, run `forge test` **and** `cargo test --workspace`.
The first regenerates the fixtures, the second checks Rust still agrees.

> **Known gap.** `forge coverage` does not run on this project (stack-too-deep at `Gate.sol:308`), so coverage has never been measured. See `report.md` L12.

---

## 10. Where to look first

Reading in this order will get you oriented fastest.

1. `contracts/src/BridgeHash.sol` (110 lines). The whole system is built on this.
2. `contracts/src/Gate.sol`, specifically `send`, `claim`, and `_verifySignatures`.
3. `crates/bridge-core/src/store.rs`. The trust boundary, and its nine attack-named tests.
4. `crates/validator/src/main.rs`, the `handle_log` recompute-and-compare step.
5. `crates/validator/src/refund.rs`, the `decide` function. The clearest statement of the system's safety rules.
6. `contracts/test/Refund.t.sol`. Twenty-three tests that explain the double-spend problem better than prose can.

For the current list of known defects and their priority, see `report.md` in the repository root.
