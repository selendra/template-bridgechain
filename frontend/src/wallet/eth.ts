// Minimal, dependency-free EVM calldata encoding + read/write helpers for the
// exact calls this app makes. We deliberately avoid ethers/viem: every function
// we touch uses only static `address`/`uint256` args, plus dynamic `bytes` for
// Gate.send — small enough to hand-encode reliably. Selectors were taken from
// `cast sig` and are asserted by the contract ABIs.

import { b58decode } from "./solana";

/** An EIP-1193 `request` function (from the connected wallet). */
export type Eip1193Request = (args: { method: string; params?: unknown[] }) => Promise<unknown>;

/** The widest amount a 32-byte (Solana) receiver can carry: `ClaimArgs.amount`
 *  and `CancelArgs.amount` on the Solana gate are `u64`, so `Gate.send` reverts
 *  `AmountTooWide` above this (H-3). Anything wider would be neither claimable
 *  nor cancellable — locked forever — which is why it is refused here too. */
export const U64_MAX = (1n << 64n) - 1n;

const SEL = {
  approve: "095ea7b3", // approve(address,uint256)
  allowance: "dd62ed3e", // allowance(address,address)
  balanceOf: "70a08231", // balanceOf(address)
  decimals: "313ce567", // decimals()
  swap: "d5bcb9b5", // swap(address,address,uint256,uint256,address)
  send: "565443e9", // send(address,uint256,uint256,bytes,bytes)
  swapAndBridge: "07c1462d", // swapAndBridge(address,uint256,uint256,uint256,address,address,uint256)
  finalize: "c2c1fffb", // finalize(bytes32,uint256,uint256,uint256,bytes,bytes,bytes)
  remoteRouter: "a6b18e64", // remoteRouter(uint256)
  gate: "7a0ebc88", // gate() — SwapRouter's immutable Gate
} as const;

function strip0x(h: string): string {
  return h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h;
}

function word(hex: string): string {
  return hex.padStart(64, "0");
}

function encAddress(addr: string): string {
  const a = strip0x(addr).toLowerCase();
  if (a.length !== 40 || /[^0-9a-f]/.test(a)) throw new Error(`bad address: ${addr}`);
  return word(a);
}

function encUint(v: bigint): string {
  if (v < 0n) throw new Error("negative uint");
  return word(v.toString(16));
}

function encBytes32(hex: string): string {
  const h = strip0x(hex).toLowerCase();
  if (h.length !== 64 || /[^0-9a-f]/.test(h)) throw new Error(`bad bytes32: ${hex}`);
  return h;
}

/** A dynamic `bytes` tail: length word + right-padded data. */
function encBytesTail(hexData: string): string {
  const data = strip0x(hexData).toLowerCase();
  if (data.length % 2 !== 0 || /[^0-9a-f]/.test(data)) throw new Error(`bad bytes: ${hexData}`);
  const padded = data.length % 64 === 0 ? data : data + "0".repeat(64 - (data.length % 64));
  return encUint(BigInt(data.length / 2)) + padded;
}

function hexToBigInt(h: string): bigint {
  if (!h || h === "0x") return 0n;
  return BigInt(h);
}

/** A bridge receiver as the `bytes` the Gate expects: a `0x` hex string is
 *  passed through (20 bytes for an EVM destination, 32 for Solana), and a
 *  base58 Solana account key is decoded to exactly 32 bytes. The shape check is
 *  strict on purpose — a key that decodes to 31 or 33 bytes is a typo, not a
 *  different address, and the Gate would accept and lock funds against it. */
export function encodeReceiver(receiver: string): string {
  const v = receiver.trim();
  if (v.startsWith("0x") || v.startsWith("0X")) return v;
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v)) throw new Error(`bad receiver: ${receiver}`);
  const bytes = b58decode(v);
  if (bytes.length !== 32) throw new Error(`bad Solana receiver: decodes to ${bytes.length} bytes, need 32`);
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- calldata builders ---------------------------------------------------

export function encodeApprove(spender: string, amount: bigint): string {
  return "0x" + SEL.approve + encAddress(spender) + encUint(amount);
}

export function encodeSwap(
  tokenIn: string,
  tokenOut: string,
  amountIn: bigint,
  minAmountOut: bigint,
  to: string
): string {
  return (
    "0x" +
    SEL.swap +
    encAddress(tokenIn) +
    encAddress(tokenOut) +
    encUint(amountIn) +
    encUint(minAmountOut) +
    encAddress(to)
  );
}

export function encodeSend(
  token: string,
  amount: bigint,
  chainIdTo: bigint,
  receiver: string,
  autoParamsHex: string
): string {
  // `receiver` is 0x-hex or a base58 Solana key (see encodeReceiver).
  const receiverHex = encodeReceiver(receiver);
  // Mirror of Gate.send's H-3 check: a 32-byte receiver is a Solana account,
  // and the Solana gate's amount is u64.
  if (strip0x(receiverHex).length === 64 && amount > U64_MAX) {
    throw new Error(`amount ${amount} exceeds 2^64-1, the widest a Solana receiver can claim (AmountTooWide)`);
  }
  // head: token, amount, chainIdTo, off(receiver), off(autoParams) => 5 words.
  const recvTail = encBytesTail(receiverHex);
  const autoTail = encBytesTail(autoParamsHex || "0x");
  const offReceiver = BigInt(5 * 32);
  const offAuto = offReceiver + BigInt(recvTail.length / 2);
  return (
    "0x" +
    SEL.send +
    encAddress(token) +
    encUint(amount) +
    encUint(chainIdTo) +
    encUint(offReceiver) +
    encUint(offAuto) +
    recvTail +
    autoTail
  );
}

export function encodeSwapAndBridge(
  tokenIn: string,
  amountIn: bigint,
  minStableOut: bigint,
  chainIdTo: bigint,
  finalToken: string,
  finalReceiver: string,
  finalMinOut: bigint
): string {
  // all 7 args are static (address/uint256) — no offsets needed.
  return (
    "0x" +
    SEL.swapAndBridge +
    encAddress(tokenIn) +
    encUint(amountIn) +
    encUint(minStableOut) +
    encUint(chainIdTo) +
    encAddress(finalToken) +
    encAddress(finalReceiver) +
    encUint(finalMinOut)
  );
}

/**
 * `abi.encode(Gate.AutoParamsTo)` — reproduces exactly what `SwapRouter.swapAndBridge`
 * builds on-chain (see SwapRouter.sol), so the frontend can reconstruct the same
 * `autoParams` bytes for a later `finalize()` call without reading them back from
 * a log. `data` is itself `abi.encode(finalToken, finalReceiver, finalMinOut)` —
 * three static words, encoded by the caller (see `encodeSwapIntent` below).
 */
export function encodeAutoParamsTo(
  executionFee: bigint,
  flags: bigint,
  fallbackAddressHex: string,
  dataHex: string
): string {
  // head: executionFee, flags, off(fallbackAddress), off(data) => 4 words.
  const fbTail = encBytesTail(fallbackAddressHex);
  const dataTail = encBytesTail(dataHex || "0x");
  const offFallback = BigInt(4 * 32);
  const offData = offFallback + BigInt(fbTail.length / 2);
  return (
    "0x" +
    encUint(executionFee) +
    encUint(flags) +
    encUint(offFallback) +
    encUint(offData) +
    fbTail +
    dataTail
  );
}

/** `abi.encode(finalToken, finalReceiver, finalMinOut)` — the swap-intent tail
 *  of `AutoParamsTo.data`. All three fields are static, so no offsets needed. */
export function encodeSwapIntent(finalToken: string, finalReceiver: string, finalMinOut: bigint): string {
  return "0x" + encAddress(finalToken) + encAddress(finalReceiver) + encUint(finalMinOut);
}

export function encodeFinalize(
  debridgeId: string,
  amount: bigint,
  chainIdFrom: bigint,
  nonce: bigint,
  receiverHex: string,
  autoParamsHex: string,
  nativeSenderHex: string
): string {
  // head: debridgeId, amount, chainIdFrom, nonce, off(receiver), off(autoParams), off(nativeSender) => 7 words.
  const recvTail = encBytesTail(receiverHex);
  const autoTail = encBytesTail(autoParamsHex);
  const nsTail = encBytesTail(nativeSenderHex);
  const offReceiver = BigInt(7 * 32);
  const offAuto = offReceiver + BigInt(recvTail.length / 2);
  const offNs = offAuto + BigInt(autoTail.length / 2);
  return (
    "0x" +
    SEL.finalize +
    encBytes32(debridgeId) +
    encUint(amount) +
    encUint(chainIdFrom) +
    encUint(nonce) +
    encUint(offReceiver) +
    encUint(offAuto) +
    encUint(offNs) +
    recvTail +
    autoTail +
    nsTail
  );
}

/** An `Eip1193Request` backed by a plain JSON-RPC endpoint, for read-only calls
 *  (e.g. `readDecimals`) against a chain the user's wallet isn't connected to —
 *  the registry's `rpcUrl`, not `window.ethereum`, is the source of truth. */
export function rpcRequest(url: string): Eip1193Request {
  let id = 0;
  return async ({ method, params }) => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params: params ?? [] }),
    });
    const json = await res.json();
    if (json.error) throw new Error(json.error.message ?? "RPC error");
    return json.result;
  };
}

// --- reads (eth_call) ----------------------------------------------------

async function ethCall(req: Eip1193Request, to: string, data: string): Promise<string> {
  return (await req({ method: "eth_call", params: [{ to, data }, "latest"] })) as string;
}

export async function readBalance(req: Eip1193Request, token: string, owner: string): Promise<bigint> {
  return hexToBigInt(await ethCall(req, token, "0x" + SEL.balanceOf + encAddress(owner)));
}

export async function readAllowance(
  req: Eip1193Request,
  token: string,
  owner: string,
  spender: string
): Promise<bigint> {
  return hexToBigInt(await ethCall(req, token, "0x" + SEL.allowance + encAddress(owner) + encAddress(spender)));
}

export async function readDecimals(req: Eip1193Request, token: string): Promise<number> {
  return Number(hexToBigInt(await ethCall(req, token, "0x" + SEL.decimals)));
}

/** Decode a single dynamic `bytes` return value: [offset][length][data...]. */
function decodeBytesReturn(hex: string): string {
  const h = strip0x(hex);
  if (h.length < 128) return "0x";
  const len = Number(hexToBigInt("0x" + h.slice(64, 128)));
  return "0x" + h.slice(128, 128 + len * 2);
}

/** The peer router registered for `chainIdTo` (empty "0x" if the corridor isn't wired). */
export async function readRemoteRouter(req: Eip1193Request, router: string, chainIdTo: bigint): Promise<string> {
  return decodeBytesReturn(await ethCall(req, router, "0x" + SEL.remoteRouter + encUint(chainIdTo)));
}

/**
 * The SwapRouter's immutable `gate()` — the authoritative Gate the router locks
 * into (M5). The `swapAndBridge` Sent event is emitted by THIS gate, so the log
 * parser must match against it, not the user-editable Gate address field (which
 * a user could mistype or point elsewhere, making the parser miss the event or
 * mis-decode a lookalike). Returns a 20-byte `0x…` address.
 */
export async function readRouterGate(req: Eip1193Request, router: string): Promise<string> {
  const raw = await ethCall(req, router, "0x" + SEL.gate);
  const h = strip0x(raw);
  if (h.length < 64) throw new Error("router gate() returned no address");
  // Address is the low 20 bytes of the returned word.
  return "0x" + h.slice(24, 64);
}

// --- writes (eth_sendTransaction) ---------------------------------------

/** Thrown when the wallet is on a different chain than the one the UI built the
 *  transaction for. Distinct from a generic error so callers can say so plainly. */
export class WrongChainError extends Error {
  constructor(readonly expected: number, readonly actual: number) {
    super(`Wallet is on chain ${actual}, but this transaction is for chain ${expected}. Switch networks and try again.`);
    this.name = "WrongChainError";
  }
}

/**
 * Every write is bound to the chain the UI encoded it for. Two independent guards:
 *
 *  1. **Re-read `eth_chainId` immediately before signing.** The React `chainId`
 *     that gated the button is a snapshot delivered by a `chainChanged` event; it
 *     can lag the wallet, and the user can switch networks while the amount is
 *     being typed or a quote is in flight. Contract addresses are NOT chain-scoped
 *     by the wallet — the same address on another chain is a different contract
 *     (or nothing), so an `approve`/`send` landing on the wrong chain can approve
 *     an unknown spender or lock funds in a contract that will never emit `Sent`.
 *
 *  2. **Send `chainId` in the transaction itself**, so the wallet performs the
 *     same check independently and rejects a mismatch even if the RPC read above
 *     was answered by a stale provider.
 */
async function sendTx(
  req: Eip1193Request,
  from: string,
  to: string,
  data: string,
  chainId: number
): Promise<string> {
  const live = Number(await req({ method: "eth_chainId" }));
  if (!Number.isFinite(live) || live !== chainId) throw new WrongChainError(chainId, live);
  const hexChainId = "0x" + chainId.toString(16);
  return (await req({
    method: "eth_sendTransaction",
    params: [{ from, to, data, chainId: hexChainId }],
  })) as string;
}

export function sendApprove(
  req: Eip1193Request,
  from: string,
  token: string,
  spender: string,
  amount: bigint,
  chainId: number
): Promise<string> {
  return sendTx(req, from, token, encodeApprove(spender, amount), chainId);
}

export function sendSwap(
  req: Eip1193Request,
  from: string,
  pool: string,
  tokenIn: string,
  tokenOut: string,
  amountIn: bigint,
  minAmountOut: bigint,
  to: string,
  chainId: number
): Promise<string> {
  return sendTx(req, from, pool, encodeSwap(tokenIn, tokenOut, amountIn, minAmountOut, to), chainId);
}

export function sendBridge(
  req: Eip1193Request,
  from: string,
  gate: string,
  token: string,
  amount: bigint,
  chainIdTo: number,
  receiver: string,
  chainIdFrom: number,
  autoParamsHex = "0x"
): Promise<string> {
  return sendTx(
    req,
    from,
    gate,
    encodeSend(token, amount, BigInt(chainIdTo), receiver, autoParamsHex),
    chainIdFrom
  );
}

export function sendSwapAndBridge(
  req: Eip1193Request,
  from: string,
  router: string,
  tokenIn: string,
  amountIn: bigint,
  minStableOut: bigint,
  chainIdTo: number,
  finalToken: string,
  finalReceiver: string,
  finalMinOut: bigint,
  chainIdFrom: number
): Promise<string> {
  return sendTx(
    req,
    from,
    router,
    encodeSwapAndBridge(tokenIn, amountIn, minStableOut, BigInt(chainIdTo), finalToken, finalReceiver, finalMinOut),
    chainIdFrom
  );
}

export function sendFinalize(
  req: Eip1193Request,
  from: string,
  router: string,
  debridgeId: string,
  amount: bigint,
  chainIdFrom: number,
  nonce: number,
  receiverHex: string,
  autoParamsHex: string,
  nativeSenderHex: string,
  /** The chain `router` lives on — the DESTINATION of the transfer, which is not
   *  `chainIdFrom` (that is a hashed field, the transfer's origin). */
  executeOnChainId: number
): Promise<string> {
  return sendTx(
    req,
    from,
    router,
    encodeFinalize(debridgeId, amount, BigInt(chainIdFrom), BigInt(nonce), receiverHex, autoParamsHex, nativeSenderHex),
    executeOnChainId
  );
}

// --- confirmation --------------------------------------------------------

type RawLog = { address: string; topics: string[]; data: string };

/** Poll for a receipt; resolves once mined (with its logs), throws on timeout. */
export async function waitReceiptFull(
  req: Eip1193Request,
  hash: string,
  timeoutMs = 90_000
): Promise<{ success: boolean; logs: RawLog[] }> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const r = (await req({ method: "eth_getTransactionReceipt", params: [hash] })) as {
      blockNumber?: string;
      status?: string;
      logs?: RawLog[];
    } | null;
    if (r && r.blockNumber) return { success: r.status === "0x1", logs: r.logs ?? [] };
    await new Promise((res) => setTimeout(res, 1200));
  }
  throw new Error("Timed out waiting for confirmation");
}

/** Poll for a receipt; resolves { success } once mined, throws on timeout. */
export async function waitReceipt(req: Eip1193Request, hash: string, timeoutMs = 90_000): Promise<{ success: boolean }> {
  const { success } = await waitReceiptFull(req, hash, timeoutMs);
  return { success };
}

/**
 * topic0 of the Gate's `Sent` event:
 *   keccak256("Sent(bytes32,bytes32,uint256,uint256,uint256,bytes,uint256,bytes,bytes,address)")
 * Hardcoded because the frontend carries no keccak implementation. If the `Sent`
 * signature ever changes, recompute with:
 *   cast keccak "Sent(bytes32,bytes32,uint256,uint256,uint256,bytes,uint256,bytes,bytes,address)"
 */
const SENT_TOPIC0 = "0x8c7ee7a778ddf9672e509e70cf61fd826a6275ae6dd14c5e474b13898a1f2bbb";

/**
 * Pull `{submissionId, debridgeId, amount, nonce}` out of the `Sent` event the
 * Gate emits during `swapAndBridge` (or a plain `send`). Match BOTH the emitting
 * address AND `topics[0]` — matching the address alone would trust the first log
 * from that address and then read fixed word offsets, so any other event the Gate
 * emits (now or later) could be mis-decoded as a `Sent`. `submissionId`/
 * `debridgeId` are indexed (topics[1]/[2]); `amount`/`nonce` are static fields at
 * fixed word offsets in the non-indexed data (word0 and word4 — see `Sent`'s
 * field order in Gate.sol).
 */
export function extractSent(
  logs: RawLog[],
  gate: string
): { submissionId: string; debridgeId: string; amount: bigint; nonce: bigint } | null {
  const g = gate.toLowerCase();
  const log = logs.find(
    (l) => l.address?.toLowerCase() === g && l.topics[0]?.toLowerCase() === SENT_TOPIC0
  );
  if (!log || log.topics.length < 3) return null;
  const data = strip0x(log.data);
  const wordAt = (i: number) => data.slice(i * 64, i * 64 + 64);
  return {
    submissionId: log.topics[1],
    debridgeId: log.topics[2],
    amount: hexToBigInt("0x" + wordAt(0)),
    nonce: hexToBigInt("0x" + wordAt(4)),
  };
}

/** Normalize a wallet/RPC error into a short human message. */
export function errMsg(e: unknown): string {
  const code = (e as { code?: number })?.code;
  const msg = e instanceof Error ? e.message : String(e);
  if (code === 4001 || /reject|denied/i.test(msg)) return "Rejected in wallet";
  // trim revert noise
  const m = msg.match(/reverted[^:]*:?\s*(.*)/i);
  return (m?.[1] || msg).slice(0, 160);
}
