import { useCallback, useEffect, useMemo, useState } from "react";
import { Dropdown, type DropdownOption } from "./Dropdown";
import { TxBanner, type TxState } from "./TxBanner";
import { ArrowRight, Glyph, Help } from "./icons";
import { chainViz, formatUnits, formatUnitsRaw, isAddress, isSolanaAccount, parseUnits, shortHex, receiverProblem } from "../data/format";
import { fetchSubmission, fetchSwapPool, fetchSwapQuote } from "../api/client";
import { useDebounced, usePoll } from "../api/hooks";
import {
  U64_MAX,
  encodeAutoParamsTo,
  encodeSwapIntent,
  errMsg,
  extractSent,
  readAllowance,
  readBalance,
  readDecimals,
  readRemoteRouter,
  readRouterGate,
  sendApprove,
  sendBridge,
  sendFinalize,
  sendSwapAndBridge,
  waitReceipt,
  waitReceiptFull,
} from "../wallet/eth";
import type { Chain, SubmissionFilter, SwapPoolInfo } from "../api/types";
import type { WalletState } from "../wallet/useWallet";
import type { SolanaWalletState } from "../wallet/useSolanaWallet";
import { SolanaBridgePanel } from "./SolanaBridgePanel";

const eqAddr = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const SLIPPAGE_OPTS = [10, 50, 100]; // bps: 0.1%, 0.5%, 1%

/** A registry entry with no EVM RPC is a non-EVM chain — today, Solana. */
// The registry tells the VMs apart by address form: an EVM gate is `0x…`, a
// Solana gate is its base58 program id. A row with neither url nor gate (the
// older "listed, not polled" form) is Solana too.
const isNonEvmChain = (c: Chain) => (c.gate ? !c.gate.startsWith("0x") : !c.rpcUrl);

interface Props {
  chains: Chain[];
  wallet: WalletState;
  /** Jump to the Explorer filtered to this corridor after a send. */
  onReview: (filter: SubmissionFilter) => void;
  /** The Solana wallet, for the bridge-out-of-Solana panel. */
  solana: SolanaWalletState;
}

/** What we captured from the source `Sent` log, needed to call `finalize()` later. */
interface PendingSwap {
  submissionId: string;
  debridgeId: string;
  amount: bigint; // stable amount bridged
  nonce: bigint;
  chainIdFrom: number;
  chainIdTo: number;
  remoteRouter: string; // the peer router the stable was sent to (= Gate.receiver)
  finalToken: string;
  finalReceiver: string;
  finalMinOut: bigint;
  routerSrc: string; // nativeSender = this router's own address
}

type Stage = "idle" | "awaiting-execution" | "ready-to-finalize" | "finalized";

// M5: the swap-and-bridge recovery action (the pending transfer + its stage) is
// persisted so a page refresh or a wallet-chain switch doesn't strand an in-flight
// transfer with no way to finalize it. On mount we restore it and then re-derive
// the live stage from the backend (indexed history / sig-store), so the resumed
// state reflects reality, not stale memory.
//
// Keyed by SUBMISSION ID, not one fixed key. Under a single key a second
// swap-and-bridge overwrites the first, and since finalize() needs exactly the
// fields captured from the source `Sent` log — debridgeId, amount, nonce,
// remoteRouter, the swap intent — the overwritten transfer loses its only
// recovery action. The stable arrives on the destination router and just sits
// there: nothing else in the UI can reconstruct those values.
const PENDING_STORE_PREFIX = "bridge.pendingSwap.v2.";
/** The v1 single-key layout this replaces; migrated on first load, then removed. */
const LEGACY_PENDING_KEY = "bridge.pendingSwap.v1";

interface PersistedFlow {
  pending: PendingSwap;
  stage: Stage;
}

// PendingSwap carries bigint fields (amount/nonce/finalMinOut) that JSON can't
// represent — tag+stringify on write, revive on read.
const bigintReplacer = (_k: string, v: unknown) =>
  typeof v === "bigint" ? { __bigint: v.toString() } : v;

const bigintReviver = (_k: string, v: unknown) =>
  v && typeof v === "object" && typeof (v as { __bigint?: string }).__bigint === "string"
    ? BigInt((v as { __bigint: string }).__bigint)
    : v;

function savePendingFlow(flow: PersistedFlow | null) {
  try {
    if (!flow || flow.stage === "idle") return;
    localStorage.setItem(
      PENDING_STORE_PREFIX + flow.pending.submissionId.toLowerCase(),
      JSON.stringify(flow, bigintReplacer)
    );
  } catch {
    /* storage disabled/full — non-fatal, we just lose refresh-resume */
  }
}

/** Drop one finished flow. Only ever removes its own key. */
function clearPendingFlow(submissionId: string) {
  try {
    localStorage.removeItem(PENDING_STORE_PREFIX + submissionId.toLowerCase());
  } catch {
    /* storage disabled — nothing to clear */
  }
}

function parseFlow(raw: string): PersistedFlow | null {
  try {
    const parsed = JSON.parse(raw, bigintReviver) as PersistedFlow;
    if (!parsed?.pending?.submissionId || parsed.stage === "idle") return null;
    return parsed;
  } catch {
    return null;
  }
}

/** Every unfinished flow, so none is silently lost. */
export function loadPendingFlows(): PersistedFlow[] {
  const out: PersistedFlow[] = [];
  try {
    // Migrate a v1 record, if any, into its own key before reading.
    const legacy = localStorage.getItem(LEGACY_PENDING_KEY);
    if (legacy) {
      const flow = parseFlow(legacy);
      if (flow) savePendingFlow(flow);
      localStorage.removeItem(LEGACY_PENDING_KEY);
    }
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key?.startsWith(PENDING_STORE_PREFIX)) continue;
      const flow = parseFlow(localStorage.getItem(key) ?? "");
      if (flow) out.push(flow);
    }
  } catch {
    return out;
  }
  return out;
}

export function BridgeView({ chains, wallet, solana, onReview }: Props) {
  // Sending FROM Solana is a different flow with a different wallet, so it gets
  // its own panel rather than a branch through this one — see SolanaBridgePanel.
  const solanaChain = useMemo(() => chains.find(isNonEvmChain) ?? null, [chains]);
  const [source, setSource] = useState<"evm" | "solana">("evm");
  useEffect(() => {
    if (!solanaChain && source === "solana") setSource("evm");
  }, [solanaChain, source]);

  const fromChainId = wallet.chainId; // sends execute on the connected chain
  const fromReg = useMemo(
    () => chains.find((c) => c.chainId === fromChainId) ?? null,
    [chains, fromChainId]
  );

  const [toChainId, setToChainId] = useState<number | null>(null);
  const toReg = useMemo(() => chains.find((c) => c.chainId === toChainId) ?? null, [chains, toChainId]);

  const [token, setToken] = useState("");
  const [gate, setGate] = useState("");
  const [amount, setAmount] = useState("");
  const [receiver, setReceiver] = useState("");
  const [tx, setTx] = useState<TxState>({ kind: "idle" });
  const [decimals, setDecimals] = useState(18);
  const [balance, setBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);

  // --- cross-chain swap ("swap on arrival") — merged into the same flow -----
  const [crossSwap, setCrossSwap] = useState(false);
  const [router, setRouter] = useState("");
  const [finalToken, setFinalToken] = useState("");
  const [slippageBps, setSlippageBps] = useState(50);
  const [stage, setStage] = useState<Stage>("idle");
  const [pending, setPending] = useState<PendingSwap | null>(null);

  // M5: on mount, resume a persisted in-flight swap-and-bridge so a refresh /
  // device switch doesn't lose the finalize recovery action. The awaiting →
  // ready transition is then re-driven from the backend (see the poll effect),
  // so the restored stage is reconciled with the indexed on-chain reality.
  // How many other unfinished transfers are waiting, so the user is told rather
  // than left to discover that only one of them is on screen.
  const [otherPendingCount, setOtherPendingCount] = useState(0);

  useEffect(() => {
    const flows = loadPendingFlows();
    // Resume the one that still needs an action first; a `finalized` record is
    // only kept so the confirmation survives a refresh.
    const restored = flows.find((f) => f.stage !== "finalized") ?? flows[0];
    if (restored) {
      setPending(restored.pending);
      setStage(restored.stage);
      setCrossSwap(true); // a persisted flow is always a cross-chain swap
      setOtherPendingCount(flows.length - 1);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Persist the recovery action whenever it changes. Writes only this transfer's
  // key, so a concurrent in-flight transfer is never overwritten.
  useEffect(() => {
    if (pending && stage !== "idle") savePendingFlow({ pending, stage });
  }, [pending, stage]);

  // Default destination = first chain that isn't the source. Skipped once a
  // transfer is in flight: the user may switch their wallet to the destination
  // chain specifically to call finalize(), and that must NOT be reinterpreted
  // as "pick a new destination" (which would desync toChainId from the actual
  // in-flight transfer's chainIdTo — see `finalizeChainId` below).
  useEffect(() => {
    if (stage !== "idle") return;
    if (toChainId != null && toChainId !== fromChainId) return;
    const other = chains.find((c) => c.chainId !== fromChainId);
    if (other) setToChainId(other.chainId);
  }, [chains, fromChainId, toChainId, stage]);

  // Once a swapAndBridge is in flight, the finalize step targets the PENDING
  // transfer's actual destination — never the live `toChainId` (which the user
  // may have to leave, by switching their wallet, to submit finalize() there).
  const finalizeChainId = pending?.chainIdTo ?? null;
  const finalizeReg = useMemo(
    () => chains.find((c) => c.chainId === finalizeChainId) ?? null,
    [chains, finalizeChainId]
  );

  // Prefill token/gate/router from the registry for the source chain. When the
  // source chain changes, reset the token to that chain's primary (first listed)
  // asset so the picker and the address field stay in sync; the user can still
  // pick another from the dropdown or type a custom address.
  useEffect(() => {
    const primary = fromReg?.tokens?.[0]?.address ?? fromReg?.token ?? "";
    if (primary) setToken(primary);
    if (fromReg?.gate && !gate) setGate(fromReg.gate);
    if (fromReg?.router && !router) setRouter(fromReg.router);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fromReg?.chainId]);

  // Default receiver = the connected account.
  useEffect(() => {
    if (!receiver && wallet.address) setReceiver(wallet.address);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wallet.address]);

  const tokenOk = isAddress(token);
  const gateOk = isAddress(gate);
  // L-4: validate the receiver against the DESTINATION VM, not just as an EVM
  // address. A Solana destination needs a base58 SPL token account; a wallet
  // pubkey there produces a transfer the gate can never release.
  const receiverIssue = receiverProblem(receiver, toChainId);
  const receiverOk = receiverIssue === null;
  const routerOk = isAddress(router);
  const finalTokenOk = isAddress(finalToken);
  const spender = crossSwap ? router : gate;
  const spenderOk = crossSwap ? routerOk : gateOk;

  // Which token+chain the numbers above were actually read for. `decimals` is
  // the dangerous one: it scales the amount into base units, so reading it for
  // token A and then encoding a transfer of token B is off by 10^(decA-decB).
  // Switching from an 18-decimal token to a 6-decimal one and submitting before
  // the read lands would send a million times the intended amount. `null` means
  // "no trustworthy read yet" and blocks the submit button — never fall back to
  // a stale value, and never to a guessed 18.
  const [readFor, setReadFor] = useState<string | null>(null);
  const readKey = `${fromChainId ?? "?"}:${token.toLowerCase()}:${spender.toLowerCase()}`;
  const onchainStale = readFor !== readKey;

  // On-chain reads (decimals/balance/allowance) against the connected chain.
  const refreshOnchain = useCallback(async () => {
    if (!wallet.address || !tokenOk) {
      setReadFor(null);
      setBalance(null);
      setAllowance(null);
      return;
    }
    // Invalidate first: everything below describes the PREVIOUS token until the
    // awaits resolve, and a submit in that window is the bug.
    setReadFor(null);
    setBalance(null);
    setAllowance(null);
    try {
      const dec = await readDecimals(wallet.request, token).catch(() => 18);
      setDecimals(Number.isFinite(dec) && dec > 0 && dec <= 36 ? dec : 18);
      const [b, a] = await Promise.all([
        readBalance(wallet.request, token, wallet.address),
        spenderOk ? readAllowance(wallet.request, token, wallet.address, spender) : Promise.resolve(0n),
      ]);
      setBalance(b);
      setAllowance(a);
      setReadFor(readKey);
    } catch {
      setBalance(null);
      setAllowance(null);
      setReadFor(null);
    }
  }, [wallet.address, wallet.request, token, spender, tokenOk, spenderOk, readKey]);

  useEffect(() => {
    refreshOnchain();
  }, [refreshOnchain]);

  // Only meaningful once the reads match the selected token (see `onchainStale`).
  const amountBase = tokenOk && !onchainStale ? parseUnits(amount, decimals) : 0n;
  const needsApprove = allowance != null && amountBase > 0n && spenderOk && allowance < amountBase;
  const insufficient = balance != null && amountBase > balance;
  // H-3: a 32-byte (Solana) receiver can only ever claim a u64 amount — the
  // Gate reverts AmountTooWide above 2^64-1, and anything that slipped past it
  // would be locked forever. Same check here, so the button says why.
  const solanaReceiver = receiverOk && !isAddress(receiver) && isSolanaAccount(receiver);
  const amountTooWide = solanaReceiver && amountBase > U64_MAX;
  const busy = tx.kind === "pending";

  // --- cross-chain swap: quote both legs (source swap, destination swap) ----
  const srcPoolQ = usePoll<SwapPoolInfo | null>(
    () => (crossSwap && fromChainId != null ? fetchSwapPool(fromChainId) : Promise.resolve(null)),
    [crossSwap, fromChainId],
    10000
  );
  const dstPoolQ = usePoll<SwapPoolInfo | null>(
    () => (crossSwap && toChainId != null ? fetchSwapPool(toChainId) : Promise.resolve(null)),
    [crossSwap, toChainId],
    10000
  );
  const srcPool = srcPoolQ.data;
  const dstPool = dstPoolQ.data;

  const debouncedAmt = useDebounced(amountBase.toString(), 300);
  const [stableQuote, setStableQuote] = useState<string | null>(null);
  const [finalQuote, setFinalQuote] = useState<string | null>(null);

  // Leg 1: tokenIn -> source stable (skipped, 1:1, if tokenIn already IS the stable).
  useEffect(() => {
    if (!crossSwap || !srcPool || fromChainId == null || !tokenOk || BigInt(debouncedAmt || "0") <= 0n) {
      setStableQuote(null);
      return;
    }
    if (eqAddr(token, srcPool.stable)) {
      setStableQuote(debouncedAmt);
      return;
    }
    let alive = true;
    fetchSwapQuote(fromChainId, token, srcPool.stable, debouncedAmt)
      .then((q) => alive && setStableQuote(q))
      .catch(() => alive && setStableQuote(null));
    return () => {
      alive = false;
    };
  }, [crossSwap, srcPool, fromChainId, token, tokenOk, debouncedAmt]);

  // Leg 2: destination stable -> finalToken (skipped, 1:1, if finalToken IS the dest stable).
  useEffect(() => {
    if (!crossSwap || !dstPool || toChainId == null || !finalTokenOk || !stableQuote || BigInt(stableQuote) <= 0n) {
      setFinalQuote(null);
      return;
    }
    if (eqAddr(finalToken, dstPool.stable)) {
      setFinalQuote(stableQuote);
      return;
    }
    let alive = true;
    fetchSwapQuote(toChainId, dstPool.stable, finalToken, stableQuote)
      .then((q) => alive && setFinalQuote(q))
      .catch(() => alive && setFinalQuote(null));
    return () => {
      alive = false;
    };
  }, [crossSwap, dstPool, toChainId, finalToken, finalTokenOk, stableQuote]);

  const stableQuoteBase = stableQuote ? BigInt(stableQuote) : 0n;
  const minStableOut = (stableQuoteBase * BigInt(10000 - slippageBps)) / 10000n;
  const finalQuoteBase = finalQuote ? BigInt(finalQuote) : 0n;
  const finalMinOut = (finalQuoteBase * BigInt(10000 - slippageBps)) / 10000n;
  const srcStableInfo = srcPool?.tokens.find((t) => t.isStable);
  const finalTokenInfo = dstPool?.tokens.find((t) => eqAddr(t.token, finalToken));
  const destReserve = finalTokenInfo ? BigInt(finalTokenInfo.reserve) : 0n;
  const destExceedsLock = crossSwap && !!finalTokenInfo && finalQuoteBase > destReserve;

  // Corridor check: is the destination router registered on the source router?
  const [remoteRouterHex, setRemoteRouterHex] = useState<string | null>(null);
  useEffect(() => {
    if (!crossSwap || !routerOk || toChainId == null || wallet.chainId !== fromChainId) {
      setRemoteRouterHex(null);
      return;
    }
    let alive = true;
    readRemoteRouter(wallet.request, router, BigInt(toChainId))
      .then((r) => alive && setRemoteRouterHex(r))
      .catch(() => alive && setRemoteRouterHex(null));
    return () => {
      alive = false;
    };
  }, [crossSwap, routerOk, router, toChainId, wallet.request, wallet.chainId, fromChainId]);
  const corridorOk = !!remoteRouterHex && remoteRouterHex !== "0x";

  const doApprove = async () => {
    if (!wallet.address || fromChainId == null) return;
    setTx({ kind: "pending", label: crossSwap ? "Approving router…" : "Approving token…" });
    try {
      const hash = await sendApprove(wallet.request, wallet.address, token, spender, amountBase, fromChainId);
      setTx({ kind: "pending", label: "Confirming approval…", hash });
      await waitReceipt(wallet.request, hash);
      await refreshOnchain();
      setTx({ kind: "idle" });
    } catch (e) {
      setTx({ kind: "error", message: errMsg(e) });
    }
  };

  const doSend = async () => {
    if (!wallet.address || toChainId == null || fromChainId == null) return;
    setTx({ kind: "pending", label: "Locking + emitting…" });
    try {
      const hash = await sendBridge(
        wallet.request,
        wallet.address,
        gate,
        token,
        amountBase,
        toChainId,
        receiver,
        fromChainId,
        "0x"
      );
      setTx({ kind: "pending", label: "Confirming send…", hash });
      const r = await waitReceipt(wallet.request, hash);
      if (!r.success) throw new Error("Send reverted on-chain");
      setTx({ kind: "done", label: "Locked — validators will sign it", hash });
      setAmount("");
      await refreshOnchain();
    } catch (e) {
      setTx({ kind: "error", message: errMsg(e) });
    }
  };

  const doSwapAndBridge = async () => {
    if (!wallet.address || toChainId == null || fromChainId == null || !remoteRouterHex) return;
    setTx({ kind: "pending", label: "Swapping + bridging…" });
    try {
      const hash = await sendSwapAndBridge(
        wallet.request,
        wallet.address,
        router,
        token,
        amountBase,
        minStableOut,
        toChainId,
        finalToken,
        receiver,
        finalMinOut,
        fromChainId
      );
      setTx({ kind: "pending", label: "Confirming…", hash });
      const r = await waitReceiptFull(wallet.request, hash);
      if (!r.success) throw new Error("swapAndBridge reverted on-chain");
      // M5: match the Sent event against the router's IMMUTABLE on-chain gate, not
      // the user-editable Gate field — the router emits through its own gate, so a
      // mistyped/mismatched field must not make us miss (or mis-decode) the event.
      // Fall back to the typed gate only if the read fails.
      const emittingGate = await readRouterGate(wallet.request, router).catch(() => gate);
      const sent = extractSent(r.logs, emittingGate);
      if (!sent) throw new Error("Sent event not found in receipt — can't finalize automatically");
      setPending({
        submissionId: sent.submissionId,
        debridgeId: sent.debridgeId,
        amount: sent.amount,
        nonce: sent.nonce,
        chainIdFrom: fromChainId,
        chainIdTo: toChainId,
        remoteRouter: remoteRouterHex,
        finalToken,
        finalReceiver: receiver,
        finalMinOut,
        routerSrc: router,
      });
      setStage("awaiting-execution");
      setTx({ kind: "done", label: "Swapped & locked — validators will sign it", hash });
      setAmount("");
      await refreshOnchain();
    } catch (e) {
      setTx({ kind: "error", message: errMsg(e) });
    }
  };

  // Poll the backend (same signature-store view Explorer uses) for the underlying
  // bridge leg to reach EXECUTED — i.e. the keeper has claimed it on the destination.
  useEffect(() => {
    if (stage !== "awaiting-execution" || !pending) return;
    let alive = true;
    const check = async () => {
      try {
        const s = await fetchSubmission(pending.submissionId);
        if (alive && s?.status === "EXECUTED") setStage("ready-to-finalize");
      } catch {
        /* backend hiccup — just retry next tick */
      }
    };
    check();
    const id = setInterval(check, 3000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [stage, pending]);

  const doFinalize = async () => {
    if (!wallet.address || !pending || !finalizeReg?.router || finalizeChainId == null) return;
    setTx({ kind: "pending", label: "Finalizing…" });
    try {
      const nativeSenderHex = "0x" + pending.routerSrc.replace(/^0x/i, "").toLowerCase();
      // Reproduce exactly what SwapRouter.swapAndBridge built on-chain: AutoParamsTo
      // with fallbackAddress = finalReceiver (packed) and data = (finalToken, finalReceiver, finalMinOut).
      const fallbackAddressHex = "0x" + pending.finalReceiver.replace(/^0x/i, "").toLowerCase();
      const intent = encodeSwapIntent(pending.finalToken, pending.finalReceiver, pending.finalMinOut);
      const autoParams = encodeAutoParamsTo(0n, 0n, fallbackAddressHex, intent);
      const hash = await sendFinalize(
        wallet.request,
        wallet.address,
        finalizeReg.router,
        pending.debridgeId,
        pending.amount,
        pending.chainIdFrom,
        Number(pending.nonce),
        pending.remoteRouter,
        autoParams,
        nativeSenderHex,
        // finalize() runs on the DESTINATION chain, not `pending.chainIdFrom`.
        finalizeChainId
      );
      setTx({ kind: "pending", label: "Confirming finalize…", hash });
      const r = await waitReceipt(wallet.request, hash);
      if (!r.success) throw new Error("finalize reverted on-chain");
      setStage("finalized");
      setTx({ kind: "done", label: `Finalized — swapped into ${finalToken ? "the destination token" : "target"}`, hash });
    } catch (e) {
      setTx({ kind: "error", message: errMsg(e) });
    }
  };

  const resetFlow = () => {
    if (pending) clearPendingFlow(pending.submissionId);
    // Another unfinished transfer may be waiting behind this one — surface it
    // instead of dropping straight back to a blank form.
    const remaining = loadPendingFlows().find((f) => f.stage !== "finalized");
    if (remaining) {
      setPending(remaining.pending);
      setStage(remaining.stage);
      setOtherPendingCount(Math.max(0, loadPendingFlows().length - 1));
      setTx({ kind: "idle" });
      return;
    }
    setStage("idle");
    setPending(null);
    setOtherPendingCount(0);
    setTx({ kind: "idle" });
  };

  const toOptions: DropdownOption[] = chains
    .filter((c) => c.chainId !== fromChainId)
    .map((c) => {
      const v = chainViz(c.chainId, c.name);
      return { value: String(c.chainId), label: c.name, glyph: <Glyph gradient={v.gradient} size={20} /> };
    });

  const fromViz = chainViz(fromChainId ?? 0, fromReg?.name);
  const fromName = fromReg?.name ?? (fromChainId ? `Chain ${fromChainId}` : "—");
  const toName = toReg?.name ?? (toChainId ? `Chain ${toChainId}` : "—");
  // While a transfer is in flight, "the destination" for display/finalize purposes
  // is pinned to the pending transfer, not the (possibly since-changed) toChainId.
  const finalizeName = finalizeReg?.name ?? (finalizeChainId ? `Chain ${finalizeChainId}` : "—");

  // Primary button
  let button: { label: string; onClick?: () => void; disabled?: boolean };
  if (!wallet.address) button = { label: "Connect Wallet", onClick: () => wallet.connect() };
  else if (stage === "ready-to-finalize") {
    if (!finalizeReg?.router) button = { label: "Destination router not configured", disabled: true };
    else if (wallet.chainId !== finalizeChainId)
      button = { label: `Switch to ${finalizeName}`, onClick: () => finalizeChainId != null && wallet.switchChain(finalizeChainId) };
    else button = { label: `Finalize on ${finalizeName}`, onClick: doFinalize };
  } else if (stage === "awaiting-execution") {
    button = { label: "Waiting for validators + keeper…", disabled: true };
  } else if (stage === "finalized") {
    button = { label: "Start a new transfer", onClick: resetFlow };
  } else if (fromChainId == null) button = { label: "Unknown network", disabled: true };
  else if (!tokenOk) button = { label: "Enter a token address", disabled: true };
  else if (!gateOk) button = { label: "Enter the Gate address", disabled: true };
  else if (crossSwap && !routerOk) button = { label: "Enter the Router address", disabled: true };
  else if (crossSwap && !finalTokenOk) button = { label: "Enter a destination token", disabled: true };
  else if (toChainId == null) button = { label: "Pick a destination", disabled: true };
  else if (!receiverOk) button = { label: receiverIssue ?? "Enter a valid receiver", disabled: true };
  // Until the reads match the selected token, `decimals` may still describe the
  // previous one — refuse to encode an amount with it rather than guess.
  else if (onchainStale) button = { label: "Reading token…", disabled: true };
  else if (amountBase <= 0n) button = { label: "Enter an amount", disabled: true };
  else if (amountTooWide) button = { label: "Amount too large for a Solana receiver (max 2^64-1 base units)", disabled: true };
  else if (insufficient) button = { label: "Insufficient balance", disabled: true };
  else if (crossSwap && !corridorOk) button = { label: "Corridor not configured", disabled: true };
  else if (crossSwap && destExceedsLock) button = { label: "Exceeds destination pool lock", disabled: true };
  else if (needsApprove) button = { label: crossSwap ? "Approve for router" : "Approve token", onClick: doApprove };
  else button = { label: crossSwap ? "Swap & Bridge" : "Bridge", onClick: crossSwap ? doSwapAndBridge : doSend };
  if (busy) button = { label: tx.label, disabled: true };

  const flowBusy = stage !== "idle";

  return (
    <section className="card">
      <div className="card__head">
        <div>
          <h2 className="card__title">Bridge</h2>
          <p className="card__subtitle">
            {source === "solana"
              ? "Lock SPL on Solana; a threshold of relayers signs the claim."
              : crossSwap
                ? "Swap locally, bridge the stable, swap again on arrival — one flow."
                : "Lock on the source chain; a threshold of validators signs the claim."}
          </p>
        </div>
      </div>

      {/* Only offered when the mesh actually has a non-EVM chain, so an
          EVM-only deployment sees the form it always saw. */}
      {solanaChain && (
        <div className="source-switch" role="tablist" aria-label="Source chain">
          <button
            role="tab"
            aria-selected={source === "evm"}
            className={`source-switch__tab${source === "evm" ? " source-switch__tab--on" : ""}`}
            onClick={() => setSource("evm")}
          >
            From EVM
          </button>
          <button
            role="tab"
            aria-selected={source === "solana"}
            className={`source-switch__tab${source === "solana" ? " source-switch__tab--on" : ""}`}
            onClick={() => setSource("solana")}
          >
            From {solanaChain.name}
          </button>
        </div>
      )}

      {source === "solana" && solanaChain ? (
        <SolanaBridgePanel solanaChain={solanaChain} chains={chains} wallet={solana} />
      ) : (
        <>

      <div className="summary__row" style={{ marginBottom: 20 }}>
        <dt>Mode</dt>
        <dd className="slippage">
          <button
            type="button"
            className={`slippage__opt${!crossSwap ? " slippage__opt--on" : ""}`}
            disabled={flowBusy}
            onClick={() => setCrossSwap(false)}
          >
            Direct
          </button>
          <button
            type="button"
            className={`slippage__opt${crossSwap ? " slippage__opt--on" : ""}`}
            disabled={flowBusy}
            onClick={() => setCrossSwap(true)}
          >
            Swap on arrival
          </button>
        </dd>
      </div>

      {/* route: from (wallet) -> to (picker) */}
      <div className="bridge-route">
        <div className="bridge-route__node">
          <span className="bridge-route__label">From</span>
          <span className="chaincell">
            <Glyph gradient={fromViz.gradient} size={22} /> {fromName}
          </span>
          <span className="bridge-route__hint">connected wallet</span>
        </div>
        <ArrowRight size={18} className="bridge-route__arrow" />
        <div className="bridge-route__node">
          <span className="bridge-route__label">To</span>
          <Dropdown
            variant="chain"
            value={toChainId != null ? String(toChainId) : ""}
            options={toOptions}
            onChange={(v) => setToChainId(Number(v))}
          />
        </div>
      </div>

      <div className="fields">
        <label className="field">
          <span className="field__label">Token (ERC-20 on {fromName})</span>
          {fromReg && fromReg.tokens.length > 0 && (
            <div className="token-picker">
              <Dropdown
                variant="token"
                placeholder="Custom address"
                value={fromReg.tokens.some((t) => eqAddr(t.address, token)) ? token.toLowerCase() : ""}
                options={fromReg.tokens.map((t) => ({
                  value: t.address.toLowerCase(),
                  label: t.symbol,
                  glyph: <span className="token-glyph">{t.symbol.slice(0, 3).toUpperCase()}</span>,
                  sub: shortHex(t.address, 6, 4),
                }))}
                onChange={(v) => setToken(v)}
              />
            </div>
          )}
          <input
            className={`field__input mono${token && !tokenOk ? " field__input--bad" : ""}`}
            placeholder="0x…"
            value={token}
            onChange={(e) => setToken(e.target.value.trim())}
          />
        </label>

        <label className="field">
          <span className="field__label">Gate contract</span>
          <input
            className={`field__input mono${gate && !gateOk ? " field__input--bad" : ""}`}
            placeholder="0x…"
            value={gate}
            onChange={(e) => setGate(e.target.value.trim())}
          />
        </label>

        {crossSwap && (
          <>
            <label className="field">
              <span className="field__label">Router contract (on {fromName})</span>
              <input
                className={`field__input mono${router && !routerOk ? " field__input--bad" : ""}`}
                placeholder="0x…"
                value={router}
                onChange={(e) => setRouter(e.target.value.trim())}
              />
            </label>

            <label className="field">
              <span className="field__label">Final token (ERC-20 on {toName})</span>
              <input
                className={`field__input mono${finalToken && !finalTokenOk ? " field__input--bad" : ""}`}
                placeholder="0x…"
                value={finalToken}
                onChange={(e) => setFinalToken(e.target.value.trim())}
              />
            </label>
          </>
        )}

        <div className="field">
          <span className="field__label">
            Amount
            {balance != null && (
              <button
                type="button"
                className="field__max"
                onClick={() => setAmount(formatUnitsRaw(balance, decimals))}
              >
                Max {formatUnits(balance, decimals)}
              </button>
            )}
          </span>
          <input
            className="field__input"
            inputMode="decimal"
            placeholder="0.0"
            value={amount}
            onChange={(e) => {
              const v = e.target.value;
              if (v === "" || /^\d*\.?\d*$/.test(v)) setAmount(v);
            }}
          />
        </div>

        <label className="field">
          <span className="field__label">
            {crossSwap ? `Final receiver (on ${toName}, after swap)` : "Receiver (destination address)"}
          </span>
          <input
            className={`field__input mono${receiver && !receiverOk ? " field__input--bad" : ""}`}
            placeholder="0x…"
            value={receiver}
            onChange={(e) => setReceiver(e.target.value.trim())}
          />
        </label>
      </div>

      <dl className="summary">
        <div className="summary__row">
          <dt>
            {crossSwap ? "Swapped to stable, then locked" : "Locked on send"} <Help size={14} />
          </dt>
          <dd>{amountBase > 0n ? formatUnits(amountBase, decimals) : "—"}</dd>
        </div>

        {crossSwap && (
          <>
            <div className="summary__row">
              <dt>
                Bridges as <Help size={14} />
              </dt>
              <dd>
                {srcStableInfo && stableQuoteBase > 0n
                  ? `${formatUnits(stableQuoteBase, srcStableInfo.decimals)} ${srcStableInfo.symbol || "stable"}`
                  : "—"}
              </dd>
            </div>
            <div className="summary__row">
              <dt>
                Arrives as (min., after slippage) <Help size={14} />
              </dt>
              <dd>
                {finalTokenInfo && finalQuoteBase > 0n
                  ? `${formatUnits(finalMinOut, finalTokenInfo.decimals)} ${finalTokenInfo.symbol || "token"}`
                  : "—"}
              </dd>
            </div>
            <div className="summary__row">
              <dt>Max slippage (both legs)</dt>
              <dd className="slippage">
                {SLIPPAGE_OPTS.map((bps) => (
                  <button
                    key={bps}
                    type="button"
                    className={`slippage__opt${slippageBps === bps ? " slippage__opt--on" : ""}`}
                    onClick={() => setSlippageBps(bps)}
                  >
                    {bps / 100}%
                  </button>
                ))}
              </dd>
            </div>
          </>
        )}

        <div className="summary__row">
          <dt>
            Signature threshold <Help size={14} />
          </dt>
          <dd>validator quorum</dd>
        </div>
      </dl>

      {/* These only describe a NEW transfer being configured — once one is in
          flight (stage !== "idle"), the wallet may be on a different chain to
          complete finalize(), which would make these checks re-evaluate against
          a stale/nonsensical pairing (e.g. "corridor from the destination back
          to itself"). Hide them until the flow returns to idle. */}
      {stage === "idle" && crossSwap && destExceedsLock && finalTokenInfo && (
        <div className="notice notice--warn">
          Output ({formatUnits(finalQuoteBase, finalTokenInfo.decimals)} {finalTokenInfo.symbol}) exceeds the
          destination pool's locked reserve. Reduce the amount.
        </div>
      )}
      {stage === "idle" && crossSwap && routerOk && toChainId != null && !corridorOk && wallet.chainId === fromChainId && (
        <div className="notice notice--warn">
          This router has no corridor registered for {toName} yet (owner must call{" "}
          <code>setRemoteRouter</code>).
        </div>
      )}

      {stage === "awaiting-execution" && (
        <div className="notice">
          Locked and signed by validators — waiting for the keeper to claim it on {finalizeName}. This updates
          automatically.
        </div>
      )}
      {stage === "ready-to-finalize" && (
        <div className="notice notice--warn">
          Claimed on {finalizeName} — click below to swap the bridged stable into the final token. This step is
          permissionless; anyone can complete it.
        </div>
      )}
      {otherPendingCount > 0 && (
        <div className="notice" data-testid="other-pending">
          {otherPendingCount} other unfinished transfer{otherPendingCount > 1 ? "s" : ""} saved on this device — you'll
          be taken to {otherPendingCount > 1 ? "them" : "it"} after finishing this one.
        </div>
      )}

      <TxBanner tx={tx} />

      {tx.kind === "done" &&
        stage !== "finalized" &&
        (pending ? pending.chainIdFrom : fromChainId) != null &&
        (pending ? pending.chainIdTo : toChainId) != null && (
          <button
            type="button"
            className="ghost-btn ghost-btn--full"
            onClick={() =>
              onReview({
                chainIdFrom: pending ? pending.chainIdFrom : fromChainId!,
                chainIdTo: pending ? pending.chainIdTo : toChainId!,
              })
            }
          >
            Track this transfer in the Explorer <ArrowRight size={14} />
          </button>
        )}

      <button type="button" className="review-btn" disabled={button.disabled || !button.onClick} onClick={button.onClick}>
        {button.label}
      </button>
        </>
      )}
    </section>
  );
}
