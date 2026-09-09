import { test, expect } from "@playwright/test";
import {
  WrongChainError,
  encodeApprove,
  encodeAutoParamsTo,
  encodeFinalize,
  encodeSend,
  encodeSwap,
  encodeSwapAndBridge,
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
  sendSwap,
  sendSwapAndBridge,
  waitReceipt,
  waitReceiptFull,
  rpcRequest,
  type Eip1193Request,
} from "../../src/wallet/eth";

/**
 * `src/wallet/eth.ts` — the hand-rolled ABI codec.
 *
 * This file has no ethers/viem to fall back on, so every selector, offset and
 * pad is asserted here. A wrong dynamic offset does not throw: it produces
 * well-formed calldata that transfers a different amount to a different address,
 * which is exactly the failure that never shows up in a UI test.
 */

const A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C = "0xcccccccccccccccccccccccccccccccccccccccc";
const FROM = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

/** Split calldata into the selector and its 32-byte words. */
function decode(calldata: string) {
  const h = calldata.replace(/^0x/, "");
  const selector = h.slice(0, 8);
  const words: string[] = [];
  for (let i = 8; i < h.length; i += 64) words.push(h.slice(i, i + 64));
  return { selector, words, byteLength: h.length / 2 };
}

const word = (v: bigint | number) => BigInt(v).toString(16).padStart(64, "0");
const addrWord = (a: string) => a.replace(/^0x/, "").toLowerCase().padStart(64, "0");

// --- static encoders ------------------------------------------------------

test.describe("encodeApprove", () => {
  test("is approve(address,uint256) with a padded spender", () => {
    const { selector, words, byteLength } = decode(encodeApprove(B, 12345n));
    expect(selector).toBe("095ea7b3"); // cast sig "approve(address,uint256)"
    expect(words).toEqual([addrWord(B), word(12345n)]);
    expect(byteLength).toBe(4 + 64);
  });

  test("encodes an unlimited approval without overflow", () => {
    const max = 2n ** 256n - 1n;
    expect(decode(encodeApprove(B, max)).words[1]).toBe("f".repeat(64));
  });

  test("rejects a malformed spender rather than padding garbage", () => {
    expect(() => encodeApprove("0x123", 1n)).toThrow(/bad address/);
    expect(() => encodeApprove("not-an-address", 1n)).toThrow(/bad address/);
  });

  test("rejects a negative amount", () => {
    expect(() => encodeApprove(B, -1n)).toThrow(/negative uint/);
  });
});

test.describe("encodeSwap", () => {
  test("is swap(address,address,uint256,uint256,address) in argument order", () => {
    const { selector, words } = decode(encodeSwap(A, B, 1n, 2n, C));
    expect(selector).toBe("d5bcb9b5");
    expect(words).toEqual([addrWord(A), addrWord(B), word(1n), word(2n), addrWord(C)]);
  });
});

test.describe("encodeSwapAndBridge", () => {
  test("packs all seven static args with no offsets", () => {
    const { selector, words } = decode(encodeSwapAndBridge(A, 100n, 90n, 1338n, B, C, 80n));
    expect(selector).toBe("07c1462d");
    expect(words).toEqual([
      addrWord(A),
      word(100n),
      word(90n),
      word(1338n),
      addrWord(B),
      addrWord(C),
      word(80n),
    ]);
  });
});

test.describe("encodeSwapIntent", () => {
  test("is the three-word tail AutoParamsTo.data carries", () => {
    const { words } = decode("0x00000000" + encodeSwapIntent(A, B, 7n).replace(/^0x/, ""));
    expect(words).toEqual([addrWord(A), addrWord(B), word(7n)]);
  });
});

// --- dynamic encoders: the offsets are the risk ---------------------------

test.describe("encodeSend", () => {
  test("head offsets point at the right tails", () => {
    const receiver = "0x" + "ee".repeat(20);
    const { selector, words } = decode(encodeSend(A, 500n, 1338n, receiver, "0x"));

    expect(selector).toBe("565443e9");
    expect(words[0]).toBe(addrWord(A));
    expect(words[1]).toBe(word(500n));
    expect(words[2]).toBe(word(1338n));

    // 5 head words => receiver tail begins at byte 160.
    const offReceiver = Number(BigInt("0x" + words[3]));
    const offAuto = Number(BigInt("0x" + words[4]));
    expect(offReceiver).toBe(160);

    // Follow the receiver offset: length word, then the data, right-padded.
    const receiverWordIndex = offReceiver / 32;
    expect(words[receiverWordIndex]).toBe(word(20n));
    expect(words[receiverWordIndex + 1].slice(0, 40)).toBe(receiver.slice(2));

    // The auto-params offset must land immediately after the receiver's tail
    // (length word + one padded data word) — 160 + 64.
    expect(offAuto).toBe(224);
    expect(words[offAuto / 32]).toBe(word(0n)); // empty bytes
  });

  test("a 32-byte Solana receiver shifts the auto-params offset accordingly", () => {
    const receiver = "0x" + "11".repeat(32);
    const { words } = decode(encodeSend(A, 1n, 7565164n, receiver, "0x"));
    const offReceiver = Number(BigInt("0x" + words[3]));
    const offAuto = Number(BigInt("0x" + words[4]));
    expect(offReceiver).toBe(160);
    expect(words[offReceiver / 32]).toBe(word(32n));
    expect(words[offReceiver / 32 + 1]).toBe("11".repeat(32));
    expect(offAuto).toBe(offReceiver + 64);
  });

  test("a 33-byte payload occupies two padded words, not one", () => {
    const data = "0x" + "ab".repeat(33);
    const { words } = decode(encodeSend(A, 1n, 1338n, data, "0x"));
    const off = Number(BigInt("0x" + words[3]));
    expect(words[off / 32]).toBe(word(33n));
    // 33 bytes => two words, the second right-padded with zeros.
    expect(words[off / 32 + 2].endsWith("00")).toBe(true);
    expect(Number(BigInt("0x" + words[4]))).toBe(off + 32 + 64);
  });

  test("rejects odd-length or non-hex bytes", () => {
    expect(() => encodeSend(A, 1n, 1338n, "0xabc", "0x")).toThrow(/bad bytes/);
    expect(() => encodeSend(A, 1n, 1338n, "0xzz", "0x")).toThrow(/bad bytes/);
  });

  // EVM -> Solana: the receiver the user types is a base58 account key, and the
  // Gate wants its 32 raw bytes. This used to go straight into the hex encoder
  // and fail closed with "bad bytes" (audit round 4, LOW).
  test("a base58 Solana receiver is decoded to its 32 bytes", () => {
    // base58 of 0x11 * 32 (same bytes as the hex test above)
    const { words } = decode(encodeSend(A, 1n, 7565164n, "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2", "0x"));
    const offReceiver = Number(BigInt("0x" + words[3]));
    expect(words[offReceiver / 32]).toBe(word(32n));
    expect(words[offReceiver / 32 + 1]).toBe("11".repeat(32));
    // byte-exact against a second vector: 0x01..0x20
    const { words: w2 } = decode(encodeSend(A, 1n, 7565164n, "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw", "0x"));
    const expected = Array.from({ length: 32 }, (_, i) => (i + 1).toString(16).padStart(2, "0")).join("");
    expect(w2[Number(BigInt("0x" + w2[3])) / 32 + 1]).toBe(expected);
    // the system program id: 32 zero bytes, all leading-zero handling
    const { words: w3 } = decode(encodeSend(A, 1n, 7565164n, "11111111111111111111111111111111", "0x"));
    expect(w3[Number(BigInt("0x" + w3[3])) / 32 + 1]).toBe("00".repeat(32));
  });

  test("a base58 key that is not exactly 32 bytes is refused", () => {
    // 31 bytes of 0x11 — well-formed base58, wrong width
    expect(() => encodeSend(A, 1n, 7565164n, "G6ShajrrdiRnD4mW22j8T5kXyKSvwXaC64S9VGSzFA", "0x")).toThrow(/32/);
    expect(() => encodeSend(A, 1n, 7565164n, "not-base58-0OIl", "0x")).toThrow(/bad receiver/);
  });

  // H-3: ClaimArgs.amount / CancelArgs.amount on the Solana gate are u64. The
  // Gate reverts AmountTooWide for a 32-byte receiver above 2^64-1; anything
  // that got past it would be locked forever, so the UI refuses it too.
  test("a 32-byte receiver caps the amount at 2^64-1", () => {
    const max = (1n << 64n) - 1n;
    const b58 = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
    expect(() => encodeSend(A, max, 7565164n, b58, "0x")).not.toThrow();
    expect(() => encodeSend(A, max + 1n, 7565164n, b58, "0x")).toThrow(/AmountTooWide/);
    expect(() => encodeSend(A, max + 1n, 7565164n, "0x" + "11".repeat(32), "0x")).toThrow(/AmountTooWide/);
    // a 20-byte EVM receiver is uncapped
    expect(() => encodeSend(A, max + 1n, 1338n, "0x" + "ee".repeat(20), "0x")).not.toThrow();
  });
});

test.describe("encodeAutoParamsTo", () => {
  test("reproduces the on-chain AutoParamsTo layout", () => {
    const fallback = "0x" + "cd".repeat(20);
    const intent = encodeSwapIntent(A, B, 42n);
    const encoded = encodeAutoParamsTo(0n, 0n, fallback, intent);
    const { words } = decode("0x00000000" + encoded.replace(/^0x/, ""));

    expect(words[0]).toBe(word(0n)); // executionFee
    expect(words[1]).toBe(word(0n)); // flags
    const offFallback = Number(BigInt("0x" + words[2]));
    const offData = Number(BigInt("0x" + words[3]));
    expect(offFallback).toBe(128); // 4 head words

    expect(words[offFallback / 32]).toBe(word(20n));
    expect(words[offFallback / 32 + 1].slice(0, 40)).toBe(fallback.slice(2));

    // data = three static words of swap intent => length 96.
    expect(offData).toBe(offFallback + 64);
    expect(words[offData / 32]).toBe(word(96n));
    expect(words[offData / 32 + 1]).toBe(addrWord(A));
    expect(words[offData / 32 + 3]).toBe(word(42n));
  });
});

test.describe("encodeFinalize", () => {
  const debridgeId = "0x" + "22".repeat(32);

  test("chains three dynamic tails from a seven-word head", () => {
    const receiver = "0x" + "33".repeat(20);
    const nativeSender = "0x" + "44".repeat(20);
    const auto = encodeAutoParamsTo(0n, 0n, receiver, encodeSwapIntent(A, B, 1n));

    const { selector, words } = decode(
      encodeFinalize(debridgeId, 999n, 1337n, 5n, receiver, auto, nativeSender)
    );
    expect(selector).toBe("c2c1fffb");
    expect(words[0]).toBe("22".repeat(32));
    expect(words[1]).toBe(word(999n));
    expect(words[2]).toBe(word(1337n));
    expect(words[3]).toBe(word(5n));

    const offReceiver = Number(BigInt("0x" + words[4]));
    const offAuto = Number(BigInt("0x" + words[5]));
    const offNs = Number(BigInt("0x" + words[6]));
    expect(offReceiver).toBe(224); // 7 head words

    // Each offset must equal the previous one plus that tail's full length.
    const tailLen = (off: number) => 32 + Math.ceil(Number(BigInt("0x" + words[off / 32])) / 32) * 32;
    expect(offAuto).toBe(offReceiver + tailLen(offReceiver));
    expect(offNs).toBe(offAuto + tailLen(offAuto));

    expect(words[offNs / 32]).toBe(word(20n));
    expect(words[offNs / 32 + 1].slice(0, 40)).toBe(nativeSender.slice(2));
  });

  test("rejects a debridgeId that is not 32 bytes", () => {
    expect(() => encodeFinalize("0x1234", 1n, 1n, 1n, "0x", "0x", "0x")).toThrow(/bad bytes32/);
  });
});

// --- the chain-id binding on writes ---------------------------------------

/** A recording EIP-1193 stub. */
function stubProvider(opts: { chainId: number; callReturn?: string } = { chainId: 1337 }) {
  const calls: { method: string; params?: unknown[] }[] = [];
  const req: Eip1193Request = async ({ method, params }) => {
    calls.push({ method, params });
    if (method === "eth_chainId") return "0x" + opts.chainId.toString(16);
    if (method === "eth_call") return opts.callReturn ?? "0x" + "0".repeat(64);
    if (method === "eth_sendTransaction") return "0x" + "ab".repeat(32);
    if (method === "eth_getTransactionReceipt") return { blockNumber: "0x1", status: "0x1", logs: [] };
    return null;
  };
  return { req, calls };
}

test.describe("chain-id binding", () => {
  /**
   * The guard exists because contract addresses are not chain-scoped by the
   * wallet. If the wallet has moved to another chain, the same `to` address is a
   * different contract (or nothing at all): an `approve` grants an unknown
   * spender, and a `send` locks funds in something that will never emit `Sent`.
   */
  test("every write refuses to sign on a chain other than the one it was built for", async () => {
    const { req } = stubProvider({ chainId: 999 }); // wallet has drifted

    const writes: [string, () => Promise<string>][] = [
      ["approve", () => sendApprove(req, FROM, A, B, 1n, 1337)],
      ["swap", () => sendSwap(req, FROM, A, B, C, 1n, 1n, FROM, 1337)],
      ["bridge", () => sendBridge(req, FROM, A, B, 1n, 1338, "0x" + "ee".repeat(20), 1337)],
      [
        "swapAndBridge",
        () => sendSwapAndBridge(req, FROM, A, B, 1n, 1n, 1338, C, FROM, 1n, 1337),
      ],
      [
        "finalize",
        () => sendFinalize(req, FROM, A, "0x" + "22".repeat(32), 1n, 1337, 1, "0x", "0x", "0x", 1338),
      ],
    ];

    for (const [name, run] of writes) {
      const err = await run().catch((e) => e);
      expect(err, name).toBeInstanceOf(WrongChainError);
      expect((err as WrongChainError).actual, name).toBe(999);
      expect(String(err), name).toMatch(/Switch networks/);
    }
  });

  test("a matching chain proceeds and stamps chainId into the transaction", async () => {
    const { req, calls } = stubProvider({ chainId: 1337 });
    const hash = await sendApprove(req, FROM, A, B, 5n, 1337);
    expect(hash).toBe("0x" + "ab".repeat(32));

    // The chain is re-read immediately before signing, not trusted from React.
    expect(calls.map((c) => c.method)).toEqual(["eth_chainId", "eth_sendTransaction"]);

    const tx = calls[1].params?.[0] as { to: string; chainId: string; data: string };
    expect(tx.to).toBe(A);
    expect(tx.chainId).toBe("0x539"); // 1337
    expect(tx.data.startsWith("0x095ea7b3")).toBe(true);
  });

  test("finalize binds to the DESTINATION chain, not the transfer's origin", async () => {
    const { req, calls } = stubProvider({ chainId: 1338 });
    // chainIdFrom is 1337 (a hashed field); finalize executes on 1338.
    await sendFinalize(req, FROM, A, "0x" + "22".repeat(32), 1n, 1337, 1, "0x", "0x", "0x", 1338);
    const tx = calls[1].params?.[0] as { chainId: string };
    expect(tx.chainId).toBe("0x53a"); // 1338
  });
});

// --- reads ----------------------------------------------------------------

test.describe("reads", () => {
  test("readBalance / readAllowance / readDecimals decode a uint word", async () => {
    const { req, calls } = stubProvider({
      chainId: 1337,
      callReturn: "0x" + (12n).toString(16).padStart(64, "0"),
    });
    expect(await readBalance(req, A, FROM)).toBe(12n);
    expect(await readAllowance(req, A, FROM, B)).toBe(12n);
    expect(await readDecimals(req, A)).toBe(12);

    // Correct selectors: balanceOf, allowance, decimals.
    const selectors = calls.map((c) => (c.params?.[0] as { data: string }).data.slice(2, 10));
    expect(selectors).toEqual(["70a08231", "dd62ed3e", "313ce567"]);
  });

  test("readRouterGate takes the low 20 bytes of the returned word", async () => {
    const { req } = stubProvider({ chainId: 1337, callReturn: "0x" + addrWord(B) });
    expect(await readRouterGate(req, A)).toBe(B);
  });

  test("readRouterGate refuses a short return instead of inventing an address", async () => {
    const { req } = stubProvider({ chainId: 1337, callReturn: "0x1234" });
    await expect(readRouterGate(req, A)).rejects.toThrow(/no address/);
  });

  test("readRemoteRouter decodes dynamic bytes, and '0x' means no corridor", async () => {
    const payload =
      "0x" +
      word(32n) + // offset
      word(20n) + // length
      B.replace(/^0x/, "").padEnd(64, "0");
    const { req } = stubProvider({ chainId: 1337, callReturn: payload });
    expect(await readRemoteRouter(req, A, 1338n)).toBe(B);

    const empty = stubProvider({ chainId: 1337, callReturn: "0x" });
    expect(await readRemoteRouter(empty.req, A, 1338n)).toBe("0x");
  });

  test("rpcRequest surfaces a JSON-RPC error object as an Error", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ error: { message: "execution reverted" } }), {
        headers: { "content-type": "application/json" },
      })) as typeof fetch;
    try {
      const req = rpcRequest("http://example.invalid");
      await expect(req({ method: "eth_call" })).rejects.toThrow("execution reverted");
    } finally {
      globalThis.fetch = original;
    }
  });
});

// --- receipts + log parsing ----------------------------------------------

test.describe("receipts", () => {
  test("waitReceipt reports a mined revert as failure, not success", async () => {
    const req: Eip1193Request = async ({ method }) =>
      method === "eth_getTransactionReceipt" ? { blockNumber: "0x1", status: "0x0", logs: [] } : null;
    expect(await waitReceipt(req, "0xdead")).toEqual({ success: false });
  });

  test("waitReceiptFull returns the logs alongside the status", async () => {
    const logs = [{ address: A, topics: ["0x00"], data: "0x" }];
    const req: Eip1193Request = async ({ method }) =>
      method === "eth_getTransactionReceipt" ? { blockNumber: "0x1", status: "0x1", logs } : null;
    expect(await waitReceiptFull(req, "0xdead")).toEqual({ success: true, logs });
  });

  test("a receipt that never appears times out rather than hanging forever", async () => {
    const req: Eip1193Request = async () => null;
    await expect(waitReceipt(req, "0xdead", 50)).rejects.toThrow(/Timed out/);
  });
});

test.describe("extractSent", () => {
  const SENT_TOPIC0 = "0x8c7ee7a778ddf9672e509e70cf61fd826a6275ae6dd14c5e474b13898a1f2bbb";
  const submissionId = "0x" + "11".repeat(32);
  const debridgeId = "0x" + "22".repeat(32);
  // Sent's non-indexed data: amount at word 0, nonce at word 4.
  const data = "0x" + word(777n) + word(0n) + word(0n) + word(0n) + word(9n);

  test("pulls the id, debridgeId, amount and nonce out of the log", () => {
    const sent = extractSent(
      [{ address: A, topics: [SENT_TOPIC0, submissionId, debridgeId], data }],
      A
    );
    expect(sent).toEqual({ submissionId, debridgeId, amount: 777n, nonce: 9n });
  });

  test("matches the gate address case-insensitively", () => {
    const sent = extractSent(
      [{ address: A.toUpperCase(), topics: [SENT_TOPIC0, submissionId, debridgeId], data }],
      A
    );
    expect(sent?.amount).toBe(777n);
  });

  /**
   * Matching only the emitting address would trust the first log from the gate
   * and then read fixed word offsets — so any other event it emits would be
   * mis-decoded as a `Sent`, producing a bogus submissionId to finalize against.
   */
  test("ignores a different event from the same gate", () => {
    const other = "0x" + "99".repeat(32);
    expect(extractSent([{ address: A, topics: [other, submissionId, debridgeId], data }], A)).toBeNull();
  });

  test("ignores a lookalike Sent from a different contract", () => {
    expect(
      extractSent([{ address: B, topics: [SENT_TOPIC0, submissionId, debridgeId], data }], A)
    ).toBeNull();
  });

  test("picks the gate's Sent out of a receipt full of other logs", () => {
    const noise = { address: B, topics: ["0x" + "77".repeat(32)], data: "0x" };
    const sent = extractSent(
      [noise, { address: A, topics: [SENT_TOPIC0, submissionId, debridgeId], data }, noise],
      A
    );
    expect(sent?.submissionId).toBe(submissionId);
  });

  test("returns null for an empty receipt", () => {
    expect(extractSent([], A)).toBeNull();
  });
});

test.describe("errMsg", () => {
  test("names a user rejection", () => {
    expect(errMsg({ code: 4001, message: "boom" })).toBe("Rejected in wallet");
    expect(errMsg(new Error("User denied transaction"))).toBe("Rejected in wallet");
  });

  test("strips revert noise down to the reason", () => {
    expect(errMsg(new Error("execution reverted: TooManySignatures"))).toBe("TooManySignatures");
  });

  test("caps the length so a wall of RPC text cannot break the banner", () => {
    expect(errMsg(new Error("x".repeat(500))).length).toBeLessThanOrEqual(160);
  });

  test("handles a non-Error throw", () => {
    expect(errMsg("plain string")).toBe("plain string");
  });
});
