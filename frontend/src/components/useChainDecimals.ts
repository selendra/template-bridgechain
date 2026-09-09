import { useEffect, useMemo, useState } from "react";
import { readDecimals, rpcRequest, type Eip1193Request } from "../wallet/eth";
import type { Chain } from "../api/types";

/** The connected wallet, reduced to what the fallback read needs. */
export interface DecimalsProvider {
  chainId: number | null;
  request: Eip1193Request;
}

/** Best-effort token decimals per source chain, resolved from the chain
 *  registry's default `token`. A `Submission` itself carries no decimals —
 *  only an opaque `debridgeId` hash — so this is a heuristic for the common
 *  case of one bridged asset per chain; it can't be exact for a chain that
 *  bridges several differently-decimaled tokens.
 *
 *  Reads go to the registry's `rpcUrl` when the API published one. Since H-4
 *  the API serves ONLY a browser-safe public url there and `null` when the
 *  operator has none — so a chain with `rpcUrl: null` is read through the
 *  connected wallet's provider instead, when the wallet is on that chain.
 *  Otherwise (no url, wallet elsewhere, or the read fails) it falls back to 18,
 *  the prior silent assumption. Re-resolved only when the (chainId, token,
 *  rpcUrl, wallet chain) tuples actually change, not on every registry poll. */
export function useChainDecimals(chains: Chain[], wallet?: DecimalsProvider | null): Record<number, number> {
  const [decimals, setDecimals] = useState<Record<number, number>>({});
  const walletChain = wallet?.chainId ?? null;
  const targets = useMemo(
    () =>
      chains.filter(
        (c): c is Chain & { token: string } => !!c.token && (!!c.rpcUrl || (walletChain !== null && walletChain === c.chainId))
      ),
    [chains, walletChain]
  );
  const key = targets.map((c) => `${c.chainId}:${c.token}:${c.rpcUrl ?? "wallet"}`).join(",");

  useEffect(() => {
    if (!key) return;
    let alive = true;
    Promise.all(
      targets.map(async (c) => {
        try {
          const req = c.rpcUrl ? rpcRequest(c.rpcUrl) : wallet!.request;
          return [c.chainId, await readDecimals(req, c.token)] as const;
        } catch {
          return [c.chainId, 18] as const;
        }
      })
    ).then((entries) => {
      if (alive) setDecimals(Object.fromEntries(entries));
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return decimals;
}
