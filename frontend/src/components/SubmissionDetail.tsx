import { useEffect, type ReactNode } from "react";
import { StatusBadge, RefundBadge } from "./StatusBadge";
import { Glyph, ArrowRight } from "./icons";
import { chainViz, formatUnits, shortHex } from "../data/format";
import { fetchHistory, fetchSubmission } from "../api/client";
import { usePoll } from "../api/hooks";
import type { Chain, HistoryEntry, Submission } from "../api/types";
import { useChainDecimals, type DecimalsProvider } from "./useChainDecimals";

interface Props {
  submissionId: string;
  chains: Chain[];
  wallet?: DecimalsProvider | null;
  onClose: () => void;
}

function Row({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="detail__row">
      <span className="detail__label">{label}</span>
      <span className={`detail__value${mono ? " detail__value--mono" : ""}`}>{children}</span>
    </div>
  );
}

function chainName(chains: Chain[], id: number) {
  return chains.find((c) => c.chainId === id)?.name ?? `Chain ${id}`;
}

export function SubmissionDetail({ submissionId, chains, wallet, onClose }: Props) {
  const { data, error, loading } = usePoll<Submission | null>(
    () => fetchSubmission(submissionId),
    [submissionId],
    6000
  );
  const decimalsByChain = useChainDecimals(chains, wallet);

  // Best-effort: only populated when graphql-api was started with --store-url.
  const { data: historyRows } = usePoll<HistoryEntry[]>(
    () => fetchHistory({ submissionId }).catch(() => []),
    [submissionId],
    6000
  );
  const refund = historyRows?.[0];

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const from = data ? chainViz(data.chainIdFrom, chainName(chains, data.chainIdFrom)) : null;
  const to = data ? chainViz(data.chainIdTo, chainName(chains, data.chainIdTo)) : null;

  return (
    <div className="drawer-scrim" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Submission detail">
        <header className="drawer__head">
          <h2>Transfer</h2>
          <button type="button" className="drawer__close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        {loading && !data && <div className="drawer__body">Loading…</div>}
        {error && !data && <div className="drawer__body notice notice--error">Couldn’t load: {error}</div>}
        {/* The store answered, and it has never heard of this id. Saying so beats
            an empty drawer, which reads as a still-loading one forever. */}
        {!loading && !error && !data && (
          <div className="drawer__body notice">
            The signature store has no record of this submission. It may have been pruned, or the
            backend may be pointed at a different store.
          </div>
        )}

        {data && (
          <div className="drawer__body">
            <div className="detail__route">
              {from && (
                <span className="chaincell">
                  <Glyph gradient={from.gradient} size={22} /> {chainName(chains, data.chainIdFrom)}
                </span>
              )}
              <ArrowRight size={16} />
              {to && (
                <span className="chaincell">
                  <Glyph gradient={to.gradient} size={22} /> {chainName(chains, data.chainIdTo)}
                </span>
              )}
              <StatusBadge status={data.status} />
              {refund && refund.refundStatus !== "none" && <RefundBadge refundStatus={refund.refundStatus} />}
            </div>

            <Row label="Amount">{formatUnits(data.amount, decimalsByChain[data.chainIdFrom] ?? 18)} </Row>
            {refund && refund.refundStatus !== "none" && (
              <>
                <Row label="Refund status">
                  {refund.refundStatus === "eligible" &&
                    "Stuck past the refund timeout — validators are attesting a cancel"}
                  {refund.refundStatus === "cancelled" &&
                    "Burned on the destination — it can no longer be delivered; the source-chain repayment is pending"}
                  {refund.refundStatus === "refunded" && "Returned to the original sender on the source chain"}
                </Row>
                {refund.cancelTx && (
                  <Row label="Cancel tx" mono>
                    {shortHex(refund.cancelTx, 8, 6)}
                  </Row>
                )}
                {refund.refundTx && (
                  <Row label="Refund tx" mono>
                    {shortHex(refund.refundTx, 8, 6)}
                  </Row>
                )}
                <Row label="Refund attestations">
                  {refund.cancelSignatureCount} cancel / {refund.refundSignatureCount} refund
                </Row>
              </>
            )}
            <Row label="Nonce">{data.nonce}</Row>
            <Row label="Receiver" mono>
              {data.receiver}
            </Row>
            {data.nativeSender && (
              <Row label="Sender" mono>
                {data.nativeSender}
              </Row>
            )}
            <Row label="Submission ID" mono>
              {data.submissionId}
            </Row>
            {data.debridgeId && (
              <Row label="deBridge ID" mono>
                {shortHex(data.debridgeId, 12, 8)}
              </Row>
            )}

            <div className="detail__sigs">
              <div className="detail__sigs-head">
                <span>Signatures</span>
                <span className="sig-count">
                  {data.signatureCount}
                  {data.meetsThreshold != null && (
                    <span className={`sig-count__badge${data.meetsThreshold ? " ok" : ""}`}>
                      {data.meetsThreshold ? "threshold met" : "below threshold"}
                    </span>
                  )}
                </span>
              </div>
              {data.signatures.length === 0 && <div className="detail__empty">No signatures yet.</div>}
              {data.signatures.map((sig, i) => (
                <div className="sig-item" key={sig.signer + i}>
                  <span className="sig-item__idx">{i + 1}</span>
                  <span className="sig-item__signer" title={sig.signer}>
                    {shortHex(sig.signer, 10, 8)}
                  </span>
                  {sig.signature && <span className="sig-item__sig">{shortHex(sig.signature, 10, 6)}</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}
