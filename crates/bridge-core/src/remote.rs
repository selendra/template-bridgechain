//! HTTP client for the `sig-store` service (Phase 7).
//!
//! Same record shape as the file-backed [`crate::store`], just over the wire.
//! The validator POSTs its signature; the keeper GETs all records. The server
//! dedupes by signer, so multiple validators converge on one record per id.

use crate::allow::{
    AllowedChain, AllowedToken, Allowlist, AttestationRequest, ClaimedRequest, SubmissionHistory,
    SwapRecord,
};
use crate::store::{SigKind, SignerSig, SubmissionRecord};

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// The store answered with more than [`MAX_RESPONSE_BYTES`] (M-9). The body
    /// is dropped unread past the cap rather than buffered.
    #[error("response body exceeds {limit} bytes (got at least {seen})")]
    TooLarge { limit: usize, seen: usize },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// How long to wait for a TCP connection to the store.
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Total budget for one request, connect included, until the body is fully read.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Largest response body this client will buffer before decoding.
///
/// 8 MiB is ~40× the biggest legitimate page the store serves (5 000
/// `SubmissionHistory` rows ≈ 200 KiB, a full `pending_claims` batch is a few
/// hundred KiB) while stopping a compromised or misconfigured store from
/// answering a poll with a multi-GB body that OOMs every validator and keeper
/// at once (M-9).
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Buffer a response body up to `cap` bytes, failing as soon as the cap is
/// exceeded — from the declared `Content-Length` if there is one, otherwise from
/// the running total as chunks arrive (a chunked or lying server cannot bypass
/// it by omitting the header).
async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, RemoteError> {
    if let Some(len) = resp.content_length() {
        if len > cap as u64 {
            return Err(RemoteError::TooLarge { limit: cap, seen: len.min(usize::MAX as u64) as usize });
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > cap {
            return Err(RemoteError::TooLarge { limit: cap, seen: buf.len() + chunk.len() });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// `error_for_status` + capped body read + JSON decode, for every response the
/// store sends us. One path so no call site can forget the bound.
async fn json_capped<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T, RemoteError> {
    let resp = resp.error_for_status()?;
    let body = read_capped(resp, MAX_RESPONSE_BYTES).await?;
    Ok(serde_json::from_slice(&body)?)
}

pub struct RemoteStore {
    base: String,
    client: reqwest::Client,
}

impl RemoteStore {
    /// Build a client for the calling service, presenting the narrowest
    /// credential it has (finding L-5).
    ///
    /// `role_env` is the service's own variable — `SIG_STORE_VALIDATOR_TOKEN`,
    /// `SIG_STORE_KEEPER_TOKEN`, `SIG_STORE_READER_TOKEN` — and wins when set.
    /// `SIG_STORE_TOKEN` remains the fallback so existing single-secret
    /// deployments keep working; it just grants far more than any one service
    /// needs, which is the thing worth migrating away from.
    pub fn for_role(base: impl Into<String>, role_env: &str) -> Self {
        let token = std::env::var(role_env)
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| std::env::var("SIG_STORE_TOKEN").ok());
        Self::with_token(base, token)
    }

    /// Legacy constructor: the shared all-scopes secret only.
    pub fn new(base: impl Into<String>) -> Self {
        Self::with_token(base, std::env::var("SIG_STORE_TOKEN").ok())
    }

    /// Build a client that authenticates with `token` (if `Some`) on every request.
    pub fn with_token(base: impl Into<String>, token: Option<String>) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = token.as_deref().filter(|t| !t.is_empty()) {
            if let Ok(mut value) =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            {
                value.set_sensitive(true);
                headers.insert(reqwest::header::AUTHORIZATION, value);
            }
        }
        // M-9: the store is UNTRUSTED. Without a timeout, a store that accepts
        // the connection and never answers hangs every validator scan loop
        // (which calls `fetch_allowlist` before each batch) and every keeper
        // tick, forever. The body cap is enforced per response in `json_capped`.
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap_or_default();
        Self { base, client }
    }

    /// A client for tests, pointed at an arbitrary base with no credential.
    #[doc(hidden)]
    pub fn for_tests(base: impl Into<String>) -> Self {
        Self::with_token(base, None)
    }

    /// Upsert one signature for a submission (server merges + dedupes by signer).
    pub async fn upsert(
        &self,
        mut record: SubmissionRecord,
        sig: SignerSig,
    ) -> Result<SubmissionRecord, RemoteError> {
        record.signatures = vec![sig];
        let url = format!("{}/submissions", self.base);
        json_capped(self.client.post(url).json(&record).send().await?).await
    }

    /// All known records (the keeper polls this).
    pub async fn load_all(&self) -> Result<Vec<SubmissionRecord>, RemoteError> {
        let url = format!("{}/submissions", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    /// One page of records, newest-first by `created_at`, for callers that
    /// must not pull the whole table at once. `GET /submissions` with no
    /// `limit` returns at most the server's default page (see sig-store), so a
    /// consumer that needs everything walks pages with this.
    pub async fn load_page(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<SubmissionRecord>, RemoteError> {
        let url = format!("{}/submissions?limit={limit}&offset={offset}", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    /// The keeper's target-side work queue for one destination chain: transfers
    /// that may still need a `claim` or a `cancel` there, filtered server-side.
    ///
    /// The keeper used to poll [`load_all`] every tick and probe the chain for
    /// every row it got back, so its per-tick cost grew with total history rather
    /// than with outstanding work — see `bridge_db::Db::pending_claims`.
    pub async fn pending_claims(
        &self,
        chain_id_to: u64,
    ) -> Result<Vec<SubmissionRecord>, RemoteError> {
        let url = format!("{}/submissions?pending=claims&chain_id_to={chain_id_to}", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    /// The keeper's source-side work queue for one origin chain: transfers that
    /// carry a refund attestation and have not been repaid yet.
    pub async fn pending_refunds(
        &self,
        chain_id_from: u64,
    ) -> Result<Vec<SubmissionRecord>, RemoteError> {
        let url =
            format!("{}/submissions?pending=refunds&chain_id_from={chain_id_from}", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    /// A single record by submissionId, if present.
    pub async fn load(&self, submission_id: &str) -> Result<Option<SubmissionRecord>, RemoteError> {
        let id = submission_id.strip_prefix("0x").unwrap_or(submission_id);
        let url = format!("{}/submissions/{id}", self.base);
        let resp = self.client.get(url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(json_capped(resp).await?))
    }

    /// The whitelisted tokens (validator/keeper enforce these before signing/claiming).
    pub async fn allowed_tokens(&self) -> Result<Vec<AllowedToken>, RemoteError> {
        let url = format!("{}/allowed/tokens", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    /// The whitelisted source→target chain pairs.
    pub async fn allowed_chains(&self) -> Result<Vec<AllowedChain>, RemoteError> {
        let url = format!("{}/allowed/chains", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    /// Both allowlists, assembled into the in-memory [`Allowlist`] the hot path
    /// checks against.
    ///
    /// The validator and the keeper are the two independent enforcement points
    /// and both need exactly this pair of fetches, so it lives here rather than
    /// being spelled out twice: a copy that fetched only one list would disable
    /// half the enforcement at that component with nothing to show for it.
    pub async fn allowlist(&self) -> Result<Allowlist, RemoteError> {
        let tokens = self.allowed_tokens().await?;
        let chains = self.allowed_chains().await?;
        Ok(Allowlist::from_parts(&tokens, &chains))
    }

    // --- history (read scope) ---------------------------------------------

    /// The transaction-history view: every observed transfer with its lifecycle
    /// status, signature counts and timestamps.
    ///
    /// Served over HTTP at the `Read` scope rather than read from Postgres, so
    /// the GraphQL API — the only component exposed to the internet — needs no
    /// database credential at all. It used to hold the same full-privilege role
    /// the sig-store does, which made the whole scope split decorative for
    /// exactly the service it was designed to contain.
    pub async fn history(&self) -> Result<Vec<SubmissionHistory>, RemoteError> {
        let url = format!("{}/history", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    /// One page of the history view (newest first). See [`RemoteStore::load_page`].
    pub async fn history_page(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<SubmissionHistory>, RemoteError> {
        let url = format!("{}/history?limit={limit}&offset={offset}", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    /// Same-chain swap history (`SwapPool.Swapped`), newest first, optionally
    /// scoped to one chain. Companion to [`RemoteStore::history`]; see there for
    /// why this is an HTTP read rather than a query.
    pub async fn swaps(
        &self,
        chain_id: Option<u64>,
        limit: u64,
    ) -> Result<Vec<SwapRecord>, RemoteError> {
        let mut url = format!("{}/swaps?limit={limit}", self.base);
        if let Some(chain_id) = chain_id {
            url.push_str(&format!("&chain_id={chain_id}"));
        }
        json_capped(self.client.get(url).send().await?).await
    }

    /// Report the keeper's `claim()` tx to the store.
    ///
    /// Advisory since M-1 (audit 2026-09-09): the store records it in
    /// `keeper_claim_tx` and does NOT move the transfer's lifecycle — only the
    /// indexer's on-chain `Claimed` observation does that. A failure here costs
    /// nothing but an annotation.
    pub async fn mark_claimed(&self, submission_id: &str, claim_tx: &str) -> Result<(), RemoteError> {
        let id = submission_id.strip_prefix("0x").unwrap_or(submission_id);
        let url = format!("{}/submissions/{id}/claimed", self.base);
        self.client
            .post(url)
            .json(&ClaimedRequest { claim_tx: claim_tx.to_string() })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    // --- refund path ------------------------------------------------------

    /// Post this validator's cancel/refund attestation. The server re-verifies it
    /// against `kind`'s own digest before counting it.
    pub async fn upsert_attestation(
        &self,
        submission_id: &str,
        kind: SigKind,
        sig: SignerSig,
    ) -> Result<SubmissionRecord, RemoteError> {
        let id = submission_id.strip_prefix("0x").unwrap_or(submission_id);
        let url = format!("{}/submissions/{id}/attestations", self.base);
        let body = AttestationRequest {
            kind: kind.as_str().to_string(),
            signer: sig.signer,
            signature: sig.signature,
        };
        json_capped(self.client.post(url).json(&body).send().await?).await
    }

    /// Submissions the refund relayer should examine. Candidates only — the
    /// caller still verifies both chains on-chain before signing anything.
    pub async fn refund_candidates(&self) -> Result<Vec<SubmissionRecord>, RemoteError> {
        let url = format!("{}/refund-candidates", self.base);
        json_capped(self.client.get(url).send().await?).await
    }

    // The `cancelled`/`refunded` lifecycle is written only by the indexer from
    // observed on-chain events, so the keeper/relayer client intentionally has no
    // method to set it (that would be reporting a candidate-gating state on the
    // caller's word). See sig-store's router note.
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serve exactly one HTTP/1.1 response: read the request head, then run
    /// `respond` against the socket. Returns the base URL.
    async fn one_shot_server<F, Fut>(respond: F) -> String
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain the request head so the client is not blocked on its write.
            let mut buf = vec![0u8; 4096];
            let mut head = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            respond(sock).await;
        });
        format!("http://{addr}")
    }

    async fn get(base: &str) -> reqwest::Response {
        RemoteStore::for_tests(base).client.get(format!("{base}/x")).send().await.unwrap()
    }

    /// A declared Content-Length past the cap is refused before a single body
    /// byte is buffered.
    #[tokio::test]
    async fn content_length_over_the_cap_is_refused_up_front() {
        let base = one_shot_server(|mut sock| async move {
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999999\r\n\r\n")
                .await
                .unwrap();
            // Never send the body; a client that waited for it would hang here.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        })
        .await;
        let resp = get(&base).await;
        match read_capped(resp, 1024).await {
            Err(RemoteError::TooLarge { limit: 1024, seen }) => assert_eq!(seen, 999_999_999),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// M-9 proper: a chunked body with no Content-Length is stopped the moment the
    /// running total crosses the cap, however much more the server has to send.
    #[tokio::test]
    async fn a_chunked_body_is_cut_off_at_the_cap() {
        let base = one_shot_server(|mut sock| async move {
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            let chunk = vec![b'['; 1024];
            for _ in 0..64 {
                if sock.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await.is_err() {
                    return; // client hung up: the cap did its job
                }
                if sock.write_all(&chunk).await.is_err() || sock.write_all(b"\r\n").await.is_err() {
                    return;
                }
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
        })
        .await;
        let resp = get(&base).await;
        match read_capped(resp, 4096).await {
            Err(RemoteError::TooLarge { limit: 4096, seen }) => {
                assert!(seen > 4096 && seen <= 4096 + 1024, "seen = {seen}")
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// The happy path still decodes — the cap is a bound, not a filter.
    #[tokio::test]
    async fn a_body_under_the_cap_decodes() {
        let body = r#"[{"chain_id_from":1,"chain_id_to":2}]"#;
        let base = one_shot_server(move |mut sock| async move {
            sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        })
        .await;
        let resp = get(&base).await;
        let decoded: Vec<AllowedChain> = json_capped(resp).await.unwrap();
        assert_eq!(decoded, vec![AllowedChain { chain_id_from: 1, chain_id_to: 2 }]);
    }

    /// A non-2xx is still surfaced as an HTTP error, before any body handling.
    #[tokio::test]
    async fn an_error_status_is_an_http_error() {
        let base = one_shot_server(|mut sock| async move {
            sock.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        })
        .await;
        let resp = get(&base).await;
        assert!(matches!(json_capped::<Vec<AllowedChain>>(resp).await, Err(RemoteError::Http(_))));
    }

    /// The client is built with both timeouts. reqwest does not expose them, so
    /// this pins the constants against a silent regression to "none".
    #[test]
    fn timeouts_are_bounded() {
        assert!(CONNECT_TIMEOUT.as_secs() >= 1 && CONNECT_TIMEOUT.as_secs() <= 30);
        assert!(REQUEST_TIMEOUT.as_secs() >= CONNECT_TIMEOUT.as_secs() && REQUEST_TIMEOUT.as_secs() <= 120);
        assert!(MAX_RESPONSE_BYTES <= 64 * 1024 * 1024);
    }
}
