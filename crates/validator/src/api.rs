//! Operator HTTP API (mirrors this repo's `AppController`).
//!
//! Single source (back-compat, what phase6.sh drives):
//!   GET  /status              -> scanner cursor, pause state, nonce map
//!   POST /pause               -> pause scanning
//!   POST /resume              -> clear pause
//!   POST /rescan {from_block} -> reset cursor and re-scan from a block
//!
//! Multiple sources: the bare routes still work when exactly one source is
//! configured; otherwise address a specific chain:
//!   GET  /status              -> array of every source's status
//!   GET  /status/{chain_id}
//!   POST /pause/{chain_id}  /resume/{chain_id}  /rescan/{chain_id}
//!
//! ## Authentication (audit 2026-09-09)
//!
//! `/status` stays reachable WITHOUT a credential — the container healthcheck and
//! monitoring read it — but an unauthenticated read gets a REDACTED view: liveness
//! (`paused`, `pause_reason`, cursor) only. The validator address and the
//! per-corridor nonce map, which together tell an attacker exactly which
//! transfer a phishing or replay attempt should target, need the bearer token.
//! With `allow_unauthenticated = true` (dev) everything is served in full.
//!
//! Every PRESENTED bearer, right or wrong, on any route draws from one small
//! token bucket; when it is empty the API answers 429 without comparing. That
//! bounds online guessing of the token at a few attempts per second. Requests
//! with no `Authorization` header do not touch the bucket, so a healthcheck can
//! never lock an operator out.
//!
//! Each source's state is shared with its scan loop via `Arc<Mutex<Runtime>>`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use bridge_core::auth::ct_eq;
use bridge_core::ratelimit::RateLimit;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::state::Runtime;

/// How many bearer attempts may arrive back to back before the API answers 429,
/// and how fast that allowance refills. An operator's hand-driven curl and a
/// dashboard polling `/status` with the token every few seconds fit inside it
/// with room to spare; a brute-force loop does not.
const AUTH_ATTEMPT_BURST: u32 = 30;
const AUTH_ATTEMPTS_PER_SECOND: f64 = 2.0;

#[derive(Clone)]
pub struct ApiState {
    /// One runtime per watched source chain, keyed by chain_id.
    pub sources: Arc<BTreeMap<u64, Arc<Mutex<Runtime>>>>,
    pub validator: String,
    /// Shared secret required as `Authorization: Bearer <token>` on the state-
    /// changing routes (pause/resume/rescan) and for the full `/status`.
    /// `None` => no credential configured.
    pub token: Option<String>,
    /// Mount the control routes anyway when `token` is `None`. Dev only — see
    /// [`router`] for why the default is to leave them off entirely.
    pub allow_unauthenticated: bool,
}

/// The auth-related state the middleware and `/status` share.
#[derive(Clone)]
struct Guard {
    token: Option<String>,
    allow_unauthenticated: bool,
    /// One bucket for every presented bearer (see the module note).
    attempts: RateLimit,
}

impl Guard {
    fn new(state: &ApiState) -> Guard {
        Guard {
            token: state.token.clone().filter(|t| !t.is_empty()),
            allow_unauthenticated: state.allow_unauthenticated,
            attempts: RateLimit::new(AUTH_ATTEMPT_BURST, AUTH_ATTEMPTS_PER_SECOND),
        }
    }

    /// Classify one request's credential.
    fn check(&self, req: &Request) -> Credential {
        let Some(expected) = self.token.as_deref() else {
            // No token configured: full access iff the operator opted into an
            // open API; otherwise "unauthenticated" — the router has already left
            // the control routes unmounted, and /status redacts.
            return if self.allow_unauthenticated { Credential::Full } else { Credential::None };
        };
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let Some(presented) = presented else { return Credential::None };
        // Draw BEFORE comparing, so an exhausted bucket refuses to evaluate the
        // guess at all — a correct token during a flood gets 429 too, briefly,
        // which is the price of the response not being an oracle.
        if !self.attempts.check("") {
            return Credential::Throttled;
        }
        if ct_eq(presented.as_bytes(), expected.as_bytes()) {
            Credential::Full
        } else {
            Credential::Wrong
        }
    }
}

enum Credential {
    /// Valid token, or an explicitly open (dev) API.
    Full,
    /// No `Authorization` header at all.
    None,
    /// A bearer was presented and does not match.
    Wrong,
    /// Too many bearers presented recently; not evaluated.
    Throttled,
}

/// Middleware for the control routes: only a valid token passes.
async fn require_token(State(g): State<Arc<Guard>>, req: Request, next: Next) -> Result<Response, StatusCode> {
    match g.check(&req) {
        Credential::Full => Ok(next.run(req).await),
        Credential::None | Credential::Wrong => Err(StatusCode::UNAUTHORIZED),
        Credential::Throttled => Err(StatusCode::TOO_MANY_REQUESTS),
    }
}

#[derive(Serialize)]
struct StatusResponse {
    /// Redacted (omitted) on an unauthenticated read.
    #[serde(skip_serializing_if = "Option::is_none")]
    validator: Option<String>,
    chain_id: u64,
    paused: bool,
    pause_reason: Option<String>,
    last_block: u64,
    next_block: u64,
    /// Last accepted nonce per corridor: `{ "<chain_from>": { "<chain_to>": n } }`.
    /// Redacted (omitted) on an unauthenticated read.
    #[serde(skip_serializing_if = "Option::is_none")]
    nonces: Option<BTreeMap<u64, BTreeMap<u64, u64>>>,
    /// `true` when fields were withheld for lack of a bearer token, so a reader
    /// can tell "no nonces yet" from "not shown to you".
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    redacted: bool,
}

#[derive(Deserialize)]
struct RescanRequest {
    from_block: u64,
}

pub fn router(state: ApiState) -> Router {
    let guard = Arc::new(Guard::new(&state));

    // Read-only status stays reachable for monitoring (redacted without a token —
    // see the module note); the state-changing routes (which can halt the
    // validator — a DoS vector) require the bearer token.
    let status = Router::new()
        .route("/status", get(status_all))
        .route("/status/:chain_id", get(status_one))
        .layer(axum::Extension(guard.clone()));

    let mut control = Router::new()
        .route("/pause", post(pause_bare))
        .route("/pause/:chain_id", post(pause_one))
        .route("/resume", post(resume_bare))
        .route("/resume/:chain_id", post(resume_one))
        .route("/rescan", post(rescan_bare))
        .route("/rescan/:chain_id", post(rescan_one));

    match guard.token.clone() {
        Some(_) => {
            info!(
                "operator API auth enabled: bearer token required for pause/resume/rescan \
                 and for the full /status (validator address + nonces)"
            );
            control = control.route_layer(middleware::from_fn_with_state(guard.clone(), require_token));
        }
        None if state.allow_unauthenticated => warn!(
            "allow_unauthenticated: operator API pause/resume/rescan are UNAUTHENTICATED \
             (anyone who can reach it can halt this validator). Dev only."
        ),
        // FAIL CLOSED: with no credential the control routes are not mounted at
        // all, so an unset VALIDATOR_API_TOKEN costs monitoring nothing and costs
        // an attacker the ability to halt this validator out of quorum. Warning
        // and serving them anyway made a missing secret indistinguishable from a
        // correct deployment except in the log.
        None => {
            warn!(
                "no operator API token configured — pause/resume/rescan are NOT mounted \
                 (a REDACTED read-only /status still is). Set VALIDATOR_API_TOKEN, or \
                 `allow_unauthenticated = true` in the [api] block for local dev."
            );
            return status.with_state(state);
        }
    }

    status.merge(control).with_state(state)
}

/// Spawn the operator API on `bind`. Returns once the listener is bound.
pub async fn serve(bind: &str, state: ApiState) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(%bind, "operator API listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

/// The single configured chain_id, or an error if there are several (used to make
/// the bare routes unambiguous in the back-compat single-source case).
fn only_chain(s: &ApiState) -> Result<u64, (StatusCode, Json<Value>)> {
    if s.sources.len() == 1 {
        Ok(*s.sources.keys().next().unwrap())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "multiple sources configured; address one with /{action}/{chain_id}",
                "chains": s.sources.keys().copied().collect::<Vec<_>>(),
            })),
        ))
    }
}

fn runtime_of<'a>(
    s: &'a ApiState,
    chain_id: u64,
) -> Result<&'a Arc<Mutex<Runtime>>, (StatusCode, Json<Value>)> {
    s.sources.get(&chain_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": format!("no source for chain_id {chain_id}") })),
        )
    })
}

async fn status_for(validator: &str, chain_id: u64, rt: &Arc<Mutex<Runtime>>, full: bool) -> StatusResponse {
    let rt = rt.lock().await;
    StatusResponse {
        validator: full.then(|| validator.to_string()),
        chain_id,
        paused: rt.paused(),
        pause_reason: rt.pause_reason().map(|r| r.as_str()),
        last_block: rt.persist.last_block,
        next_block: rt.next_block(),
        nonces: full.then(|| rt.persist.nonces.clone()),
        redacted: !full,
    }
}

/// Decide how much of `/status` this request may see. A wrong or throttled bearer
/// is an error rather than a silent downgrade, so a mistyped token is noticed.
fn status_access(guard: &Guard, req: &Request) -> Result<bool, (StatusCode, Json<Value>)> {
    match guard.check(req) {
        Credential::Full => Ok(true),
        Credential::None => Ok(false),
        Credential::Wrong => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "invalid bearer token (omit it for the redacted status)" })),
        )),
        Credential::Throttled => Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "ok": false, "error": "too many authentication attempts; retry shortly" })),
        )),
    }
}

/// One source -> the legacy single object (keeps phase6.sh working). Several ->
/// an array, one entry per chain.
async fn status_all(
    State(s): State<ApiState>,
    axum::Extension(guard): axum::Extension<Arc<Guard>>,
    req: Request,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let full = status_access(&guard, &req)?;
    if s.sources.len() == 1 {
        let (cid, rt) = s.sources.iter().next().unwrap();
        return Ok(Json(json!(status_for(&s.validator, *cid, rt, full).await)));
    }
    let mut out = Vec::with_capacity(s.sources.len());
    for (cid, rt) in s.sources.iter() {
        out.push(status_for(&s.validator, *cid, rt, full).await);
    }
    Ok(Json(json!(out)))
}

async fn status_one(
    State(s): State<ApiState>,
    axum::Extension(guard): axum::Extension<Arc<Guard>>,
    Path(chain_id): Path<u64>,
    req: Request,
) -> Result<Json<StatusResponse>, (StatusCode, Json<Value>)> {
    let full = status_access(&guard, &req)?;
    let rt = runtime_of(&s, chain_id)?;
    Ok(Json(status_for(&s.validator, chain_id, rt, full).await))
}

async fn pause_one(
    State(s): State<ApiState>,
    Path(chain_id): Path<u64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let rt = runtime_of(&s, chain_id)?;
    {
        let mut rt = rt.lock().await;
        rt.pause(crate::state::PauseReason::Operator);
        // Persist it, exactly as `resume`/`rescan` do and as `state::Persist`
        // requires: a safety stop that lived in memory only would be cleared by
        // the next container restart, and the validator would come back signing
        // into whatever the operator halted it for.
        let _ = rt.save();
    }
    info!(chain_id, "scanner paused via operator API");
    Ok(Json(json!({ "ok": true, "chain_id": chain_id, "paused": true })))
}

async fn pause_bare(State(s): State<ApiState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = only_chain(&s)?;
    pause_one(State(s), Path(cid)).await
}

async fn resume_one(
    State(s): State<ApiState>,
    Path(chain_id): Path<u64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let rt = runtime_of(&s, chain_id)?;
    {
        let mut rt = rt.lock().await;
        rt.resume();
        let _ = rt.save();
    }
    info!(chain_id, "scanner resumed via operator API");
    Ok(Json(json!({ "ok": true, "chain_id": chain_id, "paused": false })))
}

async fn resume_bare(State(s): State<ApiState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = only_chain(&s)?;
    resume_one(State(s), Path(cid)).await
}

async fn rescan_one(
    State(s): State<ApiState>,
    Path(chain_id): Path<u64>,
    Json(req): Json<RescanRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let rt = runtime_of(&s, chain_id)?;
    let next_block = {
        let mut rt = rt.lock().await;
        rt.rescan_from(req.from_block);
        let _ = rt.save();
        rt.next_block()
    };
    info!(chain_id, from_block = req.from_block, "rescan requested via operator API");
    Ok(Json(
        json!({ "ok": true, "chain_id": chain_id, "rescan_from": req.from_block, "next_block": next_block }),
    ))
}

async fn rescan_bare(
    State(s): State<ApiState>,
    body: Json<RescanRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = only_chain(&s)?;
    rescan_one(State(s), Path(cid), body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    const CHAIN: u64 = 1337;

    fn temp_state_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "validator-api-test-{}-{}-{tag}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn app(path: &std::path::Path) -> Router {
        app_with(path, None, true)
    }

    fn app_with(path: &std::path::Path, token: Option<&str>, allow_unauthenticated: bool) -> Router {
        let runtime = Runtime::load_or_init(path, 0).unwrap();
        let mut sources = BTreeMap::new();
        sources.insert(CHAIN, Arc::new(Mutex::new(runtime)));
        router(ApiState {
            sources: Arc::new(sources),
            validator: "0xtest".into(),
            token: token.map(str::to_string),
            allow_unauthenticated,
        })
    }

    async fn post_with(app: Router, uri: &str, bearer: Option<&str>) -> StatusCode {
        let mut b = Request::builder().method("POST").uri(uri);
        if let Some(t) = bearer {
            b = b.header(axum::http::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap().status()
    }

    // --- M-1: no credential, no halt button --------------------------------

    /// THE regression. `pause` takes this validator out of quorum and persists
    /// across a restart, so an open operator API is a one-request denial of
    /// service against the signer set. Warning about a missing
    /// `VALIDATOR_API_TOKEN` and mounting the routes anyway meant a lost secret
    /// was indistinguishable from a correct deployment.
    #[tokio::test]
    async fn control_routes_are_not_mounted_without_a_credential() {
        let p = temp_state_path("no-token");
        for uri in ["/pause", "/resume", "/rescan"] {
            assert_eq!(
                post_with(app_with(&p, None, false), uri, None).await,
                StatusCode::NOT_FOUND,
                "{uri} must not exist without a token"
            );
        }
        let _ = std::fs::remove_file(&p);
    }

    async fn get_status(app: Router, uri: &str, bearer: Option<&str>) -> (StatusCode, serde_json::Value) {
        let mut b = Request::builder().method("GET").uri(uri);
        if let Some(t) = bearer {
            b = b.header(axum::http::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let res = app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    /// Monitoring must survive the lockdown: losing the halt button must not cost
    /// an operator the ability to see whether this validator is stuck. But the
    /// unauthenticated view is REDACTED (audit 2026-09-09): liveness only.
    #[tokio::test]
    async fn status_stays_readable_without_a_credential_but_redacted() {
        let p = temp_state_path("no-token-status");
        let (code, v) = get_status(app_with(&p, None, false), "/status", None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["paused"], false);
        assert!(v.get("last_block").is_some());
        assert!(v.get("validator").is_none(), "validator address must be withheld: {v}");
        assert!(v.get("nonces").is_none(), "nonce map must be withheld: {v}");
        assert_eq!(v["redacted"], true);
        let _ = std::fs::remove_file(&p);
    }

    /// With a token configured, the same read is full for the token holder,
    /// redacted for nobody-in-particular, and an error for a WRONG bearer (so a
    /// typo is noticed rather than silently downgraded).
    #[tokio::test]
    async fn status_is_full_only_with_the_token() {
        let p = temp_state_path("status-token");
        let app = app_with(&p, Some("s3cret"), false);

        let (code, v) = get_status(app.clone(), "/status", Some("s3cret")).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["validator"], "0xtest");
        assert!(v.get("nonces").is_some());
        assert!(v.get("redacted").is_none());

        let (code, v) = get_status(app.clone(), "/status", None).await;
        assert_eq!(code, StatusCode::OK);
        assert!(v.get("validator").is_none() && v.get("nonces").is_none(), "{v}");

        let (code, _) = get_status(app.clone(), "/status", Some("wrong")).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);

        let (code, v) = get_status(app.clone(), &format!("/status/{CHAIN}"), None).await;
        assert_eq!(code, StatusCode::OK);
        assert!(v.get("validator").is_none(), "{v}");
        let _ = std::fs::remove_file(&p);
    }

    /// Dev mode keeps the old behaviour: everything in full, no token needed
    /// (what phase6.sh greps for).
    #[tokio::test]
    async fn an_explicitly_open_api_serves_the_full_status() {
        let p = temp_state_path("open-status");
        let (code, v) = get_status(app_with(&p, None, true), "/status", None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["validator"], "0xtest");
        assert!(v.get("nonces").is_some());
        let _ = std::fs::remove_file(&p);
    }

    /// Online guessing is bounded: after the burst of presented bearers the API
    /// stops evaluating them (429) — for the right token too, briefly, so the
    /// response is not an oracle. Requests with NO bearer are unaffected, so a
    /// healthcheck can never lock the operator out.
    #[tokio::test]
    async fn bearer_attempts_are_rate_limited() {
        let p = temp_state_path("auth-limit");
        let app = app_with(&p, Some("s3cret"), false);
        let mut saw_429 = false;
        for _ in 0..(AUTH_ATTEMPT_BURST + 5) {
            let code = post_with(app.clone(), "/pause", Some("guess")).await;
            assert!(code == StatusCode::UNAUTHORIZED || code == StatusCode::TOO_MANY_REQUESTS, "{code}");
            saw_429 |= code == StatusCode::TOO_MANY_REQUESTS;
        }
        assert!(saw_429, "a flood of wrong tokens must eventually be throttled");
        // While throttled, the right token is not evaluated either...
        assert_eq!(post_with(app.clone(), "/pause", Some("s3cret")).await, StatusCode::TOO_MANY_REQUESTS);
        // ...but the credential-less healthcheck read is untouched.
        let (code, _) = get_status(app.clone(), "/status", None).await;
        assert_eq!(code, StatusCode::OK);
        let _ = std::fs::remove_file(&p);
    }

    /// With a token the routes exist and demand it.
    #[tokio::test]
    async fn control_routes_demand_the_token_when_one_is_set() {
        let p = temp_state_path("with-token");
        assert_eq!(
            post_with(app_with(&p, Some("s3cret"), false), "/pause", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_with(app_with(&p, Some("s3cret"), false), "/pause", Some("wrong")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_with(app_with(&p, Some("s3cret"), false), "/pause", Some("s3cret")).await,
            StatusCode::OK
        );
        let _ = std::fs::remove_file(&p);
    }

    async fn post(app: Router, uri: &str) -> StatusCode {
        let req = Request::builder().method("POST").uri(uri).body(Body::empty()).unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    /// THE regression. `state::Persist` requires a safety stop to survive a
    /// restart — a crash-loop must not silently clear a halt nobody has
    /// investigated. `pause` used to mutate the in-memory `Runtime` and return
    /// without saving, so with compose's `restart: unless-stopped` a validator an
    /// operator halted mid-incident came back signing.
    ///
    /// Asserted through the ROUTER, not through `Runtime`: the pre-existing
    /// `pause_state_survives_save_and_reload` drives `Runtime` directly, which is
    /// exactly why it stayed green while the path an operator actually uses was
    /// broken.
    #[tokio::test]
    async fn an_operator_pause_is_persisted() {
        let path = temp_state_path("pause");
        let _ = std::fs::remove_file(&path);

        assert_eq!(post(app(&path), &format!("/pause/{CHAIN}")).await, StatusCode::OK);

        let reloaded = Runtime::load_or_init(&path, 0).unwrap();
        assert!(reloaded.paused(), "an operator pause must survive a restart");
        assert_eq!(reloaded.pause_reason(), Some(&crate::state::PauseReason::Operator));

        let _ = std::fs::remove_file(&path);
    }

    /// The other half: a resume must be just as durable, or a restart would
    /// re-halt a validator the operator had cleared.
    #[tokio::test]
    async fn an_operator_resume_is_persisted() {
        let path = temp_state_path("resume");
        let _ = std::fs::remove_file(&path);

        let app = app(&path);
        assert_eq!(post(app.clone(), &format!("/pause/{CHAIN}")).await, StatusCode::OK);
        assert_eq!(post(app, &format!("/resume/{CHAIN}")).await, StatusCode::OK);

        assert!(!Runtime::load_or_init(&path, 0).unwrap().paused());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn an_unknown_chain_is_not_found() {
        let path = temp_state_path("unknown");
        let _ = std::fs::remove_file(&path);
        assert_eq!(post(app(&path), "/pause/9999").await, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(&path);
    }
}
