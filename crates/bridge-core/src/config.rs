//! Small config-validation helpers shared by every service's `Config::from_toml`.
//!
//! Each service configures a list of chain blocks and must reject duplicates in
//! it: two `[[sources]]` for one chain_id means two scan loops racing on one
//! cursor, two `[[targets]]` means two claim loops contending for one nonce.
//! Every service hand-rolled the same nested-loop scan for that, so the check
//! lives here once — and as a set lookup rather than the O(n²) pairwise walk.

use std::collections::BTreeSet;
use std::fmt::Display;

/// Fail if any two entries of `items` share a `key`.
///
/// `what` names the field for the error message ("target chain_id",
/// "state_file"), which is what an operator actually needs to see: the message
/// reads `duplicate <what> <value> in config`.
pub fn ensure_unique<'a, T: 'a, K, F>(items: &'a [T], key: F, what: &str) -> anyhow::Result<()>
where
    K: Ord + Display,
    F: Fn(&'a T) -> K,
{
    let mut seen: BTreeSet<K> = BTreeSet::new();
    for item in items {
        let k = key(item);
        if !seen.insert(k) {
            // Re-derive for the message: `insert` consumed the key.
            anyhow::bail!("duplicate {what} {} in config", key(item));
        }
    }
    Ok(())
}

/// A URL safe to put in a log line: scheme and host (and port) only.
///
/// Hosted RPC providers put the API key in the PATH (`/v2/<key>`) or the query
/// (`?apikey=`), and a keyed endpoint logged at startup is a credential in every
/// log shipper, crash dump and support ticket downstream (audit 2026-09-09, H-4
/// / LOW "keyed RPC URLs logged"). Userinfo (`user:pass@`) is dropped too. If
/// the string does not parse as `scheme://host…` at all, the whole thing is
/// replaced rather than guessed at — a value we cannot classify is treated as
/// secret.
pub fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<redacted>".to_string();
    };
    // Authority ends at the first of `/`, `?`, `#`.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Drop `user:pass@`.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if scheme.is_empty() || host.is_empty() {
        return "<redacted>".to_string();
    }
    format!("{scheme}://{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_keeps_scheme_host_port_only() {
        assert_eq!(
            redact_url("https://eth-sepolia.g.alchemy.com/v2/SuPerSecretKey123"),
            "https://eth-sepolia.g.alchemy.com"
        );
        assert_eq!(redact_url("http://127.0.0.1:8545"), "http://127.0.0.1:8545");
        assert_eq!(redact_url("http://127.0.0.1:8545/"), "http://127.0.0.1:8545");
        assert_eq!(redact_url("wss://node.example:8546/ws?apikey=abc"), "wss://node.example:8546");
        assert_eq!(redact_url("https://host/path#frag"), "https://host");
    }

    #[test]
    fn redact_url_drops_userinfo_and_query() {
        assert_eq!(redact_url("https://user:pw@rpc.example.com/x?key=1"), "https://rpc.example.com");
        assert_eq!(redact_url("https://rpc.example.com?apikey=zzz"), "https://rpc.example.com");
    }

    #[test]
    fn redact_url_never_echoes_something_it_cannot_classify() {
        for s in ["", "not a url", "://", "https://", "key-only-string"] {
            let out = redact_url(s);
            assert_eq!(out, "<redacted>", "input {s:?} gave {out:?}");
        }
    }

    #[test]
    fn accepts_distinct_keys() {
        ensure_unique(&[1u64, 2, 3], |n| *n, "chain_id").unwrap();
    }

    #[test]
    fn rejects_a_repeat_and_names_it() {
        let err = ensure_unique(&[1u64, 2, 1], |n| *n, "chain_id").unwrap_err().to_string();
        assert!(err.contains("duplicate chain_id 1"), "got: {err}");
    }

    #[test]
    fn an_empty_list_is_fine() {
        ensure_unique::<u64, u64, _>(&[], |n| *n, "chain_id").unwrap();
    }
}
