//! Request signing (HMAC-SHA256) and signing-secret encryption at rest (XChaCha20-Poly1305).
//!
//! Two distinct concerns live here, both keyed off an API key's `signing_secret`:
//!
//! 1. **Request authentication** — every `/api/*` call carries `X-API-Key` (identity lookup),
//!    `X-Timestamp` (anti-replay) and `X-Signature-256` (proof of possession). The signature is an
//!    HMAC-SHA256 over the **CANONICAL_V1** string `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY` using the
//!    looked-up key's `signing_secret`, where `TARGET` is the **full request target including the
//!    query string**. See [`compute_signature`] and [`verify_signature`].
//!
//!    The same canonical string is used for outbound `CANONICAL_V1` webhook dispatches
//!    (`crate::dispatch`), so a `simply_ip_vault` instance can sign a request that another instance
//!    — or `simply_hook_executor` — verifies with identical code.
//! 2. **Secret confidentiality at rest** — unlike `key_hash` (a one-way hash), a `signing_secret`
//!    must be recoverable verbatim to verify a signature, so it cannot be hashed. It is therefore
//!    sealed with XChaCha20-Poly1305 under a key supplied out-of-band, so read access to the
//!    database alone is not enough to forge signatures. See [`SecretCipher`].

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;

use crate::error::AppError;

/// Maximum tolerated difference, in seconds, between `X-Timestamp` and the server's own clock.
///
/// A request outside this window is rejected as a replay (or as originating from a host with a
/// badly skewed clock, which is indistinguishable from a replay and equally unsafe to trust). The
/// window is deliberately symmetric — a timestamp too far in the *future* is just as suspect as one
/// too far in the past, and allowing it would let a captured request be held and replayed later.
///
/// The window bounds *how long* a captured request stays usable; it does not stop it being used
/// twice inside that window. [`crate::replay::ReplayGuard`] closes that second gap.
pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Name of the environment variable holding the master encryption key for `signing_secret` values.
pub const ENCRYPTION_KEY_ENV: &str = "VAULT_ENCRYPTION_KEY";

/// Accepted alias for [`ENCRYPTION_KEY_ENV`], matching the name `simply_hook_executor` uses so one
/// provisioning system can supply both services. [`ENCRYPTION_KEY_ENV`] wins when both are set.
pub const ENCRYPTION_KEY_ENV_ALIAS: &str = "SIGNING_SECRET_KEY";

/// Required encryption key width, in bytes.
const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce width, in bytes (192 bits).
const NONCE_LEN: usize = 24;

/// Prefix marking a value stored without encryption.
const PLAINTEXT_PREFIX: &str = "v1.plain.";
/// Prefix marking a value sealed with XChaCha20-Poly1305.
const SEALED_PREFIX: &str = "v1.xchacha20poly1305.";

/// Generates a fresh 32-byte HMAC signing secret, hex-encoded.
///
/// Deliberately the same shape and entropy as [`crate::api::generate_random_key`] — but a wholly
/// independent value: knowing a key's public `X-API-Key` must never reveal its signing secret.
pub fn generate_signing_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Builds the **CANONICAL_V1** byte string that gets signed:
/// `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`.
///
/// The four fields are joined by a single `\n` (LF), with no trailing newline. `method` is expected
/// uppercase. `target` is the request target **including the query string** when one is present —
/// see [`verify_signature`] for why.
///
/// The newline delimiter is what makes the encoding *unambiguous*: with plain concatenation, the
/// pair `("POST", "/api/ban")` and `("POS", "T/api/ban")` produce identical bytes, so a signature
/// over one is a valid signature over the other. A delimiter that cannot appear in a method or a URL
/// target removes that whole class of boundary confusion. It is also the format
/// `simply_hook_executor` speaks, so one canonical string now serves both the inbound API and
/// outbound `CANONICAL_V1` webhook dispatches.
///
/// Outbound webhook templates (`webhook_configs.hmac_template`) build their own string and pass
/// whatever `{path}` resolves to; this function does not care which of the two it is handed.
pub fn canonical_v1_payload(method: &str, target: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(method.len() + target.len() + timestamp.len() + body.len() + 3);
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(target.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(body);
    message
}

/// The mandatory algorithm tag on every `X-Signature-256` value, inbound and outbound.
///
/// Not decoration and not an accommodation for GitHub-style receivers: it is the one part of the
/// header that says *what the hex means*. See [`verify_signature`] for why a bare digest is refused.
pub const SIGNATURE_PREFIX: &str = "sha256=";

/// Computes the `X-Signature-256` header value: [`SIGNATURE_PREFIX`] followed by the hex-encoded
/// HMAC-SHA256 over the CANONICAL_V1 string.
///
/// Returns the **whole header value**, prefix included, rather than a bare digest. That is what
/// makes "produce a signature" and "produce a valid header" the same operation, so a caller cannot
/// build one without the other: the output of this function feeds straight into
/// [`verify_signature`], and there is no code path in this crate that emits a bare hex digest for a
/// caller to accidentally send.
///
/// Infallible in practice: `Hmac` accepts keys of any length, so the only error path is a
/// `secret` that cannot be used as HMAC key material at all, which is reported as
/// [`AppError::Internal`] rather than panicking (`AGENT.MD` forbids `.unwrap()`/`.expect()`).
pub fn compute_signature(
    secret: &str,
    method: &str,
    target: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<String, AppError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| {
        tracing::error!("Failed to build HMAC from signing secret: {}", e);
        AppError::Internal
    })?;
    mac.update(&canonical_v1_payload(method, target, timestamp, body));
    Ok(format!("{SIGNATURE_PREFIX}{}", hex::encode(mac.finalize().into_bytes())))
}

/// Verifies a caller-supplied `X-Signature-256` against the expected HMAC.
///
/// # Constant-time comparison
///
/// The digest comparison goes through `Mac::verify_slice`, whose implementation chain is
/// `Mac::verify_slice → CtOutput::eq → subtle::ConstantTimeEq::ct_eq`. It rejects a tag of the wrong
/// length first — that leaks only the digest width, a public constant — and then compares all 32
/// bytes in constant time. Comparing the hex strings with `==` instead would let an attacker recover
/// a valid signature one byte at a time by measuring response latency, so this must never be
/// "simplified" into an equality check on the decoded bytes or the hex text.
///
/// # Why the query string is covered
///
/// `target` is the **full request target**, query string included. An earlier revision signed the
/// path alone, on the reasoning that reverse proxies reorder or append query parameters and that
/// query parameters on `/api/*` were read-only filters. That second half stopped being true: `?hard=true`
/// on `DELETE /api/ips/{id}` escalates a reversible soft delete into an irreversible purge, and
/// `?include_deleted=true` widens `GET /api/ips` to the master trash view. With the query outside
/// the signed material, an on-path attacker who cannot forge a signature could still rewrite a
/// captured `DELETE /api/ips/{id}` into `…?hard=true` inside the replay window. Signing the whole
/// target closes that; a proxy that rewrites query strings must now be configured not to.
///
/// # Why the `sha256=` prefix is mandatory
///
/// `provided` must be exactly [`SIGNATURE_PREFIX`] followed by hex. A bare digest — 64 valid hex
/// characters with no tag — is refused, and that is a deliberate tightening of an earlier revision
/// which accepted both spellings.
///
/// The prefix names the algorithm, and an unlabelled digest is a field whose meaning depends on
/// something outside itself. Accepting both shapes cost more than it bought:
///
/// - **Agility.** The day a second algorithm is offered, every stored, logged, or transcribed bare
///   digest becomes ambiguous, and the compatibility shim needed to disambiguate them is exactly the
///   downgrade surface that makes algorithm confusion possible. Requiring the tag *now*, while
///   `sha256` is the only value it can take, is what makes adding a second one a non-event.
/// - **Convergence.** `simply_hook_executor` has always required the prefix, and the two services
///   authenticate to each other. Accepting a shape the peer rejects meant a request this service
///   would take was one the peer would refuse — a difference that shows up as a broken dispatch
///   rather than as a security finding, and so goes unnoticed until it breaks.
/// - **Cost.** None: `compute_signature` emits the prefix, so every caller using this crate's own
///   helper was already sending it.
///
/// This is a wire-format requirement, so a caller that hand-rolls the header (a `fail2ban` action, a
/// shell script) must send `X-Signature-256: sha256=<hex>` and not `<hex>` alone.
///
/// # Return value
///
/// `Some(digest)` on success, carrying the **raw decoded digest bytes**, and `None` on any failure
/// (missing prefix, malformed hex, wrong tag width, wrong secret, tampered payload).
///
/// Returning the bytes rather than a bare `bool` is what lets [`crate::replay::ReplayGuard`] key on
/// canonical material without re-parsing the header. It also normalizes spelling by construction:
/// `sha256=AB…` and `sha256=ab…` are the same signature and decode to the same bytes, so they can
/// never be recorded as two distinct single uses. The previous `bool` shape forced the middleware to
/// re-derive a token from the header text, which upheld the same property only indirectly.
pub fn verify_signature(
    secret: &str,
    method: &str,
    target: &str,
    timestamp: &str,
    body: &[u8],
    provided: &str,
) -> Option<Vec<u8>> {
    // The prefix is required, not merely tolerated: `strip_prefix` returning `None` ends the
    // verification here rather than falling back to treating the whole value as hex.
    let provided_bytes = hex::decode(provided.trim().strip_prefix(SIGNATURE_PREFIX)?.trim()).ok()?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&canonical_v1_payload(method, target, timestamp, body));
    mac.verify_slice(&provided_bytes).ok()?;

    Some(provided_bytes)
}

/// Failure modes for building the cipher or opening a stored secret.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The configured encryption key is not exactly 64 hex characters.
    #[error(
        "{ENCRYPTION_KEY_ENV} must be exactly {} hex characters ({KEY_LEN} bytes); generate one \
         with `openssl rand -hex {KEY_LEN}`",
        KEY_LEN * 2
    )]
    InvalidKey,
    /// The stored value is not in any recognized format.
    #[error("Stored signing secret is malformed or was written by a newer version")]
    MalformedCiphertext,
    /// The ciphertext failed authentication — wrong key, or the row was tampered with.
    #[error(
        "Stored signing secret could not be decrypted. This usually means {ENCRYPTION_KEY_ENV} \
         does not match the key the secret was written with"
    )]
    DecryptionFailed,
    /// The cipher itself failed.
    #[error("Encryption failed")]
    EncryptionFailed,
}

impl From<CryptoError> for AppError {
    /// Every decryption failure is an operator problem, never a caller problem, so it becomes a
    /// generic `500` rather than anything a client could learn from.
    fn from(e: CryptoError) -> Self {
        tracing::error!("Signing-secret cipher error: {e}");
        AppError::Internal
    }
}

/// How recoverable secrets are protected at rest.
///
/// Constructed **once** at startup and carried in [`crate::state::AppState`]. An earlier revision
/// re-read `VAULT_ENCRYPTION_KEY` from the environment and re-derived the key on every seal and
/// open — that is once per authenticated request, and it meant the key backing an authorization
/// decision could change under a running process.
pub enum SecretCipher {
    /// No encryption key configured: secrets are stored hex-encoded but unencrypted.
    ///
    /// Kept as a supported mode so the daemon still runs with zero configuration, but it means
    /// database confidentiality is the *only* thing protecting signing secrets.
    Plaintext,
    /// Secrets are sealed with XChaCha20-Poly1305 under the configured key.
    ///
    /// Boxed because `XChaCha20Poly1305` carries the expanded key schedule, which is large enough
    /// that an unboxed variant would inflate every `SecretCipher` — including the `Plaintext` one.
    Sealed(Box<XChaCha20Poly1305>),
}

impl std::fmt::Debug for SecretCipher {
    /// Never renders key material, so a `{:?}` of application state cannot leak it into a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext => f.write_str("SecretCipher::Plaintext"),
            Self::Sealed(_) => f.write_str("SecretCipher::Sealed(<redacted>)"),
        }
    }
}

impl SecretCipher {
    /// Builds the cipher from [`ENCRYPTION_KEY_ENV`] (or [`ENCRYPTION_KEY_ENV_ALIAS`]).
    ///
    /// A malformed key is a **hard error**, not a fallback to plaintext: an operator who set the
    /// variable believes their secrets are encrypted, and silently writing them in the clear would
    /// betray that belief at exactly the wrong moment. `main` propagates this, so the daemon refuses
    /// to start rather than degrading quietly.
    pub fn from_env() -> Result<Self, CryptoError> {
        let configured = crate::config::get_secret_or_env(ENCRYPTION_KEY_ENV)
            .or_else(|| crate::config::get_secret_or_env(ENCRYPTION_KEY_ENV_ALIAS));

        match configured {
            Some(raw) => Self::from_hex_key(raw.trim()),
            None => Ok(Self::Plaintext),
        }
    }

    /// Builds a cipher from a hex-encoded 32-byte key.
    ///
    /// The key must be exactly 64 hex characters. A free-form passphrase is refused with
    /// [`CryptoError::InvalidKey`] rather than stretched, which is the honest outcome: an earlier
    /// implementation ran whatever it was given through a single SHA-256, so it could not tell
    /// `openssl rand -hex 32` from `password` and reported neither.
    pub fn from_hex_key(hex_key: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_key).map_err(|_| CryptoError::InvalidKey)?;
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        // `TryFrom` rather than the deprecated `from_slice`: the length is already checked above,
        // so this conversion cannot fail.
        let key = Key::try_from(bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::Sealed(Box::new(XChaCha20Poly1305::new(&key))))
    }

    /// Whether secrets are actually being encrypted.
    pub fn is_encrypting(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    /// Encodes a secret for storage.
    ///
    /// Even the unencrypted mode hex-encodes, so the raw secret is never a substring of the stored
    /// column and a casual `grep` of a database dump does not surface it.
    pub fn seal(&self, plaintext: &str) -> Result<String, CryptoError> {
        match self {
            Self::Plaintext => Ok(format!("{PLAINTEXT_PREFIX}{}", hex::encode(plaintext))),
            Self::Sealed(cipher) => {
                // A fresh random nonce per secret. XChaCha20's 192-bit nonce is wide enough that
                // random generation is collision-safe with no counter state to persist — which is
                // the whole reason for preferring it over AES-GCM's 96-bit nonce here.
                let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
                let nonce = XNonce::from(nonce_bytes);
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed)?;
                Ok(format!(
                    "{SEALED_PREFIX}{}.{}",
                    hex::encode(nonce_bytes),
                    hex::encode(ciphertext)
                ))
            }
        }
    }

    /// Recovers a secret from storage.
    ///
    /// Exactly two shapes are accepted, and **anything else is an error**:
    ///
    /// 1. `v1.xchacha20poly1305.<nonce>.<ct>` — the encrypted format.
    /// 2. `v1.plain.<hex>` — the unencrypted format.
    ///
    /// These are precisely the two shapes [`SecretCipher::seal`] can produce, which is what lets this
    /// be a closed set rather than a list that only ever grows.
    ///
    /// # Why an unprefixed value is rejected
    ///
    /// A third shape used to be accepted: an unprefixed string was returned **verbatim**, on the
    /// reasoning that it was a bare secret written before any prefix existed. That fallback was a
    /// silent failure mode wearing a compatibility costume, because "no recognized prefix" is not
    /// evidence of an old row — it is evidence of *nothing in particular*, and every other cause is
    /// worse:
    ///
    /// - A `v1.plain.` or `v1.xchacha20poly1305.` value whose prefix was lost or corrupted — by a
    ///   botched migration, a truncated column, a bad restore — would be fed to `Hmac::new_from_slice`
    ///   as though the surviving hex text were the secret. Every request would then fail signature
    ///   verification with `401`, pointing the operator at the *client* rather than at the row.
    /// - A partially-written sealed value would be used as HMAC key material.
    /// - Anything an attacker managed to write into the column through an unrelated defect would be
    ///   accepted as a signing secret rather than refused.
    ///
    /// Returning [`CryptoError::MalformedCiphertext`] instead makes the failure loud and attributable:
    /// it surfaces as a `500` with the row's identity in the log, which is what an operator needs to
    /// see. The recovery path is `POST /api/keys/{id}/rotate-secret`, which is master-only and
    /// replaces just the signing secret.
    ///
    /// # Why the AES-GCM path is gone
    ///
    /// `aesgcm256:<nonce><ct>` was readable here until the 2026-08-02 cleanup pass. It was a
    /// decrypt-only bridge for rows written before XChaCha20-Poly1305, with no writer anywhere in
    /// the crate — so it kept a second AEAD, a second nonce width, and a second key-derivation rule
    /// (SHA-256 of the raw environment text, distinct from the decoded key used for everything else)
    /// compiled in to serve a format this service can no longer produce. Retiring it removes the
    /// `aes-gcm` dependency and reduces `SecretCipher::Sealed` to a single field.
    ///
    /// **Upgrade note:** any deployment still holding an unprefixed **or** an `aesgcm256:` secret must
    /// rotate that key (`POST /api/keys/{id}/rotate-secret`, master-only) before upgrading, or it
    /// stops authenticating with a `500`. `AGENT.MD` §1 and `SCHEMA.MD` §1 documented both shapes as
    /// readable and have been amended, including the query for finding stragglers.
    pub fn open(&self, stored: &str) -> Result<String, CryptoError> {
        if let Some(encoded) = stored.strip_prefix(PLAINTEXT_PREFIX) {
            let bytes = hex::decode(encoded).map_err(|_| CryptoError::MalformedCiphertext)?;
            return String::from_utf8(bytes).map_err(|_| CryptoError::MalformedCiphertext);
        }

        if let Some(body) = stored.strip_prefix(SEALED_PREFIX) {
            let (nonce_hex, ciphertext_hex) =
                body.split_once('.').ok_or(CryptoError::MalformedCiphertext)?;
            let nonce_bytes =
                hex::decode(nonce_hex).map_err(|_| CryptoError::MalformedCiphertext)?;
            if nonce_bytes.len() != NONCE_LEN {
                return Err(CryptoError::MalformedCiphertext);
            }
            let ciphertext =
                hex::decode(ciphertext_hex).map_err(|_| CryptoError::MalformedCiphertext)?;

            let Self::Sealed(cipher) = self else {
                // A sealed row with no key configured. Reported as a key mismatch rather than as
                // corruption, because the fix is to set VAULT_ENCRYPTION_KEY, and because handing
                // ciphertext back as if it were the secret would surface as a misleading 401 on
                // every request instead of the real misconfiguration.
                return Err(CryptoError::DecryptionFailed);
            };
            let nonce =
                XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::MalformedCiphertext)?;
            let plaintext = cipher
                .decrypt(&nonce, ciphertext.as_ref())
                .map_err(|_| CryptoError::DecryptionFailed)?;
            return String::from_utf8(plaintext).map_err(|_| CryptoError::MalformedCiphertext);
        }

        // Fail closed. See the "Why an unprefixed value is now rejected" note above: an unrecognized
        // shape is not evidence of a pre-prefix row, and treating it as one turns a damaged column
        // into silently-wrong HMAC key material.
        Err(CryptoError::MalformedCiphertext)
    }
}

/// Outcome of the boot-time [`ENCRYPTION_KEY_ENV`] canary. See [`check_key_canary`].
#[derive(Debug, PartialEq, Eq)]
pub enum KeyCanary {
    /// The database holds no sealed `signing_secret` yet (a fresh database, or every key still
    /// running unencrypted). There is nothing to check the configured key against.
    NoSealedSecrets,
    /// A stored secret was opened successfully: the configured key is the one the data at rest was
    /// actually sealed under.
    Verified,
}

/// Proves — once, at startup — that [`ENCRYPTION_KEY_ENV`] is the key `api_keys.signing_secret` was
/// actually sealed under, by opening one stored row.
///
/// Without this, a syntactically valid but *wrong* key passes [`SecretCipher::from_env`] cleanly
/// (64 hex characters is all that function checks) and the mismatch is discovered only on the first
/// authenticated request, in [`crate::middleware`], as a `500` — by which point the daemon has bound
/// its listener, is reporting healthy, and every credential in the database has silently stopped
/// authenticating. Failing here instead converts that into a refusal to start, which is the
/// recoverable outcome: no request has been served under the wrong key, and the operator still has
/// the previous one to restore.
///
/// `sample` is any stored `api_keys.signing_secret` value; `None` means the table is empty or every
/// row predates encryption. Deliberately a free function taking the sample by parameter, rather than
/// a method that queries the database itself, so it stays testable without one — the boot wrapper in
/// `main.rs` is the only caller that supplies a real row.
pub fn check_key_canary(cipher: &SecretCipher, sample: Option<&str>) -> Result<KeyCanary, CryptoError> {
    let Some(stored) = sample else {
        return Ok(KeyCanary::NoSealedSecrets);
    };
    cipher.open(stored)?;
    Ok(KeyCanary::Verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn canonical_v1_payload_is_newline_delimited() {
        assert_eq!(
            canonical_v1_payload("POST", "/api/ban", "1700000000", b"{\"a\":1}"),
            b"POST\n/api/ban\n1700000000\n{\"a\":1}".to_vec(),
            "CANONICAL_V1 joins the four fields with a single LF"
        );
        // An empty body still leaves the third delimiter in place, so "no body" is distinguishable
        // from a body that happens to start where the timestamp ends.
        assert_eq!(
            canonical_v1_payload("GET", "/api/ips", "1700000000", b""),
            b"GET\n/api/ips\n1700000000\n".to_vec()
        );
    }

    #[test]
    fn delimiter_removes_field_boundary_ambiguity() {
        // The concrete attack the delimiter closes: under plain concatenation these two distinct
        // requests hash identically, so a signature for one authenticates the other.
        let shifted = compute_signature("secret", "POS", "T/api/ban", "1700000000", b"");
        let real = compute_signature("secret", "POST", "/api/ban", "1700000000", b"");
        assert_ne!(real.as_deref().ok(), shifted.as_deref().ok());
    }

    #[test]
    fn signature_is_stable_and_order_sensitive() {
        let sig = compute_signature("secret", "POST", "/api/ban", "1700000000", b"{}");
        let same = compute_signature("secret", "POST", "/api/ban", "1700000000", b"{}");
        assert_eq!(sig.as_deref().ok(), same.as_deref().ok());

        // Each component must genuinely feed the MAC, so a change to any one of them changes it.
        for (m, p, t, b) in [
            ("GET", "/api/ban", "1700000000", &b"{}"[..]),
            ("POST", "/api/white", "1700000000", &b"{}"[..]),
            ("POST", "/api/ban", "1700000001", &b"{}"[..]),
            ("POST", "/api/ban", "1700000000", &b"{\"a\":1}"[..]),
        ] {
            let other = compute_signature("secret", m, p, t, b);
            assert_ne!(sig.as_deref().ok(), other.as_deref().ok());
        }
    }

    /// The query string is part of the signed target, so tampering with it invalidates the
    /// signature. This is the property that stops a captured `DELETE /api/ips/{id}` from being
    /// rewritten into `…?hard=true` on the wire.
    #[test]
    fn the_query_string_is_covered_by_the_signature() {
        let bare = compute_signature("secret", "DELETE", "/api/ips/42", "1700000000", b"");
        let escalated =
            compute_signature("secret", "DELETE", "/api/ips/42?hard=true", "1700000000", b"");
        assert_ne!(bare.as_deref().ok(), escalated.as_deref().ok());

        // Reordering or adding a filter is equally covered.
        let listing = compute_signature("secret", "GET", "/api/ips?limit=10", "1700000000", b"");
        let widened = compute_signature(
            "secret",
            "GET",
            "/api/ips?limit=10&include_deleted=true",
            "1700000000",
            b"",
        );
        assert_ne!(listing.as_deref().ok(), widened.as_deref().ok());
    }

    #[test]
    fn verify_accepts_valid_and_rejects_tampered() {
        let sig = compute_signature("s3cret", "POST", "/api/ban", "1700000000", b"body")
            .expect("HMAC of a non-empty secret cannot fail");

        assert!(sig.starts_with(SIGNATURE_PREFIX), "the computed value is a complete header value");
        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", &sig).is_some());

        // Surrounding whitespace is tolerated on either side of the tag: a header value that picked
        // up a stray space is a transport artefact, not a forgery attempt.
        assert!(
            verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", &format!("  {sig} "))
                .is_some()
        );

        // Wrong secret, mutated body, and non-hex garbage must all fail closed.
        assert!(verify_signature("other", "POST", "/api/ban", "1700000000", b"body", &sig).is_none());
        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body!", &sig).is_none());
        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", "zzz").is_none());
        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", "").is_none());
    }

    /// A tag of the wrong width must be rejected outright rather than compared against a truncated
    /// expectation — the failure mode a hand-rolled comparison would introduce.
    ///
    /// Every case keeps the `sha256=` tag and varies only the digest, so each one exercises the
    /// width check rather than the format check.
    #[test]
    fn tags_of_the_wrong_length_are_rejected() {
        let sig = compute_signature("s3cret", "GET", "/api/ips", "1700000000", b"")
            .expect("HMAC of a non-empty secret cannot fail");
        let digest = sig.strip_prefix(SIGNATURE_PREFIX).expect("compute_signature emits the tag");

        for wrong in [&digest[..62], &digest[..2], "", &format!("{digest}00")] {
            assert!(
                verify_signature(
                    "s3cret",
                    "GET",
                    "/api/ips",
                    "1700000000",
                    b"",
                    &format!("{SIGNATURE_PREFIX}{wrong}")
                )
                .is_none(),
                "a {}-character digest must be rejected",
                wrong.len()
            );
        }
        assert!(verify_signature("s3cret", "GET", "/api/ips", "1700000000", b"", &sig).is_some());
    }

    /// The `sha256=` tag is mandatory: a **correct** digest sent bare must not verify.
    ///
    /// This is the case no digest-mutation test can reach. Every other rejection here is about the
    /// bytes being wrong; this one is about a caller that computed the right bytes and framed them
    /// the old way, which is precisely what a reintroduced fallback would silently start accepting.
    #[test]
    fn a_correct_digest_without_the_mandatory_tag_does_not_verify() {
        let sig = compute_signature("s3cret", "POST", "/api/ban", "1700000000", b"body")
            .expect("HMAC of a non-empty secret cannot fail");
        let digest = sig.strip_prefix(SIGNATURE_PREFIX).expect("compute_signature emits the tag");

        assert_eq!(digest.len(), 64, "the bare form is a full-width, otherwise-valid digest");
        assert!(
            verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", digest).is_none(),
            "a bare hex digest must be refused no matter how correct it is"
        );

        // Nor may any other tag stand in for it — including ones that merely contain it, which is
        // what a `contains`-based check instead of `strip_prefix` would let through.
        for framing in [
            format!("sha512={digest}"),
            format!("SHA256={digest}"),
            format!("x-sha256={digest}"),
            format!("sha256:{digest}"),
            format!("sha256 {digest}"),
        ] {
            assert!(
                verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", &framing)
                    .is_none(),
                "{framing:?} must not be accepted as a signature"
            );
        }
    }

    #[test]
    fn plaintext_mode_round_trips_without_exposing_the_secret() {
        let cipher = SecretCipher::Plaintext;
        assert!(!cipher.is_encrypting());

        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");
        assert!(sealed.starts_with(PLAINTEXT_PREFIX));
        // Even unencrypted storage is hex-encoded, so `grep` over a dump does not surface it.
        assert!(!sealed.contains("s3cr3t"));
        assert_eq!(cipher.open(&sealed).expect("opening succeeds"), "s3cr3t");
    }

    #[test]
    fn sealed_mode_round_trips_and_hides_the_secret() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        assert!(cipher.is_encrypting());

        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");
        assert!(sealed.starts_with(SEALED_PREFIX));
        assert!(!sealed.contains("s3cr3t"));
        assert_eq!(cipher.open(&sealed).expect("opening succeeds"), "s3cr3t");
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let first = cipher.seal("same-input").expect("sealing succeeds");
        let second = cipher.seal("same-input").expect("sealing succeeds");
        assert_ne!(first, second, "identical plaintexts must not seal identically");
        assert_eq!(cipher.open(&first).expect("opens"), cipher.open(&second).expect("opens"));
    }

    #[test]
    fn a_wrong_key_cannot_open_a_sealed_secret() {
        let writer = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let other = SecretCipher::from_hex_key(
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        )
        .expect("valid key");

        let sealed = writer.seal("s3cr3t").expect("sealing succeeds");
        assert!(matches!(other.open(&sealed), Err(CryptoError::DecryptionFailed)));
        // Nor can a daemon that lost its key entirely.
        assert!(matches!(
            SecretCipher::Plaintext.open(&sealed),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");

        // Flip the final ciphertext nibble; Poly1305 authentication must reject it.
        let mut chars: Vec<char> = sealed.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();

        assert!(matches!(cipher.open(&tampered), Err(CryptoError::DecryptionFailed)));
    }

    /// Fail closed at startup: a key that is not exactly 32 bytes of hex is an error, never a
    /// silent downgrade to writing secrets in the clear.
    #[test]
    fn malformed_keys_are_rejected_rather_than_falling_back() {
        for bad in [
            "not-hex",
            "00ff",                                                               // too short
            "",                                                                   // empty
            &format!("{TEST_KEY}00"),                                             // too long
            "zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",   // bad nibble
        ] {
            assert!(
                matches!(SecretCipher::from_hex_key(bad), Err(CryptoError::InvalidKey)),
                "{bad:?} must be rejected"
            );
        }
        assert!(SecretCipher::from_hex_key(TEST_KEY).is_ok());
    }

    /// Serializes the tests that read the two encryption-key variables.
    ///
    /// They are process-global and this suite runs in parallel, so without this two tests setting
    /// different keys would interleave and each would occasionally observe the other's. Poisoning is
    /// recovered from rather than propagated: one failing test must not cascade into four.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Runs `body` with both key variables set as given (`None` meaning unset), restoring whatever
    /// was there before.
    fn with_key_env<T>(
        primary: Option<&str>,
        alias: Option<&str>,
        body: impl FnOnce() -> T,
    ) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved: Vec<(&str, Option<String>)> = [ENCRYPTION_KEY_ENV, ENCRYPTION_KEY_ENV_ALIAS]
            .into_iter()
            .map(|name| (name, std::env::var(name).ok()))
            .collect();

        // SAFETY: `ENV_LOCK` is held across the whole body, and every test touching these two
        // variables goes through this helper, so no other thread reads or writes them meanwhile.
        unsafe {
            for (name, value) in [(ENCRYPTION_KEY_ENV, primary), (ENCRYPTION_KEY_ENV_ALIAS, alias)] {
                match value {
                    Some(raw) => std::env::set_var(name, raw),
                    None => std::env::remove_var(name),
                }
            }
        }

        let outcome = body();

        // SAFETY: as above — still under `ENV_LOCK`.
        unsafe {
            for (name, value) in saved {
                match value {
                    Some(raw) => std::env::set_var(name, raw),
                    None => std::env::remove_var(name),
                }
            }
        }
        outcome
    }

    /// The same fail-closed rule as [`malformed_keys_are_rejected_rather_than_falling_back`], but
    /// through `from_env` — the call `AppState::new` actually makes at startup.
    ///
    /// Testing `from_hex_key` proves the *parser* refuses a bad key. It says nothing about whether
    /// the environment reader propagates that refusal, and the reader is where the dangerous
    /// alternative lives: a `.unwrap_or(Plaintext)` or an `.ok()` there would turn every rejection
    /// above into a silent downgrade, with all of those tests still green. Both variable names are
    /// exercised, because the alias exists precisely so one provisioning system can feed both
    /// services and an alias that failed open would be a hole in the less-travelled path.
    #[test]
    fn a_malformed_key_in_either_variable_refuses_to_build_the_cipher() {
        for bad in ["not-hex", "00ff", &format!("{TEST_KEY}00"), "password"] {
            assert!(
                matches!(with_key_env(Some(bad), None, SecretCipher::from_env), Err(CryptoError::InvalidKey)),
                "{ENCRYPTION_KEY_ENV}={bad:?} must abort rather than degrade to plaintext"
            );
            assert!(
                matches!(with_key_env(None, Some(bad), SecretCipher::from_env), Err(CryptoError::InvalidKey)),
                "{ENCRYPTION_KEY_ENV_ALIAS}={bad:?} must abort rather than degrade to plaintext"
            );
        }

        // A bad *primary* must not be rescued by a good alias: the primary wins when both are set,
        // and "wins" has to mean its failure wins too. Falling through to the alias here would let a
        // typo in the documented variable be masked by a stale value in the compatibility one.
        assert!(
            matches!(
                with_key_env(Some("not-hex"), Some(TEST_KEY), SecretCipher::from_env),
                Err(CryptoError::InvalidKey)
            ),
            "a malformed primary key must not fall through to the alias"
        );
    }

    /// The other half: the shapes `from_env` must accept, so the test above cannot pass by refusing
    /// everything.
    #[test]
    fn from_env_resolves_the_primary_the_alias_and_the_unset_case() {
        let sealed = with_key_env(Some(TEST_KEY), None, SecretCipher::from_env)
            .expect("a valid primary key builds");
        assert!(sealed.is_encrypting(), "a configured key means secrets are encrypted");

        let via_alias = with_key_env(None, Some(TEST_KEY), SecretCipher::from_env)
            .expect("a valid alias key builds");
        assert!(via_alias.is_encrypting(), "the alias is a full equivalent, not a partial one");

        // Unset — and set-but-blank, which is what an unpopulated `.env` template or a
        // `VAULT_ENCRYPTION_KEY=` line produces — is the zero-configuration case, not an error.
        for blank in [None, Some(""), Some("   ")] {
            let plaintext = with_key_env(blank, None, SecretCipher::from_env)
                .expect("no key configured is not an error");
            assert!(!plaintext.is_encrypting(), "{blank:?} must mean plaintext, not a failure");
        }

        // A blank primary alongside a real alias must use the alias rather than being treated as
        // "the primary is set", which is the bug the `.filter(|raw| !raw.trim().is_empty())` guards.
        let fallback = with_key_env(Some(""), Some(TEST_KEY), SecretCipher::from_env)
            .expect("a blank primary falls through to the alias");
        assert!(fallback.is_encrypting(), "a blank primary must not mask a configured alias");
    }

    #[test]
    fn malformed_stored_values_are_rejected() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        for malformed in [
            "v1.xchacha20poly1305.nodot",
            "v1.xchacha20poly1305.zz.zz",
            "v1.xchacha20poly1305.00ff.aabb", // nonce too short
            "v1.plain.zz",
        ] {
            assert!(cipher.open(malformed).is_err(), "{malformed:?} should not open");
        }
    }

    /// An unprefixed row is **refused**, reversing what this test used to assert.
    ///
    /// The old contract returned such a value verbatim, on the reasoning that it was a bare secret
    /// written before any prefix existed. That traded a real failure mode for a hypothetical one: a
    /// pre-prefix row is only one of the ways a value can arrive without a prefix, and every other
    /// way — a truncated column, a botched migration, a partially-written seal, a value an attacker
    /// wrote through an unrelated defect — ends with unknown bytes used as HMAC key material and no
    /// signal that anything is wrong. Failing closed makes the damaged row say so.
    ///
    /// Operators still holding a bare secret must rotate it (`POST /api/keys/{id}/rotate-secret`)
    /// before upgrading; `AGENT.MD` §1 and `SCHEMA.MD` §1 record that.
    #[test]
    fn an_unprefixed_row_is_refused_rather_than_read_verbatim() {
        for cipher in [SecretCipher::Plaintext, SecretCipher::from_hex_key(TEST_KEY).expect("valid key")] {
            assert!(
                matches!(cipher.open("bare-legacy-secret"), Err(CryptoError::MalformedCiphertext)),
                "an unprefixed value must not be accepted as a signing secret"
            );
            // The empty column — the shape a failed write leaves behind — is refused on the same path
            // rather than becoming an empty HMAC key, which would verify forgeable signatures.
            assert!(matches!(cipher.open(""), Err(CryptoError::MalformedCiphertext)));
        }
    }

    /// The retired AES-GCM format must stay unreadable.
    ///
    /// `aesgcm256:` was a decrypt-only bridge with no writer; it was removed in the 2026-08-02
    /// cleanup pass along with the `aes-gcm` dependency. This asserts the negative directly, so
    /// reinstating the branch — or accidentally widening `open` to a prefix-agnostic fallback —
    /// fails here rather than silently restoring a second cipher's worth of attack surface.
    #[test]
    fn the_retired_aes_gcm_format_is_no_longer_readable() {
        let stored = format!(
            "aesgcm256:{}{}",
            hex::encode([7u8; 12]),
            hex::encode([9u8; 32])
        );
        for cipher in [SecretCipher::Plaintext, SecretCipher::from_hex_key(TEST_KEY).expect("valid key")] {
            assert!(
                matches!(cipher.open(&stored), Err(CryptoError::MalformedCiphertext)),
                "an aesgcm256: row must be refused as malformed, not decrypted"
            );
        }
    }

    /// Sealing always produces the current format. The only two shapes that exist are the ones
    /// `open` accepts, which is what lets that function be a closed set rather than a growing list.
    #[test]
    fn sealing_always_produces_a_currently_recognized_prefix() {
        let sealed = SecretCipher::from_hex_key(TEST_KEY)
            .expect("valid key")
            .seal("s3cr3t")
            .expect("sealing succeeds");
        assert!(sealed.starts_with(SEALED_PREFIX));

        let stored = SecretCipher::Plaintext.seal("s3cr3t").expect("sealing succeeds");
        assert!(stored.starts_with(PLAINTEXT_PREFIX));
    }

    /// `Debug` must never render key material — an `AppState` dump would otherwise leak it.
    #[test]
    fn debug_redacts_key_material() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let rendered = format!("{cipher:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(TEST_KEY));
        assert_eq!(format!("{:?}", SecretCipher::Plaintext), "SecretCipher::Plaintext");
    }

    /// A second, distinct valid-format key — the canary's whole reason to exist is telling this
    /// apart from [`TEST_KEY`], since both are 64 hex characters and equally acceptable to
    /// [`SecretCipher::from_hex_key`].
    const OTHER_KEY: &str = "f1e1d1c1b1a191817161514131211101f0e0d0c0b0a090807060504030201000";

    #[test]
    fn no_stored_secret_is_not_a_failure() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        assert_eq!(check_key_canary(&cipher, None), Ok(KeyCanary::NoSealedSecrets));
    }

    #[test]
    fn the_configured_key_opens_the_stored_secret() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let stored = cipher.seal("real-signing-secret").expect("sealing succeeds");
        assert_eq!(check_key_canary(&cipher, Some(&stored)), Ok(KeyCanary::Verified));
    }

    /// The property this whole module exists for: a syntactically valid but *wrong* key must be
    /// refused, not silently accepted as though it opened the row.
    #[test]
    fn a_wrong_but_well_formed_key_fails_the_canary() {
        let written_with = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let stored = written_with.seal("real-signing-secret").expect("sealing succeeds");

        let configured_with = SecretCipher::from_hex_key(OTHER_KEY).expect("valid key");
        assert_eq!(
            check_key_canary(&configured_with, Some(&stored)),
            Err(CryptoError::DecryptionFailed)
        );
    }

    /// A stored row with no key configured at all must also fail closed, not be handed back as
    /// though the ciphertext were the plaintext secret.
    #[test]
    fn a_sealed_row_with_no_key_configured_fails_the_canary() {
        let written_with = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let stored = written_with.seal("real-signing-secret").expect("sealing succeeds");

        assert_eq!(
            check_key_canary(&SecretCipher::Plaintext, Some(&stored)),
            Err(CryptoError::DecryptionFailed)
        );
    }

    /// A corrupted/truncated row must fail closed rather than being treated as a plaintext secret.
    #[test]
    fn a_malformed_stored_value_fails_the_canary() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        assert_eq!(
            check_key_canary(&cipher, Some("not-a-recognized-envelope")),
            Err(CryptoError::MalformedCiphertext)
        );
    }
}
