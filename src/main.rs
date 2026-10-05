#[cfg(all(target_os = "linux", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::net::SocketAddr;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::net::TcpListener;
use uuid::Uuid;
use simply_ip_vault::{create_app, setup_state, api, entities};

/// Waits for a Ctrl+C or (on Unix) SIGTERM signal so `axum::serve` can shut down gracefully.
///
/// If signal registration itself fails, that branch is left pending forever instead of firing
/// immediately: an unregisterable signal should never be treated as "shutdown requested now".
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Received shutdown signal.");
}

/// Generates a default Master API Key if the database does not already contain one.
///
/// Checks specifically for the absence of a key with `is_master = true` (not merely "any key
/// exists"): if every master key were ever deleted while lower-privilege sub-keys remained,
/// administrators could otherwise be permanently locked out.
///
/// If the `INITIAL_MASTER_KEY` environment variable is set, its exact value is used as the
/// plaintext secret instead of generating a random one. This exists purely for deterministic
/// test/CI bootstrap (e.g. `scripts/test_e2e.sh`), where a caller needs to know the master key
/// up front rather than scraping it back out of stdout — it is deliberately **not** documented as
/// a normal deployment option, since a human-chosen, low-entropy secret defeats the point of
/// generating a random 256-bit key. A warning is logged whenever it's used so it can't be enabled
/// by accident in a real deployment without someone noticing in the logs.
async fn bootstrap_master_key(
    db: &DatabaseConnection,
    cipher: &simply_ip_vault::crypto::SecretCipher,
) -> Result<(), Box<dyn std::error::Error>> {
    use entities::{api_key, prelude::ApiKey};

    let existing_master = ApiKey::find()
        .filter(api_key::Column::IsMaster.eq(true))
        .one(db)
        .await?;
    if existing_master.is_some() {
        return Ok(());
    }

    let plaintext_key = match std::env::var(simply_ip_vault::config::INITIAL_MASTER_KEY_ENV) {
        Ok(fixed_key) if !fixed_key.is_empty() => {
            // Strict, and fatal. Until this check existed the variable accepted any non-empty
            // string, with the warning below as the only objection — a safeguard that reads like
            // one and stops nothing. See `config::validate_initial_master_key`.
            //
            // Logged before it is returned, and that is not decoration. `main` returns
            // `Box<dyn Error>`, which the runtime renders with **`Debug`** — so propagating this
            // alone would print `InvalidInitialMasterKey { got: 8, detail: "..." }` and throw away
            // the entire operator-facing message, remedy included. An e2e check caught exactly that.
            // Same shape as the master-pin refusal further down, for the same reason.
            simply_ip_vault::config::validate_initial_master_key(&fixed_key).map_err(|e| {
                tracing::error!("Refusing to start: {e}");
                e
            })?;
            tracing::warn!(
                "INITIAL_MASTER_KEY is set: using the provided value as the master key instead \
                 of generating a random one. This is intended for deterministic test/CI bootstrap \
                 only — do not set this in a real deployment."
            );
            fixed_key
        }
        _ => api::generate_random_key(),
    };
    // The signing secret follows the same rule as the key itself: deterministic when explicitly
    // provided for test/CI bootstrap, random otherwise.
    let signing_secret = match std::env::var("INITIAL_MASTER_SIGNING_SECRET") {
        Ok(fixed_secret) if !fixed_secret.is_empty() => {
            tracing::warn!(
                "INITIAL_MASTER_SIGNING_SECRET is set: using the provided value as the master \
                 key's HMAC signing secret instead of generating a random one. Intended for \
                 deterministic test/CI bootstrap only — do not set this in a real deployment."
            );
            fixed_secret
        }
        _ => simply_ip_vault::crypto::generate_signing_secret(),
    };

    let key_hash = api::hash_key(&plaintext_key);
    let stored_signing_secret = cipher.seal(&signing_secret)?;
    // Both families. Listing only `0.0.0.0/0` was harmless while master keys bypassed the CIDR
    // check; now that they are held to it, an IPv4-only default locks an operator out of a
    // dual-stack deployment on the very first request — `normalize_ip` rescues IPv4-*mapped* IPv6
    // (`::ffff:a.b.c.d`), but a native IPv6 peer such as `::1` matches no IPv4 prefix at all, and
    // there is no second credential in the database to recover with.
    let bound_ip =
        std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0,::/0".to_owned());

    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let now = chrono::Utc::now().naive_utc();

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(stored_signing_secret)),
        name: Set("System Master".to_owned()),
        prefix: Set(prefix),
        bound_ips: Set(Some(bound_ip.clone())),
        // This is the only write of `is_master = true` anywhere in the service, and it is also, by
        // construction, the only thing that can claim the master slot: the engine derives
        // `api_keys.master_marker` from this value and a unique index covers it. A second bootstrap
        // racing this one therefore loses at the database rather than producing a second master
        // (`RBAC_MODEL.md` §5) — uniqueness rests on the schema, not on the `find` above happening
        // to run first, and not on this function remembering to populate a marker.
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        // The root of every lineage. R3 makes this a bookkeeping fact and nothing more — being a
        // daughter of the Master confers no standing over any other daughter.
        parent_key_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    model.insert(db).await?;

    // The box is drawn against an explicit inner width rather than hardcoded runs of ═, so the
    // borders stay aligned around a 64-hex-char credential (the previous fixed layout did not).
    const W: usize = 82;
    let border = "═".repeat(W);
    let body: String = [
        format!("X-API-Key      : {plaintext_key}"),
        format!("Signing secret : {signing_secret}"),
        format!("Bound IPs      : {bound_ip}"),
        String::new(),
        "Both values are needed to sign requests (X-Timestamp + X-Signature-256).".to_owned(),
        "They will NOT be shown again — store them securely!".to_owned(),
    ]
    .iter()
    .map(|row| format!("║ {row:<W$} ║\n"))
    .collect();

    tracing::info!(
        "\n╔{border}╗\n║ {:<W$} ║\n╠{border}╣\n{body}╚{border}╝",
        "BOOTSTRAP: Master API Key Generated"
    );

    // tracing's fmt subscriber buffers writes; a reader tailing/polling the redirected log file
    // right after this point (as scripts/test_e2e.sh used to, before it switched to
    // INITIAL_MASTER_KEY) could otherwise see a truncated or missing banner for a short window.
    // Flushing explicitly makes the banner's appearance in the log deterministic.
    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    Ok(())
}

/// Startup canary for `VAULT_ENCRYPTION_KEY`: proves the configured key is the one
/// `api_keys.signing_secret` was actually sealed under, and refuses to start if it is not.
///
/// Must run after [`bootstrap_master_key`], so a fresh database has at least the master's own
/// sealed secret to check against, and before `TcpListener::bind`, so the canary can never be
/// bypassed by a request arriving before it completes.
///
/// Without this, [`simply_ip_vault::crypto::SecretCipher::from_env`] accepts any syntactically
/// valid 64-hex-character key — it has no way to know whether that key matches what the data at
/// rest was sealed under — and the mismatch surfaces only in [`simply_ip_vault::middleware`], as a
/// `500` on the first authenticated request. By then the daemon is bound, `/health` is answering,
/// and every credential in the database has silently stopped authenticating. This turns that into a
/// boot-time refusal instead.
async fn verify_encryption_key(
    db: &DatabaseConnection,
    cipher: &simply_ip_vault::crypto::SecretCipher,
) -> Result<(), Box<dyn std::error::Error>> {
    use entities::{api_key, prelude::ApiKey};
    use simply_ip_vault::crypto::{check_key_canary, KeyCanary};

    let sample = ApiKey::find()
        .filter(api_key::Column::SigningSecret.is_not_null())
        .one(db)
        .await?
        .and_then(|key| key.signing_secret);

    match check_key_canary(cipher, sample.as_deref()) {
        Ok(KeyCanary::Verified) => {
            tracing::info!(
                "Encryption key canary passed: the stored signing secret opens with the \
                 configured {}.",
                simply_ip_vault::crypto::ENCRYPTION_KEY_ENV
            );
            Ok(())
        }
        Ok(KeyCanary::NoSealedSecrets) => {
            tracing::info!(
                "Encryption key canary skipped: no sealed signing secret is stored yet."
            );
            Ok(())
        }
        Err(e) => {
            // Logged before returning, for the same reason as the master-pin refusal below: `main`
            // returns `Box<dyn Error>`, which the runtime renders with `Debug`, and propagating
            // this alone would print the enum variant rather than the operator-facing remedy in its
            // `Display` message.
            tracing::error!(
                "Refusing to start: the stored signing secret could not be decrypted with the \
                 configured {} ({e}). This means the key does not match the one secrets were \
                 sealed under — restore the previous key, or rotate every affected key's signing \
                 secret (POST /api/keys/{{id}}/rotate-secret) under the new one before retrying.",
                simply_ip_vault::crypto::ENCRYPTION_KEY_ENV
            );
            Err(Box::new(e))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://simply_ip_vault.db?mode=rwc".to_owned());

    // Built once, here, and carried in `AppState` from now on — never re-read per request.
    //
    // A malformed key stops startup rather than silently degrading to writing signing secrets in
    // the clear. An operator who set `VAULT_ENCRYPTION_KEY` believes their secrets are encrypted,
    // and the moment that belief is wrong is exactly the moment it must not be quiet.
    let cipher = simply_ip_vault::crypto::SecretCipher::from_env()?;
    if cipher.is_encrypting() {
        tracing::info!(
            "VAULT_ENCRYPTION_KEY is set: signing secrets are encrypted at rest \
             (XChaCha20-Poly1305)."
        );
    } else {
        tracing::warn!(
            "VAULT_ENCRYPTION_KEY is not set: API key signing secrets are stored UNENCRYPTED. \
             Anyone who can read the database can forge request signatures. Generate a key with \
             `openssl rand -hex 32` and set VAULT_ENCRYPTION_KEY to enable encryption at rest."
        );
    }

    // Same reasoning as the encryption warning above, and with a sharper failure mode: with no
    // trusted proxies configured, a deployment that *is* behind a reverse proxy will reject every
    // request from a CIDR-bound key with 403, because every request appears to come from the proxy.
    // That is the safe direction to fail, but only if the operator is told why.
    //
    // A *malformed* entry, by contrast, is fatal: `from_env` logs one `FATAL:` line per bad entry
    // and returns here, before the database is opened and long before `prime_with_grace` runs any
    // DNS. The check is purely syntactic, so a hostname that is merely unresolvable right now is not
    // affected — that keeps the grace period, because DNS being briefly down must not crash-loop the
    // daemon.
    let trusted_proxies = simply_ip_vault::config::TrustedProxies::from_env()?;
    if trusted_proxies.is_empty() {
        tracing::warn!(
            "{} is not set: X-Forwarded-For and X-Real-IP are IGNORED and every key is matched \
             against its raw TCP peer address. This is correct for a directly-exposed deployment; \
             behind a reverse proxy you must set it, or CIDR-bound keys will be rejected.",
            simply_ip_vault::config::TRUSTED_PROXIES_ENV
        );
    } else {
        tracing::info!(
            "{} is set: forwarding headers are honoured from {} matcher(s): {:?}",
            simply_ip_vault::config::TRUSTED_PROXIES_ENV,
            trusted_proxies.matchers().len(),
            trusted_proxies.matchers()
        );
    }

    // Two-phase: migrations run to completion, on their own single-connection pool, and that pool
    // is closed — all before the application pool below is ever opened. See `src/db.rs`'s module
    // header. This is what lets a file-backed SQLite database use more than one connection next: by
    // construction, the pool opened below can never witness a DDL statement.
    tracing::info!("Running database migrations on an isolated connection...");
    simply_ip_vault::db::run_migrations_isolated(&db_url).await?;

    tracing::info!("Connecting to database...");
    // `db::connect` rather than `Database::connect`: for SQLite it builds the pool from
    // `SqliteConnectOptions` so the session pragmas apply to *every* connection as it opens.
    // Applying them afterwards through the pool reaches only whichever connection serves the
    // statement — measured, and the reason this indirection exists. See `src/db.rs`.
    let db: DatabaseConnection = simply_ip_vault::db::connect(&db_url).await?;

    // Never fatal — every failure inside is logged and swallowed. A concurrency pragma that could
    // not be applied is a performance regression; refusing to boot over it would be an outage.
    simply_ip_vault::db::apply_sqlite_pragmas(&db).await?;

    bootstrap_master_key(&db, &cipher).await?;

    verify_encryption_key(&db, &cipher).await?;

    // Resolve every configured hostname once, now, so a typo is reported at boot rather than
    // discovered as an unexplained 403 later. Detached and non-blocking: an unresolvable entry is
    // retried after a grace period and disabled meanwhile, never a reason to refuse to start.
    trusted_proxies.prime_with_grace();

    // Retention sweep for soft-deleted IP records. Its own shutdown channel, so it drains on
    // SIGTERM instead of being cancelled mid-delete.
    let (retention_tx, retention_rx) = tokio::sync::mpsc::channel::<()>(1);
    let retention_db = db.clone();
    let retention_handle = tokio::spawn(async move {
        simply_ip_vault::retention::run_retention_worker(retention_db, retention_rx).await;
    });

    // Incremental vacuum and WAL truncation every 12 hours. Same shutdown pattern as retention.
    let (maint_tx, maint_rx) = tokio::sync::mpsc::channel::<()>(1);
    let maint_db = db.clone();
    let maint_handle = tokio::spawn(async move {
        simply_ip_vault::maintenance::run_maintenance_worker(maint_db, maint_rx).await;
    });

    // Separate retention sweep for webhook delivery history — its own table, its own schedule, its
    // own shutdown channel, for the reasons `retention::run_webhook_execution_retention_worker`'s
    // doc comment gives.
    let (exec_retention_tx, exec_retention_rx) = tokio::sync::mpsc::channel::<()>(1);
    let exec_retention_db = db.clone();
    let exec_retention_handle = tokio::spawn(async move {
        simply_ip_vault::retention::run_webhook_execution_retention_worker(
            exec_retention_db,
            exec_retention_rx,
        )
        .await;
    });

    let (state, tx, worker_handle) = setup_state(db)?;

    // Fix the Master's identity before anything can be served.
    //
    // Ordering is the entire control, so it is stated here rather than left to be inferred: this
    // runs after migrations and `bootstrap_master_key` (so the master and its uniqueness index both
    // exist) and before `TcpListener::bind` (so no request can be answered against an unpinned
    // state). From this line on, `is_master` is authoritative for exactly one id, and promoting a
    // row in the live database has no runtime effect at all.
    //
    // Fatal on every failure. The three ways this fails — no master, several, or a missing
    // uniqueness index — are each a database that cannot answer "who is Master?", and a service that
    // starts anyway would answer it with whichever row a query happened to return. Refusing to start
    // is loud, immediate, and leaves the evidence intact; the alternative is a running service whose
    // most powerful credential is decided by row order.
    let master_key_id = state.master_pin.pin_at_boot(&state.db).await.map_err(|e| {
        tracing::error!("Refusing to start: {e}");
        e
    })?;
    tracing::info!(
        "Master key pinned for the life of this process: {master_key_id}. A key promoted in the \
         database from now on will be treated as an ordinary key."
    );

    let app = create_app(state);

    let addr = simply_ip_vault::config::resolve_bind_addr();
    let listener = TcpListener::bind(addr).await?;
    // Reported from the listener rather than from `addr`: with `PORT=0` the OS assigns an ephemeral
    // port, and the requested address would then be a misleading thing to log.
    let bound = listener.local_addr().unwrap_or(addr);
    tracing::info!("Simply IP Vault API listening on http://{}", bound);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Stopping background workers...");
    drop(tx);
    drop(retention_tx);
    drop(exec_retention_tx);
    drop(maint_tx);
    let _ = worker_handle.await;
    let _ = retention_handle.await;
    let _ = exec_retention_handle.await;
    let _ = maint_handle.await;

    tracing::info!("Graceful shutdown complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;
    use simply_ip_vault::crypto::{CryptoError, SecretCipher};

    /// `sqlite::memory:` — none of the pragmas `db::connect` applies matter here, only that
    /// migrations have run and a row exists to check the canary against.
    async fn seeded_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        simply_ip_vault::db::run_migrations(&db).await.expect("every migration applies");
        db
    }

    async fn insert_key_with_secret(
        db: &DatabaseConnection,
        cipher: &SecretCipher,
        signing_secret: &str,
    ) {
        use entities::api_key;
        let now = chrono::Utc::now().naive_utc();
        let model = api_key::ActiveModel {
            id: Set(Uuid::new_v4()),
            key_hash: Set(api::hash_key("irrelevant-for-this-test")),
            signing_secret: Set(Some(cipher.seal(signing_secret).expect("sealing succeeds"))),
            name: Set("Test Key".to_owned()),
            prefix: Set("testtest".to_owned()),
            bound_ips: Set(None),
            is_master: Set(false),
            can_manage_keys: Set(false),
            can_manage_webhooks: Set(false),
            can_create_groups: Set(false),
            parent_key_id: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        model.insert(db).await.expect("insert seeded key");
    }

    const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The property this task exists for: startup must refuse to proceed when the configured key
    /// cannot open a secret that is already in the database, rather than starting and deferring the
    /// failure to the first authenticated request.
    #[tokio::test]
    async fn startup_refuses_when_the_configured_key_cannot_decrypt_an_existing_record() {
        let db = seeded_db().await;
        let written_with = SecretCipher::from_hex_key(KEY_A).expect("valid key");
        insert_key_with_secret(&db, &written_with, "the-real-secret").await;

        let configured_with = SecretCipher::from_hex_key(KEY_B).expect("valid key");
        let result = verify_encryption_key(&db, &configured_with).await;

        assert!(
            result.is_err(),
            "a wrong-but-well-formed VAULT_ENCRYPTION_KEY must fail startup, not be accepted silently"
        );
    }

    /// The matching positive: the correct key must not be refused, or the canary would take down
    /// every ordinary deployment on every boot.
    #[tokio::test]
    async fn startup_proceeds_when_the_configured_key_matches_the_stored_secret() {
        let db = seeded_db().await;
        let cipher = SecretCipher::from_hex_key(KEY_A).expect("valid key");
        insert_key_with_secret(&db, &cipher, "the-real-secret").await;

        let result = verify_encryption_key(&db, &cipher).await;
        assert!(result.is_ok(), "the correct key must not be refused: {result:?}");
    }

    /// A fresh database has nothing sealed to check against yet. The canary must not treat that as
    /// a failure — it would otherwise make first boot on a brand-new deployment impossible.
    #[tokio::test]
    async fn startup_proceeds_on_a_fresh_database_with_no_sealed_secrets() {
        let db = seeded_db().await;
        let cipher = SecretCipher::from_hex_key(KEY_A).expect("valid key");

        let result = verify_encryption_key(&db, &cipher).await;
        assert!(result.is_ok(), "an empty database must not fail the canary: {result:?}");
    }

    /// Switching to `Plaintext` (unsetting `VAULT_ENCRYPTION_KEY`) against a database holding a
    /// row sealed under a real key must also be refused — the stored envelope cannot be opened
    /// without a cipher, and that is exactly the same operator mistake in the other direction.
    #[tokio::test]
    async fn startup_refuses_plaintext_mode_against_a_previously_encrypted_database() {
        let db = seeded_db().await;
        let written_with = SecretCipher::from_hex_key(KEY_A).expect("valid key");
        insert_key_with_secret(&db, &written_with, "the-real-secret").await;

        let result = verify_encryption_key(&db, &SecretCipher::Plaintext).await;
        assert!(
            result.is_err(),
            "unsetting the encryption key against an already-encrypted database must fail startup"
        );
    }

    /// The error propagated out of `verify_encryption_key` must be the crypto error itself
    /// (downcastable), not a generic string — an operator or a monitoring hook further up needs to
    /// be able to distinguish "wrong key" from any other startup failure.
    #[tokio::test]
    async fn the_refusal_is_downcastable_to_the_underlying_crypto_error() {
        let db = seeded_db().await;
        let written_with = SecretCipher::from_hex_key(KEY_A).expect("valid key");
        insert_key_with_secret(&db, &written_with, "the-real-secret").await;

        let configured_with = SecretCipher::from_hex_key(KEY_B).expect("valid key");
        let err = verify_encryption_key(&db, &configured_with).await.unwrap_err();

        assert!(
            err.downcast_ref::<CryptoError>().is_some(),
            "expected the boxed error to be a CryptoError, got: {err}"
        );
    }
}
