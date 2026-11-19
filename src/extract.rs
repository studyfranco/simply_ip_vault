//! Request extractors that make a rejection a property of the **type**, not of a handler.
//!
//! `RBAC_MODEL.md` §5 draws the distinction this module exists for: "Removing the field from the
//! payload type is required; rejecting it at the handler is not sufficient, since a later handler can
//! reintroduce the path."
//!
//! Deleting a field from a payload struct is only half of that. Serde's default is to *ignore*
//! unknown fields, so a struct without `is_master` accepts `{"is_master": true}` and silently drops
//! it — which is worse than the handler check it replaced, because nothing refuses and nothing logs.
//! `#[serde(deny_unknown_fields)]` is what turns the field's absence into a refusal, and
//! [`StrictJson`] is what turns that refusal into the same `400` the handler used to produce.

use axum::{
    Json,
    body::Bytes,
    extract::{FromRequest, Request, rejection::JsonRejection},
};
use serde::de::DeserializeOwned;

use crate::error::AppError;

/// [`Json`], with deserialization failures reported as [`AppError::InvalidInput`] (`400`) instead of
/// axum's default `422`.
///
/// # Why not just use `Json`
///
/// Two reasons, and only the second is about status codes.
///
/// The first is that a rejection carrying serde's own message is *evidence of where the refusal
/// happened*. When a payload struct denies unknown fields, the body text names the field
/// (``unknown field `is_master` ``), which a test can distinguish from a handler's hand-written
/// message. That is what lets the compliance suite assert the control lives in the type rather than
/// in a guard some future edit could drop — an assertion it could not otherwise make, since both
/// spellings produce the same status.
///
/// The second is continuity: these endpoints answered `400` for a rejected field before the check
/// moved into the type, and moving a control inward should not change what a client sees.
///
/// # Only the content errors are remapped
///
/// A blanket "every rejection becomes `400`" would be wrong, and quietly so. The router-wide body
/// limit surfaces here as a `JsonRejection` too, and collapsing it would demote `413 Payload Too
/// Large` into an indistinguishable bad request — a caller that sent 4 MiB would be told its *fields*
/// were wrong. So the remap covers exactly the two variants that mean "we read the body and would not
/// accept it", and every other rejection keeps the status axum chose.
///
/// `simply_hook_executor` passes every status through, including for a rejected field, so a payload
/// carrying `is_master` answers `422` there and `400` here. Deliberate, and the one divergence in
/// this file: this service documented `400` for that case before the control moved into the type.
pub struct StrictJson<T>(pub T);

impl<T, S> FromRequest<S> for StrictJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            // `body_text` is the human-readable form axum would have rendered itself, so the caller
            // gets serde's field-level detail rather than a generic "invalid body".
            Err(
                rejection @ (JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_)),
            ) => Err(AppError::InvalidInput(JsonRejection::body_text(&rejection))),
            Err(other) => Err(AppError::BodyRejected(
                other.status(),
                JsonRejection::body_text(&other),
            )),
        }
    }
}

/// A [`StrictJson`] whose body may be absent entirely, yielding `T::default()`.
///
/// # Why this exists rather than `Option<Json<T>>`
///
/// `DELETE /api/keys/{id}` needs it. That endpoint is a *conversation*: the first request carries no
/// body at all — it is a question, and the answer is §6's pre-flight inventory of owned entities —
/// while the resubmission carries the resolution map. Axum's `Json` rejects an empty body outright,
/// and its `Option<Json<T>>` keys on `Content-Type` rather than on emptiness, so neither expresses
/// "absent means take no action". Demanding a literal `{}` on the first request would make the
/// common case — deleting a key that owns nothing — require a body for no reason, and would break
/// every existing client, since `DELETE` has always been callable bodyless.
///
/// # Why an extractor rather than parsing `Bytes` in the handler
///
/// It replaces exactly that: `delete_api_key` took `body: axum::body::Bytes` and called
/// `serde_json::from_slice` itself. Two things were wrong with it, and neither was visible at the
/// call site. The hand-rolled parse could not be reused, so the next bodyless endpoint would copy
/// it; and being outside the extractor layer, it was the one JSON path in the service whose
/// rejection shape nothing enforced. Moving it into a type puts the decision where
/// [`StrictJson`]'s module header says such decisions belong — in the type, not in a handler a later
/// edit can quietly rewrite.
///
/// # Emptiness is decided from the bytes
///
/// Not from `Content-Type`, so a client that sends the header without a payload behaves exactly like
/// one that sends neither. Reading through [`Bytes`] keeps the request under the router's
/// [`DefaultBodyLimit`](axum::extract::DefaultBodyLimit), so the `413` control still applies here as
/// it does everywhere else — and, as in [`StrictJson`], that status is passed through rather than
/// flattened into a `400`.
pub struct OptionalStrictJson<T>(pub T);

impl<T, S> FromRequest<S> for OptionalStrictJson<T>
where
    T: DeserializeOwned + Default,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state).await.map_err(|rejection| {
            AppError::BodyRejected(rejection.status(), rejection.body_text())
        })?;

        if bytes.is_empty() {
            return Ok(Self(T::default()));
        }

        // Generic wording rather than the endpoint-specific "Invalid resolution map" the handler used
        // to produce: this type serves any bodyless-optional payload, and a message naming one
        // caller's field would be wrong for the second adopter and misleading in the meantime.
        serde_json::from_slice(&bytes).map(Self).map_err(|e| {
            AppError::InvalidInput(format!("Failed to deserialize the JSON body: {e}"))
        })
    }
}

/// `Path<T>`, with a rejected (unparseable) path segment reported as [`AppError::BodyRejected`]
/// instead of axum's default plain-text body.
///
/// # The rejection's own status is passed through, not hardcoded to `400`
///
/// `GET /api/ips/not-a-uuid` is the case this exists for, and it does answer `400` — but that is
/// axum's `PathRejection` status for a segment that fails to parse, not a constant this wrapper
/// chose. `PathRejection::MissingPathParams` is a `500`, and it means the *route* and the handler
/// disagree about how many parameters exist — a defect in this service, which must not be reported
/// to the caller as though their request were malformed. Converging on `simply_hook_executor`'s
/// `StrictPath`, which carries the identical rationale.
///
/// The message is axum's own (`rejection.body_text()`), naming the segment that failed to parse, so
/// wrapping the shape does not mean withholding the reason.
pub struct StrictPath<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for StrictPath<T>
where
    axum::extract::Path<T>:
        axum::extract::FromRequestParts<S, Rejection = axum::extract::rejection::PathRejection>,
    T: Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(value)) => Ok(Self(value)),
            Err(rejection) => {
                use axum::extract::rejection::PathRejection;
                Err(AppError::BodyRejected(
                    PathRejection::status(&rejection),
                    PathRejection::body_text(&rejection),
                ))
            }
        }
    }
}

/// `Query<T>`, with a rejected (unparseable) query string reported as [`AppError::BodyRejected`]
/// instead of axum's default plain-text body.
///
/// `?limit=abc` against a `u64` field is the shape here. Note this governs only *malformed* query
/// strings — a value that parses but fails validation is a handler's judgement and already returns
/// [`AppError::InvalidInput`], which renders correctly; the two are deliberately distinguishable
/// (same status, different body detail), and this wrapper does not blur that.
///
/// The rejection's own status is passed through rather than hardcoded, for the same reason as
/// [`StrictPath`].
pub struct StrictQuery<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for StrictQuery<T>
where
    axum::extract::Query<T>:
        axum::extract::FromRequestParts<S, Rejection = axum::extract::rejection::QueryRejection>,
    T: Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(Self(value)),
            Err(rejection) => {
                use axum::extract::rejection::QueryRejection;
                Err(AppError::BodyRejected(
                    QueryRejection::status(&rejection),
                    QueryRejection::body_text(&rejection),
                ))
            }
        }
    }
}
