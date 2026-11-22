//! The `webhook_executions` table: one row per outbound HTTP attempt a webhook dispatch makes,
//! including retries. The delivery history behind the dashboard's "Executions" tab.

use sea_orm::entity::prelude::{TimeDateTime as DateTime, *};
use serde::{Deserialize, Serialize};

/// One HTTP attempt's outcome, on the way to or from `webhook_configs`.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "webhook_executions")]
pub struct Model {
    /// Unique execution row ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The webhook this attempt was dispatched for. `ON DELETE CASCADE` — see the migration's
    /// module header for why this row has no useful existence once its webhook is gone.
    pub webhook_id: Uuid,
    /// `IP_ADD`, `IP_UPDATE`, `IP_DELETE` (matching `webhook_configs.events`/`audit_logs.action`'s
    /// vocabulary), or `TEST` for a live "Test Webhook" dispatch.
    pub event_type: String,
    /// The HTTP status code received, if a response was received at all. `None` for a network-level
    /// failure (timeout, connection refused, DNS failure) — [`dispatch::DispatchOutcome`]'s own
    /// `status: Option<u16>` maps onto this column exactly.
    ///
    /// [`dispatch::DispatchOutcome`]: crate::dispatch::DispatchOutcome
    pub status_code: Option<i32>,
    /// Whether the receiver answered with a `2xx` status. The column the retention sweep and the
    /// executions listing's status filter both read — `status_code` is diagnostic detail, this is
    /// the outcome.
    pub is_success: bool,
    /// Wall-clock duration of this one HTTP attempt, in milliseconds. Not cumulative across
    /// retries — each retry attempt is its own row.
    pub duration_ms: i32,
    /// Whatever the receiver said back, truncated (see `dispatch::RESPONSE_SNIPPET_MAX_BYTES`) —
    /// captured on **every** attempt that reached the network, success or failure alike, not only
    /// failures. `None` only when no response was ever received at all (a network-level error,
    /// timeout, or DNS failure), in which case the failure reason is stored here instead — there is
    /// no body to have kept in that case. Renamed from `error_message` by
    /// `m20260824_110000_webhook_execution_response_body`; see that migration's module header.
    pub response_body: Option<String>,
    /// The fully resolved destination this attempt actually dialed — every `$variable` in
    /// `webhook_configs.target_url` already expanded against the triggering event (see
    /// `dispatch::resolve_event_variables`). May differ from the *current* `webhook_configs.target_url`
    /// even for an unedited webhook, whenever the template itself varies per event. `None` on rows
    /// from before `m20260824_140000_webhook_execution_event_context`, which predate the concept.
    pub resolved_target_url: Option<String>,
    /// The address the triggering event concerned — `WebhookEvent::address` at the moment this
    /// attempt was dispatched. `None` on rows predating the same migration as `resolved_target_url`.
    pub target_address: Option<String>,
    /// The triggering event's freeform cause, if it had one. `None` either because the event carried
    /// no cause or because this row predates the migration that added the column — the two are not
    /// distinguished, matching how every other nullable column on this table already treats
    /// "unknown" and "genuinely absent" as one state rather than two.
    pub cause: Option<String>,
    /// When this attempt was made.
    #[serde(with = "crate::time_serde")]
    pub created_at: DateTime,
}

/// Relations from `webhook_executions` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The webhook this attempt was dispatched for.
    #[sea_orm(
        belongs_to = "super::webhook_config::Entity",
        from = "Column::WebhookId",
        to = "super::webhook_config::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    WebhookConfig,
}

impl Related<super::webhook_config::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WebhookConfig.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
