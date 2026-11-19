//! Authorization guards: the single place a permission decision is *made*.
//!
//! Every function here answers one question from `RBAC_MODEL.md` and returns `Ok(())` or a refusal.
//! They hold no handler logic and touch no response type, which is what makes them reviewable
//! against the specification without reading an endpoint. R1, R2, R4, R5, R7 and §3/§5 all land here.

use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::entities::prelude::ApiKey;
use crate::entities::{api_key, api_key_group_permission};
use crate::error::AppError;

use super::GroupPermInput;

// `format_key_reference` used to live here and is now `super::support`. It renders a string for a
// log line; it decides nothing and refuses nobody, which is the boundary this module holds to. Every
// function below answers a question from the specification and returns `Ok(())` or a refusal.

/// Guards any operation whose *target* is another API key, on top of the caller's `can_manage_keys`
/// scope.
///
/// `can_manage_keys` delegates key administration; it does not delegate authority over the keys that
/// grant it. Without this check the scope was transitively equivalent to `is_master`, because every
/// destructive or re-keying operation accepted a master key as its target:
///
/// - `POST /keys/{id}/rotate` on a master key returns the **new plaintext key and signing secret**
///   in its response body — a complete, immediate takeover of the master credential.
/// - `POST /keys/{id}/rotate-secret` likewise hands back a working signing secret for that key.
/// - `PUT /keys/{id}` can rewrite a master key's `bound_ips`, relocating it to the attacker's own
///   network.
/// - `DELETE /keys/{id}` can remove the master keys that would otherwise contain the incident.
///
/// Returns `403` rather than `404`: the caller legitimately holds `can_manage_keys` and can already
/// see the key in `GET /api/keys`, so hiding its existence here would buy nothing and make a
/// legitimate operator's failure inscrutable.
/// The caller's own permission row for one group, or `None` when it has no access to it.
///
/// Master keys have no rows in `api_key_group_permissions` at all — their access is implicit — so
/// callers of this helper must special-case `is_master` *before* calling it, not after.
pub(crate) async fn caller_group_permission(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
    group_id: Uuid,
) -> Result<Option<api_key_group_permission::Model>, AppError> {
    api_key_group_permission::Entity::find()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(key_id))
                .add(api_key_group_permission::Column::GroupId.eq(group_id)),
        )
        .one(db)
        .await
        .map_err(AppError::DbError)
}

/// The `owner_key_id` to record when `creator` creates a resource.
///
/// `None` for a master, matching what `create_ip_group` already did for permission rows: a master is
/// not a tenant, it is the system, and pinning its id into `owner_key_id` would make an
/// administrative action look like a claim of ownership. A master-created resource is unowned until
/// someone is deliberately assigned, and [`guard_resource_lifecycle`] reads unowned as "Master only",
/// which is exactly the authority a master already had.
pub(crate) fn resource_owner(creator: &api_key::Model) -> Option<Uuid> {
    (!creator.is_master).then_some(creator.id)
}

/// **§3 — lifecycle authority.** Deleting or renaming a resource is restricted to the Master and the
/// designated `owner_key_id`, and to nobody else.
///
/// `RBAC_MODEL.md` §3: "Resource lifecycle actions — deleting or renaming the entity itself — are
/// restricted exclusively to Master and the designated `owner_key_id`. Holding manage rights or any
/// operational verb confers no lifecycle authority: a parent that merely uses a resource must not be
/// able to delete it."
///
/// That last clause is the whole point, and it is why this is a separate guard rather than another
/// branch inside [`guard_group_manage`]. `can_manage` is authority over a resource's **permission
/// rows** — who may read and write its contents. Lifecycle authority is over the resource's
/// **existence**. Conflating them means the key you trusted to hand out read access can also delete
/// the thing everyone was reading, and no combination of operational verbs adds up to that.
///
/// # An unowned resource is Master-only
///
/// `owner_key_id` is `NULL` on every row that predates the column, and on everything a master
/// creates. There is no owner to admit, so only the master passes — which withholds authority rather
/// than inventing it, and is recoverable in one call to the owner-reassignment endpoint.
pub(crate) fn guard_resource_lifecycle(
    caller: &api_key::Model,
    owner_key_id: Option<Uuid>,
    resource: &str,
    action: &str,
) -> Result<(), AppError> {
    if caller.is_master || owner_key_id.is_some_and(|owner| owner == caller.id) {
        return Ok(());
    }

    Err(AppError::Forbidden(format!(
        "Permission denied: only the master key or this {resource}'s owner may {action} it. \
         Managing its permissions or holding read/write/delete on its contents confers no authority \
         over the {resource} itself."
    )))
}

/// Validates an `owner_key_id` a caller asked to assign, and returns it ready to store.
///
/// No database-level foreign key backs these columns (SQLite has no `ALTER TABLE … ADD CONSTRAINT`;
/// see the migration), so the reference is checked here instead — this is the only path by which one
/// can be introduced. A master key is refused as an owner for the same reason
/// [`resource_owner`] never records one: ownership is a tenancy relationship, and the master is not a
/// tenant. `None` clears ownership, returning the resource to Master-only.
pub(crate) async fn resolve_owner_assignment(
    db: &sea_orm::DatabaseConnection,
    requested: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let Some(owner_id) = requested else {
        return Ok(None);
    };

    let owner = ApiKey::find_by_id(owner_id)
        .one(db)
        .await?
        .ok_or_else(|| AppError::InvalidInput("No such key to assign ownership to".to_owned()))?;

    if owner.is_master {
        return Err(AppError::InvalidInput(
            "The master key cannot be a resource owner; leave owner_key_id null instead, which \
             already means master-only"
                .to_owned(),
        ));
    }

    Ok(Some(owner_id))
}

/// **R2 — management of a resource is a conjunction.** The single authority test for touching *any*
/// key's permissions on one group, in either direction.
///
/// `RBAC_MODEL.md` R2: "Managing a specific resource requires holding both global `can_manage_keys`
/// AND a `can_manage = true` row for that specific resource. Neither alone is sufficient.
/// `can_manage_keys` is never a global bypass of per-resource RBAC."
///
/// Each half answers a different question, and each is useless without the other:
///
/// - `can_manage_keys` is authority over **credentials**. It says the caller may administer keys at
///   all; it says nothing about *which* groups it may reach. On its own it made per-group RBAC
///   advisory — a key scoped to one group could rewrite every other key's access to every group in
///   the installation.
/// - `can_manage` is authority over **one resource**. It says which group. On its own it admitted a
///   key holding no global scope whatsoever to rewriting other keys' credentials, which is exactly
///   the tier boundary §1 draws: a Daughter key "may never" manage resources.
///
/// `action` names the operation (`"grant"` / `"revoke"`) and appears verbatim in the client-facing
/// message, which is otherwise identical between the two paths so a caller probing them cannot tell
/// which one refused it. The message states the *rule*, never the caller's state: "you hold one half
/// but not the other" would be a usable oracle.
///
/// # What this replaced, and why the previous split was wrong
///
/// Until now grant and revoke were gated differently on purpose: revocation accepted `can_manage`
/// alone, on the reasoning that removing a verb cannot raise anyone's authority and so needs no
/// anti-escalation proof. That reasoning is sound as far as it goes, and it is not what R2 governs.
/// Revocation is an **integrity** operation — stripping the credential another tenant's `fail2ban`
/// writes with stops that tenant's blocking, and the symptom sits several audit-log pages from the
/// cause — and R2's answer is that authority over *anyone's* credentials, in either direction, starts
/// at `can_manage_keys`. The resource-scoped half then bounds it to one group. R6 still holds and is
/// unchanged: the revoker need not hold the verb being removed, and may revoke its own permissions.
pub(crate) fn guard_group_manage(
    caller: &api_key::Model,
    caller_perm: Option<&api_key_group_permission::Model>,
    group_name: &str,
    action: &str,
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }

    if caller.can_manage_keys && caller_perm.is_some_and(|p| p.can_manage) {
        return Ok(());
    }

    Err(AppError::Forbidden(format!(
        "Permission denied: you cannot {action} permissions on group '{group_name}'. Managing a \
         group's permissions requires both the global can_manage_keys scope and can_manage = true \
         on your own grant for that group; neither alone is sufficient."
    )))
}

/// Whether the caller holds a `can_manage` row on **any** group.
///
/// A cheap pre-gate, run before any group is resolved so that a caller with no administrative
/// standing at all is refused without learning whether a group or a grant exists. It is deliberately
/// the *weaker* half of [`guard_group_manage`] — "does this caller administer anything?" — because a
/// pre-gate that consulted the target group would make the `403` depend on what exists. The precise
/// test runs later, once the group is known.
pub(crate) async fn holds_any_group_manage(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
) -> Result<bool, AppError> {
    api_key_group_permission::Entity::find()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(key_id))
                .add(api_key_group_permission::Column::CanManage.eq(true)),
        )
        .one(db)
        .await
        .map(|found| found.is_some())
        .map_err(AppError::DbError)
}

/// The pre-gate both permission-administration endpoints run before touching any group.
///
/// Both halves of R2 are checked here in their group-independent form — `can_manage_keys` costs
/// nothing, and the `can_manage`-anywhere lookup is one indexed query issued only for callers that
/// already passed the first half. A caller failing this is refused without a single lookup against
/// the group or the target key, which is what keeps the `403` from confirming that either exists.
pub(crate) async fn guard_may_administer_any_group(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }

    if caller.can_manage_keys && holds_any_group_manage(db, caller.id).await? {
        return Ok(());
    }

    Err(AppError::Forbidden("Permission denied".to_owned()))
}

/// Whether `requested` would give the target any verb it does not already hold.
///
/// This is the question that decides **which gate applies** to an update, and it is deliberately
/// asked against the *target's* current row rather than the caller's: "does this raise anyone's
/// authority?" is a different question from "does this exceed the caller's own?" (the latter is
/// [`guard_delegated_group_grant`]'s anti-escalation check, which still applies to grants).
///
/// A row that does not exist yet counts as a grant regardless of its contents, matching `AGENT.MD`
/// §2 — creating a permission row is an act of conferral even when the verbs start empty, and a
/// resource-scoped `can_manage` must not be able to mint rows.
pub(crate) fn widens_permissions(
    requested: &GroupPermInput,
    target_perm: Option<&api_key_group_permission::Model>,
) -> bool {
    let Some(held) = target_perm else {
        return true;
    };
    (requested.capabilities.can_read && !held.can_read)
        || (requested.capabilities.can_write && !held.can_write)
        || (requested.capabilities.can_delete && !held.can_delete)
        || (requested.can_manage && !held.can_manage)
}

/// **R1 + R7 — granting is bounded by non-amplification on top of the R2 conjunction.**
///
/// Layered on [`guard_group_manage`]: R2 is necessary to touch a group's grants at all, and
/// *additionally* each verb being conferred is checked independently against the caller's own row —
/// holding `can_read` on a group does not confer the right to grant `can_write` on it. R7 states
/// exactly this composition: "Granting is bounded by R1 and R2 together, simultaneously and without
/// exception."
///
/// # Only the granting direction is checked per verb
///
/// `over_grants` tests `requested && !held`, so a verb being set to **false** is never examined.
/// Reducing a permission therefore needs no proof of authority over the verb removed, which is R6:
/// "the revoker need not hold the verb being removed". That asymmetry with granting is the whole
/// point — conferring a verb can raise someone's authority above the caller's own, and removing one
/// cannot raise anyone's at all. The dedicated revoke route applies the same rule, so "revoke the
/// row" and "update the row to a lower value" are governed identically rather than by two rules that
/// happen to disagree (R6, final sentence).
pub(crate) fn guard_delegated_group_grant(
    caller: &api_key::Model,
    caller_perm: Option<&api_key_group_permission::Model>,
    group_name: &str,
    action: &str,
    requested: &GroupPermInput,
) -> Result<(), AppError> {
    guard_group_manage(caller, caller_perm, group_name, action)?;

    if caller.is_master {
        return Ok(());
    }

    // Guaranteed `Some` by the R2 gate above, which refuses a non-master holding no `can_manage` row.
    // Fails **closed** rather than returning `Ok`: this branch is unreachable today, and the one way
    // it becomes reachable is a future edit that loosens the gate — at which point "unreachable" and
    // "grants everything unchecked" would be one refactor apart.
    let Some(held) = caller_perm else {
        return Err(AppError::Forbidden(format!(
            "Permission denied: you cannot {action} permissions on group '{group_name}'"
        )));
    };

    let over_grants = (requested.capabilities.can_read && !held.can_read)
        || (requested.capabilities.can_write && !held.can_write)
        || (requested.capabilities.can_delete && !held.can_delete)
        // `can_manage` is a verb like any other here: a caller may only confer the administrative
        // right over a group if it holds that right itself. Redundant against the R2 gate as written
        // — a non-master reaching this line necessarily holds `can_manage` — and kept because R1
        // states the rule per verb, and a verb list that quietly omits one is how the next verb added
        // to this table gets forgotten. It is also what implements R5: manage may propagate sideways
        // between parents, bounded by R1 and R2, and never upward to a daughter (which the
        // conjunction blocks, since the recipient still needs `can_manage_keys`).
        || (requested.can_manage && !held.can_manage);

    if over_grants {
        tracing::warn!(
            "Blocked privilege delegation: key {} attempted to {} permissions on group '{}' \
             exceeding its own (read={} write={} delete={})",
            caller.prefix,
            action,
            group_name,
            held.can_read,
            held.can_write,
            held.can_delete
        );
        return Err(AppError::Forbidden(format!(
            "Permission denied: you cannot {action} permissions on group '{group_name}' beyond your own"
        )));
    }

    Ok(())
}

/// **R4 — only Master creates parents.** Every global scope, and only a master key may hand any of
/// them out.
///
/// `RBAC_MODEL.md` R4: "Only the Master key may grant `can_manage_keys` or resource-creation rights.
/// A parent key can never mint another parent key." §1 puts resource-creation rights "at the same
/// tier as `can_manage_keys`", granted strictly by Master and "never implied by `can_manage_keys`" —
/// managing keys and being able to point a dispatch target at an arbitrary URL are separate powers.
///
/// `is_master` is **not** on this list, because it is no longer grantable by anyone: §5 makes master
/// status a bootstrap-only property, and neither key payload can express the field at all — the
/// structs omit it and deny unknown fields, so serde refuses the request before any scope is
/// considered. A scope nobody can request does not need a rule about who may request it.
///
/// Each entry is a *path back to* master authority rather than a leaf capability:
///
/// - `can_manage_keys` is the scope that reaches every other key — granting it creates a second
///   administrator, so a non-master able to grant it could multiply itself without limit and, in
///   combination with any future gap in [`guard_master_target`], reach a master key.
/// - `can_create_groups` mints managed resources whose creator is auto-granted full read/write/delete
///   (`AGENT.MD` §2), which is the one way to obtain group access without a master signing off.
/// - `can_manage_webhooks` mints dispatch targets. This service's spelling of the specification's
///   `can_create_webhooks`, and the last of the three to be locked down: it was previously delegable
///   on the reasoning that it "confers no authority over keys or groups". That reasoning was too
///   narrow. A webhook is a standing export of everything that happens in a group to a URL its
///   creator chooses, and the scope was freely amplifiable — a parent that did **not** hold it could
///   hand it out (R1's plainest violation, since a caller may only grant rights it holds itself).
///
/// Because every global scope is now master-only, R1's "may only grant rights it currently holds"
/// is satisfied for globals by the strictly stronger R4: a non-master grants none of them at all.
pub(crate) const MASTER_ONLY_SCOPES: [&str; 3] = [
    "can_manage_keys",
    "can_create_groups",
    "can_manage_webhooks",
];

/// Rejects any attempt by a non-master to grant one of [`MASTER_ONLY_SCOPES`].
///
/// `held` describes the target's current values, so this permits a no-op re-submission of a scope
/// the target already has (an idempotent `PUT` from a dashboard that posts every field) while still
/// refusing an actual elevation. Revoking is always allowed — removing authority is not escalation.
pub(crate) fn guard_scope_elevation(
    caller: &api_key::Model,
    requested: [Option<bool>; 3],
    held: [bool; 3],
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }

    for ((request, current), name) in requested
        .iter()
        .zip(held.iter())
        .zip(MASTER_ONLY_SCOPES.iter())
    {
        if *request == Some(true) && !*current {
            tracing::warn!(
                "Blocked privilege escalation: key {} attempted to grant {}",
                caller.prefix,
                name
            );
            return Err(AppError::Forbidden(format!(
                "Only a master key can grant '{name}'"
            )));
        }
    }
    Ok(())
}

pub(crate) fn guard_master_target(
    caller: &api_key::Model,
    target: &api_key::Model,
) -> Result<(), AppError> {
    if target.is_master && !caller.is_master {
        tracing::warn!(
            "Blocked privilege escalation: key {} (master=false) attempted to operate on master key {}",
            caller.prefix,
            target.prefix
        );
        return Err(AppError::Forbidden(
            "Only a master key can modify, rotate, or delete another master key".to_owned(),
        ));
    }
    Ok(())
}

/// The refusal `RBAC_MODEL.md` §5 requires for every API operation on the Master key that is not an
/// edit of its own `bound_ips`.
///
/// "The Master key is immutable through the API **except for its own `bound_ips`** […] No other
/// field, permission, or rotation is reachable through the API," and "The Master key cannot be
/// deleted through the API." That covers deletion, both rotation endpoints, and every field of the
/// generic update except one — so the operations are named in the message rather than the caller
/// being left to guess which of several checks refused it.
///
/// This is strictly stronger than [`guard_master_target`], which only ever blocked *non*-masters and
/// therefore left the Master free to rotate, rename and re-scope itself. Uniqueness (§5, enforced by
/// the unique index over the engine-derived `master_marker`) means "the Master key" is unambiguous:
/// there is no second master for this to be relative to.
///
/// The dependency runs one way only. §5 requires that the Master's undeletability "must not rest on
/// the uniqueness constraint holding", and it does not: this guard refuses on the target row's own
/// `is_master`, so it would refuse each of two masters independently if a database ever held two.
///
/// # Why rotation is refused too, when it looks like routine hygiene
///
/// It reads like a regression — the one credential most worth rotating is the one that now cannot
/// be. But `POST /keys/{id}/rotate` returns the new plaintext in its response body, so an API-reachable
/// master rotation is an API-reachable way to *mint a working master credential* from any session
/// that already has one. The specification's answer is to take the operation out of the API surface
/// entirely: delete the row directly in the database and the service re-mints at next boot
/// (`bootstrap_master_key`). That is a deliberate trade of convenience for a smaller blast radius,
/// and it requires database access, which an HTTP-only compromise does not have.
pub(crate) fn guard_master_immutable(
    target: &api_key::Model,
    operation: &str,
) -> Result<(), AppError> {
    if !target.is_master {
        return Ok(());
    }

    tracing::warn!(
        "Blocked master mutation: attempt to {} master key {}",
        operation,
        target.prefix
    );
    Err(AppError::Forbidden(format!(
        "The master key is immutable through the API and cannot be {operation}. Only its own \
         bound_ips may be edited, by itself. To re-mint it, delete the row directly in the database \
         and restart the service."
    )))
}
