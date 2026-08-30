//! Code-first OpenAPI 3.1 document for the VENDOR EXTENSION surface
//! (`x-*`) of the machine-manager SOVD servers.
//!
//! Generated with `utoipa` from the actual handlers/types in [`super::routes`]
//! and [`super::pull_update`] (plus the three SOVDd-resident `x-ota-*` update
//! verbs, declared here as path carriers because their handlers live in
//! SOVDd). The ISO 17978-3 base surface is deliberately NOT annotated — the
//! document delegates it by reference (see the `info.description`).
//!
//! Two consumers:
//!   * `docs/openapi-extensions.json` — the committed, reviewable subset, kept
//!     current by `tests/openapi_current.rs` (`UPDATE_OPENAPI=1` rewrites it).
//!   * the live `GET /vehicle/v1/docs` capability description — the vendor
//!     paths + schemas are contributed to SOVDd's §7.5 document via its neutral
//!     `CapabilityExtensions` hook (see [`capability_extensions`]).

/// The bearer security scheme (`x-ota-pull-update` is the only op that
/// requires it; the dev/sim binary defaults to open auth).
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "sumo-machine-manager SOVD — vendor extensions (x-*)",
        description = "OpenAPI 3.1 description of the VENDOR EXTENSION surface (the `x-*` \
operations) exposed by the sumo-machine-manager SOVD servers. Every operation here is a vendor \
extension per the ISO 17978-1 extension rules — none is part of the ISO 17978-3 base surface, \
which this document deliberately does NOT annotate. For the ISO 17978-3 surface see the standard's \
own OpenAPI artifact (ISO 17978-3 ed.1 `openapi-specification-1.1.0-rc1.zip`, \
https://standards.iso.org/iso/17978/-3/ed-1/en/) and the sumo conformance file \
`docs/sovd_iso17978_spec.yaml` in the sumo-workspace (the 42/57 baseline). Auth: only \
`x-ota-pull-update` (POST) requires a bearer token (an Operational `update:execute` JWT bound to \
the device); the dev/sim `vm-sovd` binary defaults to open auth, so the requirement is advisory \
there."
    ),
    tags(
        (name = "x-extensions", description = "vendor extensions to ISO 17978-3 (the x-* operations).")
    ),
    paths(
        super::routes::update_state,
        super::routes::hsm_keys_list,
        super::routes::hsm_csr_execute,
        super::routes::device_id,
        super::routes::commit_trials,
        super::routes::rollback_trials,
        super::pull_update::handle_post,
        super::pull_update::get_pull_update_status,
        doc::x_ota_commit,
        doc::x_ota_rollback,
        doc::x_ota_force_rollback,
    ),
    components(schemas(
        super::routes::UpdateStateResponse,
        super::routes::HsmKeyEntry,
        super::routes::HsmKeysResponse,
        super::routes::CsrRequest,
        super::routes::CsrResult,
        super::routes::VerdictRequest,
        super::pull_update::PullUpdateRequest,
        sovd_core::OperationStatus,
        sovd_core::OperationExecution,
        super::routes::VerdictExecution,
    )),
    modifiers(&SecurityAddon)
)]
struct XExtensionsApi;

/// The in-process vendor-extension OpenAPI document; `info.version` is pinned to
/// the crate version.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <XExtensionsApi as utoipa::OpenApi>::openapi();
    doc.info.version = env!("CARGO_PKG_VERSION").to_string();
    // The crate declares no license; drop the empty `license.name` utoipa
    // synthesizes from Cargo metadata rather than ship it in the artifact.
    doc.info.license = None;
    doc
}

/// The committed-artifact rendering: pretty JSON with a trailing newline. Key
/// order is stable across runs (utoipa emits sorted schema maps), so a
/// byte-equality regen test is meaningful.
pub fn openapi_json_pretty() -> String {
    let mut s = serde_json::to_string_pretty(&openapi()).expect("OpenApi serializes to JSON");
    s.push('\n');
    s
}

/// The vendor paths + schemas as a SOVDd capability-description extension,
/// registered on `sovd_api::AppState` so the merged `GET /vehicle/v1/docs`
/// advertises them.
// TODO(openapi-docs): the pinned `sovd-api` git dep does not yet carry the
// `CapabilityExtensions` hook, so this is gated off by default; drop the gate
// after the SOVDd lock bump lands the hook.
#[cfg(feature = "sovd-docs-hook")]
pub fn capability_extensions() -> sovd_api::CapabilityExtensions {
    let doc = serde_json::to_value(openapi()).expect("OpenApi serializes to JSON");
    sovd_api::CapabilityExtensions::from_openapi(&doc)
}

pub(crate) mod doc {
    //! Path carriers for the SOVDd-resident vendor routes: their handlers live
    //! in SOVDd's `sovd-api`, so these zero-body fns exist only to attach the
    //! path items to the generated document — they are never called.
    #![allow(dead_code)]

    /// Path carrier — handler lives in SOVDd (`sovd-api` updates.rs).
    #[utoipa::path(
        put,
        path = "/vehicle/v1/components/{component_id}/updates/{update_id}/x-ota-commit",
        tag = "x-extensions",
        params(
            ("component_id" = String, Path, description = "Target component."),
            ("update_id" = String, Path, description = "The /updates entry; must be paused at execute/awaiting-verdict."),
        ),
        responses(
            (status = 202, description = "Commit verdict posted; poll .../status.", headers(("Location" = String, description = "URL of the update status resource."))),
            (status = 409, description = "The update is not paused at awaiting-verdict."),
        ),
    )]
    pub(crate) fn x_ota_commit() {}

    /// Path carrier — handler lives in SOVDd (`sovd-api` updates.rs).
    #[utoipa::path(
        put,
        path = "/vehicle/v1/components/{component_id}/updates/{update_id}/x-ota-rollback",
        tag = "x-extensions",
        params(
            ("component_id" = String, Path, description = "Target component."),
            ("update_id" = String, Path, description = "The /updates entry; must be paused at execute/awaiting-verdict."),
        ),
        responses(
            (status = 202, description = "Rollback verdict posted; poll .../status.", headers(("Location" = String, description = "URL of the update status resource."))),
            (status = 409, description = "The update is not paused at awaiting-verdict."),
        ),
    )]
    pub(crate) fn x_ota_rollback() {}

    /// Path carrier — handler lives in SOVDd (`sovd-api` updates.rs).
    #[utoipa::path(
        put,
        path = "/vehicle/v1/components/{component_id}/x-ota-force-rollback",
        tag = "x-extensions",
        params(
            ("component_id" = String, Path, description = "Target component."),
        ),
        responses(
            (status = 204, description = "Backend trial state cleared unconditionally (idempotent)."),
        ),
    )]
    pub(crate) fn x_ota_force_rollback() {}
}
