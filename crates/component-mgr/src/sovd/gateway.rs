//! In-guest federating SOVD gateway composition.
//!
//! The gateway is the guest's single SOVD front door: it serves the onboard
//! pull-update operation + the guest's own component resources, and proxies
//! host-owned components to the host SOVD. This module owns the **pure router
//! assembly**. Constructing the host proxy backends is async + needs the live
//! host SOVD (`SovdProxyBackend::new` fetches entity info at construction), so
//! that is a startup concern: the deploying binary builds the
//! `sovd_proxy::SovdProxyBackend` entries and passes them in via `backends`.
//! Each proxy impls `DiagnosticBackend`, so a proxied host component is simply
//! another entry in the SOVD entity map — federation falls out of the map.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use machine_mgr::Machine;
use sovd_api::{create_router, AppState, Authorizer};
use sovd_core::DiagnosticBackend;

use crate::sovd::admin_state::admin_state_router;
use crate::sovd::routes::{hsm_router, node_verdict_router, pull_update_router};

/// Build the in-guest federating gateway router.
///
/// `backends` is the SOVD entity map — the guest's own component backends PLUS
/// any host-owned components registered as proxy backends (proxying to the host
/// SOVD). Both local and proxied entries are served uniformly by
/// [`create_router`]; that is the federation.
///
/// Authorization is **route-scoped**: only the onboard pull-update and
/// admin-state routes enforce a token (inline, via `authorizer`), so we
/// deliberately do NOT flip on the global `create_router` authorizer — the
/// rest of the surface keeps its current behaviour (the separate,
/// already-tracked global-enforcement migration owns that). `trust_anchor` is
/// the device's pinned manifest-signing key (verifies every fetched campaign
/// dependency) — resolved once at gateway construction, since a guest gateway
/// only starts on a provisioned device.
pub fn gateway_router(
    machine: Arc<dyn Machine>,
    backends: HashMap<String, Arc<dyn DiagnosticBackend>>,
    authorizer: Arc<dyn Authorizer>,
    trust_anchor: Vec<u8>,
) -> Router {
    let anchor: crate::sovd::pull_update::TrustAnchorSource =
        Arc::new(move || Some(trust_anchor.clone()));
    create_router(AppState::new(backends))
        .merge(hsm_router(machine.clone()))
        .merge(node_verdict_router(machine.clone()))
        .merge(admin_state_router(machine.clone(), authorizer.clone()))
        .merge(pull_update_router(machine, authorizer, anchor))
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use machine_mgr::{Capabilities, Component, EntityInfo, MachineRegistry};
    use tower::ServiceExt;

    use crate::sovd::authz::TieredAuthorizer;

    /// A no-op component so the Machine has an entity to resolve.
    struct BareStub {
        caps: Capabilities,
    }

    #[async_trait]
    impl Component for BareStub {
        fn id(&self) -> &str {
            "vm1"
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
    }

    fn test_machine() -> Arc<dyn Machine> {
        Arc::new(
            MachineRegistry::builder(EntityInfo {
                id: "vehicle".into(),
                name: "vehicle".into(),
                entity_type: "vehicle".into(),
                description: None,
                href: "/vehicle/v1".into(),
                status: None,
            })
            .with_arc(Arc::new(BareStub {
                caps: Capabilities::default(),
            }) as Arc<dyn Component>)
            .build(),
        )
    }

    /// The gateway wires the onboard pull-update route AND its route-scoped
    /// authz: a tokenless request is rejected (401) before any install — proving
    /// the route is reachable through the composed gateway and the inline
    /// authorizer runs.
    #[tokio::test]
    async fn gateway_enforces_authz_on_pull_update() {
        let authorizer: Arc<dyn Authorizer> = Arc::new(TieredAuthorizer::new(Vec::new()));
        let router = gateway_router(
            test_machine(),
            HashMap::new(),
            authorizer,
            b"anchor".to_vec(),
        );

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/vehicle/v1/operations/x-sumo-pull-update/executions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"component":"vm1","l1_base64":"","cas_base_url":"http://localhost"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Same proof for the admin-state route: reachable through the composed
    /// gateway (so vm-sovd's `--gateway` serves it) with its route-scoped
    /// authz running — a tokenless disable is 401, never executed.
    #[tokio::test]
    async fn gateway_enforces_authz_on_admin_state() {
        let authorizer: Arc<dyn Authorizer> = Arc::new(TieredAuthorizer::new(Vec::new()));
        let router = gateway_router(
            test_machine(),
            HashMap::new(),
            authorizer,
            b"anchor".to_vec(),
        );

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/vehicle/v1/components/vm1/operations/x-sumo-admin-state/executions")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"state":"disabled"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
