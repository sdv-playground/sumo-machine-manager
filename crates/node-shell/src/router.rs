//! The router the node serves: SOVDd's, the binary's vendor routes and the
//! node-level routes, wrapped once in the node topology.

use std::sync::Arc;

use axum::response::IntoResponse;

/// The 202 a node-level `PUT {base}/status/restart` answers on `tree`, built
/// before the reset happens. `/v1` (ISO 17978-3 §7.19.4): no body, `Location`
/// to the server's `status` (`/v1/status`; the node's
/// `/v1/components/{node}/status` on a node server), where readiness is read.
/// Legacy: the vendor body with `status: running` — the reset has not happened
/// when the response leaves — and `Location`/`href` to the
/// `status/restart/{exec_id}` stub.
pub fn restart_response(
    tree: sovd_api::Tree,
    exec_id: &str,
    message: &str,
) -> (
    axum::http::StatusCode,
    axum::http::HeaderMap,
    Option<serde_json::Value>,
) {
    let (location, body) = if tree == sovd_api::Tree::V1 {
        (format!("{}/status", sovd_api::Tree::V1.server()), None)
    } else {
        let href = format!("{}/status/restart/{exec_id}", tree.base());
        let body = serde_json::json!({
            "status": "running",
            "exec_id": exec_id,
            "message": message,
            "href": href,
        });
        (href, Some(body))
    };
    let mut headers = axum::http::HeaderMap::new();
    if let Ok(v) = axum::http::HeaderValue::from_str(&location) {
        headers.insert(axum::http::header::LOCATION, v);
    }
    (axum::http::StatusCode::ACCEPTED, headers, body)
}

/// Mount the `GET {base}/status/restart/{exec_id}` stub the legacy body's
/// `href` names — on the legacy tree only: it is not an ISO resource, a `/v1`
/// client reads `GET /v1/status`.
fn mount_restart_status_stub(router: axum::Router, tree: sovd_api::Tree) -> axum::Router {
    if tree != sovd_api::Tree::Legacy {
        return router;
    }
    router.route(
        &format!("{}/status/restart/{{exec_id}}", tree.base()),
        axum::routing::get(
            |axum::extract::Path(exec_id): axum::extract::Path<String>| async move {
                // Stateless status stub — entity restart is fire-and-forget
                // (mirrors sovd-api/handlers/reset.rs::status_restart_execution).
                // By the time it is reachable the process has restarted, so
                // `completed` is truthful.
                axum::Json(serde_json::json!({
                    "status": "completed",
                    "exec_id": exec_id,
                }))
            },
        ),
    )
}

/// `GET /v1/status` — the node's status (ISO 17978-3 §7.19.2, Table 280) in
/// the body SOVDd serves for a component: `status` is `notReady` once a
/// `status/restart` was accepted (the reset is under way; a fresh process is
/// `ready`), `restart` links the node's `status/restart`, and `x-runtime`
/// carries `node_boot_id` — the boot id `status/x-boot-id` serves, as on
/// every component's status — so a tester sees the reboot happened.
fn node_status(
    boot_id: &str,
    restart_accepted: Arc<std::sync::atomic::AtomicBool>,
) -> axum::routing::MethodRouter {
    let boot_id = boot_id.to_string();
    axum::routing::get(move || {
        let restarting = restart_accepted.load(std::sync::atomic::Ordering::Relaxed);
        let mut extensions = serde_json::Map::new();
        extensions.insert(
            "x-runtime".into(),
            serde_json::json!({ "node_boot_id": boot_id }),
        );
        let body = sovd_core::EntityStatusBody {
            status: if restarting {
                sovd_core::EntityStatus::NotReady
            } else {
                sovd_core::EntityStatus::Ready
            },
            restart: vec![format!("{}/status/restart", sovd_api::Tree::V1.server())],
            extensions,
            ..Default::default()
        };
        async move { axum::Json(body) }
    })
}

/// The router a node serves: SOVDd's over `state`, the binary's `vendor`
/// routes, and the node-level routes at their root form on both trees —
/// `GET status/x-boot-id`, `POST operations/factory-reset/executions` (when
/// `factory_reset` is given; it builds the handler for the route's path),
/// `PUT status/restart` (`restart` builds its handler per tree, e.g.
/// [`restart_route`]) and the legacy restart-status stub — plus, on `/v1`
/// only, `GET status` (the node status, authorized by SOVDd's auth layer as a
/// component's status read is), wrapped once, outermost, in the node topology
/// (a no-op without a node).
///
/// Through a node, status (`x-boot-id` included), restart and factory reset
/// are reached at `/v1/components/{node}/…` and their root forms answer 404.
pub fn sovd_router(
    state: &sovd_api::AppState,
    vendor: axum::Router,
    boot_id: &str,
    factory_reset: Option<impl Fn(&str) -> axum::routing::MethodRouter>,
    restart: impl Fn(sovd_api::Tree) -> axum::routing::MethodRouter,
) -> axum::Router {
    let mut router = sovd_api::create_router(state.clone()).merge(vendor);
    let restart_accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let boot_id_get = axum::routing::get({
        let b = boot_id.to_string();
        move || {
            let b = b.clone();
            async move { b }
        }
    });
    for tree in sovd_api::Tree::ALL {
        router = router.route(
            &format!("{}/status/x-boot-id", tree.base()),
            boot_id_get.clone(),
        );
        // ECU-level operation per ISO 17978-3 §7.14 (operations.executions).
        // A factory reset is a whole-ECU op, not a component's — same
        // reasoning that put status/restart at the entity root
        // (`PUT /vehicle/v1/status/restart`). POST creates an execution.
        if let Some(factory_reset) = &factory_reset {
            let path = format!("{}/operations/factory-reset/executions", tree.base());
            router = router.route(&path, factory_reset(&path));
        }
        // A 202 means the reset is under way: the node status says so.
        let accepted = restart_accepted.clone();
        let restart = restart(tree).layer(axum::middleware::map_response(
            move |resp: axum::response::Response| {
                if resp.status() == axum::http::StatusCode::ACCEPTED {
                    accepted.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                async move { resp }
            },
        ));
        router = router.route(&format!("{}/status/restart", tree.base()), restart);
        router = mount_restart_status_stub(router, tree);
    }
    router = router.route(
        &format!("{}/status", sovd_api::Tree::V1.base()),
        node_status(boot_id, restart_accepted).route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            sovd_api::auth::require_auth,
        )),
    );
    sovd_api::with_node_topology(router, state)
}

/// The reason carried by an authorizer denial — `AuthError` has no `Display`.
/// The 401/403 split is not used here: denials stay 403 as before.
pub fn auth_error_message(e: &sovd_api::AuthError) -> &str {
    match e {
        sovd_api::AuthError::Unauthenticated(m) | sovd_api::AuthError::Forbidden(m) => m,
    }
}

/// The node's restart, for [`sovd_router`]'s `restart`: `PUT
/// {base}/status/restart` on `tree`, authorized by `authz` as a
/// HighConsequence `ResetExecute` (ISO 17978-3 §5.4.4) — a denial is 403
/// `restart denied: <reason>` — then `reset`, and the 202 of
/// [`restart_response`] with the message `reset` returns. `reset` is the
/// node's: it runs before the response leaves, so it schedules the teardown
/// and the reset (a detached task) rather than running them.
pub fn restart_route(
    tree: sovd_api::Tree,
    authz: Arc<dyn sovd_api::Authorizer>,
    reset: Arc<dyn Fn() -> &'static str + Send + Sync>,
) -> axum::routing::MethodRouter {
    let restart_path = format!("{}/status/restart", tree.base());
    axum::routing::put(move |headers: axum::http::HeaderMap| {
        let authz = authz.clone();
        let path = restart_path.clone();
        let reset = reset.clone();
        async move {
            // Auth: a HighConsequence ResetExecute token bound to this
            // ECU's id (ISO 17978-3 §5.4.4) — same model as factory-reset.
            let bearer = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            let req = sovd_api::AccessRequest {
                bearer,
                method: &axum::http::Method::PUT,
                path: &path,
                component: None,
                capability: sovd_api::Capability::ResetExecute,
            };
            if let Err(e) = authz.authorize(&req).await {
                let e = auth_error_message(&e);
                tracing::warn!("ECU restart denied: {e}");
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    format!("restart denied: {e}\n"),
                )
                    .into_response();
            }
            tracing::warn!("ECU restart requested via PUT {path}");
            // The 202 is per tree (restart_response): ISO 17978-3 §7.19.4 on
            // /v1, the vendor body on legacy. It leaves before the teardown
            // and reset, which `reset` schedules.
            let exec_id = uuid::Uuid::new_v4().to_string();
            let message = reset();
            match restart_response(tree, &exec_id, message) {
                (status, headers, Some(body)) => {
                    (status, headers, axum::Json(body)).into_response()
                }
                (status, headers, None) => (status, headers).into_response(),
            }
        }
    })
}

#[cfg(test)]
mod restart_tests {
    use super::{mount_restart_status_stub, restart_response};
    use axum::http::{header, StatusCode};
    use sovd_api::Tree;

    #[test]
    fn v1_restart_is_202_location_status_no_body() {
        let (status, headers, body) = restart_response(Tree::V1, "e1", "m");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(headers.get(header::LOCATION).unwrap(), "/v1/status");
        assert_eq!(headers.len(), 1, "nothing but Location");
        assert!(body.is_none());
    }

    #[test]
    fn legacy_restart_is_202_running() {
        let (status, headers, body) = restart_response(Tree::Legacy, "e1", "m");
        assert_eq!(status, StatusCode::ACCEPTED);
        let href = "/vehicle/v1/status/restart/e1";
        assert_eq!(headers.get(header::LOCATION).unwrap(), href);
        assert_eq!(
            body.unwrap(),
            serde_json::json!({
                "status": "running",
                "exec_id": "e1",
                "message": "m",
                "href": href,
            })
        );
    }

    #[tokio::test]
    async fn status_stub_on_legacy_only() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let router = Tree::ALL
            .into_iter()
            .fold(axum::Router::new(), mount_restart_status_stub);
        let get = |uri: &str| {
            let req = Request::get(uri).body(Body::empty()).unwrap();
            router.clone().oneshot(req)
        };

        let resp = get("/vehicle/v1/status/restart/e1").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "status": "completed", "exec_id": "e1" })
        );

        let resp = get("/v1/status/restart/e1").await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
