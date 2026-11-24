//! The SOVD node topology on the shell's router: what is served where with a
//! node (`identification_prefix: hpc-host` → node `hpc`) and without one.
//! A small node binary built through `read_ecu_id`, `configured_identification`,
//! `node_topology`, `sovd_state` and `sovd_router` as a binary's `main` builds
//! it; the restart and factory-reset handlers are stand-ins (the real ones
//! authorize and reset the node): the restart answers `restart_response`, as
//! [`node_shell::restart_route`] does once authorized, and the factory reset
//! records the path it was built for and refuses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use component_mgr::sovd::ident_data;
use component_mgr::suit_provider::SuitProvider;
use machine_mgr::{Machine, MachineRegistry};
use node_shell::{
    configured_identification, node_topology, read_ecu_id, restart_response, sovd_router,
    sovd_state, ShellConfig,
};
use nv_store::store::NvStore;
use sovd_core::{DiagnosticBackend, EntityInfo};
use tower::ServiceExt;

const ECU_ID: &str = "f88a13a329a72db168066272a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
const BOOT_ID: &str = "6f1b6a52-3f0e-4c64-9d2b-2b8f7a0e9c11";
const IDENTIFICATION: &str = "hpc-host-f88a13a329a72db1";
const NODE: &str = "identification_prefix: hpc-host\n";

/// The hsm component as far as `x-ecu-id` and `read_ecu_id` read it.
struct Hsm(machine_mgr::Capabilities);

#[async_trait::async_trait]
impl machine_mgr::Component for Hsm {
    fn id(&self) -> &str {
        "hsm"
    }
    fn capabilities(&self) -> &machine_mgr::Capabilities {
        &self.0
    }
    async fn get_device_id(&self) -> machine_mgr::MachineResult<Option<String>> {
        Ok(Some(ECU_ID.into()))
    }
}

/// Denies, recording the path it was asked to authorize.
struct RecordingDeny(Mutex<Option<String>>);

#[async_trait::async_trait]
impl sovd_api::Authorizer for RecordingDeny {
    async fn authorize(
        &self,
        req: &sovd_api::AccessRequest<'_>,
    ) -> Result<sovd_api::ClientContext, sovd_api::AuthError> {
        *self.0.lock().unwrap() = Some(req.path.to_string());
        Err("test: denied".into())
    }
    fn is_open(&self) -> bool {
        false
    }
}

fn machine() -> Arc<dyn Machine> {
    Arc::new(
        MachineRegistry::builder(EntityInfo {
            id: "vehicle".into(),
            name: "Vehicle".into(),
            entity_type: "vehicle".into(),
            description: None,
            href: "/vehicle/v1".into(),
            status: None,
        })
        .with_arc(Arc::new(Hsm(Default::default())))
        .build()
        .unwrap(),
    )
}

fn component(id: &str, bank_set: u8) -> Arc<dyn DiagnosticBackend> {
    Arc::new(
        component_mgr::backend::ComponentBackend::new(
            nv_store::types::BankSet(bank_set),
            Arc::new(Mutex::new(NvStore::new(
                nv_store::block::MemBlockDevice::new(nv_store::store::MIN_NV_DEVICE_SIZE as usize),
            ))),
            Arc::new(SuitProvider::with_factory_authority()),
            component_mgr::backend::ComponentConfig::default(),
        )
        .with_id(id.into()),
    )
}

/// The members both servers serve: two components and two `ident_data`
/// entities, reading `dir`'s records.
fn backends(dir: &tempfile::TempDir) -> HashMap<String, Arc<dyn DiagnosticBackend>> {
    std::fs::write(dir.path().join("platform"), "version=PSW_1.10\n").unwrap();
    std::fs::write(dir.path().join("boot"), "version=BOOT_2.0\n").unwrap();
    let ident_data: Vec<ident_data::IdentDataSpec> = serde_yaml::from_str(&format!(
        "
  - entity: platform
    file: {d}/platform
    sw_version: {{ key: version }}
    items: [{{ id: platform-version, name: Platform version, key: version }}]
  - entity: boot
    file: {d}/boot
    sw_version: {{ key: version }}
    items: [{{ id: boot-version, name: Boot version, key: version }}]
",
        d = dir.path().display()
    ))
    .unwrap();
    let mut backends = HashMap::from([
        ("host-app".to_string(), component("host-app", 1)),
        ("vm1".to_string(), component("vm1", 2)),
    ]);
    for spec in ident_data {
        let backend: Arc<dyn DiagnosticBackend> =
            Arc::new(ident_data::IdentDataBackend::new(spec.clone()));
        backends.insert(spec.entity, backend);
    }
    backends
}

/// The shell's keys among the binary's other ones, as in its config file.
fn config(extra: &str) -> ShellConfig {
    serde_yaml::from_str(&format!("nv_store: /tmp/nv-store.bin\n{extra}")).unwrap()
}

/// The restart handler a binary mounts, minus its authorization and reset.
fn restart(tree: sovd_api::Tree) -> axum::routing::MethodRouter {
    axum::routing::put(move || async move {
        match restart_response(tree, "e1", "m") {
            (status, headers, Some(body)) => (status, headers, axum::Json(body)).into_response(),
            (status, headers, None) => (status, headers).into_response(),
        }
    })
}

struct Server {
    router: axum::Router,
    /// The path the factory-reset handler was last built for.
    factory_reset_paths: Arc<Mutex<Vec<String>>>,
    identification: Option<String>,
}

/// The shell's router over `backends` for the config `extra`, assembled as a
/// binary's `main` assembles it.
async fn server(extra: &str, backends: HashMap<String, Arc<dyn DiagnosticBackend>>) -> Server {
    let cfg = config(extra);
    let machine = machine();
    let ecu_id = read_ecu_id(&cfg, machine.as_ref()).await;
    let identification = configured_identification(&cfg, ecu_id.as_deref());
    let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new());
    let state = sovd_state(backends, node_topology(&cfg, identification.as_deref()))
        .unwrap()
        .with_node_data(Arc::new(component_mgr::sovd::routes::UpdateStateData::new(
            coord.clone(),
            machine.clone(),
        )));
    let vendor = axum::Router::new()
        .merge(component_mgr::sovd::routes::device_id_router(
            machine.clone(),
        ))
        .merge(component_mgr::sovd::routes::node_verdict_router(
            machine.clone(),
        ))
        .merge(component_mgr::sovd::routes::update_state_router(
            coord, machine,
        ));
    let factory_reset_paths = Arc::new(Mutex::new(Vec::new()));
    let factory_reset = {
        let paths = factory_reset_paths.clone();
        move |path: &str| {
            paths.lock().unwrap().push(path.to_string());
            axum::routing::post(|| async { (StatusCode::FORBIDDEN, "factory-reset denied") })
        }
    };
    Server {
        router: sovd_router(&state, vendor, BOOT_ID, Some(factory_reset), restart),
        factory_reset_paths,
        identification,
    }
}

/// The node server (`hpc`) and the node-less one, over the same members.
async fn servers(dir: &tempfile::TempDir) -> (Server, Server) {
    let members = backends(dir);
    // One map cloned for both, so both list the members in one order.
    (
        server(NODE, members.clone()).await,
        server("", members).await,
    )
}

/// A router without a factory reset.
fn no_factory_reset() -> Option<fn(&str) -> axum::routing::MethodRouter> {
    None
}

async fn send(router: &axum::Router, method: &str, uri: &str) -> (StatusCode, HeaderMap, String) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

async fn get_json(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let (status, _, body) = send(router, "GET", uri).await;
    (status, serde_json::from_str(&body).unwrap_or_default())
}

fn ids_and_hrefs(listing: &serde_json::Value) -> Vec<(String, String)> {
    let mut items: Vec<(String, String)> = listing["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["id"].as_str().unwrap().into(),
                i["href"].as_str().unwrap().into(),
            )
        })
        .collect();
    items.sort();
    items
}

const MEMBERS: [&str; 4] = ["boot", "host-app", "platform", "vm1"];

#[tokio::test]
async fn the_node_server_lists_the_node_alone_on_v1() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    let (status, body) = get_json(&node.router, "/v1/components").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ids_and_hrefs(&body),
        [("hpc".to_string(), "/v1/components/hpc".to_string())]
    );
    assert_eq!(body["items"][0]["type"], "node", "{body}");

    // Without a node, /v1 is flat as before.
    let (_, body) = get_json(&flat.router, "/v1/components").await;
    let ids: Vec<String> = ids_and_hrefs(&body).into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, MEMBERS);
}

#[tokio::test]
async fn the_node_document_carries_the_mdns_identification() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;
    // The identification mDNS advertises (start_mdns gets the same value).
    assert_eq!(node.identification.as_deref(), Some(IDENTIFICATION));
    assert_eq!(flat.identification, None);

    let (status, body) = get_json(&node.router, "/v1/components/hpc").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], "hpc");
    assert_eq!(body["name"], "hpc");
    assert_eq!(body["type"], "node");
    assert_eq!(body["x-identification"], IDENTIFICATION);
    assert_eq!(body["status"], "/v1/components/hpc/status");
    assert_eq!(body["operations"], "/v1/components/hpc/operations");
    assert_eq!(body["data"], "/v1/components/hpc/data");
    assert_eq!(body["subcomponents"], "/v1/components/hpc/subcomponents");
}

#[tokio::test]
async fn the_subcomponents_are_the_components_and_ident_entities() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = servers(&dir).await;

    let (status, body) = get_json(&node.router, "/v1/components/hpc/subcomponents").await;
    assert_eq!(status, StatusCode::OK);
    let expected: Vec<(String, String)> = MEMBERS
        .iter()
        .map(|id| {
            (
                id.to_string(),
                format!("/v1/components/hpc/subcomponents/{id}"),
            )
        })
        .collect();
    assert_eq!(ids_and_hrefs(&body), expected);
}

/// A member's documents through the node form are the node-less server's
/// flat ones, but for the URLs they render, which take the node form.
#[tokio::test]
async fn a_member_through_the_node_is_the_flat_member_without_one() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    for id in MEMBERS {
        for rest in ["", "/data", "/status", "/updates", "/operations"] {
            let nested = format!("/v1/components/hpc/subcomponents/{id}{rest}");
            let (status, _, body) = send(&node.router, "GET", &nested).await;
            let expected = send(&flat.router, "GET", &format!("/v1/components/{id}{rest}")).await;
            assert_eq!(status, expected.0, "{nested}: {body}");
            assert_eq!(
                body.replace("/v1/components/hpc/subcomponents/", "/v1/components/"),
                expected.2,
                "{nested}"
            );
        }
    }
    let (status, body) = get_json(
        &node.router,
        "/v1/components/hpc/subcomponents/platform/data/sw-version",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["version"], "PSW_1.10", "{body}");
}

#[tokio::test]
async fn a_flat_member_path_on_the_node_server_names_the_node_form() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = servers(&dir).await;

    for id in MEMBERS {
        let (status, _, body) =
            send(&node.router, "GET", &format!("/v1/components/{id}/data")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(
            body.contains(&format!("/v1/components/hpc/subcomponents/{id}/data")),
            "{body}"
        );
    }
}

#[tokio::test]
async fn the_node_restart_is_202_location_node_status_no_body() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    let (status, headers, body) =
        send(&node.router, "PUT", "/v1/components/hpc/status/restart").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(headers[header::LOCATION], "/v1/components/hpc/status");
    assert_eq!(body, "");

    // The root form is the node's: 404 naming the node form.
    let (status, _, body) = send(&node.router, "PUT", "/v1/status/restart").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("/v1/components/hpc/status/restart"), "{body}");

    // Without a node: as before.
    let (status, headers, body) = send(&flat.router, "PUT", "/v1/status/restart").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(headers[header::LOCATION], "/v1/status");
    assert_eq!(body, "");
}

/// The handler is built for the root form on each tree and reached under the
/// node; the root form is not served.
#[tokio::test]
async fn the_factory_reset_is_reached_under_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;
    let root = "/v1/operations/factory-reset/executions";
    assert_eq!(
        *node.factory_reset_paths.lock().unwrap(),
        [
            root.to_string(),
            "/vehicle/v1/operations/factory-reset/executions".to_string(),
        ]
    );

    let (status, _, body) = send(
        &node.router,
        "POST",
        "/v1/components/hpc/operations/factory-reset/executions",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "factory-reset denied");

    let (status, _, body) = send(&node.router, "POST", root).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, _, _) = send(&flat.router, "POST", root).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Without a factory reset there is no route for it, on either tree.
#[tokio::test]
async fn no_factory_reset_no_route() {
    let state = sovd_state(HashMap::new(), None).unwrap();
    let router = sovd_router(
        &state,
        axum::Router::new(),
        BOOT_ID,
        no_factory_reset(),
        restart,
    );
    for uri in [
        "/v1/operations/factory-reset/executions",
        "/vehicle/v1/operations/factory-reset/executions",
    ] {
        let (status, _, body) = send(&router, "POST", uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
    }
}

#[tokio::test]
async fn the_hsm_ecu_id_is_served_under_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    let (status, _, body) = send(
        &node.router,
        "GET",
        "/v1/components/hpc/subcomponents/hsm/x-ecu-id",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, ECU_ID);
    let (status, _, _) = send(&node.router, "GET", "/v1/components/hsm/x-ecu-id").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        send(&flat.router, "GET", "/v1/components/hsm/x-ecu-id")
            .await
            .2,
        ECU_ID
    );
}

#[tokio::test]
async fn the_update_state_is_node_level_data() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    let (status, _, body) = send(
        &node.router,
        "GET",
        "/v1/components/hpc/data/x-update-state",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        send(&flat.router, "GET", "/v1/data/x-update-state").await.2
    );
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["id"], "x-update-state", "{body}");
    assert_eq!(body["data"]["phase"], "Idle", "{body}");
    assert_eq!(body.as_object().unwrap().len(), 2, "{body}");
    let (status, _, _) = send(&node.router, "GET", "/v1/data/x-update-state").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The node's status, at the URL the node restart's `Location` names.
#[tokio::test]
async fn the_node_status_is_where_the_restart_points() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;
    let ready = |base: &str| {
        serde_json::json!({
            "status": "ready",
            "restart": [format!("{base}/status/restart")],
            "x-runtime": { "node_boot_id": BOOT_ID },
        })
    };

    let (status, body) = get_json(&node.router, "/v1/components/hpc/status").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, ready("/v1/components/hpc"));
    // The node document links it.
    let (_, doc) = get_json(&node.router, "/v1/components/hpc").await;
    assert_eq!(doc["status"], "/v1/components/hpc/status");

    // The root form is the node's: 404 naming the node form.
    let (status, _, body) = send(&node.router, "GET", "/v1/status").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("/v1/components/hpc/status"), "{body}");

    // Without a node: the root form.
    let (status, body) = get_json(&flat.router, "/v1/status").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, ready("/v1"));
}

/// Once a restart is accepted the node is going down: `notReady` at the
/// `Location` the 202 names, on either server.
#[tokio::test]
async fn an_accepted_restart_makes_the_node_not_ready() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    for (server, restart) in [
        (&node, "/v1/components/hpc/status/restart"),
        (&flat, "/v1/status/restart"),
    ] {
        let (status, headers, _) = send(&server.router, "PUT", restart).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let location = headers[header::LOCATION].to_str().unwrap();
        let (status, body) = get_json(&server.router, location).await;
        assert_eq!(status, StatusCode::OK, "{location}: {body}");
        assert_eq!(body["status"], "notReady", "{location}: {body}");
        assert_eq!(body["x-runtime"]["node_boot_id"], BOOT_ID);
    }
}

/// A restart the handler refuses leaves the node ready.
#[tokio::test]
async fn a_refused_restart_leaves_the_node_ready() {
    let state = sovd_state(HashMap::new(), None).unwrap();
    let refuse = |_| axum::routing::put(|| async { StatusCode::FORBIDDEN.into_response() });
    let router = sovd_router(
        &state,
        axum::Router::new(),
        BOOT_ID,
        no_factory_reset(),
        refuse,
    );

    let (status, _, _) = send(&router, "PUT", "/v1/status/restart").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, body) = get_json(&router, "/v1/status").await;
    assert_eq!(body["status"], "ready", "{body}");
}

/// The status read is authorized as a component's status read is: by
/// SOVDd's auth layer, as a `Read` of no component.
#[tokio::test]
async fn the_node_status_read_is_authorized_by_the_auth_layer() {
    let authz = Arc::new(RecordingDeny(Mutex::new(None)));
    let state = sovd_state(HashMap::new(), None)
        .unwrap()
        .with_authorizer(authz.clone());
    let router = sovd_router(
        &state,
        axum::Router::new(),
        BOOT_ID,
        no_factory_reset(),
        restart,
    );

    let (status, _, body) = send(&router, "GET", "/v1/status").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(authz.0.lock().unwrap().as_deref(), Some("/v1/status"));
}

/// The legacy tree has no node status: `/vehicle/v1/status` answers what
/// it answered before `/v1/status` was served.
#[tokio::test]
async fn the_legacy_tree_serves_no_node_status() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    let body = r#"{"error_code":"incomplete-request","message":"No resource at /vehicle/v1/status","parameters":{"http_code":["404"]}}"#;
    for server in [&node, &flat] {
        let (status, headers, got) = send(&server.router, "GET", "/vehicle/v1/status").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(headers[header::CONTENT_LENGTH], body.len().to_string());
        assert_eq!(got, body);
    }
}

/// SOVDd v0.1.11 maps the whole status tree to the node: on a node server
/// `x-boot-id` is served under the node and its root form answers 404.
#[tokio::test]
async fn x_boot_id_is_served_under_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    for (server, uri, status) in [
        (&node, "/v1/status/x-boot-id", StatusCode::NOT_FOUND),
        (&node, "/vehicle/v1/status/x-boot-id", StatusCode::OK),
        (&node, "/v1/components/hpc/status/x-boot-id", StatusCode::OK),
        (&flat, "/v1/status/x-boot-id", StatusCode::OK),
        (&flat, "/vehicle/v1/status/x-boot-id", StatusCode::OK),
    ] {
        let (got, _, body) = send(&server.router, "GET", uri).await;
        assert_eq!(got, status, "{uri}: {body}");
        if status == StatusCode::OK {
            assert_eq!(body, BOOT_ID, "{uri}");
        }
    }
}

/// The device-facing tool's legacy paths answer byte-identically with and
/// without the node: status, headers and body.
#[tokio::test]
async fn the_legacy_tree_is_byte_identical_with_and_without_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    for (method, uri) in [
        ("PUT", "/vehicle/v1/status/restart"),
        ("GET", "/vehicle/v1/status/restart/e1"),
        ("GET", "/vehicle/v1/status/x-boot-id"),
        ("POST", "/vehicle/v1/operations/factory-reset/executions"),
        ("GET", "/vehicle/v1/components"),
        ("GET", "/vehicle/v1/components/vm1"),
        // (a data read carries a timestamp: the listing instead)
        ("GET", "/vehicle/v1/components/platform/data"),
        ("GET", "/vehicle/v1/components/hsm/x-ecu-id"),
        ("GET", "/vehicle/v1/data/x-update-state"),
    ] {
        let with = send(&node.router, method, uri).await;
        assert_eq!(
            with,
            send(&flat.router, method, uri).await,
            "{method} {uri}"
        );
        assert_ne!(with.0, StatusCode::NOT_FOUND, "{method} {uri}: {}", with.2);
    }
    // The legacy restart keeps its vendor body and stub href.
    let (status, headers, body) = send(&node.router, "PUT", "/vehicle/v1/status/restart").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(headers[header::LOCATION], "/vehicle/v1/status/restart/e1");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["status"], "running");
    assert_eq!(body["href"], "/vehicle/v1/status/restart/e1");
}

/// The ident entities' backends carry `/vehicle/v1` hrefs, but SOVDd renders
/// every URL it serves through the tree: none reaches a `/v1` response.
#[tokio::test]
async fn ident_entities_render_no_legacy_urls_on_v1() {
    let dir = tempfile::tempdir().unwrap();
    let (node, flat) = servers(&dir).await;

    for id in ["boot", "platform"] {
        for rest in [
            "",
            "/data",
            "/data?categories=identData",
            &format!("/data/{id}-version"),
            "/data/sw-version",
            "/status",
            "/updates",
            "/operations",
            "/faults",
            "/docs",
        ] {
            for (server, uri) in [
                (&flat, format!("/v1/components/{id}{rest}")),
                (
                    &node,
                    format!("/v1/components/hpc/subcomponents/{id}{rest}"),
                ),
            ] {
                let (_, headers, body) = send(&server.router, "GET", &uri).await;
                assert!(!body.contains("/vehicle/v1"), "{uri}: {body}");
                let location = headers.get(header::LOCATION);
                assert!(
                    location.is_none_or(|l| !l.to_str().unwrap().contains("/vehicle/v1")),
                    "{uri}"
                );
            }
        }
    }
}

#[test]
fn a_node_id_colliding_with_a_component_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut members = backends(&dir);
    members.insert("hpc".into(), component("hpc", 3));
    let cfg = config(NODE);
    let Err(err) = sovd_state(members, node_topology(&cfg, None)) else {
        panic!("a colliding node id was accepted");
    };
    assert!(err.contains("'hpc'"), "{err}");

    // An explicit node colliding with an ident entity alike.
    let cfg = config("node: { id: platform }\n");
    assert!(sovd_state(backends(&dir), node_topology(&cfg, None)).is_err());
}

#[tokio::test]
async fn the_ecu_id_is_read_for_a_node_or_a_prefix_only() {
    let machine = machine();
    let read = |extra: &'static str| {
        let machine = machine.clone();
        async move { read_ecu_id(&config(extra), machine.as_ref()).await }
    };
    assert_eq!(read(NODE).await.as_deref(), Some(ECU_ID));
    assert_eq!(read("node: { id: hpc }\n").await.as_deref(), Some(ECU_ID));
    assert_eq!(read("").await, None);
}

/// The shell's restart handler: a denial is 403 with the authorizer's
/// reason and runs no reset; an authorized one runs the node's reset and
/// answers the 202 with its message.
#[tokio::test]
async fn the_restart_route_authorizes_then_resets() {
    struct Allow;
    #[async_trait::async_trait]
    impl sovd_api::Authorizer for Allow {
        async fn authorize(
            &self,
            _: &sovd_api::AccessRequest<'_>,
        ) -> Result<sovd_api::ClientContext, sovd_api::AuthError> {
            Ok(sovd_api::ClientContext {
                subject: "tester".into(),
                scopes: Vec::new(),
            })
        }
        fn is_open(&self) -> bool {
            false
        }
    }
    let resets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reset: Arc<dyn Fn() -> &'static str + Send + Sync> = {
        let resets = resets.clone();
        Arc::new(move || {
            resets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            "ECU restart initiated"
        })
    };
    let state = sovd_state(HashMap::new(), None).unwrap();
    let router_with = |authz: Arc<dyn sovd_api::Authorizer>| {
        let reset = reset.clone();
        sovd_router(
            &state,
            axum::Router::new(),
            BOOT_ID,
            no_factory_reset(),
            move |tree| node_shell::restart_route(tree, authz.clone(), reset.clone()),
        )
    };

    let deny = Arc::new(RecordingDeny(Mutex::new(None)));
    let denied = router_with(deny.clone());
    let (status, _, body) = send(&denied, "PUT", "/v1/status/restart").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "restart denied: test: denied\n");
    assert_eq!(
        deny.0.lock().unwrap().as_deref(),
        Some("/v1/status/restart")
    );
    assert_eq!(resets.load(std::sync::atomic::Ordering::Relaxed), 0);

    let allowed = router_with(Arc::new(Allow));
    let (status, headers, body) = send(&allowed, "PUT", "/v1/status/restart").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(headers[header::LOCATION], "/v1/status");
    assert_eq!(body, "");
    let (status, headers, body) = send(&allowed, "PUT", "/vehicle/v1/status/restart").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["message"], "ECU restart initiated");
    assert_eq!(headers[header::LOCATION], body["href"].as_str().unwrap());
    assert_eq!(resets.load(std::sync::atomic::Ordering::Relaxed), 2);
}

/// The node status and boot id are documented on `/v1` (in the node form on
/// a node server) and the legacy capability description is what it is
/// without the shell's rows.
#[tokio::test]
async fn the_v1_only_routes_are_documented_on_v1_only() {
    let dir = tempfile::tempdir().unwrap();
    let router = |extra: &str, rows: bool| {
        let cfg = config(extra);
        let ext = sovd_api::CapabilityExtensions::default();
        let ext = if rows {
            node_shell::capability_extensions(ext)
        } else {
            ext
        };
        let state = sovd_state(backends(&dir), node_topology(&cfg, None))
            .unwrap()
            .with_capability_extensions(ext);
        sovd_router(
            &state,
            axum::Router::new(),
            BOOT_ID,
            no_factory_reset(),
            restart,
        )
    };
    for (extra, status, boot_id) in [
        ("", "/v1/status", "/v1/status/x-boot-id"),
        (
            "node: { id: hpc }\n",
            "/v1/components/hpc/status",
            "/v1/components/hpc/status/x-boot-id",
        ),
    ] {
        let (_, docs) = get_json(&router(extra, true), "/v1/docs").await;
        assert_eq!(
            docs["paths"][status]["get"]["operationId"], "node_status",
            "{extra}"
        );
        assert_eq!(
            docs["paths"][boot_id]["get"]["operationId"], "node_boot_id",
            "{extra}"
        );
        let (_, without) = get_json(&router(extra, false), "/v1/docs").await;
        assert!(without["paths"].get(status).is_none(), "{extra}");

        let legacy = send(&router(extra, true), "GET", "/vehicle/v1/docs").await;
        assert_eq!(legacy.0, StatusCode::OK);
        assert_eq!(
            legacy,
            send(&router(extra, false), "GET", "/vehicle/v1/docs").await
        );
    }
}
