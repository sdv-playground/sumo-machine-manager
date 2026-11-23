//! Who the server is: its identification (the name mDNS advertises and the
//! node document carries), the ECU id it may be derived from, and the `/v1`
//! node the backends are served under.

use std::collections::HashMap;
use std::sync::Arc;

use machine_mgr::Machine;
use sovd_core::DiagnosticBackend;

use crate::ShellConfig;

/// The SOVD server identification from config: an explicit `identification`
/// wins; else `<identification_prefix>-<first 16 hex of the ECU id>` — the
/// name enrolment gives the device (Tower roster id, leaf SAN `<it>.local`).
/// A prefix without a usable ECU id is warned about and yields `None`.
pub fn configured_identification(cfg: &ShellConfig, ecu_id: Option<&str>) -> Option<String> {
    if let Some(id) = &cfg.identification {
        return Some(id.clone());
    }
    let prefix = cfg.identification_prefix.as_deref()?;
    let name = ecu_id.and_then(|id| prefixed_identification(prefix, id));
    if name.is_none() {
        tracing::warn!(
            prefix,
            ecu_id = ecu_id.unwrap_or("<unavailable>"),
            "identification_prefix set but no usable ECU id — not deriving an identification"
        );
    }
    name
}

/// `<prefix>-<first 16 hex chars of ecu_id>`; `None` if the id is shorter.
pub fn prefixed_identification(prefix: &str, ecu_id: &str) -> Option<String> {
    ecu_id.get(..16).map(|hex| format!("{prefix}-{hex}"))
}

/// The ECU id — the hsm component's device id, read through the very call
/// `GET …/components/hsm/x-ecu-id` serves — when a node or an
/// `identification_prefix` is configured; `None` otherwise or when unavailable.
pub async fn read_ecu_id(cfg: &ShellConfig, machine: &dyn Machine) -> Option<String> {
    if cfg.node.is_none() && cfg.identification_prefix.is_none() {
        return None;
    }
    machine
        .component("hsm")?
        .get_device_id()
        .await
        .ok()
        .flatten()
}

/// The `/v1` node of `cfg` ([`ShellConfig::effective_node`]), carrying the unit's
/// `identification` (the name mDNS advertises) on its document when known.
pub fn node_topology(
    cfg: &ShellConfig,
    identification: Option<&str>,
) -> Option<sovd_api::NodeTopology> {
    let (id, name) = cfg.effective_node()?;
    let node = sovd_api::NodeTopology::new(id, name);
    Some(match identification {
        Some(identification) => node.with_identification(identification),
        None => node,
    })
}

/// The SOVD state over `backends`; with `node`, `/v1` serves them as the
/// node's subcomponents. `Err` names the problem when the node id is not a
/// path segment or is also a component's (or `ident_data` entity's) id.
pub fn sovd_state(
    backends: HashMap<String, Arc<dyn DiagnosticBackend>>,
    node: Option<sovd_api::NodeTopology>,
) -> Result<sovd_api::AppState, String> {
    let state = sovd_api::AppState::new(backends);
    match node {
        Some(node) => state.with_node(node),
        None => Ok(state),
    }
}

#[cfg(test)]
mod mdns_identification_tests {
    use super::{configured_identification, prefixed_identification};
    use crate::ShellConfig;

    const ECU_ID: &str = "f88a13a329a72db168066272a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";

    fn cfg(extra: &str) -> ShellConfig {
        serde_yaml::from_str(&format!("nv_store: /tmp/nv-store.bin\n{extra}")).unwrap()
    }

    #[test]
    fn prefix_takes_the_first_16_hex_of_the_ecu_id() {
        assert_eq!(
            prefixed_identification("cvc-host", ECU_ID).as_deref(),
            Some("cvc-host-f88a13a329a72db1")
        );
    }

    #[test]
    fn an_ecu_id_shorter_than_16_hex_yields_none() {
        assert_eq!(prefixed_identification("cvc-host", "f88a13a329a72db"), None);
    }

    #[test]
    fn explicit_identification_wins_over_the_prefix() {
        let c = cfg("identification: rig1\nidentification_prefix: cvc-host");
        assert_eq!(
            configured_identification(&c, Some(ECU_ID)).as_deref(),
            Some("rig1")
        );
    }

    #[test]
    fn prefix_without_an_ecu_id_falls_through() {
        let c = cfg("identification_prefix: cvc-host");
        assert_eq!(configured_identification(&c, None), None);
        assert_eq!(
            configured_identification(&c, Some(ECU_ID)).as_deref(),
            Some("cvc-host-f88a13a329a72db1")
        );
        assert_eq!(configured_identification(&cfg(""), Some(ECU_ID)), None);
    }

    #[test]
    fn the_prefixed_name_is_the_advertised_instance() {
        let name = prefixed_identification("cvc-host", ECU_ID).unwrap();
        let adv = sovd_mdns::SovdAdvertiser::new(
            &[
                sovd_mdns::Identity::Configured(&name),
                sovd_mdns::Identity::Hostname,
            ],
            sovd_mdns::Scheme::Http,
            "0.0.0.0:4000",
        )
        .unwrap();
        assert_eq!(adv.instance, name);
        assert_eq!(adv.identification, name);
        assert_eq!(
            adv.accessurl,
            "http://cvc-host-f88a13a329a72db1.local:4000/v1"
        );
    }
}
