//! The shell's config keys — top-level keys of the node binary's own config
//! file. A binary embeds [`ShellConfig`] with `#[serde(flatten)]`, so the keys
//! keep their names and place and a config parses as it did before the shell
//! existed; keys the shell does not know are left to the binary.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ShellConfig {
    #[serde(default = "default_bind")]
    pub bind: String,

    /// Serve the host SOVD surface over TLS using the HSM-held `tls-identity`
    /// leaf (server-only TLS — the client authenticates with an operator token,
    /// not a client cert; the link-B backend signs the handshake and the private
    /// key never leaves the HSM). Best-effort: until the leaf is provisioned over
    /// the SOVD path, the server logs a warning and serves plain HTTP; a restart
    /// after provisioning lights up HTTPS. **Defaults to true** — a provisioned
    /// device serves HTTPS automatically (the conformant posture); set
    /// `sovd_tls: false` to force plain HTTP.
    #[serde(default = "default_sovd_tls")]
    pub sovd_tls: bool,

    /// Advertise the host SOVD endpoint over mDNS / DNS-SD (ISO 17978-3 §5.11)
    /// so SOVD clients can discover it on the local link (conformance
    /// C-010 / C-011). Active on both transports — the `accessurl` scheme
    /// tells the client whether to dial `http` or `https`. On HTTPS the
    /// advertised `<id>.local` hostname is the `tls-identity` leaf SAN, so a
    /// client dialing it verifies the server cert by hostname. **Defaults to
    /// true**; set `sovd_mdns: false` to disable. On QNX the advertiser uses a
    /// hand-rolled pure-Rust DNS-SD responder; off-QNX it uses `mdns-sd`.
    #[serde(default = "default_sovd_mdns")]
    pub sovd_mdns: bool,

    /// SOVD server identification: the mDNS instance name before enrolment
    /// and the TXT `identification` value (verbatim). When absent the
    /// leaf-cert SAN (https) or the OS hostname is used.
    #[serde(default)]
    pub identification: Option<String>,

    /// Role prefix of the SOVD server identification; with it the server is
    /// identified as `<prefix>-<first 16 hex of the ECU id>` — the Tower roster
    /// id, e.g. `cvc-host-…` — from first boot, before a TLS leaf exists. An
    /// explicit `identification` wins.
    #[serde(default)]
    pub identification_prefix: Option<String>,

    /// The SOVD node this server is on `/v1` (SOVDd node topology): `/v1`
    /// then serves the node alone, its components and `ident_data` entities as
    /// the node's subcomponents (`/v1/components/<id>/subcomponents/<entity>`),
    /// and the node-level resources (restart, factory reset, updates, verdict)
    /// under `/v1/components/<id>`. `/vehicle/v1` is unaffected. Absent = the
    /// node derived from `identification_prefix` (see [`ShellConfig::effective_node`]).
    #[serde(default)]
    pub node: Option<NodeConfig>,
}

/// The `node:` key: the node's component id on `/v1` and its name (default
/// the id).
#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
}

impl ShellConfig {
    /// The node this server is on `/v1`, as `(id, name)`: an explicit `node`
    /// (name defaulting to the id); else derived from `identification_prefix`,
    /// whose first `-`-separated label is the node (`cvc-host` → `cvc`, named
    /// `cvc`; a prefix without `-` is the node itself); else `None`, and `/v1`
    /// is served flat as before. A prefix with an empty first label (`""`,
    /// `-x`) derives no node.
    pub fn effective_node(&self) -> Option<(String, String)> {
        if let Some(node) = &self.node {
            let name = node.name.clone().unwrap_or_else(|| node.id.clone());
            return Some((node.id.clone(), name));
        }
        let prefix = self.identification_prefix.as_deref()?;
        let id = prefix.split('-').next().filter(|id| !id.is_empty())?;
        Some((id.to_string(), id.to_string()))
    }
}

fn default_bind() -> String {
    "0.0.0.0:4000".into()
}

fn default_sovd_tls() -> bool {
    // TLS on by default — a provisioned device serves HTTPS (the conformant
    // posture); the best-effort fallback still serves HTTP until provisioned.
    true
}

fn default_sovd_mdns() -> bool {
    // mDNS advertising on by default — a provisioned device makes its SOVD
    // endpoint discoverable (ISO 17978-3 §5.11), tracking the HTTPS path.
    true
}

#[cfg(test)]
mod node_tests {
    use super::ShellConfig;

    // The binary's other keys around the shell's, as in its config file.
    fn node(extra: &str) -> Option<(String, String)> {
        serde_yaml::from_str::<ShellConfig>(&format!("nv_store: /tmp/nv-store.bin\n{extra}"))
            .unwrap()
            .effective_node()
    }

    fn some(id: &str, name: &str) -> Option<(String, String)> {
        Some((id.into(), name.into()))
    }

    #[test]
    fn an_explicit_node_wins_over_the_prefix() {
        assert_eq!(
            node("node: { id: hpc, name: HPC }\nidentification_prefix: cvc-host"),
            some("hpc", "HPC")
        );
        // The name defaults to the id.
        assert_eq!(
            node("node: { id: hpc }\nidentification_prefix: cvc-host"),
            some("hpc", "hpc")
        );
    }

    #[test]
    fn the_prefix_first_label_is_the_node() {
        assert_eq!(node("identification_prefix: cvc-host"), some("cvc", "cvc"));
        assert_eq!(node("identification_prefix: cvc-vm1-x"), some("cvc", "cvc"));
        // No `-`: the prefix is the node itself.
        assert_eq!(node("identification_prefix: cvc"), some("cvc", "cvc"));
    }

    #[test]
    fn no_node_without_a_usable_prefix() {
        assert_eq!(node(""), None);
        assert_eq!(node("identification: cvc-host-f88a13a329a72db1"), None);
        // An empty first label derives nothing.
        assert_eq!(node("identification_prefix: \"-x\""), None);
        assert_eq!(node("identification_prefix: \"\""), None);
    }
}
