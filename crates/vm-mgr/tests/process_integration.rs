//! Native process-runner integration coverage.
//!
//! This is intentionally below the Supernova/autoloader scenario: it proves
//! that the reusable VM lifecycle can launch a real child process from the
//! selector-resolved bank without involving QEMU or QNX.

#[cfg(all(unix, feature = "process"))]
mod unix {
    use tempfile::tempdir;
    use vm_mgr::config::{BackendType, VmServiceConfig};
    use vm_mgr::manager::VmManager;

    #[test]
    fn process_backend_launches_from_selected_bank_and_stops() {
        let root = tempdir().unwrap();
        let bank = root.path().join("bank_a");
        std::fs::create_dir_all(&bank).unwrap();

        let config: VmServiceConfig = serde_yaml::from_str(&format!(
            r#"
bind: 127.0.0.1:0
vms:
  vm1:
    backend: process
    image_dir: {}
    process_command: /bin/sh
    process_args: ["-c", "sleep 30"]
"#,
            root.path().display()
        ))
        .unwrap();
        assert_eq!(config.vms["vm1"].backend, BackendType::Process);

        let mut manager = VmManager::with_device_transport(config, None);
        manager
            .set_vm_bank("vm1", Some(vm_mgr::config::Bank::A))
            .unwrap();
        manager.start_vm("vm1").unwrap();
        assert!(manager.runtime_identity("vm1").is_some());

        manager.stop_vm("vm1").unwrap();
        assert!(manager.runtime_identity("vm1").is_none());
    }
}
