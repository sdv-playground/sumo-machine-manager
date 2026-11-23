use super::super::*;
use nv_store::block::MemBlockDevice;

/// The `?bank=` suffix carried to vm-service after an OTA flip. `notify_vm_service`
/// itself needs a live socket, so the URL-building is factored here and tested pure.
#[test]
fn bank_query_maps_each_bank() {
    type Cb = ComponentBackend<MemBlockDevice>;
    assert_eq!(Cb::bank_query(Some(Bank::A)), "?bank=a");
    assert_eq!(Cb::bank_query(Some(Bank::B)), "?bank=b");
    assert_eq!(Cb::bank_query(None), "");
}
