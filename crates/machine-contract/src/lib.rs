//! machine-contract — the thin, dep-light contract an out-of-tree machine
//! manager implements.
//!
//! A per-board machine manager (the host machine manager's RT provider, a
//! vendor's slave-ECU bank activator) has to satisfy four synchronous seams to
//! plug into the OTA engine: [`BankProvider`] (the whole A/B story for one
//! kind), [`BankActivator`] (make a staged bank the live image),
//! [`Deactivator`] (take a component's runtime down) and [`ImageRecord`] (the
//! platform's own image table, ordered against seal/activate). Nothing in that
//! set is async and nothing in it speaks HTTP, so nothing in it needs SOVDd, a
//! tokio runtime, or a tracing subscriber — this crate carries `nv-store` (for
//! `Bank` / `BankSet`) and `serde` and stops there. An implementer takes one
//! git dependency and inherits only nv-store's own closure (it needs nv-store
//! anyway — that is where `Bank` / `BankSet` come from).
//!
//! Two smaller seams ride along for the identical reason — both are implemented
//! by the platform and called by the OTA engine, never the other way round:
//! [`WallClockFloor`] (step the host clock forward to a proven time floor, over
//! the platform's `libc`) and [`FloorSink`] (make a floor advance durable, over
//! the platform's HSM slot plus that clock). They were defined inside
//! `component-mgr`, which meant a ~15-line impl of either had to link SUIT,
//! streaming, SOVD and tokio to name the trait it satisfied. `component-mgr`
//! re-exports both at their previous paths (`sovd::time_floor`, `sovd::authz`),
//! so no import changed. The floor's *authority* — the HSM monotonic slot
//! plumbing — stayed in `component-mgr`: it is called, not implemented.
//!
//! [`ResetKind`] is defined here for the same reason: it is the return of
//! `BankProvider::activate`, so naming a reset kind must not cost an implementer
//! a dependency on SOVDd. `machine-mgr` is the SOVD edge and converts to and
//! from the canonical `sovd_core::ResetKind` exhaustively in both directions.
//!
//! What deliberately stayed in `machine-mgr`:
//!
//! - **`Component`** — it is async (`#[async_trait]`) and its signatures speak
//!   sovd-core wire types. It is the diagnostics-facing surface, not the
//!   platform-facing one.
//! - **`Capabilities`** — a component's DECLARATION of what it supports, whose
//!   truth is the implementer's responsibility (a `Capabilities` that claims an
//!   operation the impl answers `NotSupported` is a bug in the impl, not
//!   something this crate can enforce). It rides with `Component`.
//!
//! See `docs/reusable-component-convention.md` for the convention an
//! out-of-tree component follows end to end.
//!
//! `machine-mgr` re-exports every name below — both flat
//! (`machine_mgr::BankProvider`) and by module path
//! (`machine_mgr::bank_provider::BankError`) — so consumers that predate this
//! crate keep compiling unchanged.

pub mod bank_activator;
pub mod bank_provider;
pub mod deactivator;
pub mod floor_sink;
pub mod image_record;
pub mod reset_kind;
pub mod wall_clock_floor;

pub use bank_activator::{BankActivator, BankActivatorError};
pub use bank_provider::{
    BankError, BankProvider, FirmwareIdentity, InstalledFile, InstalledFirmware,
};
pub use deactivator::{DeactivateError, DeactivateOutcome, Deactivator};
pub use floor_sink::{FloorSink, NoopFloorSink};
pub use image_record::ImageRecord;
pub use reset_kind::ResetKind;
pub use wall_clock_floor::{DisciplineOutcome, NoopWallClockFloor, WallClockFloor};
