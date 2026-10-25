//! The boot stage's own record ([`BootRecord`]) and the one generic
//! [`SelectorStore`] over it ([`RecordSelectorStore`]).
//!
//! A boot stage keeps a record of its own: two copies, a generation it issues
//! (possibly from a hardware counter), its own commit and rollback — and only
//! the rows of the components it routes. The record stays minimal: nothing
//! goes into it that the boot stage does not need to boot. Everything else the
//! node needs — the **manager rows** (the components whose bank the machine
//! manager selects after boot) and the transaction header — lives in side
//! files next to it, tied to the record by generation. That mechanism is the
//! same for every port, so a host implements only [`BootRecord`] and builds the
//! store with [`RecordSelectorStore::over`].
//!
//! The reference store is the same adapter over a file record that routes
//! every component: [`FileSelectorStore`], whose `primary` / `secondary` /
//! `transaction` files are unchanged from the store it replaces.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::selector::{
    next_generation, BootVector, ComponentEntry, SelectorBlob, SelectorError, SelectorStore,
    Signer, SlotSelect, Transaction, COMMITTED, PRIMARY, ROWS, SECONDARY, TRANSACTION,
};
use crate::types::BankSet;

/// One of the two copies of a [`BootRecord`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordCopy {
    /// What boots.
    Primary,
    /// The committed copy: the rows at the floor, whichever copy of the record
    /// holds them. Absent when no copy is at the floor — then there is nothing
    /// to roll back to and a commit anchors the vector.
    Secondary,
}

/// The boot stage's own record: the rows it routes, at a generation it issues.
/// The only hardware-dependent surface a port implements; run
/// `contract::exercise_record` (feature `test-seams`) against it, and
/// `contract::exercise` against the [`RecordSelectorStore`] over it.
pub trait BootRecord: Send + Sync {
    /// Whether the boot stage routes this component (its row lives in the record).
    fn routes(&self, component_id: &str) -> bool;
    /// Whether every component is routed (the reference file record). Gates the
    /// adapter's "manager rows" warnings and its header attribution rule.
    fn routes_everything(&self) -> bool {
        false
    }
    /// `Ok(Some)`: the authenticated rows of a copy and its generation.
    /// `Ok(None)`: absent — erased, never written, or a failed authenticity
    /// check; the record is readable and holds no usable copy. `Err`: the
    /// record could not be read (I/O, allocation, a check that could not run);
    /// the caller must not treat this as absent.
    ///
    /// A copy that is at the floor is the committed copy
    /// ([`RecordCopy::Secondary`]) even when it is the one that boots.
    fn read(&self, copy: RecordCopy) -> Result<Option<BootVector>, SelectorError>;
    /// primary := `rows` at a generation the record issues, strictly above both
    /// copies. Returns it. On `Err` the primary is unchanged.
    fn activate(&self, rows: &BTreeMap<String, ComponentEntry>) -> Result<u64, SelectorError>;
    /// secondary := primary (same generation). Idempotent; `Ok` without a primary.
    fn commit(&self) -> Result<(), SelectorError>;
    /// primary := secondary; returns the restored generation; `Err(NoTrial)`
    /// when the copies are already equal. A boot stage's anti-rollback check
    /// gates on the secondary's generation.
    fn rollback(&self) -> Result<u64, SelectorError>;
    /// Migration hook: a header the record itself still carries from an older
    /// layout.
    fn legacy_transaction(&self) -> Option<(u64, Transaction)> {
        None
    }
}

// ---------------------------------------------------------------------------
// Signed files — the one file helper the adapter and the file record share
// ---------------------------------------------------------------------------

/// A directory of signed [`SelectorBlob`] JSON files, all signed and verified
/// by one [`Signer`].
#[derive(Clone)]
pub(crate) struct SignedFiles {
    dir: PathBuf,
    signer: Arc<dyn Signer>,
}

impl std::fmt::Debug for SignedFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedFiles")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl SignedFiles {
    pub(crate) fn new(dir: PathBuf, signer: Arc<dyn Signer>) -> Self {
        Self { dir, signer }
    }

    /// Sign `entries` (and `transaction`) at `generation`.
    fn sign(
        &self,
        generation: u64,
        entries: BTreeMap<String, ComponentEntry>,
        transaction: Option<Transaction>,
    ) -> SelectorBlob {
        SelectorBlob::signed(generation, entries, transaction, &*self.signer)
    }

    /// Read + parse a file: `Ok(None)` if it doesn't exist, `Err` if it
    /// exists and could not be read. A parse error warns and is treated as
    /// absent (the same "garbled selector → absent" posture as a failed
    /// signature).
    fn read_blob(&self, name: &str) -> Result<Option<SelectorBlob>, SelectorError> {
        let path = self.dir.join(name);
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match serde_json::from_reader(file) {
            Ok(blob) => Ok(Some(blob)),
            Err(e) if e.is_io() => Err(std::io::Error::from(e).into()),
            Err(e) => {
                tracing::warn!(?path, error = %e, "selector slot unreadable — treating as absent");
                Ok(None)
            }
        }
    }

    /// [`Self::read_blob`], keeping only a blob that verifies. A PRESENT blob
    /// that fails verification warns rather than vanishing silently: it reads
    /// as absent (an absent primary is the host's reseed-from-NV trigger), and
    /// this line is the only record of why.
    fn read_verified(&self, name: &str) -> Result<Option<SelectorBlob>, SelectorError> {
        Ok(self.read_blob(name)?.filter(|b| {
            let valid = b.is_valid(&*self.signer);
            if !valid {
                tracing::warn!(
                    generation = b.generation,
                    "boot selector {name} failed verification — treated as absent (will be reseeded)"
                );
            }
            valid
        }))
    }

    /// Atomically + durably write a file: serialize into `<name>.tmp`, **fsync
    /// it**, rename over `<name>`, then fsync the renamed file. The first
    /// failing step is returned as `Err`; the caller must not treat the file as
    /// written (a failure before the rename leaves the prior file intact).
    ///
    /// The fsyncs matter because a hardware reboot can follow a bank activation
    /// IMMEDIATELY, and the reboot path is kernel-direct — without the flush a
    /// just-sealed selection could sit only in the block cache and be lost
    /// across the reset, so the next boot reads the STALE (pre-seal) file.
    /// (`reboot_now` also `sync()`s globally, but flushing here makes each
    /// write durable on its own, independent of that path.)
    fn write_blob(&self, name: &str, blob: &SelectorBlob) -> Result<(), SelectorError> {
        std::fs::create_dir_all(&self.dir)?;
        let final_path = self.dir.join(name);
        let tmp_path = self.dir.join(format!("{name}.tmp"));
        let file = std::fs::File::create(&tmp_path)?;
        serde_json::to_writer_pretty(&file, blob)
            .map_err(|e| SelectorError::Serialize(e.to_string()))?;
        // Flush the payload to disk BEFORE the rename — the rename is only
        // atomic for ordering, not durability.
        file.sync_all()?;
        std::fs::rename(&tmp_path, &final_path)?;
        // Re-open + fsync the renamed file so the directory entry the next boot
        // reads is itself durable, not just the tmp payload.
        std::fs::File::open(&final_path)?.sync_all()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// The [`SelectorStore`] over any [`BootRecord`]: the record holds the rows it
/// routes, and three side files in `dir` — signed [`SelectorBlob`]s, written
/// tmp + fsync + rename — hold the rest, tied to the record by generation:
///
/// - `rows`: the manager rows (ids the record does not route), at the record's
///   primary generation;
/// - `committed`: the committed manager rows, at the record's secondary
///   generation;
/// - `transaction`: the header (empty entries), at the primary generation it
///   was recorded for.
///
/// The record is the authority and issues the generation; every verb drives it
/// first and writes the side files at the generation it returned. A read is the
/// union of the record's rows and the manager rows at the copy's generation
/// (the record wins on a key collision). The adapter is stateless.
///
/// Failure rules, beyond the [`SelectorStore`] write order:
/// - a record or a side file that could not be read is `Err` from every verb
///   that reads it — never read as absent, so `commit` over an unreadable
///   primary is `Err` (`read_transaction`, which has no error channel, logs it
///   and reads no header); a side file that does not parse or verify is
///   absent, as a missing one is;
/// - `activate`: a failed `rows` write rolls the record back when it was not
///   in trial before, and is `Err` (with a standing trial the record is left
///   alone — a rollback would discard the trial; a retry heals);
/// - `commit`: a failed `committed` write is `Err` after the record committed;
///   the retry is idempotent, and until then the rows at the committed
///   generation read as committed;
/// - `rollback`: `NoTrial` is checked before any write, the header is written
///   first, the record next, the `rows` last (a failed `rows` write is logged:
///   the reads fall back to the committed rows);
/// - `read_transaction`: a header recorded for a generation other than the
///   record's primary is returned only when manager rows exist at its
///   generation — a header without them was left by an older layout and is
///   never read as the boot stage's rollback.
///
/// Manager rows are never written empty as a fallback, except over a record
/// that routes every component.
#[derive(Clone, Debug)]
pub struct RecordSelectorStore<R: BootRecord + Clone> {
    record: R,
    files: SignedFiles,
}

impl<R: BootRecord + Clone> RecordSelectorStore<R> {
    /// The host entry point: a store over `record`, its side files in `dir`,
    /// signed and verified with `signer`.
    pub fn over(record: R, dir: impl Into<PathBuf>, signer: Box<dyn Signer>) -> Self {
        Self {
            record,
            files: SignedFiles::new(dir.into(), signer.into()),
        }
    }

    /// The side file `name` iff it was written for `generation`; `Err` when it
    /// exists and could not be read.
    fn rows_at(
        &self,
        name: &str,
        generation: u64,
    ) -> Result<Option<BTreeMap<String, ComponentEntry>>, SelectorError> {
        Ok(self
            .files
            .read_verified(name)?
            .filter(|b| b.generation == generation)
            .map(|b| b.entries))
    }

    /// The first of `names` with rows at `generation`.
    fn first_rows_at(
        &self,
        names: [&str; 2],
        generation: u64,
    ) -> Result<Option<BTreeMap<String, ComponentEntry>>, SelectorError> {
        for name in names {
            if let Some(rows) = self.rows_at(name, generation)? {
                return Ok(Some(rows));
            }
        }
        Ok(None)
    }

    /// No manager rows at `generation`: the newer of `rows` / `committed`
    /// (stale rows before absent ones — absent rows mean components that never
    /// launch), loudly.
    fn newest_rows(
        &self,
        generation: u64,
    ) -> Result<BTreeMap<String, ComponentEntry>, SelectorError> {
        let mut newest: Option<SelectorBlob> = None;
        for name in [ROWS, COMMITTED] {
            if let Some(b) = self.files.read_verified(name)? {
                if newest.as_ref().is_none_or(|n| b.generation >= n.generation) {
                    newest = Some(b);
                }
            }
        }
        if !self.record.routes_everything() {
            tracing::warn!(
                generation,
                rows_generation = ?newest.as_ref().map(|b| b.generation),
                "boot-vector: no manager rows at the record generation — using the newest found"
            );
        }
        Ok(newest.map_or_else(BTreeMap::new, |b| b.entries))
    }

    /// `record` ∪ `rows`; the record wins on a key collision.
    fn union(&self, mut record: BootVector, rows: BTreeMap<String, ComponentEntry>) -> BootVector {
        for (id, entry) in rows {
            match record.entries.entry(id) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(entry);
                }
                std::collections::btree_map::Entry::Occupied(slot) => {
                    tracing::warn!(
                        component = %slot.key(),
                        "boot-vector: a manager row collides with a record row — the record wins"
                    );
                }
            }
        }
        record
    }

    fn generation(&self, copy: RecordCopy) -> Result<Option<u64>, SelectorError> {
        Ok(self.record.read(copy)?.map(|v| v.generation))
    }

    /// Manager rows at `generation`, or `Err` — empty only over a record that
    /// routes every component.
    fn required(
        &self,
        rows: Option<BTreeMap<String, ComponentEntry>>,
        generation: u64,
    ) -> Result<BTreeMap<String, ComponentEntry>, SelectorError> {
        match rows {
            Some(rows) => Ok(rows),
            None if self.record.routes_everything() => Ok(BTreeMap::new()),
            None => Err(SelectorError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no manager rows at generation {generation}"),
            ))),
        }
    }

    fn write_rows(
        &self,
        name: &str,
        generation: u64,
        rows: BTreeMap<String, ComponentEntry>,
    ) -> Result<(), SelectorError> {
        self.files
            .write_blob(name, &self.files.sign(generation, rows, None))
    }

    /// The header and its generation, under the attribution rule of
    /// [`SelectorStore::read_transaction`] here; `Err` when the header, the
    /// record or a side file could not be read.
    fn attributed_transaction(&self) -> Result<Option<(u64, Transaction)>, SelectorError> {
        let header = match self.files.read_verified(TRANSACTION)? {
            Some(b) => b.transaction.map(|t| (b.generation, t)),
            None => None,
        };
        let Some((generation, header)) = header.or_else(|| self.record.legacy_transaction()) else {
            return Ok(None);
        };
        if !self.record.routes_everything() {
            let primary = self.generation(RecordCopy::Primary)?;
            if primary != Some(generation)
                && self.first_rows_at([ROWS, COMMITTED], generation)?.is_none()
            {
                tracing::warn!(
                    header_generation = generation,
                    ?primary,
                    "boot-vector: transaction header with no manager rows at its generation — dropped"
                );
                return Ok(None);
            }
        }
        Ok(Some((generation, header)))
    }

    /// Sign + write the header for `generation` (empty entries).
    fn write_header(&self, generation: u64, header: &Transaction) -> Result<(), SelectorError> {
        let blob = self
            .files
            .sign(generation, BTreeMap::new(), Some(header.clone()));
        self.files.write_blob(TRANSACTION, &blob)
    }
}

impl<R: BootRecord + Clone> SelectorStore for RecordSelectorStore<R> {
    fn read_primary(&self) -> Result<Option<BootVector>, SelectorError> {
        let Some(r) = self.record.read(RecordCopy::Primary)? else {
            return Ok(None);
        };
        // The boot stage rolled back: manager rows follow the committed copy.
        let rows = match self.first_rows_at([ROWS, COMMITTED], r.generation)? {
            Some(rows) => rows,
            None => self.newest_rows(r.generation)?,
        };
        Ok(Some(self.union(r, rows)))
    }

    fn read_secondary(&self) -> Result<Option<BootVector>, SelectorError> {
        let Some(s) = self.record.read(RecordCopy::Secondary)? else {
            return Ok(None);
        };
        let rows = match self.rows_at(COMMITTED, s.generation)? {
            Some(rows) => Some(rows),
            // A record committed at this generation makes its rows committed,
            // even when the `committed` write did not land.
            None if self.generation(RecordCopy::Primary)? == Some(s.generation) => {
                self.rows_at(ROWS, s.generation)?
            }
            None => None,
        };
        let rows = match rows {
            Some(rows) => rows,
            None => self.newest_rows(s.generation)?,
        };
        Ok(Some(self.union(s, rows)))
    }

    fn activate(
        &self,
        entries: &BTreeMap<String, ComponentEntry>,
        header: &Transaction,
    ) -> Result<u64, SelectorError> {
        let (record_rows, manager_rows): (BTreeMap<_, _>, BTreeMap<_, _>) = entries
            .iter()
            .map(|(id, e)| (id.clone(), e.clone()))
            .partition(|(id, _)| self.record.routes(id));
        let was_trial = self.generation(RecordCopy::Primary)?.unwrap_or(0)
            != self.generation(RecordCopy::Secondary)?.unwrap_or(0);
        let generation = self.record.activate(&record_rows)?;
        if let Err(e) = self.write_rows(ROWS, generation, manager_rows) {
            if was_trial {
                tracing::warn!(
                    generation,
                    error = %e,
                    "boot-vector: manager rows not written during a standing trial — record left as is; a retry heals"
                );
            } else if let Err(re) = self.record.rollback() {
                tracing::warn!(
                    generation,
                    error = %e,
                    rollback_error = %re,
                    "boot-vector: manager rows not written and the record could not be rolled back"
                );
            } else {
                tracing::warn!(
                    generation,
                    error = %e,
                    "boot-vector: manager rows not written — record rolled back"
                );
            }
            return Err(e);
        }
        if let Err(e) = self.write_header(generation, header) {
            tracing::warn!(
                generation,
                error = %e,
                "boot vector activated but its transaction header was lost — trial boots of this trial are not counted"
            );
        }
        Ok(generation)
    }

    fn commit(&self) -> Result<(), SelectorError> {
        let Some(generation) = self.generation(RecordCopy::Primary)? else {
            return Ok(());
        };
        self.record.commit()?;
        let rows = self.first_rows_at([ROWS, COMMITTED], generation)?;
        let rows = self.required(rows, generation)?;
        self.write_rows(COMMITTED, generation, rows)
    }

    fn rollback(&self, header: &Transaction) -> Result<u64, SelectorError> {
        let primary = self.generation(RecordCopy::Primary)?;
        let floor = self
            .generation(RecordCopy::Secondary)?
            .filter(|&s| primary != Some(s))
            .ok_or(SelectorError::NoTrial)?;
        let rows = self.first_rows_at([COMMITTED, ROWS], floor)?;
        let rows = self.required(rows, floor)?;
        self.write_header(floor, header)?;
        let generation = self.record.rollback()?;
        if let Err(e) = self.write_rows(ROWS, generation, rows) {
            tracing::warn!(
                generation,
                error = %e,
                "boot-vector: rolled back but the manager rows were not rewritten — reads follow the committed rows"
            );
        }
        Ok(generation)
    }

    fn read_transaction(&self) -> Option<(u64, Transaction)> {
        self.attributed_transaction().unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "boot-vector: transaction header could not be attributed — read as none"
            );
            None
        })
    }

    fn write_transaction(
        &self,
        generation: u64,
        header: &Transaction,
    ) -> Result<(), SelectorError> {
        self.write_header(generation, header)
    }
}

// ---------------------------------------------------------------------------
// The file record — the host/sim reference record
// ---------------------------------------------------------------------------

/// The reference [`BootRecord`]: two JSON files of [`SelectorBlob`]s,
/// `primary` and `secondary`, routing every component. JSON (not the canonical
/// binary encoding) purely so the files are **human-inspectable** during
/// bring-up; a missing file, or a blob that does not parse or fails
/// [`SelectorBlob::is_valid`], reads as absent; a file that exists and cannot
/// be read is `Err`.
///
/// It issues `max(primary, secondary) + 1` on `activate`. With a legacy slot
/// map configured ([`FileSelectorStore::with_legacy_slot_map`]) every copy
/// write also emits `selectors`.
///
/// Migration: a primary written by v0.1.14 carries the header inside its own
/// blob; [`BootRecord::legacy_transaction`] returns it, verified.
#[derive(Clone, Debug)]
pub struct FileBootRecord {
    files: SignedFiles,
    legacy_slot_map: Option<BTreeMap<String, BankSet>>,
}

impl FileBootRecord {
    pub(crate) fn new(files: SignedFiles) -> Self {
        Self {
            files,
            legacy_slot_map: None,
        }
    }

    fn name(copy: RecordCopy) -> &'static str {
        match copy {
            RecordCopy::Primary => PRIMARY,
            RecordCopy::Secondary => SECONDARY,
        }
    }

    /// Sign + write a copy (no header), with the legacy slot map if configured.
    fn write_copy(
        &self,
        copy: RecordCopy,
        generation: u64,
        entries: BTreeMap<String, ComponentEntry>,
    ) -> Result<(), SelectorError> {
        let mut blob = self.files.sign(generation, entries, None);
        blob.selectors = self.legacy_slot_map.as_ref().map(|map| {
            blob.entries
                .iter()
                .filter_map(|(id, e)| map.get(id).map(|&set| (set, SlotSelect::new(e.bank))))
                .collect()
        });
        self.files.write_blob(Self::name(copy), &blob)
    }
}

impl BootRecord for FileBootRecord {
    fn routes(&self, _component_id: &str) -> bool {
        true
    }
    fn routes_everything(&self) -> bool {
        true
    }
    fn read(&self, copy: RecordCopy) -> Result<Option<BootVector>, SelectorError> {
        Ok(self
            .files
            .read_verified(Self::name(copy))?
            .map(|b| BootVector {
                generation: b.generation,
                entries: b.entries,
            }))
    }
    fn activate(&self, rows: &BTreeMap<String, ComponentEntry>) -> Result<u64, SelectorError> {
        let generation = next_generation(
            self.read(RecordCopy::Primary)?.as_ref(),
            self.read(RecordCopy::Secondary)?.as_ref(),
        );
        self.write_copy(RecordCopy::Primary, generation, rows.clone())?;
        Ok(generation)
    }
    fn commit(&self) -> Result<(), SelectorError> {
        match self.read(RecordCopy::Primary)? {
            Some(p) => self.write_copy(RecordCopy::Secondary, p.generation, p.entries),
            None => Ok(()),
        }
    }
    fn rollback(&self) -> Result<u64, SelectorError> {
        let primary = self.read(RecordCopy::Primary)?;
        let secondary = self
            .read(RecordCopy::Secondary)?
            .filter(|s| primary.as_ref() != Some(s))
            .ok_or(SelectorError::NoTrial)?;
        self.write_copy(RecordCopy::Primary, secondary.generation, secondary.entries)?;
        Ok(secondary.generation)
    }
    fn legacy_transaction(&self) -> Option<(u64, Transaction)> {
        // An unreadable primary fails `read`; here it carries no header.
        let blob = self.files.read_verified(PRIMARY).ok().flatten()?;
        Some((blob.generation, blob.transaction?))
    }
}

/// The file-backed reference [`SelectorStore`]: the [`RecordSelectorStore`]
/// over a [`FileBootRecord`], record and side files in one directory under one
/// signer. Files: `primary` / `secondary` (the copies, no header),
/// `transaction` (empty entries at the primary generation it belongs to,
/// carrying the header), and `rows` / `committed` (empty entries — the file
/// record routes every component).
pub type FileSelectorStore = RecordSelectorStore<FileBootRecord>;

impl FileSelectorStore {
    /// A store over `dir`, signing and verifying every blob with `signer`.
    pub fn new(dir: impl Into<PathBuf>, signer: Box<dyn Signer>) -> Self {
        let files = SignedFiles::new(dir.into(), signer.into());
        Self {
            record: FileBootRecord::new(files.clone()),
            files,
        }
    }

    /// Also emit the legacy slot map (`selectors`, `slot -> {bank}`) on every
    /// copy write, translating each entry's component id to its slot via `map`
    /// (an id absent from `map` gets no slot). For a boot stage that still
    /// reads the previous shape; removed when no deployed boot stage needs it.
    /// Nothing reads the map back — it is outside the digest, so a tampered
    /// map changes nothing. The side files never carry it.
    pub fn with_legacy_slot_map(mut self, map: BTreeMap<String, BankSet>) -> Self {
        self.record.legacy_slot_map = Some(map);
        self
    }
}

// ---------------------------------------------------------------------------
// In-memory test record
// ---------------------------------------------------------------------------

/// In-memory [`BootRecord`] routing a chosen set of components: both copies in
/// cells behind mutexes, with the file record's generation rule. Clones share
/// the cells. [`Self::set_fail_writes`] makes `activate` / `commit` /
/// `rollback` fail and change nothing; [`Self::set_next_generation`] makes the
/// next `activate` issue a chosen generation; [`Self::boot_stage_rollback`]
/// models the boot stage restoring the secondary; [`Self::set_fail_reads`]
/// makes the record unreadable; [`Self::tear_committed`] leaves no copy at the
/// floor.
#[cfg(feature = "test-seams")]
#[derive(Debug, Default, Clone)]
pub struct InMemoryBootRecord {
    routed: Arc<std::collections::BTreeSet<String>>,
    primary: Arc<std::sync::Mutex<Option<BootVector>>>,
    secondary: Arc<std::sync::Mutex<Option<BootVector>>>,
    next_generation: Arc<std::sync::Mutex<Option<u64>>>,
    fail_writes: Arc<std::sync::atomic::AtomicBool>,
    fail_reads: Arc<std::sync::atomic::AtomicBool>,
    writes: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "test-seams")]
impl InMemoryBootRecord {
    /// An empty record routing exactly `ids`.
    pub fn routing<'a>(ids: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            routed: Arc::new(ids.into_iter().map(str::to_string).collect()),
            ..Self::default()
        }
    }

    /// While `fail` is set, `activate` / `commit` / `rollback` return `Err`
    /// and change nothing.
    pub fn set_fail_writes(&self, fail: bool) {
        self.fail_writes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// While `fail` is set, `read` returns `Err(Unreadable)` — the backend
    /// reports that its check could not run — and so does every verb that
    /// reads a copy.
    pub fn set_fail_reads(&self, fail: bool) {
        self.fail_reads
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Number of write verbs that succeeded (failed ones are not counted).
    pub fn write_count(&self) -> usize {
        self.writes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Make the next successful `activate` issue exactly `generation`; later
    /// ones follow the usual rule again.
    pub fn set_next_generation(&self, generation: u64) {
        *self.next_generation.lock().expect("generation poisoned") = Some(generation);
    }

    /// What the boot stage does when the node fails to start: primary :=
    /// secondary. Not a record verb — it models the boot stage acting on its
    /// own, so it ignores [`Self::set_fail_writes`] and is not counted in
    /// [`Self::write_count`].
    pub fn boot_stage_rollback(&self) {
        let secondary = self.secondary.lock().expect("secondary poisoned").clone();
        *self.primary.lock().expect("primary poisoned") = secondary;
    }

    /// No copy at the floor: the secondary reads absent, the primary stays.
    /// Not a record verb, like [`Self::boot_stage_rollback`].
    pub fn tear_committed(&self) {
        *self.secondary.lock().expect("secondary poisoned") = None;
    }

    /// `Err` while writes are set to fail.
    fn check_writable(&self) -> Result<(), SelectorError> {
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SelectorError::Io(std::io::Error::other(
                "injected boot record write failure",
            )));
        }
        Ok(())
    }

    fn count_write(&self) {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "test-seams")]
impl BootRecord for InMemoryBootRecord {
    fn routes(&self, component_id: &str) -> bool {
        self.routed.contains(component_id)
    }
    fn read(&self, copy: RecordCopy) -> Result<Option<BootVector>, SelectorError> {
        if self.fail_reads.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SelectorError::Unreadable("test".to_string()));
        }
        Ok(match copy {
            RecordCopy::Primary => self.primary.lock().expect("primary poisoned").clone(),
            RecordCopy::Secondary => self.secondary.lock().expect("secondary poisoned").clone(),
        })
    }
    fn activate(&self, rows: &BTreeMap<String, ComponentEntry>) -> Result<u64, SelectorError> {
        self.check_writable()?;
        let (primary, secondary) = (
            self.read(RecordCopy::Primary)?,
            self.read(RecordCopy::Secondary)?,
        );
        let generation = self
            .next_generation
            .lock()
            .expect("generation poisoned")
            .take()
            .unwrap_or_else(|| next_generation(primary.as_ref(), secondary.as_ref()));
        *self.primary.lock().expect("primary poisoned") = Some(BootVector {
            generation,
            entries: rows.clone(),
        });
        self.count_write();
        Ok(generation)
    }
    fn commit(&self) -> Result<(), SelectorError> {
        self.check_writable()?;
        if let Some(primary) = self.read(RecordCopy::Primary)? {
            *self.secondary.lock().expect("secondary poisoned") = Some(primary);
        }
        self.count_write();
        Ok(())
    }
    fn rollback(&self) -> Result<u64, SelectorError> {
        self.check_writable()?;
        let primary = self.read(RecordCopy::Primary)?.map(|p| p.generation);
        let secondary = self
            .read(RecordCopy::Secondary)?
            .filter(|s| primary != Some(s.generation))
            .ok_or(SelectorError::NoTrial)?;
        let generation = secondary.generation;
        *self.primary.lock().expect("primary poisoned") = Some(secondary);
        self.count_write();
        Ok(generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::*;
    use crate::types::Bank;

    /// Unique per-run path under the system temp dir so concurrent test
    /// binaries don't collide.
    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sumo-selector-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn entries(id: &str, bank: Bank) -> BTreeMap<String, ComponentEntry> {
        BTreeMap::from([(id.to_string(), ComponentEntry::new(bank, BTreeMap::new()))])
    }

    fn header() -> Transaction {
        Transaction {
            armed_boot_id: [0; 16],
            trial_boots: 0,
            counted_boot_id: [0; 16],
            resolution: None,
        }
    }

    /// Plant `blob` as the file `name` in `dir`, bypassing the store.
    #[cfg(feature = "test-seams")]
    fn plant(dir: &std::path::Path, name: &str, blob: &SelectorBlob) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), serde_json::to_vec_pretty(blob).unwrap()).unwrap();
    }

    #[test]
    fn file_store_write_into_uncreatable_dir_is_err() {
        // A regular file sits where the store directory should be, so
        // `create_dir_all` (and every later step) cannot succeed.
        let file = temp_path("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let store = FileSelectorStore::new(file.join("store"), Box::new(StubSigner));

        assert!(store.activate(&entries("os", Bank::B), &header()).is_err());
        assert!(store.write_transaction(1, &header()).is_err());
        assert!(
            store.read_primary().is_err(),
            "a store path that cannot be opened is unreadable, not absent"
        );

        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn file_store_successful_write_round_trips() {
        let dir = temp_path("ok");
        let store = FileSelectorStore::new(&dir, Box::new(StubSigner));

        assert_eq!(
            store.activate(&entries("os", Bank::A), &header()).unwrap(),
            1
        );
        store.commit().expect("commit");
        assert_eq!(
            store.activate(&entries("os", Bank::B), &header()).unwrap(),
            2
        );
        let reader = FileSelectorStore::new(&dir, Box::new(StubSigner));
        assert_eq!(
            reader.read_primary().unwrap(),
            Some(BootVector {
                generation: 2,
                entries: entries("os", Bank::B)
            })
        );
        assert_eq!(
            reader.read_secondary().unwrap(),
            Some(BootVector {
                generation: 1,
                entries: entries("os", Bank::A)
            })
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn legacy_slot_map_only_when_configured_and_outside_the_digest() {
        let mut written = entries("os", Bank::B);
        written.insert(
            "vm1".to_string(),
            ComponentEntry::new(Bank::A, BTreeMap::new()),
        );
        let raw = |dir: &std::path::Path, name: &str| -> SelectorBlob {
            serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap()
        };

        // Not configured: no `selectors` key in the JSON.
        let plain_dir = temp_path("plain");
        let plain = FileSelectorStore::new(&plain_dir, Box::new(StubSigner));
        plain.activate(&written, &header()).unwrap();
        let json = std::fs::read_to_string(plain_dir.join("primary")).unwrap();
        assert!(!json.contains("selectors"), "{json}");
        assert_eq!(plain.read_primary().unwrap().unwrap().entries, written);

        // Configured: `slot -> {bank}` derived from the entries; an id with no
        // slot is left out. The transaction file never carries the map.
        let legacy_dir = temp_path("legacy");
        let map = BTreeMap::from([("os".to_string(), BankSet(0))]);
        let legacy =
            FileSelectorStore::new(&legacy_dir, Box::new(StubSigner)).with_legacy_slot_map(map);
        legacy.activate(&written, &header()).unwrap();
        legacy.commit().unwrap();
        let want = Some(BTreeMap::from([(BankSet(0), SlotSelect::new(Bank::B))]));
        let read = raw(&legacy_dir, "primary");
        assert_eq!(read.selectors, want);
        assert_eq!(raw(&legacy_dir, "secondary").selectors, want);
        assert_eq!(raw(&legacy_dir, "transaction").selectors, None);
        assert_eq!(read.entries, written);
        assert!(read.is_valid(&StubSigner));

        // A modified legacy map does not affect validity (the digest is
        // recomputed over the entries alone).
        let mut tampered = read;
        tampered.selectors = Some(BTreeMap::from([(BankSet(0), SlotSelect::new(Bank::A))]));
        assert!(tampered.is_valid(&StubSigner));

        std::fs::remove_dir_all(&plain_dir).unwrap();
        std::fs::remove_dir_all(&legacy_dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn contract_holds_for_the_file_store() {
        let dir = temp_path("contract");
        contract::exercise(&FileSelectorStore::new(&dir, Box::new(TestSigner)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn contract_holds_for_a_record_that_routes_part_of_the_vector() {
        let dir = temp_path("contract-partial");
        contract::exercise(&RecordSelectorStore::over(
            InMemoryBootRecord::routing(["os"]),
            &dir,
            Box::new(TestSigner),
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn record_contract_holds_for_the_file_record() {
        let dir = temp_path("record-contract");
        contract::exercise_record(&FileBootRecord::new(SignedFiles::new(
            dir.clone(),
            Arc::new(TestSigner),
        )));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn record_contract_holds_for_the_in_memory_record() {
        contract::exercise_record(&InMemoryBootRecord::routing(["os"]));
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn tampered_copy_reads_as_absent() {
        let dir = temp_path("tampered");
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));

        // A copy whose signature doesn't verify under TestSigner (empty sig —
        // StubSigner would have produced this).
        let entries = entries("vm1", Bank::B);
        let generation = 9;
        let bad = SelectorBlob {
            generation,
            entries: entries.clone(),
            transaction: None,
            sha256: SelectorBlob::compute_sha256(generation, &entries, None),
            signature: Vec::new(), // invalid under TestSigner
            selectors: None,
        };
        plant(&dir, PRIMARY, &bad);
        plant(&dir, SECONDARY, &bad);
        assert_eq!(store.read_primary().unwrap(), None);
        assert_eq!(store.read_secondary().unwrap(), None);

        // Also reject a copy with a tampered digest (sig over a different sha).
        let tampered = SelectorBlob {
            generation,
            entries,
            transaction: None,
            sha256: [0u8; 32], // doesn't match contents
            signature: TestSigner.sign(&[0u8; 32]),
            selectors: None,
        };
        plant(&dir, PRIMARY, &tampered);
        assert_eq!(store.read_primary().unwrap(), None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- blobs signed over the retired per-slot encoding ---

    #[cfg(feature = "test-seams")]
    #[test]
    fn legacy_slot_blob_reads_as_absent() {
        // A blob correctly signed over the OLD encoding — `[set, bank]` per
        // slot, the selection carried only in the slot map — no longer
        // verifies: the digest is over the entries, and there are none. Both
        // copies read as absent, so the node looks unseeded and the host
        // reseeds it from NV.
        use crate::types::slots;
        use sha2::{Digest, Sha256};

        let generation: u64 = 5;
        let mut legacy = generation.to_le_bytes().to_vec();
        legacy.extend_from_slice(&[slots::VM1.0, Bank::A as u8]);
        let sha256: [u8; 32] = Sha256::digest(&legacy).into();
        let mut selectors = BTreeMap::new();
        selectors.insert(slots::VM1, SlotSelect::new(Bank::A));
        let blob = SelectorBlob {
            generation,
            entries: BTreeMap::new(),
            transaction: None,
            sha256,
            signature: TestSigner.sign(&sha256),
            selectors: Some(selectors),
        };
        assert!(
            TestSigner.verify(&blob.sha256, &blob.signature),
            "the signature itself is good — only the digest is stale"
        );

        let dir = temp_path("legacy-slot");
        plant(&dir, PRIMARY, &blob);
        plant(&dir, SECONDARY, &blob);
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));
        assert_eq!(store.read_primary().unwrap(), None, "PRIMARY rejected");
        assert_eq!(store.read_secondary().unwrap(), None, "SECONDARY rejected");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- the store contract: header, copies, generations ---

    #[cfg(feature = "test-seams")]
    #[test]
    fn activate_writes_the_primary_before_the_header_so_a_failed_header_leaves_the_trial_without_one(
    ) {
        let dir = temp_path("primary-first");
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));
        assert_eq!(
            store.activate(&entries("os", Bank::A), &header()).unwrap(),
            1
        );
        store.commit().unwrap();

        // Fault injection: a directory at `transaction.tmp` makes
        // `File::create` fail in `write_blob` for the header only; the
        // primary goes through `primary.tmp`, which is unaffected.
        std::fs::create_dir(dir.join("transaction.tmp")).unwrap();
        let mut armed = header();
        armed.trial_boots = 1;
        assert_eq!(
            store.activate(&entries("os", Bank::B), &armed).unwrap(),
            2,
            "a lost header does not fail the activation"
        );

        assert_eq!(
            store.read_primary().unwrap(),
            Some(BootVector {
                generation: 2,
                entries: entries("os", Bank::B)
            }),
            "the primary moved"
        );
        assert_eq!(
            store.read_transaction(),
            Some((1, header())),
            "the previous header is left, below the primary"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn rollback_writes_the_header_before_the_primary_so_a_failed_primary_leaves_the_trial_in_place()
    {
        let dir = temp_path("rollback-header-first");
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));
        store.activate(&entries("os", Bank::A), &header()).unwrap();
        store.commit().unwrap();
        assert_eq!(
            store.activate(&entries("os", Bank::B), &header()).unwrap(),
            2
        );
        let trial = store.read_primary().unwrap().unwrap();
        let primary_bytes = std::fs::read(dir.join(PRIMARY)).unwrap();

        // Fault injection: a directory at `primary.tmp` makes the primary
        // write fail; the header goes through `transaction.tmp`.
        std::fs::create_dir(dir.join("primary.tmp")).unwrap();
        let mut resolved = header();
        resolved.resolution = Some(Resolution {
            outcome: Outcome::RolledBack,
            reason: Reason::Verdict,
        });
        assert!(
            store.rollback(&resolved).is_err(),
            "the primary write fails"
        );

        assert_eq!(
            store.read_primary().unwrap(),
            Some(trial),
            "primary unchanged"
        );
        assert_eq!(
            std::fs::read(dir.join(PRIMARY)).unwrap(),
            primary_bytes,
            "primary bytes unchanged"
        );
        assert_eq!(
            store.read_transaction(),
            Some((1, resolved)),
            "the rollback header sits at the committed generation, below the primary"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn v0_1_14_primary_with_an_embedded_header_reads_as_the_transaction() {
        let dir = temp_path("v0-1-14");
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));
        let e = entries("os", Bank::B);
        let mut embedded = header();
        embedded.trial_boots = 3;
        let blob = SelectorBlob::signed(7, e.clone(), Some(embedded.clone()), &TestSigner);
        plant(&dir, PRIMARY, &blob);

        let vector = BootVector {
            generation: 7,
            entries: e.clone(),
        };
        assert_eq!(store.read_primary().unwrap(), Some(vector.clone()));
        assert_eq!(store.read_transaction(), Some((7, embedded)));

        // A transaction file, once written, wins over the embedded header.
        let mut other = header();
        other.trial_boots = 9;
        store.write_transaction(7, &other).unwrap();
        assert_eq!(store.read_transaction(), Some((7, other)));
        assert_eq!(store.read_primary().unwrap(), Some(vector));

        // A tampered signature: neither the vector nor the header is trusted.
        let dir2 = temp_path("v0-1-14-bad");
        let store2 = FileSelectorStore::new(&dir2, Box::new(TestSigner));
        let mut bad = blob;
        bad.signature = vec![0xFF; 32];
        plant(&dir2, PRIMARY, &bad);
        assert_eq!(store2.read_primary().unwrap(), None);
        assert_eq!(store2.read_transaction(), None);

        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&dir2).unwrap();
    }

    #[test]
    fn transaction_file_is_not_written_into_the_copies() {
        let dir = temp_path("header-file");
        let store = FileSelectorStore::new(&dir, Box::new(StubSigner));
        let raw = |name: &str| -> SelectorBlob {
            serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap()
        };

        let generation = store.activate(&entries("os", Bank::A), &header()).unwrap();
        store.commit().unwrap();
        let mut counted = header();
        counted.trial_boots = 2;
        store.write_transaction(generation, &counted).unwrap();

        assert!(
            raw(PRIMARY).transaction.is_none(),
            "primary carries no header"
        );
        assert!(
            raw(SECONDARY).transaction.is_none(),
            "secondary carries no header"
        );
        let t = raw(TRANSACTION);
        assert!(t.entries.is_empty(), "the header file carries no entries");
        assert_eq!(t.transaction, Some(counted));
        assert_eq!(t.generation, raw(PRIMARY).generation);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- the adapter over a record that routes part of the vector ---

    /// Read a side file straight off disk, bypassing the store.
    #[cfg(feature = "test-seams")]
    fn raw(dir: &std::path::Path, name: &str) -> SelectorBlob {
        serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap()
    }

    /// `{os: os_bank, vm1: vm1_bank}`.
    #[cfg(feature = "test-seams")]
    fn vector(os: Bank, vm1: Bank) -> BTreeMap<String, ComponentEntry> {
        let mut v = entries("os", os);
        v.extend(entries("vm1", vm1));
        v
    }

    #[cfg(feature = "test-seams")]
    fn partial_store(
        tag: &str,
    ) -> (
        PathBuf,
        InMemoryBootRecord,
        RecordSelectorStore<InMemoryBootRecord>,
    ) {
        let dir = temp_path(tag);
        let record = InMemoryBootRecord::routing(["os"]);
        let store = RecordSelectorStore::over(record.clone(), &dir, Box::new(TestSigner));
        (dir, record, store)
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn manager_rows_live_in_the_rows_file_at_the_record_generation() {
        let (dir, record, store) = partial_store("rows-file");
        let mut armed = header();
        armed.trial_boots = 1;
        let g = store.activate(&vector(Bank::A, Bank::A), &armed).unwrap();

        let primary = record.read(RecordCopy::Primary).unwrap().unwrap();
        assert_eq!(primary.generation, g);
        assert_eq!(primary.entries, entries("os", Bank::A), "record: os only");

        let rows = raw(&dir, ROWS);
        assert!(rows.is_valid(&TestSigner));
        assert_eq!(rows.generation, g);
        assert_eq!(rows.entries, entries("vm1", Bank::A), "rows: vm1 only");

        let tx = raw(&dir, TRANSACTION);
        assert!(tx.is_valid(&TestSigner));
        assert_eq!(tx.generation, g);
        assert!(tx.entries.is_empty());
        assert_eq!(tx.transaction, Some(armed));

        assert_eq!(
            store.read_primary().unwrap(),
            Some(BootVector {
                generation: g,
                entries: vector(Bank::A, Bank::A)
            })
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn rows_write_failure_after_activate_rolls_an_untrialed_record_back_and_is_err() {
        let (dir, record, store) = partial_store("rows-fail-untrialed");
        store
            .activate(&vector(Bank::A, Bank::A), &header())
            .unwrap();
        store.commit().unwrap();
        let before_record = record.read(RecordCopy::Primary).unwrap();
        let before_read = store.read_primary().unwrap();

        // Fault injection: a directory at `rows.tmp` fails the rows write only.
        std::fs::create_dir(dir.join("rows.tmp")).unwrap();
        assert!(store
            .activate(&vector(Bank::B, Bank::B), &header())
            .is_err());

        assert_eq!(
            record.read(RecordCopy::Primary).unwrap(),
            before_record,
            "the record was rolled back"
        );
        assert_eq!(store.read_primary().unwrap(), before_read);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn rows_write_failure_during_a_standing_trial_is_err_and_leaves_the_record_alone() {
        let (dir, record, store) = partial_store("rows-fail-trial");
        store
            .activate(&vector(Bank::A, Bank::A), &header())
            .unwrap();
        store.commit().unwrap();
        let mut armed = header();
        armed.trial_boots = 1;
        let t = store.activate(&vector(Bank::A, Bank::B), &armed).unwrap();
        let committed = record.read(RecordCopy::Secondary).unwrap();

        std::fs::create_dir(dir.join("rows.tmp")).unwrap();
        assert!(store
            .activate(&vector(Bank::B, Bank::B), &header())
            .is_err());

        // A rollback would discard the standing trial, so the record moved and
        // stayed; a retry heals.
        assert!(
            record
                .read(RecordCopy::Primary)
                .unwrap()
                .unwrap()
                .generation
                > t
        );
        assert_eq!(record.read(RecordCopy::Secondary).unwrap(), committed);
        assert_eq!(
            store.read_transaction(),
            Some((t, armed)),
            "the trial header is still readable"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn failed_committed_write_still_reads_as_committed_and_commit_retry_writes_it() {
        let (dir, _record, store) = partial_store("committed-fail");
        store
            .activate(&vector(Bank::A, Bank::A), &header())
            .unwrap();
        store.commit().unwrap();
        let t = store
            .activate(&vector(Bank::B, Bank::B), &header())
            .unwrap();

        std::fs::create_dir(dir.join("committed.tmp")).unwrap();
        assert!(store.commit().is_err());
        let secondary = store.read_secondary().unwrap().unwrap();
        assert_eq!(secondary.generation, t);
        assert_eq!(secondary.entries, vector(Bank::B, Bank::B));
        assert_eq!(
            store.read_secondary().unwrap(),
            store.read_primary().unwrap()
        );

        std::fs::remove_dir(dir.join("committed.tmp")).unwrap();
        store.commit().expect("the retry writes it");
        let committed = raw(&dir, COMMITTED);
        assert_eq!(committed.generation, t);
        assert_eq!(committed.entries, entries("vm1", Bank::B));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn failed_record_rollback_leaves_the_header_below_and_the_trial_rows_intact() {
        let (dir, record, store) = partial_store("rollback-fail");
        let f = store
            .activate(&vector(Bank::A, Bank::A), &header())
            .unwrap();
        store.commit().unwrap();
        store
            .activate(&vector(Bank::A, Bank::B), &header())
            .unwrap();
        let trial = store.read_primary().unwrap().unwrap();
        let mut resolved = header();
        resolved.resolution = Some(Resolution {
            outcome: Outcome::RolledBack,
            reason: Reason::Verdict,
        });

        record.set_fail_writes(true);
        assert!(store.rollback(&resolved).is_err());
        assert_eq!(store.read_transaction(), Some((f, resolved.clone())));
        assert_eq!(store.read_primary().unwrap().as_ref(), Some(&trial));
        assert_eq!(trial.entries["vm1"].bank, Bank::B, "the trial row stands");

        record.set_fail_writes(false);
        assert_eq!(store.rollback(&resolved).unwrap(), f);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn write_transaction_never_touches_the_rows() {
        let (dir, _record, store) = partial_store("tx-leaves-rows");
        let g = store
            .activate(&vector(Bank::A, Bank::A), &header())
            .unwrap();
        let rows_bytes = std::fs::read(dir.join(ROWS)).unwrap();

        let mut other = header();
        other.trial_boots = 4;
        store.write_transaction(g, &other).unwrap();

        assert_eq!(std::fs::read(dir.join(ROWS)).unwrap(), rows_bytes);
        assert_eq!(store.read_transaction(), Some((g, other)));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn file_record_side_files_have_empty_rows() {
        let dir = temp_path("file-side-files");
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));
        let g = store
            .activate(&vector(Bank::A, Bank::B), &header())
            .unwrap();
        store.commit().unwrap();

        for name in [ROWS, COMMITTED] {
            let blob = raw(&dir, name);
            assert!(blob.is_valid(&TestSigner), "{name}");
            assert_eq!(blob.generation, g, "{name}");
            assert!(blob.entries.is_empty(), "{name} carries no entries");
        }
        for name in [PRIMARY, SECONDARY] {
            let blob = raw(&dir, name);
            assert_eq!(blob.generation, g, "{name}");
            assert_eq!(blob.entries, vector(Bank::A, Bank::B), "{name}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn unreadable_record_is_err_from_every_read_and_commit_never_succeeds_over_it() {
        let (dir, record, store) = partial_store("unreadable");
        store
            .activate(&vector(Bank::A, Bank::A), &header())
            .unwrap();
        let mut resolved = header();
        resolved.resolution = Some(Resolution {
            outcome: Outcome::RolledBack,
            reason: Reason::Verdict,
        });

        record.set_fail_reads(true);
        assert!(matches!(
            store.read_primary(),
            Err(SelectorError::Unreadable(_))
        ));
        assert!(store.read_secondary().is_err());
        assert!(
            store.commit().is_err(),
            "a commit over an unreadable primary is Err, never Ok"
        );
        assert!(store
            .activate(&vector(Bank::B, Bank::B), &header())
            .is_err());
        assert!(
            matches!(store.rollback(&resolved), Err(SelectorError::Unreadable(_))),
            "an unreadable record is not NoTrial"
        );

        record.set_fail_reads(false);
        assert_eq!(
            store.read_secondary().unwrap(),
            None,
            "nothing was committed"
        );
        assert_eq!(
            store.read_primary().unwrap().unwrap().entries["vm1"].bank,
            Bank::A
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn no_copy_at_the_floor_has_no_trial_to_roll_back_and_a_commit_anchors_it() {
        let (dir, record, store) = partial_store("torn-committed");
        store
            .activate(&vector(Bank::A, Bank::A), &header())
            .unwrap();
        store.commit().unwrap();
        store
            .activate(&vector(Bank::B, Bank::B), &header())
            .unwrap();

        record.tear_committed();
        assert!(matches!(store.read_secondary(), Ok(None)));
        assert!(matches!(
            store.rollback(&header()),
            Err(SelectorError::NoTrial)
        ));

        store.commit().expect("the commit anchors the vector");
        let primary = store.read_primary().unwrap();
        assert_eq!(primary.as_ref().unwrap().entries, vector(Bank::B, Bank::B));
        assert_eq!(store.read_secondary().unwrap(), primary);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn unreadable_side_file_is_err_while_a_missing_one_falls_back() {
        let (dir, _record, store) = partial_store("unreadable-rows");
        store
            .activate(&vector(Bank::A, Bank::B), &header())
            .unwrap();
        store.commit().unwrap();

        // Missing `rows`: the manager rows fall back to `committed`.
        std::fs::remove_file(dir.join(ROWS)).unwrap();
        let primary = store.read_primary().unwrap().unwrap();
        assert_eq!(primary.entries, vector(Bank::A, Bank::B));

        // `rows` exists and cannot be read: Err, never the fallback.
        std::fs::create_dir(dir.join(ROWS)).unwrap();
        assert!(matches!(store.read_primary(), Err(SelectorError::Io(_))));
        assert!(store.read_secondary().is_ok(), "`committed` still reads");
        assert!(store.commit().is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
