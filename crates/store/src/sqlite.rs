use super::*;

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::{broadcast, Mutex};

/// Per-shard watch replay depth, sized from `u7s_watch_replay_depth`: over a full conformance run
/// the deepest replay any client needed was 25 events (2,359 opens, mean 0.10). Roughly 2.5s of
/// cover at the busiest shard's ~200 ev/s burst; overrunning it costs a 410 and one client relist,
/// not correctness.
const RING_CAPACITY: usize = 512;
/// Live-event fan-out shared by EVERY watch — deliberately not sharded, so each stream filters
/// this one channel down to its own prefix and a busy resource type can lag a quiet one's watcher.
/// Overflow yields `Lagged`, recovered from that shard's ring; such recovery is extremely rare.
const BROADCAST_CAPACITY: usize = 1024;

/// How long a per-watcher stream coalesces global-bookmark broadcasts (one per write, to
/// every open watch) before yielding a single `WatchEvent::Bookmark`. KCM's EnsureReady()
/// only requires eventual convergence of an informer's sync RV, not a bookmark synchronous
/// with every write, so this is safe to debounce. 150ms keeps 8x headroom under the 2s
/// delivery deadline asserted by `write_to_different_prefix_delivers_bookmark_to_watch`.
const GLOBAL_BOOKMARK_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(150);

/// How long a shard with zero attached watchers is kept alive before its ring/deletion_log are
/// reclaimed. 120s comfortably beats real client-go reconnect latency (usually <5s), so a
/// reconnect within the window finds the ring intact; beyond it, the client gets a 410 and
/// relists — the same outcome upstream kube-apiserver produces once its own cacher expires a
/// watch, not a new failure mode. Shortened under `#[cfg(test)]` so grace-period tests don't
/// need to block for two real minutes.
#[cfg(not(test))]
pub(crate) const RING_SHARD_IDLE_GRACE: std::time::Duration = std::time::Duration::from_secs(120);
#[cfg(test)]
pub(crate) const RING_SHARD_IDLE_GRACE: std::time::Duration = std::time::Duration::from_millis(200);

/// Cap on `ReclaimedHorizons::entries`' size — see that type's doc for why, unlike `shards`, it
/// cannot rely on reuse alone to stay bounded (a namespace-scoped or CRD-derived watch prefix is
/// by construction often never reused). 4096 is far more distinct abandoned resource-type/
/// namespace prefixes than any real cluster's compaction-horizon bookkeeping needs to track
/// precisely at once; see `preserve_reclaimed_horizon` for how entries beyond this cap are
/// folded into `ReclaimedHorizons::overflow` rather than discarded.
const MAX_RECLAIMED_HORIZONS: usize = 4096;

/// One tombstone in a shard's `DeletionLog`, in one of two fidelity tiers — see
/// `push_into_shard`'s doc for the policy that moves an entry between them.
///
/// - Full: complete last-known body, needed so a selector-scoped watch can correctly decide
///   whether the deleted object still matches (see watch.rs's `WatchEvent::Deleted` handling)
///   before emitting a synthetic DELETE. Not dead weight: a full conformance run showed 81% of
///   watch opens carry a label/field selector (`u7s_apiserver_watch_opens_total`), so this
///   fidelity is actually consumed by real traffic, not just a theoretical need.
/// - Stripped: revision only, body discarded to bound memory once a tombstone has aged past
///   the Full tier. Replay degrades to `body: None`, which watch.rs's `encode_watch_event`
///   already handles today via `build_tombstone_object`'s "no body available, send
///   unconditionally" fallback (`watch.rs:295-298`) — no new wire-format code needed.
#[derive(Debug)]
enum DeletionLogEntry {
    Full(Arc<InternalEvent>),
    Stripped { revision: u64 },
}

impl DeletionLogEntry {
    /// The deletion's revision, available unconditionally in both tiers: evict-on-recreate,
    /// eviction ordering, and replay's `last_replayed` tracking all need it regardless of
    /// whether the body was stripped.
    fn revision(&self) -> u64 {
        match self {
            DeletionLogEntry::Full(event) => event.revision,
            DeletionLogEntry::Stripped { revision } => *revision,
        }
    }

    /// Render this tombstone as the `WatchEvent::Deleted` a replaying watcher receives. See
    /// this enum's own doc for why a Stripped entry's `body: None` is already a handled case,
    /// not a gap.
    fn to_watch_event(&self, key: &str) -> WatchEvent {
        match self {
            DeletionLogEntry::Full(event) => internal_to_watch(event),
            DeletionLogEntry::Stripped { revision } => WatchEvent::Deleted {
                key: key.to_string(),
                revision: *revision,
                body: None,
            },
        }
    }
}

/// Deletion-log storage: `by_key` gives O(1) lookup for evict-on-recreate and the
/// prefix-scan replay watchers use; `by_revision` mirrors it as a revision-sorted index
/// so the lowest-revision entry can be evicted in O(log n) via `pop_first()` instead of
/// an O(n) scan over `by_key`. `full_revisions` is a further revision-sorted subset of
/// `by_revision`, covering only entries still in the Full tier, so the Full -> Stripped
/// downgrade policy (see `push_into_shard`) can likewise find its victim in O(log n)
/// instead of scanning `by_key` for the lowest-revision Full entry. All three are always
/// mutated together. Revisions are unique and monotonically assigned by the single global
/// write-connection-guarded counter (see `push_event_locked`'s doc comment), so neither
/// index ever collides on the same revision key.
#[derive(Default)]
struct DeletionLog {
    by_key: HashMap<String, DeletionLogEntry>,
    by_revision: BTreeMap<u64, String>,
    full_revisions: BTreeSet<u64>,
}

/// One resource type's ring buffer + deletion log, keyed by its resource-type root prefix (see
/// `shard_key`). Before sharding, a single busy resource type (e.g. Pods, which writes orders
/// of magnitude more often than e.g. Namespaces) could evict a quiet resource type's watch
/// history out of one shared ring, and every watch-open/Lagged-recovery scan walked the combined
/// occupancy of every resource type in the store instead of just its own prefix.
pub(crate) struct RingShard {
    ring: RwLock<VecDeque<Arc<InternalEvent>>>,
    /// Push timestamps for `ring`'s entries, as whole seconds since the store's epoch, in
    /// lockstep with it: `push_secs[i]` is when `ring[i]` was pushed. Feeds
    /// `WATCH_RING_SPAN_SECONDS`, which reports how much history this shard actually covers —
    /// the property that decides whether a reconnecting watch survives (see that histogram's
    /// doc, which also explains why it is a span between two push times and not an age relative
    /// to now).
    ///
    /// A side deque rather than a field on `InternalEvent` or a `(event, secs)` tuple in `ring`
    /// itself, for one reason: widening `ring`'s element from 8 bytes (a thin `Arc`) to 16
    /// (`Arc` + `u32` + padding) would double the retained-event cost of every shard. Neither
    /// deque is pre-allocated — both grow on demand as events are pushed — so this deque costs
    /// only 4 extra bytes per event actually retained, instead of doubling `ring`'s own 8 for
    /// every entry.
    ///
    /// INVARIANT: `push_secs.len() == ring.len()`. Upheld because `push_event_locked` is the
    /// only code that touches this field at all, and it pushes/pops both deques together while
    /// holding `ring`'s write guard. Do not read or mutate it elsewhere without preserving that.
    push_secs: RwLock<VecDeque<u32>>,
    /// This shard's own compaction floor: the revision of the oldest entry its ring still holds,
    /// as of its most recent eviction. 0 until this shard has evicted anything, which correctly
    /// means "nothing of this resource type has been discarded, so no revision of it is expired."
    ///
    /// Authoritative for expiry decisions. `SqliteStore::compaction_horizon` is a cross-shard
    /// maximum and must NOT be used to expire a watch — see its field doc.
    horizon: AtomicU64,
    deletion_log: RwLock<DeletionLog>,
    /// Number of currently-open `watch()` streams attached to this shard. Incremented when a
    /// stream resolves (or creates) this shard at open, decremented when the stream ends —
    /// see `watch`'s `ShardWatcherGuard`. The idle-GC callback re-checks this under `shards`'
    /// write lock before tearing a shard down, so a watch that reconnects during the grace
    /// window (bumping this back above zero) defeats the pending teardown.
    watchers: AtomicUsize,
}

impl RingShard {
    fn new() -> Self {
        Self {
            ring: RwLock::new(VecDeque::new()),
            push_secs: RwLock::new(VecDeque::new()),
            horizon: AtomicU64::new(0),
            deletion_log: RwLock::new(DeletionLog::default()),
            watchers: AtomicUsize::new(0),
        }
    }
}

/// RAII handle a `watch()` stream holds for exactly as long as it is open. Registers itself as
/// one of `shard`'s live watchers on construction; on drop (stream ended, whether by client
/// disconnect, error, or being polled to completion), deregisters, and if that was the LAST
/// watcher, schedules `shard` for idle-GC after `RING_SHARD_IDLE_GRACE`.
///
/// Lives as a local binding inside `watch()`'s `async_stream::stream!` body, not in `watch()`'s
/// own outer scope — a generator's live locals are dropped exactly when the generator itself is
/// dropped, which for a `Stream` is exactly when the client's connection (or whatever is polling
/// it) goes away. That is the one signal this whole lifecycle needs: "is anyone still reading
/// this stream," which nothing else in `watch()`'s own body observes.
struct ShardWatcherGuard {
    shards: Arc<RwLock<BTreeMap<String, Arc<RingShard>>>>,
    reclaimed_horizons: Arc<RwLock<ReclaimedHorizons>>,
    key: String,
    shard: Arc<RingShard>,
}

impl ShardWatcherGuard {
    fn attach(
        shards: Arc<RwLock<BTreeMap<String, Arc<RingShard>>>>,
        reclaimed_horizons: Arc<RwLock<ReclaimedHorizons>>,
        key: String,
        shard: Arc<RingShard>,
    ) -> Self {
        shard.watchers.fetch_add(1, Ordering::AcqRel);
        Self {
            shards,
            reclaimed_horizons,
            key,
            shard,
        }
    }
}

impl Drop for ShardWatcherGuard {
    fn drop(&mut self) {
        // fetch_sub returns the PRE-decrement value, so `== 1` means we just took the count to
        // zero — the moment a shard becomes eligible for idle-GC, not merely "some watcher left."
        if self.shard.watchers.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        schedule_idle_gc(
            Arc::clone(&self.shards),
            Arc::clone(&self.reclaimed_horizons),
            self.key.clone(),
            Arc::clone(&self.shard),
        );
    }
}

/// Schedule `shard` for removal from `shards` after `RING_SHARD_IDLE_GRACE`, if it still has
/// zero attached watchers when the grace period elapses. Shared by the two events that can make
/// a shard's continued existence unjustified: `ShardWatcherGuard::drop` (a watch closed, taking
/// `watchers` from one to zero) and `get_or_create_shard` (a write just created the shard and no
/// watch has EVER attached to it — see that function's doc for why a write can create a shard
/// now, and why "zero watchers since creation" needs the exact same grace-then-reap treatment as
/// "zero watchers as of just now," or a written-but-never-watched resource type's shard would
/// live for the rest of the process's life).
fn schedule_idle_gc(
    shards: Arc<RwLock<BTreeMap<String, Arc<RingShard>>>>,
    reclaimed_horizons: Arc<RwLock<ReclaimedHorizons>>,
    key: String,
    shard: Arc<RingShard>,
) {
    tokio::spawn(async move {
        tokio::time::sleep(RING_SHARD_IDLE_GRACE).await;
        // Re-check AND remove under the SAME write-lock acquisition: a watch that reconnects
        // during the grace window re-attaches via `find_shard_key`/`get_or_create_shard`
        // (each of which also needs `shards`' lock), so by the time this write-lock is
        // granted, any such reconnect has already either bumped `watchers` back above zero
        // (this check then correctly declines) or has not happened yet (in which case it
        // will simply create a fresh shard afterward, exactly as if this one had never
        // existed). `Arc::ptr_eq` guards against the pathological case where this exact key
        // was removed and then recreated as a DIFFERENT shard in between — removing that new
        // one instead would silently orphan whatever just attached to it.
        let removed = {
            let mut guard = shards.write().expect("shards poisoned");
            let idle = guard
                .get(&key)
                .is_some_and(|s| Arc::ptr_eq(s, &shard) && s.watchers.load(Ordering::Acquire) == 0);
            if idle {
                guard.remove(&key)
            } else {
                None
            }
        };
        if let Some(shard) = &removed {
            // Preserve this shard's floor before it is dropped for good — see
            // `reclaimed_horizons`' doc for why "no shard" alone can no longer mean "never
            // written" once idle-GC can reclaim one that genuinely held history.
            preserve_reclaimed_horizon(&reclaimed_horizons, &key, shard);
            crate::metrics::WATCH_RING_SHARD_EVICTIONS_TOTAL
                .with_label_values(&[crate::metrics::prefix_bucket(&key)])
                .inc();
            tracing::debug!(shard = %key, "watch: idle ring shard evicted after grace period");
        }
    });
}

/// Preserve `shard`'s compaction floor into `reclaimed_horizons` before its entry in `shards`
/// is dropped for good — the discriminator `compaction_horizon_for`/`get_or_create_shard`
/// consult once a shard can be reclaimed mid-life (see `reclaimed_horizons`' doc).
///
/// The floor to preserve is NOT just `shard.horizon` (the eviction floor, 0 until the ring has
/// overflowed at least once): a shard that never evicted anything still held every event it
/// ever saw, and that whole history becomes unreplayable the moment its ring is gone. Reading
/// the ring's own back (its highest still-held revision) and taking the max with the eviction
/// floor is what makes a quiet, never-evicting shard's teardown still correctly expire a stale
/// reconnect instead of only a busy, already-evicting one's.
///
/// Skips the insert when the computed floor is 0 (an empty shard that never held anything, or
/// whose ring was never even created before this happened) — such an entry would carry no
/// information over a map-miss and would only cost this map's own bound story an entry it does
/// not need.
///
/// Enforces `MAX_RECLAIMED_HORIZONS` on `entries` by folding an over-cap victim's floor into
/// `overflow` (an `AtomicU64` via `fetch_max`, never another map key) instead of discarding it:
/// a later lookup for the evicted key would otherwise see `find_reclaimed_horizon` return 0 ("no
/// horizon known") and wrongly treat a from_revision that really is stale as already caught up,
/// silently skipping every event it should have replayed. Folding into the atomic rather than a
/// parent map key (an earlier design tried and abandoned) is what makes this insert
/// structurally always net -1 on `entries` when over cap, with no cap re-check needed: the fold
/// destination can never itself be a novel key that leaves the map still over cap.
///
/// The victim is the entry with the SMALLEST preserved horizon, not an arbitrary or
/// insertion-order one: revisions only ever increase, so a low horizon is both the entry least
/// likely to still matter to any currently-connected watch (whose own from_revision is likely
/// much closer to the store's current, much larger revision) and a reasonable proxy for "least
/// recently abandoned" without needing a separate ordering structure just for this bound.
fn preserve_reclaimed_horizon(
    reclaimed_horizons: &RwLock<ReclaimedHorizons>,
    key: &str,
    shard: &RingShard,
) {
    let ring_top = shard
        .ring
        .read()
        .expect("ring poisoned")
        .back()
        .map_or(0, |event| event.revision);
    let horizon = shard.horizon.load(Ordering::Relaxed).max(ring_top);
    if horizon == 0 {
        return;
    }
    let mut guard = reclaimed_horizons
        .write()
        .expect("reclaimed_horizons poisoned");
    guard.entries.insert(key.to_string(), horizon);
    if guard.entries.len() <= MAX_RECLAIMED_HORIZONS {
        return;
    }
    let Some(victim_key) = guard
        .entries
        .iter()
        .min_by_key(|(_, &horizon)| horizon)
        .map(|(k, _)| k.clone())
    else {
        return;
    };
    if let Some(victim_horizon) = guard.entries.remove(&victim_key) {
        guard.overflow.fetch_max(victim_horizon, Ordering::Relaxed);
    }
}

/// The one-level-up shard root a lookup for `prefix` falls back to when nothing matches
/// `prefix` exactly: strip the trailing namespace segment a namespace-scoped watch prefix
/// carries. `find_shard`'s doc establishes that every prefix this crate ever looks up here is
/// exactly a resource-type root, or that root plus one namespace segment — never deeper — so
/// this is the only OTHER string that could ever be a genuine shard key for `prefix`, and one
/// hop is always sufficient (no loop needed). `None` only if `prefix` has no further segment to
/// strip.
fn parent_prefix(prefix: &str) -> Option<String> {
    let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
    trimmed.rsplit_once('/').map(|(root, _)| format!("{root}/"))
}

/// Compaction floors preserved for torn-down shard prefixes (see
/// `SqliteStore::reclaimed_horizons`'s doc for what an entry means and when one is created).
///
/// Bounded at `MAX_RECLAIMED_HORIZONS` entries — unlike `shards`, this cannot rely on reuse
/// alone to stay small, since a namespace-scoped or CRD-derived watch prefix is often never
/// reused. `overflow` is what makes the cap safe rather than lossy: every entry evicted past the
/// cap folds its floor in here via `fetch_max` (see `preserve_reclaimed_horizon`), so
/// `find_reclaimed_horizon` always has a valid, monotonically non-decreasing lower bound to fall
/// back to for ANY evicted prefix, regardless of its shape (resource-type root, childless root,
/// or namespace child) — no per-shape special-casing needed, unlike the fold-to-a-parent-map-key
/// design this replaced, whose fold target was itself just another map key subject to
/// the same unbounded-growth problem one tier up.
#[derive(Default)]
pub(crate) struct ReclaimedHorizons {
    entries: HashMap<String, u64>,
    overflow: AtomicU64,
}

pub struct SqliteStore {
    /// Single write connection. Mutex ensures serial access across spawn_blocking calls.
    /// ALL rusqlite calls must go through spawn_blocking — rusqlite is synchronous.
    write_conn: Arc<Mutex<Connection>>,
    /// Read connection (WAL allows concurrent readers).
    /// For Phase 1 with one vCPU, a single read connection is sufficient.
    /// For :memory: databases, this is the same connection as write_conn.
    read_conn: Arc<Mutex<Connection>>,
    /// Broadcast channel for live events after writes. Deliberately NOT sharded — every open
    /// watch stream already filters this one channel down to its own prefix; sharding delivery
    /// itself is a separate, larger fan-out axis tracked independently of the ring/deletion_log
    /// sharding this type does.
    tx: broadcast::Sender<Arc<InternalEvent>>,
    /// Per-resource-type shards (ring buffer + deletion log), created lazily — normally by the
    /// first `watch()` on a resource type, or by a write if that write is a delete nobody's
    /// shard has recorded yet (see `push_event_locked`'s doc for why deletes are special) — and
    /// idle-GC'd after `RING_SHARD_IDLE_GRACE` if no watcher ever attaches. A typical run only
    /// ever writes a few dozen of the ~40+ core resource types plus whatever CRDs are installed,
    /// so pre-populating every possible shard up front would waste memory on types nobody ever
    /// writes. See `shard_key` for how a write's shard is derived, and `RingShard`'s doc for why
    /// sharding this way matters.
    shards: Arc<RwLock<BTreeMap<String, Arc<RingShard>>>>,
    /// Compaction floor preserved for a resource-type prefix whose shard has been torn down
    /// (idle-GC today; CRD-delete eager teardown later). Once a shard can be reclaimed, its
    /// absence from `shards` stops meaning "this resource type was never written" and starts
    /// also meaning "history existed and was discarded" — see `compaction_horizon_for`'s doc.
    /// An entry here is what tells the two apart: it survives the shard itself, keyed to the
    /// exact map key the shard lived under.
    ///
    /// Reconnecting/rewriting the same resource type over and over does not grow this: an entry
    /// is consumed (removed) the instant `get_or_create_shard` recreates its prefix's shard. But
    /// unlike `shards`, that reuse alone cannot bound it — see `ReclaimedHorizons`'s doc for how
    /// it stays bounded even under namespace/CRD churn that never reuses a prefix.
    reclaimed_horizons: Arc<RwLock<ReclaimedHorizons>>,
    /// Lowest revision still in the ring buffer of whichever shard has compacted furthest, across
    /// every resource type (advanced via `fetch_max` from each shard's own eviction — see
    /// `push_event_locked`). Deliberately one process-wide value rather than per-shard: the HTTP
    /// layer's eager pre-watch 410 check (`compaction_horizon()`) runs before it knows which
    /// shard a watch belongs to, so a per-shard horizon would need a wider API change than this
    /// sharding pass makes. This means a busy shard can occasionally make a quiet shard's watch
    /// look "expired" a little earlier than strictly necessary — the same conservative direction
    /// the old single global ring already had, never the reverse (silently serving a revision a
    /// shard has actually already evicted as if it were still present).
    compaction_horizon: Arc<AtomicU64>,
    /// Revision of the most recently committed write. List reads are compared against
    /// this: if the read snapshot is older, the list is retried via the write connection
    /// to guarantee the returned resourceVersion never regresses after a write.
    last_written_revision: Arc<AtomicU64>,
    /// Monotonic zero point for ring push timestamps (`RingShard::push_secs`). Stored as an
    /// `Instant` rather than a wall-clock `SystemTime` so the derived ages stay correct across
    /// NTP steps and DST — the metric measures elapsed retention, not a calendar time.
    epoch: Instant,
}

impl SqliteStore {
    pub fn new(db_path: &str) -> Result<Self> {
        let write_conn = open_conn(db_path, WRITE_CACHE_SIZE_KIB)?;

        // Run migrations on the write connection.
        write_conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS objects (
                key      TEXT    NOT NULL PRIMARY KEY,
                value    BLOB    NOT NULL,
                revision INTEGER NOT NULL,
                ns       TEXT,
                obj_name TEXT
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');

            CREATE INDEX IF NOT EXISTS idx_pods_nodename
            ON objects (json_extract(value, '$.spec.nodeName'))
            WHERE key LIKE '/registry/pods/%';

            CREATE INDEX IF NOT EXISTS idx_ns_name ON objects(ns, obj_name) WHERE ns IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_name ON objects(obj_name);
        ",
        )?;

        let write_conn = Arc::new(Mutex::new(write_conn));

        // For :memory: databases (tests), share the write connection for reads.
        // Separate in-memory connections are always distinct databases.
        // For file databases, open a second connection for concurrent reads under WAL.
        let read_conn = if db_path == ":memory:" {
            Arc::clone(&write_conn)
        } else {
            Arc::new(Mutex::new(open_conn(db_path, READ_CACHE_SIZE_KIB)?))
        };

        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        let shards = Arc::new(RwLock::new(BTreeMap::new()));
        let reclaimed_horizons = Arc::new(RwLock::new(ReclaimedHorizons::default()));
        let compaction_horizon = Arc::new(AtomicU64::new(0));
        let last_written_revision = Arc::new(AtomicU64::new(0));

        Ok(Self {
            write_conn,
            read_conn,
            tx,
            shards,
            reclaimed_horizons,
            compaction_horizon,
            last_written_revision,
            epoch: Instant::now(),
        })
    }

    /// Test-only helper: broadcast an event without going through a real write. Production
    /// code calls `push_event_locked` directly from inside the `spawn_blocking` closure that
    /// holds `write_conn`'s guard (see its doc comment); tests use this to simulate specific
    /// broadcast orderings without needing a real concurrent write race. `ns` mirrors the
    /// namespace a real write would have parsed from the object body (see `shard_key`) — pass
    /// `Some(namespace)` for a namespaced test key, `None` for a cluster-scoped one.
    #[cfg(test)]
    fn push_event(&self, event: Arc<InternalEvent>, ns: Option<&str>) {
        self.push_event_at(event, ns, self.epoch.elapsed().as_secs() as u32);
    }

    /// Test-only helper: like `push_event`, but with the push timestamp supplied explicitly
    /// instead of read from the store's epoch, so tests can drive
    /// `WATCH_RING_SPAN_SECONDS` across a span of simulated seconds without sleeping.
    #[cfg(test)]
    fn push_event_at(&self, event: Arc<InternalEvent>, ns: Option<&str>, now_secs: u32) {
        let shard = shard_key(&event.key, ns);
        // Pre-create the shard exactly as a real watch would (`push_event_locked` only creates
        // one itself for a delete with no existing match — see its doc; a create/update with no
        // shard is still dropped on the floor by design). This helper exists to drive
        // ring/deletion_log internals directly for tests that never open a real watch, so it
        // stands in for that watch here rather than making every ring-behavior test also open
        // one.
        get_or_create_shard(&self.shards, &self.reclaimed_horizons, &shard);
        push_event_locked(
            &self.tx,
            &self.shards,
            &self.reclaimed_horizons,
            &shard,
            ns,
            &self.compaction_horizon,
            now_secs,
            event,
        );
    }

    /// Test-only helper: look up the shard a given (key, ns) pair routes to, so tests can
    /// inspect a shard's ring/deletion_log directly instead of hardcoding its resource-type
    /// root string. Panics if nothing has been pushed to that shard yet.
    #[cfg(test)]
    fn shard_for_test(&self, key: &str, ns: Option<&str>) -> Arc<RingShard> {
        let shard = shard_key(key, ns);
        Arc::clone(
            self.shards
                .read()
                .expect("shards poisoned")
                .get(&shard)
                .unwrap_or_else(|| panic!("no shard {shard} — push at least one event first")),
        )
    }

    /// Return the cross-shard MAXIMUM compaction floor.
    ///
    /// Do NOT use this to decide whether a watch is expired — use `compaction_horizon_for`.
    /// Because this is a max over every shard, the busiest resource type's floor dominates it,
    /// and expiring against it would reject watches on quiet resource types whose own history is
    /// completely intact. It survives as a coarse, whole-store summary (and as the `Store` trait's
    /// default backing for `compaction_horizon_for`).
    pub fn compaction_horizon(&self) -> u64 {
        self.compaction_horizon.load(Ordering::Relaxed)
    }

    /// Return the compaction floor for the one shard `prefix` can match — the revision below
    /// which THIS resource type's watch history has actually been discarded.
    ///
    /// Falls back to `reclaimed_horizons` when no LIVE shard matches: a shard can be torn down
    /// (idle-GC) while its resource type still has real, now-unreplayable history behind it, so
    /// "no live shard" alone stopped meaning "never written" once reclamation shipped — see that
    /// field's doc. Only when NEITHER a live shard NOR a reclaimed-horizon entry matches is
    /// nothing of this type known to have ever been written, and 0 (not expired) is correct.
    pub fn compaction_horizon_for(&self, prefix: &str) -> u64 {
        if let Some(shard) = find_shard(&self.shards.read().expect("shards poisoned"), prefix) {
            return shard.horizon.load(Ordering::Relaxed);
        }
        find_reclaimed_horizon(
            &self
                .reclaimed_horizons
                .read()
                .expect("reclaimed_horizons poisoned"),
            prefix,
        )
    }

    /// Directly set the compaction floor for the shard `prefix` routes to, creating that shard
    /// if it does not exist yet. Intended for tests that simulate compaction without needing to
    /// overflow the ring buffer (which requires RING_CAPACITY+1 writes).
    ///
    /// Takes a prefix because expiry is per-shard: setting a store-wide value would no longer
    /// affect any watch, since `compaction_horizon_for` consults only the matching shard.
    /// Also advances the cross-shard maximum, so a test seeding a floor sees a consistent
    /// `compaction_horizon()` too.
    pub fn set_compaction_horizon_for_test(&self, prefix: &str, horizon: u64) {
        // Resolve in its own statement so the read guard is dropped before get_or_create_shard
        // takes the write lock — std's RwLock is not reentrant, so holding both here would
        // deadlock this thread against itself.
        let existing = find_shard(&self.shards.read().expect("shards poisoned"), prefix);
        let shard = match existing {
            Some(shard) => shard,
            None => get_or_create_shard(&self.shards, &self.reclaimed_horizons, prefix),
        };
        shard.horizon.store(horizon, Ordering::Relaxed);
        self.compaction_horizon
            .fetch_max(horizon, Ordering::Relaxed);
    }
}

/// Push one event into ONE shard's ring buffer and deletion log (occupancy/span/deletion-log-len
/// metrics included), evicting past `RING_CAPACITY` exactly as a real write would. Does NOT
/// touch the broadcast channel — callers decide separately whether and how to notify live
/// watchers.
///
/// Two callers, two different reasons a shard needs an event pushed into it without necessarily
/// meaning "notify every watcher right now":
/// - `push_event_locked`'s per-matched-shard loop (a real write) — broadcasts separately,
///   exactly once, after this runs for every shard the write is relevant to.
/// - `SqliteStore::watch`'s snapshot-seeding of a freshly-created shard — backfills it with the
///   CURRENT state of everything under its prefix (as synthetic ADDED events, oldest revision
///   first) so a resource type's first-ever watch sees pre-existing objects exactly as upstream
///   kube-apiserver's watch cache would (always warm from an initial LIST at cacher-init, never
///   lazily empty for a first-time watcher) — see that function's doc for why this is necessary,
///   not optional, now that writes no longer create shards. Broadcasting these would be wrong:
///   they are not new writes, and every OTHER already-open watch has already seen them for real.
fn push_into_shard(
    shard_key_label: &str,
    shard: &RingShard,
    compaction_horizon: &AtomicU64,
    now_secs: u32,
    event: &Arc<InternalEvent>,
) {
    // Write to ring buffer synchronously using std::sync::RwLock.
    // This avoids a spawned task race between write and watch replay.
    {
        let mut guard = shard.ring.write().expect("ring poisoned");
        // Held for exactly as long as `guard`, and only ever taken here — this is what keeps
        // `push_secs` in lockstep with `ring` (see the field's INVARIANT note).
        let mut secs_guard = shard.push_secs.write().expect("push_secs poisoned");
        guard.push_back(Arc::clone(event));
        secs_guard.push_back(now_secs);
        if guard.len() > RING_CAPACITY {
            guard.pop_front();
            secs_guard.pop_front();
            // Update compaction horizon to the revision of the oldest remaining entry.
            if let Some(oldest) = guard.front() {
                // fetch_max, not store: this atomic is shared across every shard (see its field
                // doc on `SqliteStore`), so a plain `.store()` here would let a quiet shard's
                // low-revision eviction regress the horizon backward after some other, busier
                // shard already advanced it past that point — silently un-expiring revisions
                // that busier shard's ring has already discarded.
                // This shard's own floor — the value every expiry decision for this resource
                // type is made against. fetch_max for the same reason as the global below:
                // concurrent writers to this shard can evict out of order.
                shard.horizon.fetch_max(oldest.revision, Ordering::Relaxed);
                compaction_horizon.fetch_max(oldest.revision, Ordering::Relaxed);
                tracing::debug!(
                    new_horizon = oldest.revision,
                    ring_len = guard.len(),
                    "push_into_shard: ring buffer compacted"
                );
            }
        }
        // Unconditional (not just on eviction): this is the only write path onto the ring, so
        // this is the one place that can cheaply observe true occupancy on every push, not just
        // once the ring is already full. Sampled after the eviction check above so it always
        // reflects final post-eviction occupancy. Still holding the write guard — length
        // already computed, zero extra lock acquisition. Labeled by `shard_key_label` (this
        // shard's own identity), not necessarily a write's canonical resource-type root — they
        // can differ (see `matching_shards`'s doc), and mislabeling would corrupt the per-shard
        // breakdown.
        crate::metrics::WATCH_RING_OCCUPANCY
            .with_label_values(&[shard_key_label])
            .set(guard.len() as i64);
        debug_assert_eq!(
            guard.len(),
            secs_guard.len(),
            "push_secs must stay in lockstep with ring — a drift here silently corrupts the \
             retained-history gauge that ring sizing decisions are made from"
        );
        // The wall-clock span this shard's retained events cover: `now_secs` is this push's own
        // stamp, i.e. the NEWEST retained entry, so this is newest-minus-oldest and not the
        // oldest entry's age relative to real "now". Observed on every push, not just set — see
        // `WATCH_RING_SPAN_SECONDS`' doc for why this must be a histogram over every push rather
        // than a gauge a poller samples. `saturating_sub` rather than a bare subtraction so a
        // monotonic-source anomaly can only ever report 0, never wrap a u32 into a nonsense
        // multi-decade span.
        crate::metrics::WATCH_RING_SPAN_SECONDS
            .with_label_values(&[shard_key_label])
            .observe(f64::from(
                secs_guard
                    .front()
                    .map_or(0, |oldest| now_secs.saturating_sub(*oldest)),
            ));
    }
    // Maintain the deletion_log: persist tombstones so watchers that reconnect after ring
    // compaction can still receive DELETED events for objects deleted before compaction.
    //
    // Eviction policy (three-pronged to bound memory without dropping needed tombstones):
    //
    // 1. Evict-on-recreate: when a PUT event arrives for a key that has a tombstone in
    //    deletion_log, remove it. The tombstone is stale — the key now exists again, so
    //    any watcher reconnecting will see the live object in a fresh list response. Keeping
    //    a DELETED tombstone for a live key would cause a watcher to emit a spurious DELETED
    //    event for the current incarnation.
    //
    // 2. Full -> Stripped downgrade at FULL_TIER_CAP: once a shard holds more than
    //    RING_CAPACITY full-body tombstones, the lowest-revision one is DOWNGRADED (not
    //    removed) to a revision-only Stripped entry — same key, same by_revision entry, no
    //    resize. A selector-scoped watch needs the body only to decide whether a deletion it
    //    JUST missed still matches; conformance data shows 81% of watch opens carry a
    //    selector (`u7s_apiserver_watch_opens_total`), so this tier is real, not speculative.
    //    Per-shard `u7s_deletion_log_body_size_bytes` from a full run: the busiest shards'
    //    tombstones average well under RING_CAPACITY's own doc's 1-6KB estimate (e.g.
    //    configmaps ~800B, podtemplates ~320B avg), with pods the heaviest tail observed
    //    (~3.8KB avg, ~16KB p99) — informing FULL_TIER_CAP's sizing below.
    //
    // 3. Outright eviction at STRIPPED_TIER_CAP: once the WHOLE log (both tiers) exceeds
    //    this larger cap, the lowest-revision entry is evicted via by_revision's
    //    pop_first() — always a Stripped one in practice, since (2) keeps the Full tier
    //    bounded to FULL_TIER_CAP. In the same conformance run, the busiest shard (events)
    //    accumulated 4,557 tombstones — comfortably exercising this eviction path, not just
    //    the downgrade path — while most shards never got close to either cap.
    {
        let mut guard = shard.deletion_log.write().expect("deletion_log poisoned");
        if event.value.is_none() {
            // Deletion: insert as a Full-tier tombstone (indexed by revision, and as a
            // Full-tier candidate for the downgrade policy below).
            guard
                .by_key
                .insert(event.key.clone(), DeletionLogEntry::Full(Arc::clone(event)));
            guard.by_revision.insert(event.revision, event.key.clone());
            guard.full_revisions.insert(event.revision);
            // Insert-time, not eviction-time: captures every tombstone's body size, including
            // ones the caps below later downgrade or evict, instead of only the (arbitrary,
            // cap-dependent) subset that happens to survive. Feeds data-driven deletion_log
            // tier-cap sizing — see the metric's own doc. Full-tier only: a Stripped entry
            // never carries a body to observe (a Full->Stripped downgrade observation is a
            // follow-on, not this metric's job).
            crate::metrics::DELETION_LOG_BODY_SIZE_BYTES
                .with_label_values(&[shard_key_label])
                .observe(event.deleted_body.as_ref().map_or(0, Bytes::len) as f64);

            // Tier 1: downgrade the lowest-revision Full entry once the Full tier exceeds
            // RING_CAPACITY. `full_revisions` mirrors `by_revision` for exactly this tier's
            // entries, giving O(log n) victim lookup via pop_first() instead of scanning
            // `by_key` for the lowest-revision Full entry.
            const FULL_TIER_CAP: usize = RING_CAPACITY;
            if guard.full_revisions.len() > FULL_TIER_CAP {
                if let Some(downgrade_revision) = guard.full_revisions.pop_first() {
                    if let Some(downgrade_key) = guard.by_revision.get(&downgrade_revision).cloned()
                    {
                        guard.by_key.insert(
                            downgrade_key,
                            DeletionLogEntry::Stripped {
                                revision: downgrade_revision,
                            },
                        );
                    }
                }
            }

            // Tier 2: evict outright once the whole log exceeds a larger cap. `by_revision`
            // keeps revision -> key sorted, so this is O(log n) via pop_first() instead of
            // an O(n) linear scan over `by_key`. 2x (not 8x) RING_CAPACITY: a full conformance
            // run's busiest shard peaked at 870 live tombstones, comfortably under this cap,
            // while the old 8x bought ~875KB of pure Stripped-tier index overhead per
            // saturated shard that no observed traffic ever needed.
            const STRIPPED_TIER_CAP: usize = 2 * RING_CAPACITY;
            if guard.by_key.len() > STRIPPED_TIER_CAP {
                if let Some((oldest_revision, oldest_key)) = guard.by_revision.pop_first() {
                    guard.by_key.remove(&oldest_key);
                    guard.full_revisions.remove(&oldest_revision);
                    tracing::debug!(
                        evicted_key = %oldest_key,
                        cap = STRIPPED_TIER_CAP,
                        "push_into_shard: deletion tombstone log evicted oldest entry"
                    );
                }
            }
        } else {
            // Creation/update: evict any stale tombstone for this key, keeping both the
            // revision index and the full-tier set in sync too.
            if let Some(old) = guard.by_key.remove(&event.key) {
                let old_revision = old.revision();
                guard.by_revision.remove(&old_revision);
                guard.full_revisions.remove(&old_revision);
            }
        }
        // Unconditional (not just on eviction), same reasoning as WATCH_RING_OCCUPANCY above:
        // this is the only write path onto the deletion log, so this cheaply observes its true
        // length on every write, still holding the write guard.
        crate::metrics::DELETION_LOG_LEN
            .with_label_values(&[shard_key_label])
            .set(guard.by_key.len() as i64);
    }
}

/// Push one write's event onto the ring buffer, deletion log, and broadcast channel.
///
/// Callers in `put`/`delete`/`delete_namespace_resources` invoke this from INSIDE the
/// `spawn_blocking` closure, while still holding the `write_conn` mutex guard used to
/// assign this write's own revision. This is required for correctness, not just style:
/// under heavy concurrent write load (e.g. a real conformance run's kubelet heartbeats,
/// node lease renewals, and many controllers writing at once), two concurrent writers'
/// `spawn_blocking` closures finish revision assignment in strict order (guaranteed by
/// the mutex), but if the broadcast call happened AFTER the closure returned (in the
/// async caller, post-`.await`), the tokio scheduler could poll and resume the
/// higher-revision writer's continuation before the lower-revision writer's — sending
/// the higher-revision event to the broadcast channel first. A watcher on the same
/// prefix would then see its `last_replayed` dedup high-water mark jump to the higher
/// revision before the lower-revision event ever arrives, causing the dedup check
/// (`event.revision <= last_replayed`) to silently discard it. This is how a Deployment
/// DeleteCollection's own DELETED event could vanish: an unrelated, concurrently-committed
/// Deployment/ReplicaSet write on the same prefix with a higher revision raced ahead of it
/// into the broadcast channel. Calling this while still holding the write lock makes
/// broadcast order match revision-assignment order for every writer, closing the race.
#[allow(clippy::too_many_arguments)]
fn push_event_locked(
    tx: &broadcast::Sender<Arc<InternalEvent>>,
    shards: &Arc<RwLock<BTreeMap<String, Arc<RingShard>>>>,
    reclaimed_horizons: &Arc<RwLock<ReclaimedHorizons>>,
    shard_key: &str,
    ns: Option<&str>,
    compaction_horizon: &AtomicU64,
    now_secs: u32,
    event: Arc<InternalEvent>,
) {
    // Every EXISTING shard this write is relevant to (zero, one, or occasionally more than one —
    // see `matching_shards`'s doc). Normally NOT `get_or_create_shard`: shards are created by
    // `watch()` (see that function's doc and `RingShard`'s field doc on `SqliteStore::shards`) —
    // a create/update to a resource type nobody has ever watched simply has nothing to fan out
    // to, and persists via the caller's sqlite write regardless; a LATER first watch's
    // `list()`-based backfill will see the object exactly as it is now, so nothing is lost.
    //
    // A DELETE is the one exception: `list()`-based backfill only reflects objects that still
    // exist, so it can never reconstruct a delete for an object that is already gone by the time
    // a watch first opens. If no shard exists yet to remember this delete, it is gone forever —
    // this is exactly the "list/watch/create/delete" pattern upstream's CRD e2e fixtures use to
    // prime a watch cache (create, delete, then watch from the create's own revision expecting
    // the delete): with zero watchers attached the whole time, `matching_shards` below would
    // otherwise find nothing, and the delete would silently vanish. So a delete with no matching
    // shard creates one (idle-GC'd exactly like any other if nobody ever attaches a watcher —
    // see `get_or_create_shard`'s doc) instead of being dropped.
    let matched = matching_shards(&shards.read().expect("shards poisoned"), shard_key, ns);

    // `now_secs` is seconds since the store's epoch, taken by the caller (see `SqliteStore::epoch`)
    // rather than read here, for two reasons: it is used for BOTH this event's push stamp and the
    // age subtraction below, so taking it once means a write can never report a negative age by
    // racing the clock forward between the two; and it keeps this function a pure function of its
    // arguments, so `push_event_at` can drive the retained-history histogram deterministically in
    // tests instead of sleeping.
    if matched.is_empty() && event.value.is_none() {
        let shard = get_or_create_shard(shards, reclaimed_horizons, shard_key);
        push_into_shard(shard_key, &shard, compaction_horizon, now_secs, &event);
    } else {
        for (matched_key, shard) in &matched {
            push_into_shard(matched_key, shard, compaction_horizon, now_secs, &event);
        }
    }
    // Best-effort broadcast of the specific event.
    let event_revision = event.revision;
    let _ = tx.send(event);
    // Broadcast a global bookmark, tagged with this write's own shard root (e.g.
    // "/registry/pods/" — always trailing-slash-terminated, so it can never collide with a
    // real object key, which always ends in a name segment instead), to advance all
    // informers' sync RVs. KCM's ConsistencyStore.EnsureReady() checks each informer's
    // LastStoreSyncResourceVersion against the RV of writes the controller made.
    // A StatefulSet watch only sees StatefulSet events — without a global bookmark,
    // its sync RV lags pod write RVs and EnsureReady requeues indefinitely.
    //
    // Use this event's own revision (not last_written_revision) so that concurrent
    // writes cannot inject a higher RV into this event's bookmark.  If write-B
    // commits and bumps last_written_revision to N+1 before write-A calls
    // last_written_revision.load(), write-A's bookmark would carry rv=N+1, advancing
    // watchers' last_replayed to N+1 before write-B's event(rv=N+1) is broadcast —
    // causing write-B's event to be dedup-skipped and silently dropped.
    let _ = tx.send(Arc::new(InternalEvent {
        key: shard_key.to_string(),
        revision: event_revision,
        value: None,
        is_create: false,
        deleted_body: None,
    }));
}

/// Look up `shard`'s `RingShard` in `shards`, creating it on first use. Read-locks first (the
/// common case, once every resource type in use has its shard) and only takes the write lock to
/// insert a brand-new entry, so steady-state writes never contend with each other on this map.
///
/// Called from the watch-open path (`SqliteStore::watch`) AND from `push_event_locked` for a
/// delete that no existing shard is watching yet (see that function's doc for why deletes are
/// the one write that cannot skip shard creation). Whichever caller actually creates the entry
/// gets it scheduled for `schedule_idle_gc` here — a shard created by a delete may never gain a
/// watcher at all, unlike the watch-open caller which always attaches one immediately after, so
/// this is the one place that can correctly cover both origins with a single grace-period check.
///
/// A brand-new shard's `horizon` is seeded from `reclaimed_horizons`, not always 0: if this exact
/// key — or its shard-root parent, per `find_reclaimed_horizon`'s one-hop rule — was torn down
/// earlier (idle-GC) and is only now being recreated, the discarded history behind it must not be
/// forgotten just because a live shard object exists again. This matters even when `shard` itself
/// was NEVER torn down before: a namespace-scoped CHILD watch's first-ever open creates a shard
/// keyed to the child prefix, and if its resource-type ROOT was torn down earlier with a real
/// floor still sitting in `entries` (not yet evicted past the cap), that floor is exactly as
/// applicable to the child as it would be to a reconnect on the root itself — skipping the
/// parent-hop here would seed the child's `horizon` at 0, and `compaction_horizon_for` reads a
/// LIVE shard's own `horizon` field directly (see that method's doc), so once seeded wrong it
/// stays wrong for this shard's entire lifetime: every from_revision would be wrongly treated as
/// caught up, silently skipping every event that really was discarded.
///
/// Uses `find_reclaimed_horizon` for the lookup — the exact same exact/parent/overflow chain
/// `compaction_horizon_for` falls back to for a shard that doesn't exist at all — so the two can
/// never drift apart on what floor a given prefix is entitled to. Only the EXACT entry (never a
/// matched parent entry, which may still be relevant to a sibling or the root itself) is then
/// removed: consuming it here is what keeps `reclaimed_horizons` from growing forever for a
/// resource type that keeps getting reclaimed-then-reused, since once its floor is baked into the
/// live shard's own `horizon` field, the side entry no longer carries information the live shard
/// doesn't already have.
fn get_or_create_shard(
    shards: &Arc<RwLock<BTreeMap<String, Arc<RingShard>>>>,
    reclaimed_horizons: &Arc<RwLock<ReclaimedHorizons>>,
    shard: &str,
) -> Arc<RingShard> {
    if let Some(existing) = shards.read().expect("shards poisoned").get(shard) {
        return Arc::clone(existing);
    }
    let mut guard = shards.write().expect("shards poisoned");
    if let Some(existing) = guard.get(shard) {
        return Arc::clone(existing);
    }
    let seeded_horizon = {
        let mut rh = reclaimed_horizons
            .write()
            .expect("reclaimed_horizons poisoned");
        let seeded = find_reclaimed_horizon(&rh, shard);
        rh.entries.remove(shard);
        seeded
    };
    let created = Arc::new(RingShard::new());
    created.horizon.store(seeded_horizon, Ordering::Relaxed);
    guard.insert(shard.to_string(), Arc::clone(&created));
    drop(guard);
    schedule_idle_gc(
        Arc::clone(shards),
        Arc::clone(reclaimed_horizons),
        shard.to_string(),
        Arc::clone(&created),
    );
    created
}

/// Unconditionally remove and return `key`'s shard, if present, atomically under `shards`' write
/// lock — so a concurrent `get_or_create_shard`/`matching_shards` read can never observe a
/// half-removed entry. Preserves the removed shard's floor into `reclaimed_horizons` (see that
/// field's doc) exactly like idle-GC's own inline removal does, before the shard itself is
/// dropped.
///
/// Not called by this crate's own idle-GC (`ShardWatcherGuard`'s drop): that path needs its
/// idle-check (`watchers == 0`) and the removal to happen under the SAME write-lock acquisition
/// (so a reconnecting watch can't slip in between the two), which means it does its own
/// conditional variant of this one-line removal inline rather than composing this fully
/// unconditional helper. This exists for a caller with a genuinely different invariant:
/// `evict_resource_type`'s CRD-delete eager teardown removes a shard because its resource TYPE
/// no longer exists, which is unconditionally correct regardless of `watchers`.
pub(crate) fn tear_down_shard(
    shards: &RwLock<BTreeMap<String, Arc<RingShard>>>,
    reclaimed_horizons: &RwLock<ReclaimedHorizons>,
    key: &str,
) -> Option<Arc<RingShard>> {
    let removed = shards.write().expect("shards poisoned").remove(key);
    if let Some(shard) = &removed {
        preserve_reclaimed_horizon(reclaimed_horizons, key, shard);
    }
    removed
}

/// Every existing shard relevant to a write whose own resource-type root is `root` (as returned
/// by `shard_key`) and whose object lives in namespace `ns` (`None` for cluster-scoped), paired
/// with each shard's own key (for per-shard metric labeling). Plural (unlike `find_shard`'s
/// single best match) because a watch can create a shard keyed to ITS OWN prefix (see
/// `SqliteStore::watch`), and a namespace-scoped watch's prefix (e.g.
/// `/registry/configmaps/default/`) is NOT derivable from a cluster-scoped or all-namespaces
/// watch's shard root (e.g. `/registry/configmaps/`) or vice versa — both can exist
/// simultaneously for the same resource type, and a single write can be relevant to both.
/// Fanning out to every match (instead of picking one, as `find_shard` does for a watch
/// resolving ITS OWN already-known shard) is what keeps every open watch's ring accurate
/// regardless of how many different-granularity shards currently exist for its resource type.
///
/// Checks at most two exact keys — `root` itself, and (when `ns` is `Some`) `root` plus that one
/// namespace segment — rather than scanning every live shard with a `starts_with` check. This
/// relies on the same invariant `find_shard`/`find_shard_key` already document and depend on: a
/// watch's own prefix, and therefore every key that can ever live in `shards`, is always EXACTLY
/// one of those two shapes for a given resource type (see `group_list_prefix` and `cr_list_prefix`
/// in the apiserver crate, and crd.rs's own `list_prefix` — the independent places a watch prefix
/// gets built, all producing one of these two shapes), so no other shard key could ever be a
/// prefix of this write's key. Two `BTreeMap::get` calls replace what used to be an O(shard-count)
/// `.iter().filter(starts_with)` scan run on every single write.
fn matching_shards(
    shards: &BTreeMap<String, Arc<RingShard>>,
    root: &str,
    ns: Option<&str>,
) -> Vec<(String, Arc<RingShard>)> {
    let mut matched = Vec::new();
    if let Some(shard) = shards.get(root) {
        matched.push((root.to_string(), Arc::clone(shard)));
    }
    if let Some(ns) = ns {
        let ns_key = format!("{root}{ns}/");
        if let Some(shard) = shards.get(&ns_key) {
            matched.push((ns_key, Arc::clone(shard)));
        }
    }
    matched
}

/// Derive the resource-type root prefix a write's ring/deletion_log entry belongs to (e.g.
/// `/registry/pods/` or `/registry/apps/deployments/`) — the same string
/// `keys::group_list_prefix(group, plural, None)` produces in the apiserver crate, since both
/// derive from the exact same {group, plural} identity for a given key.
///
/// Takes `ns` (the object's namespace, already tracked in the `objects.ns` column / parsed from
/// `metadata.namespace` for every write) rather than requiring every caller of `put`/`delete`/
/// `create_if_namespace_active` to separately pass its {group, plural} down: a namespaced key
/// always ends in `.../<namespace>/<name>` and a cluster-scoped key always ends in `.../<name>`
/// regardless of how many segments precede it (core vs. non-core group), so knowing only whether
/// the object is namespaced is enough to strip exactly the right number of trailing segments —
/// without it, a bare 3-segment key is genuinely ambiguous (e.g. "/registry/pods/default/" could
/// be a core resource "pods" in namespace "default", or a cluster-scoped resource "default" in
/// group "pods"). Threading {group, plural} through instead would touch every one of the ~500
/// call sites across the apiserver crate that write directly via a concrete `Store`, most of
/// them test fixtures, for the same resulting shard string.
fn shard_key(key: &str, ns: Option<&str>) -> String {
    let segments_to_strip = if ns.is_some() { 2 } else { 1 };
    let mut root = key;
    for _ in 0..segments_to_strip {
        root = root.rsplit_once('/').map_or(root, |(head, _)| head);
    }
    format!("{root}/")
}

/// Find the most specific EXISTING shard a watch on `prefix` should reuse: the longest shard key
/// that is itself a prefix of `prefix`. A watch prefix is always either exactly a shard's root
/// (cluster-scoped, or "all namespaces" of a namespaced type) or that root plus one namespace
/// segment, so among shards that could ever be relevant to it, the longest match is the most
/// specific (e.g. prefers an existing namespace-scoped shard over a broader all-namespaces one
/// if both happen to exist). `None` means no shard currently covers this resource type at all —
/// `SqliteStore::watch` creates one keyed to `prefix` itself in that case.
///
/// Checks at most two exact keys rather than scanning every live shard, for the same reason
/// `matching_shards` does: `prefix` is itself always one of the two shapes that doc establishes,
/// so the only candidates that could ever be a prefix of `prefix` are `prefix` itself (the
/// longest possible match, since every other candidate is strictly shorter) and, if that misses,
/// `parent_prefix(prefix)` (the one-level-up root a namespace-scoped `prefix` falls back to) —
/// no other live key could ever qualify. Mirrors `find_reclaimed_horizon`'s exact/parent chain.
fn find_shard(shards: &BTreeMap<String, Arc<RingShard>>, prefix: &str) -> Option<Arc<RingShard>> {
    if let Some(shard) = shards.get(prefix) {
        return Some(Arc::clone(shard));
    }
    let parent = parent_prefix(prefix)?;
    shards.get(&parent).map(Arc::clone)
}

/// Like `find_shard`, but also returns the exact map key the match lives under — `watch()` needs
/// this (unlike every other `find_shard` caller, which only needs the shard's contents) so its
/// idle-GC teardown can later remove the SAME entry again, even when it differs from this watch's
/// own `prefix` (a reused, more broadly-scoped shard created by an earlier, different watch).
fn find_shard_key(
    shards: &BTreeMap<String, Arc<RingShard>>,
    prefix: &str,
) -> Option<(String, Arc<RingShard>)> {
    if let Some(shard) = shards.get(prefix) {
        return Some((prefix.to_string(), Arc::clone(shard)));
    }
    let parent = parent_prefix(prefix)?;
    shards.get(&parent).map(|shard| (parent, Arc::clone(shard)))
}

/// The fallback `compaction_horizon_for` consults when no LIVE shard matches `prefix`, and the
/// lookup `get_or_create_shard` shares to seed a brand-new shard's `horizon` field (see that
/// function's doc for why sharing this exact chain, rather than duplicating a subset of it,
/// matters) — both need the same answer to "what floor is `prefix` entitled to right now", and
/// only ONE of them consumes (removes) what it finds. Three O(1) steps, replacing the old
/// `.iter().filter(starts_with).max_by_key` linear scan that used to run on every watch-open
/// (`watch.rs`'s pre-watch 410 check):
/// 1. Exact match on `prefix` itself.
/// 2. Exact match on `parent_prefix(prefix)` (the one-level-up shard root) — see that function's
///    doc for why one hop is always enough.
/// 3. `overflow` — the unconditional last resort. Every entry ever evicted past
///    `MAX_RECLAIMED_HORIZONS` folded its floor in here (see `preserve_reclaimed_horizon`), so
///    this always holds a valid lower bound regardless of `prefix`'s shape (resource-type root,
///    childless root, or namespace child) — no per-shape special-casing needed.
fn find_reclaimed_horizon(reclaimed_horizons: &ReclaimedHorizons, prefix: &str) -> u64 {
    if let Some(horizon) = reclaimed_horizons.entries.get(prefix) {
        return *horizon;
    }
    if let Some(parent) = parent_prefix(prefix) {
        if let Some(horizon) = reclaimed_horizons.entries.get(&parent) {
            return *horizon;
        }
    }
    reclaimed_horizons.overflow.load(Ordering::Relaxed)
}

/// `PRAGMA cache_size` for the write connection: SQLite's own historical default (`-2000` is
/// ~1.95 MiB — negative means kibibytes, not pages). The write connection only ever serves a
/// single writer at a time (behind `write_conn`'s mutex), so it has far less to gain from a
/// large page cache than the read connection, which backs every concurrent LIST scan — see
/// `READ_CACHE_SIZE_KIB`'s doc for why the cut is made here rather than there.
const WRITE_CACHE_SIZE_KIB: i64 = -2000;
/// `PRAGMA cache_size` for the read connection (and the single shared connection `:memory:`
/// databases use for both roles — see `SqliteStore::new`): kept at SQLite's pre-existing
/// `-8000` (~7.8 MiB) rather than cut like the write connection's, since this is the connection
/// LIST scans and most other reads run against, and is therefore the one most likely to thrash
/// on a smaller cache.
const READ_CACHE_SIZE_KIB: i64 = -8000;

fn open_conn(path: &str, cache_size_kib: i64) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA cache_size   = {cache_size_kib};
        PRAGMA busy_timeout = 5000;
        -- Keep the WAL file small so read connections do not fall far behind write connections.
        -- At 1000 (the SQLite default), the WAL can hold 1000 pages before checkpointing.
        -- Under high write bursts (conformance runs), the read connection lags and the
        -- stale-read guard in get()/list() must retry via the write connection repeatedly,
        -- causing KCM's RS controller to log 'read version N is not as new as written version M'
        -- and requeue in a tight loop for up to 15 minutes.  At 100, checkpoints are more
        -- frequent so the read connection stays within ~100 pages of the write head.
        PRAGMA wal_autocheckpoint = 100;
    "
    ))?;
    Ok(conn)
}

/// Stamps metadata.resourceVersion into the stored JSON.
/// Parses the JSON, sets the field, re-serializes.
/// Also extracts ns and obj_name from the single parse to avoid a second deserialization.
fn stamp_resource_version(
    value: &Bytes,
    revision: u64,
) -> Result<(Bytes, Option<String>, Option<String>)> {
    let mut obj: serde_json::Value = serde_json::from_slice(value)?;
    let ns = obj["metadata"]["namespace"].as_str().map(str::to_owned);
    let obj_name = obj["metadata"]["name"].as_str().map(str::to_owned);
    obj["metadata"]["resourceVersion"] = serde_json::Value::String(revision.to_string());
    Ok((Bytes::from(serde_json::to_vec(&obj)?), ns, obj_name))
}

/// Compares `new_value` against `stored_value` for semantic equality, ignoring
/// `metadata.resourceVersion` — the only field the store itself unconditionally stamps on
/// every write regardless of content (see `stamp_resource_version`). `metadata.generation`
/// is deliberately NOT excluded: callers only bump it when the spec actually changes, so a
/// generation difference is a real content change, not a write-path artifact.
///
/// This must be a value-level (parsed JSON) comparison rather than raw byte-equality: u7s
/// does not control JSON key ordering the way upstream's protobuf/etcd3 encoding does, so
/// two semantically-identical objects can serialize to different byte sequences.
///
/// Malformed JSON on either side compares as unequal — an unparsable stored value should
/// never suppress a write, since we cannot prove the content is actually unchanged.
fn semantically_equal_ignoring_resource_version(new_value: &[u8], stored_value: &[u8]) -> bool {
    let (Ok(mut new_json), Ok(mut stored_json)) = (
        serde_json::from_slice::<serde_json::Value>(new_value),
        serde_json::from_slice::<serde_json::Value>(stored_value),
    ) else {
        return false;
    };
    if let Some(m) = new_json.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        m.remove("resourceVersion");
    }
    if let Some(m) = stored_json
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
    {
        m.remove("resourceVersion");
    }
    new_json == stored_json
}

// Full write procedure — runs inside spawn_blocking.
// Returns (new_revision, stamped_value, is_create, is_noop, ns). `ns` is the object's
// `metadata.namespace` (used by the caller to derive its ring/deletion_log shard — see
// `shard_key`); it is `None` in the `is_noop` case since callers skip sharding a suppressed
// write entirely.
fn put_sync(
    conn: &Connection,
    key: &str,
    value: Bytes,
    expected_revision: Option<u64>,
    last_written: &AtomicU64,
) -> Result<(u64, Bytes, bool, bool, Option<String>)> {
    // 1. Begin exclusive write transaction. Transaction guard: any `?` early-return below
    // (named or not) rolls back automatically on drop (see list_sync), so a transient error
    // from any of the fallible calls that follow can't leave this shared write connection
    // wedged mid-transaction — which would otherwise block every future write on the process.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let conn: &Connection = &tx;

    // 2. Read current stored revision AND value: the no-op check below (step 3.5) needs the
    // value to compare against, and the optimistic concurrency check needs the revision.
    // SQLite stores integers as i64; cast to u64 (revisions fit in i63 range).
    let stored: Option<(u64, Vec<u8>)> = conn
        .query_row(
            "SELECT revision, value FROM objects WHERE key = ?1",
            params![key],
            |r| {
                Ok((
                    r.get::<_, i64>(0).map(|v| v as u64)?,
                    r.get::<_, Vec<u8>>(1)?,
                ))
            },
        )
        .optional()?;

    let is_create = stored.is_none();
    let stored_rv = stored.as_ref().map(|(rv, _)| *rv);

    // 3. Optimistic concurrency check. A precondition violation is a real conflict and takes
    // priority over the no-op check below — mirroring real kube-apiserver, where the CAS
    // check in the registry layer runs strictly before storage's GuaranteedUpdate ever
    // compares bytes. Callers like patch_pod_status's RevisionMismatch retry loop depend on
    // genuinely stale writes being rejected even when the writer's payload happens to be
    // content-identical to what's currently stored.
    match (stored_rv, expected_revision) {
        (_, None) => {}       // unconditional
        (None, Some(0)) => {} // create-only, absent: OK
        (Some(_), Some(0)) => {
            return Err(StoreError::AlreadyExists {
                key: key.to_string(),
            });
        }
        (None, Some(exp)) => {
            return Err(StoreError::RevisionMismatch {
                expected: exp,
                current: 0,
            });
        }
        (Some(stored_rv), Some(exp)) if stored_rv == exp => {} // match: OK
        (Some(stored_rv), Some(exp)) => {
            return Err(StoreError::RevisionMismatch {
                expected: exp,
                current: stored_rv,
            });
        }
    }

    // 3.5. No-op short-circuit (mirrors etcd3's GuaranteedUpdate byte-equality check): if the
    // precondition above passed AND this is an update (not a create — a first write for a key
    // must never be treated as a no-op) AND the new content is semantically identical to what's
    // already stored, skip the write entirely. Return the EXISTING revision so this looks like
    // a normal successful put() to the caller, without bumping the global revision or firing a
    // watch/MODIFIED event. This is what absorbs kubelet's routine, unchanged status re-PATCHes
    // (every 10s per pod) without flooding every watcher in the cluster.
    if let Some((existing_revision, existing_value)) = &stored {
        if semantically_equal_ignoring_resource_version(&value, existing_value) {
            // No write happened: let `tx` drop below without committing, which rolls back
            // the (empty) transaction instead of leaving it open.
            tracing::debug!(key, existing_revision, "put_sync: no-op write suppressed");
            return Ok((
                *existing_revision,
                Bytes::from(existing_value.clone()),
                false,
                true,
                None,
            ));
        }
    }

    // 4. Increment global revision counter.
    conn.execute(
        "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'",
        [],
    )?;

    // 5. Read the new revision.
    let new_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )?;

    // 6. Stamp metadata.resourceVersion in the JSON value and extract indexed columns
    //    from the single parse, avoiding a second deserialization of the stamped bytes.
    let (stamped_value, ns, obj_name) = stamp_resource_version(&value, new_revision)?;

    // 7. Upsert the object.
    conn.execute(
        "INSERT INTO objects (key, value, revision, ns, obj_name) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, revision = excluded.revision,
         ns = excluded.ns, obj_name = excluded.obj_name",
        params![
            key,
            stamped_value.as_ref(),
            new_revision as i64,
            ns,
            obj_name
        ],
    )?;

    tx.commit()?;
    // Update last_written_revision immediately after COMMIT on this blocking thread.
    // Doing this here (rather than in the async caller) eliminates the scheduling window
    // where a concurrent list on the read connection could see the new WAL data but
    // load a stale last_written_revision from the async task queue — causing the list
    // guard to miss the stale-read and return an older resourceVersion to the reflector.
    last_written.fetch_max(new_revision, Ordering::Release);
    Ok((new_revision, stamped_value, is_create, false, ns))
}

// Returns (new_revision, last_value, ns) — `ns` (the deleted object's `metadata.namespace`,
// read back from the `objects.ns` column rather than re-parsed from `last_value`) is used by the
// caller to derive its ring/deletion_log shard — see `shard_key`.
fn delete_sync(
    conn: &Connection,
    key: &str,
    expected_revision: Option<u64>,
    last_written: &AtomicU64,
) -> Result<(u64, Bytes, Option<String>)> {
    // Transaction guard (see put_sync): any `?` early-return below rolls back automatically
    // on drop, so a transient error mid-transaction can't wedge the shared write connection.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let conn: &Connection = &tx;

    let stored: Option<(u64, Vec<u8>, Option<String>)> = conn
        .query_row(
            "SELECT revision, value, ns FROM objects WHERE key = ?1",
            params![key],
            |r| {
                Ok((
                    r.get::<_, i64>(0).map(|v| v as u64)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?;

    // Optimistic concurrency check (same logic as put).
    match stored.as_ref().map(|(rv, _, _)| *rv) {
        None => {
            return Err(StoreError::NotFound {
                key: key.to_string(),
            });
        }
        Some(_) if expected_revision.is_none() => {}
        Some(_) if expected_revision == Some(0) => {}
        Some(stored_rv) => {
            if let Some(exp) = expected_revision {
                if stored_rv != exp {
                    return Err(StoreError::RevisionMismatch {
                        expected: exp,
                        current: stored_rv,
                    });
                }
            }
        }
    }

    let (_, value_bytes, ns) = stored.unwrap();
    let last_value = Bytes::from(value_bytes);

    conn.execute(
        "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'",
        [],
    )?;
    let new_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )?;

    conn.execute("DELETE FROM objects WHERE key = ?1", params![key])?;
    tx.commit()?;
    // Same rationale as put_sync: update last_written_revision on the blocking thread
    // immediately after COMMIT so the list guard sees it before any reader can observe
    // the new WAL state from a concurrent read connection.
    last_written.fetch_max(new_revision, Ordering::Release);
    Ok((new_revision, last_value, ns))
}

/// Atomically check `ns_key`'s `status.phase` and, only if it is not `"Terminating"`,
/// create-only-insert `value` at `key`. Both the namespace read and the insert run inside one
/// `BEGIN IMMEDIATE … COMMIT` transaction, guarded by `write_conn`'s mutex like every other
/// write path here — so a concurrent `put_sync` flipping `ns_key`'s phase (e.g.
/// `delete_namespace`'s Terminating write) can never land between this function's read of
/// `ns_key` and its insert at `key`: the two operations either fully precede or fully follow
/// each other, never interleave.
// Returns (new_revision, stamped_value, ns) — `ns` is used by the caller to derive its
// ring/deletion_log shard (see `shard_key`).
fn create_if_namespace_active_sync(
    conn: &Connection,
    ns_key: Option<&str>,
    key: &str,
    value: Bytes,
    last_written: &AtomicU64,
) -> std::result::Result<(u64, Bytes, Option<String>), CreateNamespacedError> {
    // Transaction guard (see put_sync): any `?` early-return below rolls back automatically
    // on drop, so a transient error mid-transaction can't wedge the shared write connection.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let conn: &Connection = &tx;

    if let Some(ns_key) = ns_key {
        let ns_value: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM objects WHERE key = ?1",
                params![ns_key],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(ns_bytes) = ns_value {
            if let Ok(ns_json) = serde_json::from_slice::<serde_json::Value>(&ns_bytes) {
                if ns_json["status"]["phase"].as_str() == Some("Terminating") {
                    return Err(CreateNamespacedError::NamespaceTerminating);
                }
            }
        }
    }

    let exists: bool = conn
        .query_row("SELECT 1 FROM objects WHERE key = ?1", params![key], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false);
    if exists {
        return Err(CreateNamespacedError::Store(StoreError::AlreadyExists {
            key: key.to_string(),
        }));
    }

    conn.execute(
        "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'",
        [],
    )?;
    let new_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )?;

    let (stamped_value, ns, obj_name) = stamp_resource_version(&value, new_revision)?;
    conn.execute(
        "INSERT INTO objects (key, value, revision, ns, obj_name) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key,
            stamped_value.as_ref(),
            new_revision as i64,
            ns,
            obj_name
        ],
    )?;

    tx.commit()?;
    last_written.fetch_max(new_revision, Ordering::Release);
    Ok((new_revision, stamped_value, ns))
}

/// Delete all objects in a namespace atomically.
///
/// Returns (key, body, revision) for each deleted object. Each object gets its own distinct
/// revision so that watchers receive a separate DELETED event per object. A shared revision
/// would cause the watch stream's dedup check (`event.revision <= last_replayed`) to drop
/// all but the first DELETED event — controllers would miss deletions and wedge in a 409-loop.
///
/// All deletes stay inside ONE `BEGIN IMMEDIATE … COMMIT` transaction (namespace delete
/// remains atomic on the storage side); only the revision assignment is per-object.
fn delete_namespace_sync(
    conn: &Connection,
    namespace: &str,
    last_written: &AtomicU64,
) -> Result<Vec<(String, Bytes, u64)>> {
    // Transaction guard (see put_sync): any `?` early-return below rolls back automatically
    // on drop, so a transient error mid-transaction can't wedge the shared write connection.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let conn: &Connection = &tx;

    // Collect all keys and their current bodies in the namespace.
    let mut stmt = conn.prepare_cached("SELECT key, value FROM objects WHERE ns = ?1")?;
    let pairs: Vec<(String, Bytes)> = stmt
        .query_map(params![namespace], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .filter_map(|r| r.ok())
        .map(|(k, v)| (k, Bytes::from(v)))
        .collect();
    // Drop the cached statement's borrow of `conn` (i.e. of `tx`) now: `tx.commit()` below
    // needs to move `tx` by value, which the borrow checker won't allow while `stmt` is live.
    drop(stmt);

    if pairs.is_empty() {
        // Nothing to delete: let `tx` drop below without committing (no-op rollback).
        return Ok(vec![]);
    }

    // Assign each deleted object its own distinct revision (etcd-like per-object mod-revision).
    // All deletes are in the same transaction so the namespace delete remains atomic on storage.
    let mut result: Vec<(String, Bytes, u64)> = Vec::with_capacity(pairs.len());
    for (key, body) in pairs {
        conn.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'",
            [],
        )?;
        let rev: u64 = conn.query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
            [],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )?;
        conn.execute("DELETE FROM objects WHERE key = ?1", params![key])?;
        result.push((key, body, rev));
    }

    tx.commit()?;
    // Same rationale as put_sync: update immediately after COMMIT on the blocking thread.
    let max_rev = result.last().map_or(0, |(_, _, r)| *r);
    last_written.fetch_max(max_rev, Ordering::Release);
    Ok(result)
}

fn get_sync(conn: &Connection, key: &str) -> Result<Option<StoreObject>> {
    let result = conn
        .query_row(
            "SELECT key, value, revision FROM objects WHERE key = ?1",
            params![key],
            |r| {
                Ok(StoreObject {
                    key: r.get::<_, String>(0)?,
                    value: Bytes::from(r.get::<_, Vec<u8>>(1)?),
                    revision: r.get::<_, i64>(2).map(|v| v as u64)?,
                })
            },
        )
        .optional()?;
    Ok(result)
}

/// Compute the exclusive upper bound for a prefix range scan.
/// Increments the last byte of the prefix that is not 0xFF.
/// Returns empty string if no upper bound is possible (all 0xFF — pathological).
fn prefix_upper_bound(prefix: &str) -> String {
    let mut bytes = prefix.as_bytes().to_vec();
    for b in bytes.iter_mut().rev() {
        if *b < 0xFF {
            *b += 1;
            return String::from_utf8(bytes).unwrap();
        }
        *b = 0x00;
    }
    String::new() // no upper bound needed
}

fn query_all(conn: &Connection, sql: &str, p: &[&dyn rusqlite::ToSql]) -> Result<Vec<StoreObject>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt
        .query_map(p, |r| {
            Ok(StoreObject {
                key: r.get(0)?,
                value: Bytes::from(r.get::<_, Vec<u8>>(1)?),
                revision: r.get::<_, i64>(2).map(|v| v as u64)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn list_sync(conn: &Connection, prefix: &str, opts: &ListOptions) -> Result<ListResponse> {
    // Transaction guard: any `?` early-return below rolls back automatically on drop
    // (rusqlite::Transaction defaults to DropBehavior::Rollback), so the many fallible
    // queries in this function can't abandon the connection mid-transaction the way a
    // bare `execute_batch("BEGIN ...")` + manual COMMIT would.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Deferred)?;
    let conn: &Connection = &tx;

    let upper = prefix_upper_bound(prefix);
    let ck = opts.continue_key.as_deref().unwrap_or("");

    // When limit is set with no field selector, use SQL-level pagination (fetch limit+1).
    // When a field selector is present, collect all matching rows then paginate in memory,
    // because in-memory filtering may discard rows between the cursor and the limit boundary.
    let (items, continue_key) = match &opts.field_selector {
        // SQL index fast-path: metadata.name=<value> — uses idx_name index.
        Some(FieldSelector {
            field,
            value,
            negated: false,
        }) if field == "metadata.name" => {
            let raw = if upper.is_empty() {
                if ck.is_empty() {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects \
                         WHERE key >= ?1 AND obj_name = ?2 ORDER BY key ASC",
                        &[&prefix, value as &dyn rusqlite::ToSql],
                    )?
                } else {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects \
                         WHERE key >= ?1 AND obj_name = ?2 AND key > ?3 ORDER BY key ASC",
                        &[&prefix, value as &dyn rusqlite::ToSql, &ck],
                    )?
                }
            } else if ck.is_empty() {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key >= ?1 AND key < ?2 AND obj_name = ?3 ORDER BY key ASC",
                    &[&prefix, &upper, value as &dyn rusqlite::ToSql],
                )?
            } else {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key >= ?1 AND key < ?2 AND obj_name = ?3 AND key > ?4 ORDER BY key ASC",
                    &[&prefix, &upper, value as &dyn rusqlite::ToSql, &ck],
                )?
            };
            paginate_in_memory(raw, opts.limit)
        }

        // SQL index fast-path: metadata.namespace=<value> — uses idx_ns index.
        Some(FieldSelector {
            field,
            value,
            negated: false,
        }) if field == "metadata.namespace" => {
            let raw = if upper.is_empty() {
                if ck.is_empty() {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects \
                         WHERE key >= ?1 AND ns = ?2 ORDER BY key ASC",
                        &[&prefix, value as &dyn rusqlite::ToSql],
                    )?
                } else {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects \
                         WHERE key >= ?1 AND ns = ?2 AND key > ?3 ORDER BY key ASC",
                        &[&prefix, value as &dyn rusqlite::ToSql, &ck],
                    )?
                }
            } else if ck.is_empty() {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key >= ?1 AND key < ?2 AND ns = ?3 ORDER BY key ASC",
                    &[&prefix, &upper, value as &dyn rusqlite::ToSql],
                )?
            } else {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key >= ?1 AND key < ?2 AND ns = ?3 AND key > ?4 ORDER BY key ASC",
                    &[&prefix, &upper, value as &dyn rusqlite::ToSql, &ck],
                )?
            };
            paginate_in_memory(raw, opts.limit)
        }

        // Indexed fast-path: spec.nodeName on pods — uses the partial index.
        //
        // An empty selector value must match pods whose nodeName key is absent/null
        // (unscheduled pods) to align with the in-memory `pod_matches_field_selector`
        // and k8s semantics (`spec.nodeName=` selects unscheduled pods). Plain SQL
        // equality against NULL never matches, so that case needs an explicit OR.
        Some(FieldSelector {
            field,
            value,
            negated: false,
        }) if field == "spec.nodeName" && prefix.starts_with("/registry/pods/") => {
            let like_prefix = format!("{}%", prefix);
            let raw = if ck.is_empty() {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key LIKE ?1 AND (json_extract(value, '$.spec.nodeName') = ?2 \
                     OR (?2 = '' AND json_extract(value, '$.spec.nodeName') IS NULL)) \
                     ORDER BY key ASC",
                    &[&like_prefix, value as &dyn rusqlite::ToSql],
                )?
            } else {
                query_all(
                    conn,
                    "SELECT key, value, revision FROM objects \
                     WHERE key LIKE ?1 AND (json_extract(value, '$.spec.nodeName') = ?2 \
                     OR (?2 = '' AND json_extract(value, '$.spec.nodeName') IS NULL)) \
                     AND key > ?3 ORDER BY key ASC",
                    &[&like_prefix, value as &dyn rusqlite::ToSql, &ck],
                )?
            };
            paginate_in_memory(raw, opts.limit)
        }

        // Generic field selector: full scan + in-memory filter + in-memory pagination.
        Some(FieldSelector {
            field,
            value,
            negated,
        }) => {
            let raw = if upper.is_empty() {
                if ck.is_empty() {
                    query_all(
                        conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 ORDER BY key ASC",
                        &[&prefix],
                    )?
                } else {
                    query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key > ?2 ORDER BY key ASC",
                        &[&prefix, &ck],
                    )?
                }
            } else if ck.is_empty() {
                query_all(conn,
                    "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 ORDER BY key ASC",
                    &[&prefix, &upper],
                )?
            } else {
                query_all(conn,
                    "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 AND key > ?3 ORDER BY key ASC",
                    &[&prefix, &upper, &ck],
                )?
            };

            // Walk the dot-separated path in the parsed JSON and compare to expected value.
            let filtered: Vec<StoreObject> = raw
                .into_iter()
                .filter(|obj| {
                    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) else {
                        return false;
                    };
                    let matches = crate::json_path_equals(&parsed, field, value);
                    if *negated {
                        !matches
                    } else {
                        matches
                    }
                })
                .collect();
            paginate_in_memory(filtered, opts.limit)
        }

        // No field selector: SQL-level pagination when limit is set (fetch limit+1 rows).
        None => {
            let limit = clamp_list_limit(opts.limit);
            let fetch_limit = limit.map(|l| (l + 1) as i64);
            let raw = if upper.is_empty() {
                match (ck.is_empty(), fetch_limit) {
                    (true, None)       => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 ORDER BY key ASC",
                        &[&prefix])?,
                    (true, Some(lim))  => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 ORDER BY key ASC LIMIT ?2",
                        &[&prefix, &lim])?,
                    (false, None)      => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key > ?2 ORDER BY key ASC",
                        &[&prefix, &ck])?,
                    (false, Some(lim)) => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key > ?2 ORDER BY key ASC LIMIT ?3",
                        &[&prefix, &ck, &lim])?,
                }
            } else {
                match (ck.is_empty(), fetch_limit) {
                    (true, None)       => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 ORDER BY key ASC",
                        &[&prefix, &upper])?,
                    (true, Some(lim))  => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 ORDER BY key ASC LIMIT ?3",
                        &[&prefix, &upper, &lim])?,
                    (false, None)      => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 AND key > ?3 ORDER BY key ASC",
                        &[&prefix, &upper, &ck])?,
                    (false, Some(lim)) => query_all(conn,
                        "SELECT key, value, revision FROM objects WHERE key >= ?1 AND key < ?2 AND key > ?3 ORDER BY key ASC LIMIT ?4",
                        &[&prefix, &upper, &ck, &lim])?,
                }
            };
            // If we fetched limit+1 rows, there are more items. Discard the extra row
            // and use the last returned item's key as the cursor for the next page.
            if let Some(limit) = limit.map(|l| l as usize) {
                if raw.len() > limit {
                    let mut items = raw;
                    items.pop(); // discard the probe row; it belongs to the next page
                    let ck = items.last().map(|o| o.key.clone());
                    (items, ck)
                } else {
                    (raw, None)
                }
            } else {
                (raw, None)
            }
        }
    };

    let snapshot_revision: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'revision'",
        [],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )?;

    // When there are more pages, count the remaining items so callers can populate
    // metadata.remainingItemCount in list responses (required by chunking conformance).
    let remaining_count = match &continue_key {
        None => None,
        Some(cursor) => {
            let upper = prefix_upper_bound(prefix);
            let count: u64 = if upper.is_empty() {
                conn.query_row(
                    "SELECT COUNT(*) FROM objects WHERE key >= ?1 AND key > ?2",
                    params![prefix, cursor],
                    |r| r.get::<_, i64>(0).map(|v| v as u64),
                )?
            } else {
                conn.query_row(
                    "SELECT COUNT(*) FROM objects WHERE key >= ?1 AND key < ?2 AND key > ?3",
                    params![prefix, &upper, cursor],
                    |r| r.get::<_, i64>(0).map(|v| v as u64),
                )?
            };
            Some(count)
        }
    };

    tx.commit()?;

    Ok(ListResponse {
        items,
        revision: snapshot_revision,
        continue_key,
        remaining_count,
    })
}

/// Clamp a client-supplied LIST `limit` to a value safe for the SQL-level pagination
/// fast-path's `fetch_limit = limit + 1` widening cast to `i64`.
///
/// `limit == u64::MAX` would wrap `limit + 1` to 0, turning `LIMIT 0` into a permanently
/// empty page instead of the requested (effectively unlimited) list. A `limit` anywhere in
/// `i64::MAX-1 ..= u64::MAX` casts to a *negative* `i64`, which SQLite silently treats as
/// "no limit" rather than erroring. Both are treated the same as an absent `limit`
/// (unlimited) here, matching `paginate_in_memory` below, which already tolerates huge
/// limits safely via a `usize` comparison instead of an `i64` cast.
fn clamp_list_limit(limit: Option<u64>) -> Option<u64> {
    limit.filter(|&l| l < i64::MAX as u64 - 1)
}

/// Apply in-memory pagination: if limit is set, return at most limit items and
/// set continue_key to the last item's key if more remain.
fn paginate_in_memory(
    mut items: Vec<StoreObject>,
    limit: Option<u64>,
) -> (Vec<StoreObject>, Option<String>) {
    if let Some(limit) = limit {
        let limit = limit as usize;
        if items.len() > limit {
            items.truncate(limit);
            let ck = items.last().map(|o| o.key.clone());
            (items, ck)
        } else {
            (items, None)
        }
    } else {
        (items, None)
    }
}

impl Store for SqliteStore {
    async fn get(&self, key: &str) -> Result<Option<StoreObject>> {
        let conn = self.read_conn.clone();
        let key_str = key.to_string();
        let obj = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            get_sync(&conn, &key_str)
        })
        .await??;

        // Guard: if the returned object's revision is older than the most recently committed
        // write, the WAL read connection returned a stale view. Retry via the write connection
        // to ensure read-after-write consistency — a GET immediately after a PUT must never
        // return an older resourceVersion than what the PUT returned.
        let min_rev = self.last_written_revision.load(Ordering::Acquire);
        if obj.as_ref().is_some_and(|o| o.revision < min_rev) || (obj.is_none() && min_rev > 0) {
            let write_conn = self.write_conn.clone();
            let key_str2 = key.to_string();
            return tokio::task::spawn_blocking(move || {
                let conn = write_conn.blocking_lock();
                get_sync(&conn, &key_str2)
            })
            .await?;
        }

        Ok(obj)
    }

    async fn list(&self, prefix: &str, opts: ListOptions) -> Result<ListResponse> {
        let read_conn = self.read_conn.clone();
        let prefix = prefix.to_string();
        let prefix2 = prefix.clone();
        let opts2 = opts.clone();
        let resp = tokio::task::spawn_blocking(move || {
            let conn = read_conn.blocking_lock();
            list_sync(&conn, &prefix, &opts2)
        })
        .await??;

        // Guard: if the read snapshot is older than the most recently committed write,
        // the WAL read connection returned a stale view. Retry via the write connection,
        // which always reflects the latest committed state. This prevents the KCM informer
        // from seeing a list resourceVersion that regresses below a revision it already
        // observed from a watch event.
        let min_rev = self.last_written_revision.load(Ordering::Acquire);
        if resp.revision < min_rev {
            let write_conn = self.write_conn.clone();
            return tokio::task::spawn_blocking(move || {
                let conn = write_conn.blocking_lock();
                list_sync(&conn, &prefix2, &opts)
            })
            .await?;
        }

        Ok(resp)
    }

    async fn put(&self, key: &str, value: Bytes, expected_revision: Option<u64>) -> Result<u64> {
        let conn = self.write_conn.clone();
        let key_str = key.to_string();
        let last_written = Arc::clone(&self.last_written_revision);
        let tx = self.tx.clone();
        let shards = Arc::clone(&self.shards);
        let reclaimed_horizons = Arc::clone(&self.reclaimed_horizons);
        let compaction_horizon = Arc::clone(&self.compaction_horizon);
        let epoch = self.epoch;
        let start = std::time::Instant::now();
        let (revision, is_noop, is_create) = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let (revision, stamped_value, is_create, is_noop, ns) =
                put_sync(&conn, &key_str, value, expected_revision, &last_written)?;
            // Skip the broadcast entirely for no-op writes: no revision was bumped and no
            // storage mutation happened, so notifying watchers would be a phantom MODIFIED
            // event for content that never changed — exactly the flood this check exists to
            // prevent. Broadcast while still holding write_conn's guard for real writes — see
            // push_event_locked's doc comment for why this ordering matters under concurrent
            // writers.
            if !is_noop {
                let shard = shard_key(&key_str, ns.as_deref());
                push_event_locked(
                    &tx,
                    &shards,
                    &reclaimed_horizons,
                    &shard,
                    ns.as_deref(),
                    &compaction_horizon,
                    epoch.elapsed().as_secs() as u32,
                    Arc::new(InternalEvent {
                        key: key_str,
                        revision,
                        value: Some(stamped_value),
                        is_create,
                        deleted_body: None,
                    }),
                );
            }
            Ok::<(u64, bool, bool), StoreError>((revision, is_noop, is_create))
        })
        .await??;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        tracing::debug!(
            key,
            elapsed_ms,
            is_noop,
            is_create,
            "store: write committed"
        );

        Ok(revision)
    }

    async fn create_if_namespace_active(
        &self,
        ns_key: Option<&str>,
        key: &str,
        value: Bytes,
    ) -> std::result::Result<u64, CreateNamespacedError> {
        let conn = self.write_conn.clone();
        let ns_key_owned = ns_key.map(|s| s.to_string());
        let key_str = key.to_string();
        let last_written = Arc::clone(&self.last_written_revision);
        let tx = self.tx.clone();
        let shards = Arc::clone(&self.shards);
        let reclaimed_horizons = Arc::clone(&self.reclaimed_horizons);
        let compaction_horizon = Arc::clone(&self.compaction_horizon);
        let epoch = self.epoch;
        let start = std::time::Instant::now();
        let revision = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let (revision, stamped_value, ns) = create_if_namespace_active_sync(
                &conn,
                ns_key_owned.as_deref(),
                &key_str,
                value,
                &last_written,
            )?;
            // Broadcast while still holding write_conn's guard — see push_event_locked's doc
            // comment for why this ordering matters under concurrent writers. A namespaced
            // create is always a fresh key (create-only, gated on AlreadyExists above), so
            // is_create is unconditionally true here — unlike put's no-op suppression, there is
            // no case where this write should be silently absorbed.
            let shard = shard_key(&key_str, ns.as_deref());
            push_event_locked(
                &tx,
                &shards,
                &reclaimed_horizons,
                &shard,
                ns.as_deref(),
                &compaction_horizon,
                epoch.elapsed().as_secs() as u32,
                Arc::new(InternalEvent {
                    key: key_str,
                    revision,
                    value: Some(stamped_value),
                    is_create: true,
                    deleted_body: None,
                }),
            );
            Ok::<u64, CreateNamespacedError>(revision)
        })
        .await??;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        tracing::debug!(key, elapsed_ms, "store: namespaced create committed");

        Ok(revision)
    }

    async fn delete(&self, key: &str, expected_revision: Option<u64>) -> Result<(u64, Bytes)> {
        let conn = self.write_conn.clone();
        let key_str = key.to_string();
        let last_written = Arc::clone(&self.last_written_revision);
        let tx = self.tx.clone();
        let shards = Arc::clone(&self.shards);
        let reclaimed_horizons = Arc::clone(&self.reclaimed_horizons);
        let compaction_horizon = Arc::clone(&self.compaction_horizon);
        let epoch = self.epoch;
        let start = std::time::Instant::now();
        let (revision, last_value) = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let (revision, last_value, ns) =
                delete_sync(&conn, &key_str, expected_revision, &last_written)?;
            // Broadcast while still holding write_conn's guard — see push_event_locked's
            // doc comment for why this ordering matters under concurrent writers.
            let shard = shard_key(&key_str, ns.as_deref());
            push_event_locked(
                &tx,
                &shards,
                &reclaimed_horizons,
                &shard,
                ns.as_deref(),
                &compaction_horizon,
                epoch.elapsed().as_secs() as u32,
                Arc::new(InternalEvent {
                    key: key_str,
                    revision,
                    value: None,
                    is_create: false,
                    deleted_body: Some(last_value.clone()),
                }),
            );
            Ok::<(u64, Bytes), StoreError>((revision, last_value))
        })
        .await??;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        tracing::debug!(key, elapsed_ms, "store: delete committed");

        Ok((revision, last_value))
    }

    async fn list_namespace_objects(&self, namespace: &str) -> Result<Vec<StoreObject>> {
        let conn = self.write_conn.clone();
        let ns = namespace.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt =
                conn.prepare_cached("SELECT key, value, revision FROM objects WHERE ns = ?1")?;
            let items: Vec<StoreObject> = stmt
                .query_map(rusqlite::params![ns], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2).map(|v| v as u64)?,
                    ))
                })?
                .filter_map(|r| r.ok())
                .map(|(key, value, revision)| StoreObject {
                    key,
                    value: Bytes::from(value),
                    revision,
                })
                .collect();
            Ok(items)
        })
        .await?
    }

    async fn delete_namespace_resources(&self, namespace: &str) -> Result<Vec<String>> {
        let conn = self.write_conn.clone();
        let ns = namespace.to_string();
        let last_written = Arc::clone(&self.last_written_revision);
        let tx = self.tx.clone();
        let shards = Arc::clone(&self.shards);
        let reclaimed_horizons = Arc::clone(&self.reclaimed_horizons);
        let compaction_horizon = Arc::clone(&self.compaction_horizon);
        let epoch = self.epoch;
        let keys = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let deleted = delete_namespace_sync(&conn, &ns, &last_written)?;
            let keys: Vec<String> = deleted.iter().map(|(k, _, _)| k.clone()).collect();
            // Broadcast each tombstone while still holding write_conn's guard — see
            // push_event_locked's doc comment for why this ordering matters under
            // concurrent writers. This single namespace delete fans out across every resource
            // type the namespace ever held (pods, secrets, deployments, ...), so — unlike
            // put/delete/create_if_namespace_active, which each write exactly one key — there is
            // no single shard for the whole call; each deleted object routes to its own shard
            // individually, derived from its own key (every row here is namespaced by
            // construction, via `WHERE ns = ?1` in `delete_namespace_sync`).
            for (key, body, revision) in deleted {
                let shard = shard_key(&key, Some(&ns));
                push_event_locked(
                    &tx,
                    &shards,
                    &reclaimed_horizons,
                    &shard,
                    Some(&ns),
                    &compaction_horizon,
                    epoch.elapsed().as_secs() as u32,
                    Arc::new(InternalEvent {
                        key,
                        revision,
                        value: None,
                        is_create: false,
                        deleted_body: Some(body),
                    }),
                );
            }
            Ok::<Vec<String>, StoreError>(keys)
        })
        .await??;

        Ok(keys)
    }

    async fn watch(
        &self,
        prefix: &str,
        from_revision: u64,
    ) -> Result<impl futures_core::Stream<Item = WatchEvent> + Send + 'static> {
        // Subscribe FIRST to avoid missing events between replay and live.
        let mut rx = self.tx.subscribe();

        // Create-on-first-watch: a watch is what brings a resource type's shard into being now
        // (see `push_event_locked`'s doc — writes no longer do). `find_shard_key` first, so a
        // watch that can reuse an EXISTING shard (created by an earlier watch, of the same or a
        // different granularity — see `matching_shards`' doc) inherits its full retained history
        // instead of starting from empty; only a genuinely first-ever watch on this resource type
        // falls through to creating a fresh shard keyed to `prefix` itself.
        //
        // Resolved in two lock acquisitions rather than one (find, then possibly create) — same
        // trade-off `set_compaction_horizon_for_test` already documents: std's RwLock is not
        // reentrant, so holding the read guard into the write-lock branch would deadlock. The
        // resulting gap (a concurrent idle-GC could theoretically fire between the two) is
        // self-healing, not a correctness bug: at worst it costs a duplicate shard, never a lost
        // event, since `matching_shards` fans writes out to every shard that exists.
        let (shard_key_owned, shard, created_fresh) = {
            let found = find_shard_key(&self.shards.read().expect("shards poisoned"), prefix);
            match found {
                Some((key, shard)) => (key, shard, false),
                None => (
                    prefix.to_string(),
                    get_or_create_shard(&self.shards, &self.reclaimed_horizons, prefix),
                    true,
                ),
            }
        };

        // Backfill a freshly-created shard with the CURRENT state of everything under this
        // watch's own prefix, as synthetic ADDED events ordered oldest-revision-first. Without
        // this, a resource type's first-ever watch would see nothing for anything written
        // before it opened, unlike upstream kube-apiserver — whose watch cache is always warm
        // from an initial LIST at cacher-init, never lazily empty for a first-time watcher. This
        // is what keeps `resource_version=0, watch=true` working for a cold-start informer (e.g.
        // KCM's metadata informer) now that writes alone no longer keep a shard's history alive.
        // Not broadcast (`push_into_shard` only touches THIS shard's ring/deletion_log): these
        // are not new writes, and every other already-open watch has already seen them for real.
        // An EXISTING, reused shard (the `false` branch) needs none of this — it has been
        // accumulating real history since whichever earlier watch created it.
        if created_fresh {
            let mut items = self.list(prefix, ListOptions::default()).await?.items;
            items.sort_by_key(|o| o.revision);
            let seed_secs = self.epoch.elapsed().as_secs() as u32;
            for obj in &items {
                let event = Arc::new(InternalEvent {
                    key: obj.key.clone(),
                    revision: obj.revision,
                    value: Some(obj.value.clone()),
                    is_create: true,
                    deleted_body: None,
                });
                push_into_shard(
                    &shard_key_owned,
                    &shard,
                    &self.compaction_horizon,
                    seed_secs,
                    &event,
                );
            }
        }

        // Registers this stream as one of `shard`'s live watchers for as long as it stays open —
        // see `ShardWatcherGuard`'s doc for why it must be held inside the generator below, not
        // here.
        let watcher_guard = ShardWatcherGuard::attach(
            Arc::clone(&self.shards),
            Arc::clone(&self.reclaimed_horizons),
            shard_key_owned,
            Arc::clone(&shard),
        );

        // Expire against THIS shard's floor, never the cross-shard maximum. The store-wide value
        // is dominated by whichever resource type churns hardest, so using it here would reject a
        // watch on a quiet type whose own ring still holds every event it ever saw.
        let horizon = shard.horizon.load(Ordering::Relaxed);

        // Collect ring buffer snapshot while holding read lock (std::sync::RwLock — synchronous).
        let replayed: Vec<Arc<InternalEvent>> = {
            let guard = shard.ring.read().expect("ring poisoned");
            guard
                .iter()
                .filter(|e| e.key.starts_with(prefix) && e.revision > from_revision)
                .cloned()
                .collect()
        };

        // How far behind this client actually was. Recorded here rather than only logged because
        // it is the requirement half of ring sizing — see WATCH_REPLAY_DEPTH's doc, including
        // why the value is only trustworthy at a capacity where this shard never fills.
        // How far behind this client actually was. Recorded here rather than only logged because
        // it is the requirement half of ring sizing — see WATCH_REPLAY_DEPTH's doc, including
        // why the value is only trustworthy at a capacity where this shard never fills.
        crate::metrics::WATCH_REPLAY_DEPTH
            .with_label_values(&[crate::metrics::prefix_bucket(prefix)])
            .observe(replayed.len() as f64);

        tracing::debug!(
            prefix,
            from_revision,
            horizon,
            replayed_count = replayed.len(),
            receiver_count = self.tx.receiver_count(),
            "watch: stream opened"
        );

        let prefix_owned = prefix.to_string();
        // Captured for lag recovery: allows re-subscribing and re-scanning ring buffer
        // without terminating the stream when the broadcast channel lags transiently.
        let tx_clone = self.tx.clone();
        // Re-resolved (via `find_shard`) on every use inside the stream below, rather than
        // reusing the `shard` computed above, so a watch opened before this resource type's
        // first-ever write still recovers correctly if that write (and its shard) arrives later
        // in the stream's lifetime.
        let shards_arc = Arc::clone(&self.shards);

        let stream = async_stream::stream! {
            // Moved in (not just referenced) so it lives exactly as long as this generator does
            // — see `ShardWatcherGuard`'s doc for why that, and not `watch()`'s own outer scope,
            // is the lifetime that must drive idle-GC eligibility.
            let _watcher_guard = watcher_guard;

            // Yield compacted event if from_revision is before the horizon.
            // Before yielding Compacted, emit any deletion tombstones from the deletion_log
            // that the client missed (revision > from_revision). These are deletions that were
            // compacted out of the main ring buffer — without replaying them here, the client
            // would reconnect after a relist and never see the DELETED events, deadlocking any
            // watcher that waits for a DELETED event for an object deleted in the compaction window.
            if from_revision > 0 && from_revision < horizon {
                let tombstones: Vec<WatchEvent> = {
                    let shards_guard = shards_arc.read().expect("shards poisoned");
                    match find_shard(&shards_guard, &prefix_owned) {
                        Some(shard) => {
                            let guard = shard.deletion_log.read().expect("deletion_log poisoned");
                            guard
                                .by_key
                                .iter()
                                .filter(|(key, entry)| {
                                    key.starts_with(&prefix_owned) && entry.revision() > from_revision
                                })
                                .map(|(key, entry)| entry.to_watch_event(key))
                                .collect()
                        }
                        None => Vec::new(),
                    }
                };
                for tombstone in tombstones {
                    yield tombstone;
                }
                tracing::debug!(
                    prefix = %prefix_owned,
                    from_revision,
                    horizon,
                    "watch: compacted at connect (from_revision below horizon)"
                );
                yield WatchEvent::Compacted { requested: from_revision, horizon };
                return;
            }

            // Replay historical events from ring buffer. Consumed BY VALUE (not `&replayed`):
            // `async_stream::stream!` expands to `async move`, so `replayed` is captured into
            // this generator's own state regardless; iterating by reference only borrows it,
            // leaving the owning Vec (and every Arc<InternalEvent> in it) alive as a named
            // local for the generator's ENTIRE remaining lifetime — up to the 30-minute
            // `stream_timeout_secs` default — instead of being dropped once this loop exits.
            // Moving each event out as it's yielded means the for loop's own (much smaller)
            // scope owns them instead, so they're released the moment this loop is done.
            let mut last_replayed = from_revision;
            for event in replayed {
                last_replayed = last_replayed.max(event.revision);
                yield internal_to_watch(&event);
            }

            // Tracks the highest revision seen from global bookmarks. Used only for emitting
            // BOOKMARK events to clients; deliberately separate from last_replayed so that a
            // global bookmark from a *different* resource's write cannot advance last_replayed
            // and cause a later out-of-order event on this prefix to be dedup-skipped.
            let mut bookmark_rv: u64 = from_revision;

            // Debounces the global-bookmark yield below: a global bookmark is broadcast on
            // every write in the whole store, to every open watch, so yielding one immediately
            // per broadcast makes every watcher's allocation rate scale with cluster-wide write
            // volume rather than its own prefix. Armed only while a bookmark update is pending
            // (not a periodic tick) so an idle watcher never wakes for this timer, and the first
            // pending update's deadline is never pushed out by later updates arriving inside the
            // same window — see GLOBAL_BOOKMARK_DEBOUNCE for why the window is safe.
            let debounce_sleep = tokio::time::sleep(GLOBAL_BOOKMARK_DEBOUNCE);
            tokio::pin!(debounce_sleep);
            let mut bookmark_debounce_pending = false;

            // Forward live broadcast events, skipping already-replayed revisions.
            loop {
                tokio::select! {
                    _ = &mut debounce_sleep, if bookmark_debounce_pending => {
                        bookmark_debounce_pending = false;
                        // Emit BOOKMARK at the highest observed RV across both specific
                        // events and bookmarks, so clients still see advancing bookmarks.
                        yield WatchEvent::Bookmark { revision: bookmark_rv.max(last_replayed) };
                        continue;
                    }
                    recv_result = rx.recv() => match recv_result {
                    Ok(event) => {
                        // A global bookmark (key holds the writer's shard root, always
                        // trailing-slash-terminated — see push_event_locked) is delivered to
                        // all watches regardless of prefix — it advances the informer's sync RV
                        // without carrying an object (KCM ConsistencyStore relies on this).
                        //
                        // Do NOT update last_replayed here: a global bookmark may arrive from
                        // a concurrent write on a completely different prefix, with a revision
                        // higher than a pending event on this watcher's prefix. Advancing
                        // last_replayed from a cross-prefix bookmark would cause that pending
                        // event to be dedup-skipped and silently dropped.
                        if event.key.ends_with('/') {
                            // This watcher's own prefix is either exactly its shard's root or
                            // that root plus one namespace segment (see `shard_key`), so
                            // `prefix_owned.starts_with(&event.key)` is true only when this
                            // bookmark came from the SAME shard this watcher is on. The trailing
                            // per-matched-event bookmark just above already delivered an
                            // equal-or-higher-revision bookmark to this watcher a moment earlier
                            // via a different, unthrottled path — this one carries no new
                            // information, so drop it before it can even arm the debounce timer.
                            if prefix_owned.starts_with(event.key.as_str()) {
                                continue;
                            }
                            if event.revision > bookmark_rv {
                                bookmark_rv = event.revision;
                                if !bookmark_debounce_pending {
                                    bookmark_debounce_pending = true;
                                    debounce_sleep
                                        .as_mut()
                                        .reset(tokio::time::Instant::now() + GLOBAL_BOOKMARK_DEBOUNCE);
                                }
                            }
                            continue;
                        }
                        if !event.key.starts_with(&prefix_owned) {
                            continue;
                        }
                        // Deduplicate: skip if already covered by replay or a previous live event.
                        if event.revision <= last_replayed {
                            tracing::debug!(
                                prefix = %prefix_owned,
                                key = %event.key,
                                rv = event.revision,
                                last_replayed,
                                "watch: dedup skip"
                            );
                            continue;
                        }
                        tracing::debug!(
                            prefix = %prefix_owned,
                            key = %event.key,
                            rv = event.revision,
                            "watch: yielding live event"
                        );
                        last_replayed = event.revision;
                        yield internal_to_watch(&event);
                        // Immediately follow every event with a BOOKMARK at the same RV.
                        // client-go only advances LastStoreSyncResourceVersion on BOOKMARK events.
                        // KCM ConsistencyStore checks the pod informer's LastStoreSyncResourceVersion
                        // immediately after writing a pod — without a trailing BOOKMARK the check
                        // always sees a stale RV and requeues indefinitely.
                        yield WatchEvent::Bookmark { revision: last_replayed };
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // The broadcast channel dropped messages because this receiver was too slow.
                        // Labeled by prefix_bucket, not the raw prefix: a namespace-scoped watch
                        // prefix includes the namespace segment, which would otherwise mint one
                        // time series per namespace a long conformance run ever creates.
                        crate::metrics::WATCH_BROADCAST_LAGGED_TOTAL
                            .with_label_values(&[crate::metrics::prefix_bucket(&prefix_owned)])
                            .inc_by(n);
                        // Attempt recovery: re-subscribe (to capture all future events) then
                        // re-scan the ring buffer for events missed during the lag.  This avoids
                        // terminating the stream with a 410 error for a transient slow-consumer
                        // scenario — which forces the client to relist and re-watch, wasting
                        // another full round-trip and potentially lagging again.
                        //
                        // If the ring buffer has also been compacted past last_replayed, we
                        // fall back to yielding Compacted so the client can relist from a valid
                        // revision rather than silently skipping events.
                        rx = tx_clone.subscribe();
                        // Timed separately from the `for event in &catchup { yield ... }` loop
                        // below: `yield` inside this generator suspends on the consumer's poll
                        // rate (backpressure), which would fold client-drain latency into this
                        // measurement. This histogram exists to isolate the O(shard-ring) scan
                        // itself — the part that runs synchronously while holding the shard's
                        // ring read lock and blocks whichever tokio worker is polling this stream.
                        let recovery_scan_started = std::time::Instant::now();
                        let catchup: Vec<Arc<InternalEvent>> = {
                            let shards_guard = shards_arc.read().expect("shards poisoned");
                            match find_shard(&shards_guard, &prefix_owned) {
                                Some(shard) => {
                                    let guard = shard.ring.read().expect("ring poisoned");
                                    guard
                                        .iter()
                                        .filter(|e| {
                                            e.key.starts_with(&prefix_owned) && e.revision > last_replayed
                                        })
                                        .cloned()
                                        .collect()
                                }
                                None => Vec::new(),
                            }
                        };
                        crate::metrics::WATCH_LAG_RECOVERY_DURATION_SECONDS
                            .with_label_values(&[crate::metrics::prefix_bucket(&prefix_owned)])
                            .observe(recovery_scan_started.elapsed().as_secs_f64());
                        for event in &catchup {
                            last_replayed = last_replayed.max(event.revision);
                            yield internal_to_watch(event);
                        }
                        // If the ring buffer was also compacted past last_replayed (events lost
                        // from both broadcast and ring buffer), signal the gap to the consumer.
                        // Before signalling Compacted, replay any deletion tombstones from the
                        // deletion_log that are not already covered by the ring buffer catchup.
                        // Without this, a namespace deleted during the lag+compaction window
                        // would never deliver its DELETED event: the client would reconnect after
                        // a relist, open a new Watch at the current revision, and wait forever.
                        // This shard's own floor, re-resolved rather than captured: the shard may
                        // not have existed when the watch opened. Using the cross-shard maximum
                        // here would declare recovery failed — and force the client into a
                        // relist — because some unrelated busy resource type evicted, even
                        // though this prefix's ring still holds everything since last_replayed.
                        let current_horizon = {
                            let shards_guard = shards_arc.read().expect("shards poisoned");
                            find_shard(&shards_guard, &prefix_owned)
                                .map_or(0, |shard| shard.horizon.load(Ordering::Relaxed))
                        };
                        let recovered = current_horizon <= last_replayed;
                        tracing::debug!(
                            prefix = %prefix_owned,
                            missed = n,
                            last_replayed,
                            current_horizon,
                            recovered,
                            "watch: lag detected, ring-buffer recovery attempted"
                        );
                        if current_horizon > last_replayed {
                            // Use from_revision (the watcher's original start) rather than
                            // last_replayed as the lower bound for deletion_log replay.
                            //
                            // Why: after ring catchup, last_replayed is advanced by non-prefix
                            // events (e.g. pod writes advancing the ring), so last_replayed may
                            // now be GREATER than the tombstone's revision even though the
                            // tombstone was never delivered. A deletion at revision D and
                            // last_replayed at D+500 would be silently skipped with
                            // `> last_replayed`, causing sonobuoy delete --wait to deadlock.
                            //
                            // Using from_revision ensures every deletion since the watcher
                            // started is delivered before Compacted. The client relists after
                            // Compacted anyway, so a pre-Compacted duplicate DELETED is harmless.
                            let tombstones: Vec<(u64, WatchEvent)> = {
                                let shards_guard = shards_arc.read().expect("shards poisoned");
                                match find_shard(&shards_guard, &prefix_owned) {
                                    Some(shard) => {
                                        let guard =
                                            shard.deletion_log.read().expect("deletion_log poisoned");
                                        guard
                                            .by_key
                                            .iter()
                                            .filter(|(key, entry)| {
                                                key.starts_with(&prefix_owned)
                                                    && entry.revision() > from_revision
                                            })
                                            .map(|(key, entry)| (entry.revision(), entry.to_watch_event(key)))
                                            .collect()
                                    }
                                    None => Vec::new(),
                                }
                            };
                            for (revision, tombstone) in tombstones {
                                last_replayed = last_replayed.max(revision);
                                yield tombstone;
                            }
                            tracing::debug!(
                                prefix = %prefix_owned,
                                last_replayed,
                                current_horizon,
                                "watch: compacted after lag recovery (ring also compacted past last_replayed)"
                            );
                            yield WatchEvent::Compacted {
                                requested: last_replayed,
                                horizon: current_horizon,
                            };
                            return;
                        }
                        // Ring buffer covered the gap; continue watching from last_replayed.
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Structurally unreachable: `tx_clone` (captured above) lives inside
                        // this same generator for as long as this `rx.recv()` call is being
                        // polled, so this stream always holds at least one Sender handle of
                        // its own. The broadcast channel's sender count can therefore never
                        // reach zero from this stream's point of view — dropping the
                        // originating `SqliteStore` only releases `SqliteStore::tx`, never the
                        // clone this stream is holding. Kept as an exhaustive match arm rather
                        // than deleted so a future change to `tx_clone`'s capture strategy that
                        // defeats this invariant fails loudly instead of silently leaking watch
                        // streams that poll a dead channel forever.
                        unreachable!(
                            "watch() retains its own broadcast Sender clone for this stream's \
                             entire lifetime, so RecvError::Closed can never be observed here"
                        )
                    }
                    }
                }
            }
        };

        Ok(stream)
    }

    fn compaction_horizon(&self) -> u64 {
        self.compaction_horizon.load(Ordering::Relaxed)
    }

    fn evict_resource_type(&self, prefix: &str) {
        // Every shard rooted at `prefix` — the reverse direction from `matching_shards` (which
        // finds shards that are a prefix of a WRITE's key): here `prefix` is the shorter,
        // caller-supplied resource-type root, and we want every shard key that EXTENDS it (the
        // exact cluster-scoped root itself, plus a namespace-scoped shard for EACH namespace
        // that ever had its own watch on this type — unlike `find_shard`/`find_shard_key`, this
        // count has no fixed bound, since nothing stops distinct watches on different namespaces
        // of the same CRD from each getting their own shard entry, so a fixed two-key check
        // would silently leave other namespaces' shards live after a CRD delete).
        //
        // `shards` is a `BTreeMap`, so every key sharing `prefix` as a byte-prefix sorts
        // contiguously starting at `prefix` itself (lexicographic order agrees with string-prefix
        // order) — `range(prefix..)` seeks there directly and `take_while` stops at the first key
        // that no longer matches, visiting exactly this root's shards (plus at most one
        // non-matching key) instead of every shard for every OTHER resource type in the store.
        // Collected before removing so `tear_down_shard`'s own write-lock acquisition per key
        // never nests inside this read lock.
        let rooted: Vec<String> = self
            .shards
            .read()
            .expect("shards poisoned")
            .range(prefix.to_string()..)
            .take_while(|(shard, _)| shard.starts_with(prefix))
            .map(|(shard, _)| shard.clone())
            .collect();
        for shard_key in rooted {
            tear_down_shard(&self.shards, &self.reclaimed_horizons, &shard_key);
        }
    }

    // Without this override, a generic `S: Store` caller (e.g. handlers/watch.rs's
    // `watch_generic_impl<S: Store>`) resolves `compaction_horizon_for` to the trait default
    // above (cross-shard max) — Rust generic dispatch never falls back to a concrete type's
    // inherent methods, so the identically-named inherent method at `SqliteStore::compaction_horizon_for`
    // is invisible from inside a function bounded only by `S: Store`. Delegating here makes the
    // two call shapes agree.
    fn compaction_horizon_for(&self, prefix: &str) -> u64 {
        SqliteStore::compaction_horizon_for(self, prefix)
    }

    fn current_revision(&self) -> u64 {
        self.last_written_revision.load(Ordering::Acquire)
    }

    fn watch_receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

pub(crate) fn internal_to_watch(event: &InternalEvent) -> WatchEvent {
    match &event.value {
        Some(value) => {
            let obj = StoreObject {
                key: event.key.clone(),
                value: value.clone(),
                revision: event.revision,
            };
            if event.is_create {
                WatchEvent::Added(obj)
            } else {
                WatchEvent::Modified(obj)
            }
        }
        None => WatchEvent::Deleted {
            key: event.key.clone(),
            revision: event.revision,
            body: event.deleted_body.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::time::Duration;

    fn svc_value(name: &str, rv: u64) -> Bytes {
        Bytes::from(format!(
            r#"{{"apiVersion":"v1","kind":"Service","metadata":{{"name":"{name}","namespace":"default","resourceVersion":"{rv}"}}}}"#,
            name = name,
            rv = rv
        ))
    }

    /// A file-backed store's write and read connections must use DIFFERENT `cache_size`
    /// budgets — the write connection cut down to SQLite's own historical default, the read
    /// connection left at the larger, pre-existing size.
    ///
    /// Why it matters: before this split, both connections opened at the larger size, so a
    /// single running apiserver paid ~15.6 MiB of malloc'd, dhat-invisible C-side page cache
    /// for two connections where only one (the read connection, serving concurrent LIST
    /// scans) actually benefits from a large cache — the write connection is serialized
    /// behind `write_conn`'s mutex and never has more than one query in flight. A regression
    /// back to a shared, uncut size would silently re-inflate that footprint without ever
    /// showing up in the project's dhat-based heap profiling, which cannot see SQLite's own
    /// malloc'd pages.
    #[tokio::test]
    async fn file_backed_store_cuts_the_write_connections_cache_but_not_the_reads() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let tid = std::thread::current().id();
        let db_path =
            std::env::temp_dir().join(format!("u7s-sqlite-cache-size-test-{nanos}-{tid:?}.db"));
        let db_path_str = db_path
            .to_str()
            .expect("temp path must be valid UTF-8")
            .to_string();

        let store = SqliteStore::new(&db_path_str).expect("file-backed store");

        let write_cache: i64 = store
            .write_conn
            .lock()
            .await
            .query_row("PRAGMA cache_size", [], |row| row.get(0))
            .expect("read write connection's cache_size");
        let read_cache: i64 = store
            .read_conn
            .lock()
            .await
            .query_row("PRAGMA cache_size", [], |row| row.get(0))
            .expect("read read connection's cache_size");

        assert_eq!(
            write_cache, WRITE_CACHE_SIZE_KIB,
            "the write connection must use the smaller cache_size — a regression back to the \
             larger shared size would cost several extra MiB of C-side page cache per open \
             store on a connection that only ever serves one writer at a time"
        );
        assert_eq!(
            read_cache, READ_CACHE_SIZE_KIB,
            "the read connection must keep the larger cache_size — it backs every LIST scan \
             and is the connection most likely to thrash if cut as aggressively as the write \
             connection's"
        );

        drop(store);
        let _ = std::fs::remove_file(&db_path_str);
        let _ = std::fs::remove_file(format!("{db_path_str}-wal"));
        let _ = std::fs::remove_file(format!("{db_path_str}-shm"));
    }

    /// The ring's replay snapshot (`replayed` in `watch()`) must be released once its events
    /// are yielded, not retained for the whole stream's lifetime.
    ///
    /// Why it matters: `async_stream::stream!` expands to `async move`, so `replayed` (built
    /// and cloned from the ring BEFORE the generator is constructed) is captured into the
    /// generator's own state regardless of how the replay loop iterates it. If that loop only
    /// borrows (`for event in &replayed`), the owning Vec — and every `Arc<InternalEvent>` in
    /// it — stays alive as a named local for the generator's ENTIRE remaining life, i.e. the
    /// whole stream, up to the 30-minute `stream_timeout_secs` default. Across many concurrent
    /// watchers that all replayed a deep backlog, that is retained memory that scales with
    /// concurrent-watcher count instead of with `RING_CAPACITY` alone.
    ///
    /// Fails on revert to `for event in &replayed`: this test pushes exactly one tracked event,
    /// opens a watch (snapshotting it into `replayed`, one extra `Arc` clone), drains the one
    /// historical event, then drives the generator ONE poll further (past the replay loop's own
    /// exit, into the live-forwarding select — which blocks on an empty broadcast receiver and
    /// returns `Pending`, since nothing was pushed after the watch opened). A borrow-based loop
    /// never drops `replayed`, so `Arc::strong_count` would stay elevated at 3 instead of
    /// falling to 2 once the loop's own (much smaller) scope has closed.
    #[tokio::test]
    async fn watch_replay_snapshot_is_released_once_yielded_not_pinned_for_stream_lifetime() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/watch-replay-lifetime-test/";
        let key = format!("{prefix}obj-1");

        let tracked = Arc::new(InternalEvent {
            key: key.clone(),
            revision: 1,
            value: Some(Bytes::from(
                r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"obj-1"}}"#,
            )),
            is_create: true,
            deleted_body: None,
        });
        // One clone lands in the shard's ring (push_into_shard). `tx.send`'s own clone is
        // dropped right back out: with zero subscribers at this point (watch() hasn't run
        // yet), tokio's broadcast channel returns the value inside its `Err`, which
        // `push_event_locked`'s `let _ = tx.send(event);` immediately discards. So this is 2
        // total (tracked + the ring's copy), not 3.
        store.push_event(Arc::clone(&tracked), None);

        let stream = store.watch(prefix, 0).await.expect("watch must succeed");
        futures_util::pin_mut!(stream);

        // watch() snapshots the ring into `replayed` (one more clone) before returning the
        // stream — this is the count the rest of the test must see drop by exactly one.
        assert_eq!(
            Arc::strong_count(&tracked),
            3,
            "watch() must have snapshotted the ring into `replayed` at open time; without that \
             baseline this test cannot distinguish a released snapshot from one never taken"
        );

        match stream.next().await {
            Some(WatchEvent::Added(obj)) => assert_eq!(obj.key, key, "replayed the wrong object"),
            other => panic!("expected the historical Added event first, got {other:?}"),
        }

        // One more poll: nothing was pushed since watch() subscribed, so the live-forwarding
        // select has nothing to deliver and must return Pending — but reaching that point
        // requires the generator to first run past the replay loop's exit.
        let next_fut = stream.next();
        futures_util::pin_mut!(next_fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(
            matches!(
                std::future::Future::poll(next_fut, &mut cx),
                std::task::Poll::Pending
            ),
            "second poll should have nothing to deliver (no live events were pushed since watch \
             opened), not another item"
        );

        assert_eq!(
            Arc::strong_count(&tracked),
            2,
            "the replay snapshot must be released once its one event is yielded — a count \
             stuck at 3 means the ring's replay Vec is being retained for the stream's entire \
             lifetime instead of being dropped right after the historical-replay loop exits"
        );
    }

    /// Verify that a global bookmark carrying a higher revision (from a concurrent write that
    /// already committed and bumped `last_written_revision`) does NOT cause a subsequent
    /// specific event at that same revision to be dedup-skipped.
    ///
    /// Why it matters: before the fix, push_event read last_written_revision AFTER the commit,
    /// so if write-B (rv=2) committed between write-A's commit and write-A's push_event call,
    /// write-A's bookmark would carry rv=2.  A watcher receiving event(svc-a,rv=1) then
    /// bookmark(rv=2) then event(svc-b,rv=2) would skip svc-b (rv=2 <= last_replayed=2).
    /// The controller watching services would never see svc-b — it disappears silently.
    ///
    /// The fix: use the event's own revision for the global bookmark so concurrent writes
    /// cannot contaminate each other's bookmarks.
    #[tokio::test]
    async fn watch_bookmark_race_loses_event_without_fix() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Subscribe the watcher before any writes so it enters the live-event loop.
        let stream = store
            .watch("/registry/services/", 0)
            .await
            .expect("watch failed");
        futures_util::pin_mut!(stream);

        // Simulate the race: write-B (rv=2) has already committed and bumped
        // last_written_revision to 2 before write-A calls push_event for rv=1.
        // With the bug, push_event reads last_written_revision=2 and broadcasts
        // bookmark(rv=2) — a revision higher than write-A's own event.
        store.last_written_revision.store(2, Ordering::Release);

        // push_event for svc-a (rv=1).
        // BUG:   broadcasts event(svc-a,rv=1) + bookmark(rv=2)  [reads last_written_revision=2]
        // FIX:   broadcasts event(svc-a,rv=1) + bookmark(rv=1)  [uses event.revision]
        store.push_event(
            Arc::new(InternalEvent {
                key: "/registry/services/default/svc-a".into(),
                revision: 1,
                value: Some(svc_value("svc-a", 1)),
                is_create: true,
                deleted_body: None,
            }),
            Some("default"),
        );

        // push_event for svc-b (rv=2) — the concurrent write.
        // Broadcasts event(svc-b,rv=2) + bookmark(rv=2).
        store.push_event(
            Arc::new(InternalEvent {
                key: "/registry/services/default/svc-b".into(),
                revision: 2,
                value: Some(svc_value("svc-b", 2)),
                is_create: true,
                deleted_body: None,
            }),
            Some("default"),
        );

        // Collect Added events for a short window.
        // With BUG:  watcher sees event(svc-a,rv=1)→Added, bookmark(rv=2)→last_replayed=2,
        //            event(svc-b,rv=2)→rv<=last_replayed→SKIP.  svc-b is never delivered.
        // With FIX:  watcher sees event(svc-a,rv=1)→Added, bookmark(rv=1), then
        //            event(svc-b,rv=2)→rv>last_replayed=1→Added.  Both delivered.
        let mut added_keys: Vec<String> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Added(obj))) => {
                    added_keys.push(obj.key.clone());
                }
                Ok(Some(WatchEvent::Bookmark { .. })) => {}
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break, // timeout
            }
        }

        assert!(
            added_keys.contains(&"/registry/services/default/svc-a".to_string()),
            "svc-a must be delivered as Added; without this a watcher misses the service entirely"
        );
        assert!(
            added_keys.contains(&"/registry/services/default/svc-b".to_string()),
            "svc-b must be delivered as Added; push_event must use event.revision for the global \
             bookmark, not last_written_revision — otherwise a concurrent write that commits first \
             causes the bookmark to carry a future rv, advancing last_replayed and dedup-skipping \
             svc-b's event so controllers never see it"
        );
    }

    /// Verify that a global bookmark from a *different* resource's write does not advance
    /// `last_replayed` on a watcher for a different prefix, causing a subsequent lower-rv
    /// event on that prefix to be dedup-skipped.
    ///
    /// Why it matters: an Endpoints write at rv=365 fires a global bookmark(rv=365). A Services
    /// watcher receives that bookmark BEFORE the service event at rv=364 (delayed by scheduling).
    /// If the bookmark advances `last_replayed=365`, the service event(rv=364) is dedup-skipped
    /// and controllers (KCM) never see the service — no EndpointSlice is ever created.
    ///
    /// The fix: global bookmarks must NOT advance `last_replayed` used for dedup. Track bookmark
    /// progress separately (`bookmark_rv`); use `max(last_replayed, bookmark_rv)` only for
    /// emitting BOOKMARK events to clients.
    #[tokio::test]
    async fn watch_cross_resource_bookmark_skips_event() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Subscribe to /registry/services/ from rv=0.
        let stream = store
            .watch("/registry/services/", 0)
            .await
            .expect("watch failed");
        futures_util::pin_mut!(stream);

        let tx = store.tx.clone();

        // 1. Global bookmark at rv=365 (from a concurrent Endpoints write on a different prefix).
        //    This arrives BEFORE the service event at rv=364 due to scheduling jitter.
        tx.send(Arc::new(InternalEvent {
            key: "/registry/endpoints/".to_string(),
            revision: 365,
            value: None,
            is_create: false,
            deleted_body: None,
        }))
        .expect("send bookmark");

        // 2. Service event at rv=364 (arrived late due to scheduling).
        tx.send(Arc::new(InternalEvent {
            key: "/registry/services/default/svc-a".into(),
            revision: 364,
            value: Some(Bytes::from(
                r#"{"apiVersion":"v1","kind":"Service","metadata":{"name":"svc-a","namespace":"default","resourceVersion":"364"}}"#,
            )),
            is_create: true,
            deleted_body: None,
        }))
        .expect("send svc-a event");

        // Collect Added events for a short window.
        // With BUG:  watcher receives bookmark(rv=365)→last_replayed=365, then
        //            svc-a(rv=364)→rv<=last_replayed→SKIP.  svc-a is never delivered.
        // With FIX:  bookmark only updates bookmark_rv, last_replayed stays at 0;
        //            svc-a(rv=364)→rv>last_replayed=0→Added.  svc-a is delivered.
        let mut added_keys: Vec<String> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Added(obj))) => {
                    added_keys.push(obj.key.clone());
                }
                Ok(Some(WatchEvent::Bookmark { .. })) => {}
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break, // timeout
            }
        }

        assert!(
            added_keys.contains(&"/registry/services/default/svc-a".to_string()),
            "svc-a must be delivered as Added even when a global bookmark with a higher rv \
             (from a different resource's write) arrives before the service event; \
             if global bookmarks advance last_replayed, the service event is dedup-skipped \
             and controllers like KCM never create EndpointSlices for the service"
        );
    }

    /// GET after PUT must return a revision >= the revision returned by PUT.
    ///
    /// KCM tracks the last revision it wrote and rejects reads whose resourceVersion is lower
    /// ("read version N is not as new as written version M"). Without the stale-read guard on
    /// get(), the WAL read connection can return an older object revision, triggering repeated
    /// optimistic concurrency failures in the controller reconcile loop.
    ///
    /// The guard fires when obj.revision < last_written_revision, retrying via the write
    /// connection. This test verifies the invariant holds: get after put returns the written rv.
    #[tokio::test]
    async fn get_after_put_returns_at_least_written_revision() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/apps/replicasets/default/rs-a";
        let value = Bytes::from(
            r#"{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"name":"rs-a","namespace":"default"}}"#,
        );

        let written_rv = store.put(key, value, None).await.expect("put must succeed");

        // Simulate a concurrent write that bumped last_written_revision above written_rv.
        // On a file-backed WAL store, the read connection may not have replayed the latest
        // WAL frame yet, causing get() to return an object with revision < last_written_revision.
        // The guard must detect this and retry via the write connection.
        store
            .last_written_revision
            .store(written_rv + 1, Ordering::Release);

        let obj = store
            .get(key)
            .await
            .expect("get must not error")
            .expect("object must exist after put");

        assert!(
            obj.revision >= written_rv,
            "get must return revision >= the revision returned by put ({written_rv}); \
             returning a lower revision causes KCM optimistic concurrency failures: \
             'read version {} is not as new as written version {written_rv}'",
            obj.revision
        );
    }

    /// GET for an existing pod must not return None when the WAL read snapshot predates the
    /// pod's creation.
    ///
    /// Without this fix, a GET that 404s an existing pod makes the kubelet tear down and
    /// recreate the sandbox ~1/sec, so Job pods never hold Running and every Job conformance
    /// test times out. The apiserver logged 105,684 pod-GET 404s in 5 min for only 6 pods.
    ///
    /// The stale-read guard must cover the None case (obj is None AND min_rev > 0), not just
    /// the Some(stale) case (obj.revision < min_rev).
    ///
    /// This test constructs a SqliteStore with a stale read_conn (empty in-memory DB that
    /// has no rows) and a write_conn that has the pod committed. last_written_revision is set
    /// to 1, signalling that writes have occurred that the read snapshot cannot see.
    /// With the fix: get() detects None + min_rev > 0 and retries via write_conn → Some.
    /// Without the fix: get() returns None directly → assertion fails → test fails on revert.
    #[tokio::test(flavor = "multi_thread")]
    async fn get_returns_some_when_stale_read_snapshot_misses_creation() {
        use std::sync::RwLock;
        use tokio::sync::broadcast;

        let key = "/registry/core/pods/job-ns/foo-d1a7f";
        let pod_value = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"foo-d1a7f","namespace":"job-ns"}}"#,
        );

        // Build a write connection with the full schema and the pod committed.
        let write_raw = Connection::open_in_memory().expect("write conn");
        write_raw
            .execute_batch(
                "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
                 revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
                 CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL); \
                 INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');",
            )
            .expect("schema");
        let last_written = Arc::new(AtomicU64::new(0));
        let written_rv = {
            put_sync(&write_raw, key, pod_value, None, &last_written)
                .expect("put_sync")
                .0
        };
        let write_conn = Arc::new(Mutex::new(write_raw));

        // Build a STALE read connection: a separate in-memory DB with the schema but NO rows.
        // This simulates the WAL read connection whose snapshot predates the pod's creation.
        let stale_raw = Connection::open_in_memory().expect("stale read conn");
        stale_raw
            .execute_batch(
                "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
                 revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
                 CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL); \
                 INSERT OR IGNORE INTO meta (key, value) VALUES ('revision', '0');",
            )
            .expect("stale schema");
        let read_conn = Arc::new(Mutex::new(stale_raw));

        // Confirm the stale read returns None — this is the production symptom.
        let stale_result =
            tokio::task::block_in_place(|| get_sync(&read_conn.blocking_lock(), key))
                .expect("get_sync on stale conn must not error");
        assert!(
            stale_result.is_none(),
            "stale read connection must return None (no rows) — test setup broken"
        );

        // Assemble the store with the stale read_conn and write_conn that has the pod.
        let (tx, _) = broadcast::channel(16);
        let store = SqliteStore {
            write_conn,
            read_conn,
            tx,
            shards: Arc::new(RwLock::new(BTreeMap::new())),
            reclaimed_horizons: Arc::new(RwLock::new(ReclaimedHorizons::default())),
            compaction_horizon: Arc::new(AtomicU64::new(0)),
            last_written_revision: last_written,
            epoch: Instant::now(),
        };

        // last_written_revision is already written_rv (set by put_sync).
        // get() must detect: obj == None AND min_rev == written_rv > 0 → retry via write_conn.
        let obj = store.get(key).await.expect("get must not error");

        assert!(
            obj.is_some(),
            "get must return Some for an existing pod (written at rv={written_rv}), not None; \
             a None response causes the kubelet to 404 the pod and tear down the sandbox ~1/sec, \
             so Job pods never hold Running and Job conformance tests time out"
        );
    }

    /// LIST after PUT must return a snapshot revision >= the revision returned by PUT.
    ///
    /// Under high write bursts with a large WAL (wal_autocheckpoint=1000), the read connection
    /// lags behind the write connection and list() returns a stale snapshot revision.
    /// KCM's RS controller compares the list resourceVersion against its last written revision
    /// and requeues in a tight loop for up to 15 minutes when the list RV is lower.
    ///
    /// The stale-read guard in list() detects this (resp.revision < last_written_revision)
    /// and retries via the write connection which always reflects the latest committed state.
    /// This test verifies the guard fires and the returned revision is current.
    #[tokio::test]
    async fn list_after_put_returns_at_least_written_revision() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/apps/replicasets/";
        let key = "/registry/apps/replicasets/default/rs-a";
        let value = Bytes::from(
            r#"{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"name":"rs-a","namespace":"default"}}"#,
        );

        let written_rv = store.put(key, value, None).await.expect("put must succeed");

        // Simulate WAL lag: bump last_written_revision above written_rv, as if a concurrent write
        // committed but the read connection's WAL snapshot has not yet replayed those frames.
        // On a file-backed WAL store under high write bursts, wal_autocheckpoint=1000 means the
        // read connection can trail the write connection by up to 1000 pages.
        store
            .last_written_revision
            .store(written_rv + 1, Ordering::Release);

        let resp = store
            .list(prefix, ListOptions::default())
            .await
            .expect("list must not error");

        assert!(
            resp.revision >= written_rv,
            "list must return snapshot revision >= the revision returned by put ({written_rv}); \
             a lower revision causes KCM's RS controller to log \
             'read version {} is not as new as written version {written_rv}' \
             and requeue in a tight loop for up to 15 minutes",
            resp.revision
        );
    }

    /// Repeated list() calls must return consistent results — verifies prepare_cached does not
    /// corrupt query state across calls.
    ///
    /// Why it matters: prepare_cached reuses the cached statement handle; if the handle is
    /// left in a bad state (rows not consumed, reset not called), a subsequent list on the same
    /// connection returns wrong results or errors, breaking any controller that lists repeatedly.
    #[tokio::test]
    async fn repeated_list_returns_consistent_results() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/core/configmaps/";

        for i in 0..5u32 {
            let key = format!("/registry/core/configmaps/default/cm-{i}");
            let val = Bytes::from(format!(
                r#"{{"apiVersion":"v1","kind":"ConfigMap","metadata":{{"name":"cm-{i}","namespace":"default"}}}}"#
            ));
            store.put(&key, val, None).await.expect("put must succeed");
        }

        let first = store
            .list(prefix, ListOptions::default())
            .await
            .expect("first list");
        let second = store
            .list(prefix, ListOptions::default())
            .await
            .expect("second list");

        assert_eq!(
            first.items.len(),
            second.items.len(),
            "repeated list() must return the same item count; a mismatch means prepare_cached \
             left the statement in a corrupted state, causing controllers to see inconsistent \
             object counts across reflector resyncs"
        );
        assert_eq!(
            first.items.len(),
            5,
            "list must return all 5 inserted configmaps; returning fewer breaks reflector \
             initial list completeness"
        );
    }

    /// PUT followed by GET must return the correctly stamped resourceVersion and the identical
    /// ns/obj_name that were in the original value — verifying that extracting indexed columns
    /// from the pre-stamp parse yields the same result as extracting from the stamped bytes.
    ///
    /// Why it matters: if the single-parse optimization extracts ns/obj_name from the wrong
    /// JSON document (e.g. before namespace is set, or from a stale value), the indexed columns
    /// in SQLite diverge from the stored object, breaking field-selector queries by namespace
    /// or name — controllers that list pods by nodeName or services by namespace never find
    /// their objects and reconcile loops stall indefinitely.
    #[tokio::test]
    async fn put_stamps_rv_and_preserves_ns_obj_name() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/pods/prod/web-abc";
        let raw = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web-abc","namespace":"prod"}}"#,
        );

        let rv = store.put(key, raw, None).await.expect("put must succeed");

        let obj = store
            .get(key)
            .await
            .expect("get must not error")
            .expect("object must exist after put");

        let parsed: serde_json::Value =
            serde_json::from_slice(&obj.value).expect("stored value must be valid JSON");

        assert_eq!(
            parsed["metadata"]["resourceVersion"].as_str(),
            Some(rv.to_string().as_str()),
            "stored object must have resourceVersion stamped to the revision returned by put; \
             a mismatch means the stamp did not propagate to the stored bytes"
        );
        assert_eq!(
            parsed["metadata"]["namespace"].as_str(),
            Some("prod"),
            "namespace must survive the single-parse stamp path; if extraction reads from the \
             wrong parse result the indexed ns column is wrong and namespace-scoped list queries \
             return empty results"
        );
        assert_eq!(
            parsed["metadata"]["name"].as_str(),
            Some("web-abc"),
            "name must survive the single-parse stamp path; if extraction reads from the wrong \
             parse result the indexed obj_name column is wrong and name field-selector queries \
             return empty results"
        );

        // Verify the indexed columns are queryable via field selector (proves SQLite columns match).
        let by_ns = store
            .list(
                "/registry/core/pods/",
                ListOptions {
                    field_selector: Some(FieldSelector {
                        field: "metadata.namespace".to_string(),
                        value: "prod".to_string(),
                        negated: false,
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect("list by namespace");

        assert_eq!(
            by_ns.items.len(),
            1,
            "field-selector list by namespace=prod must return 1 pod; returning 0 means the \
             ns indexed column was not correctly populated by the single-parse put path, \
             breaking all namespace-scoped list queries"
        );
    }

    /// The spec.nodeName SQL fast-path must match unscheduled pods (no nodeName key) against
    /// an empty-value selector, and must still match only the exact value for a real selector.
    ///
    /// Why it matters: `fieldSelector=spec.nodeName=` is k8s shorthand for "unscheduled pods"
    /// and backs the scheduler's stranded-pod safety net. `json_extract(...) = ?` is SQL-NULL
    /// (never true) for an absent key, so a naive fast-path silently returns zero pods for that
    /// query — the safety net finds nothing to reconcile and stranded pods are never rescheduled.
    #[tokio::test]
    async fn nodename_fast_path_empty_selector_matches_unscheduled_pods() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        store
            .put(
                "/registry/pods/default/unscheduled",
                Bytes::from(r#"{"metadata":{"name":"unscheduled","namespace":"default"}}"#),
                None,
            )
            .await
            .expect("put unscheduled pod");
        store
            .put(
                "/registry/pods/default/scheduled",
                Bytes::from(
                    r#"{"metadata":{"name":"scheduled","namespace":"default"},"spec":{"nodeName":"node-1"}}"#,
                ),
                None,
            )
            .await
            .expect("put scheduled pod");

        let unscheduled = store
            .list(
                "/registry/pods/",
                ListOptions {
                    field_selector: Some(FieldSelector {
                        field: "spec.nodeName".to_string(),
                        value: String::new(),
                        negated: false,
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect("list with empty-value nodeName selector");
        assert_eq!(
            unscheduled.items.len(),
            1,
            "spec.nodeName= must match the pod with no nodeName key; if the SQL fast-path \
             compares json_extract's NULL to '' with plain equality it matches nothing and the \
             scheduler's stranded-pod safety net stalls forever"
        );

        let scheduled = store
            .list(
                "/registry/pods/",
                ListOptions {
                    field_selector: Some(FieldSelector {
                        field: "spec.nodeName".to_string(),
                        value: "node-1".to_string(),
                        negated: false,
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect("list with real-value nodeName selector");
        assert_eq!(
            scheduled.items.len(),
            1,
            "spec.nodeName=node-1 must match only the pod scheduled to node-1, not the \
             unscheduled pod; the empty-value OR clause must not widen the common (real value) \
             match path"
        );
    }

    /// A LIST `limit=u64::MAX` must not turn into `LIMIT 0`.
    ///
    /// `clamp_list_limit` feeds `list_sync`'s SQL fast-path `fetch_limit = limit + 1` cast.
    /// If it let `u64::MAX` through, `limit + 1` wraps to 0 (or panics under debug
    /// overflow-checks, which `cargo test` builds with by default) and the resulting
    /// `LIMIT 0` would hand a client asking for "everything" a permanently empty page
    /// instead of their results.
    #[test]
    fn clamp_list_limit_rejects_u64_max_to_avoid_wrapping_fetch_limit_to_zero() {
        assert_eq!(
            clamp_list_limit(Some(u64::MAX)),
            None,
            "limit=u64::MAX must be treated as unlimited; passing it through unchanged would \
             wrap the SQL fast-path's `limit + 1` computation to 0, silently emptying every \
             page for a client that asked for an unlimited list"
        );
    }

    /// A LIST `limit` anywhere in `2^63..=u64::MAX-1` must not reach the SQL fast-path's
    /// `as i64` cast, because that cast reinterprets it as a *negative* i64 and SQLite
    /// treats a negative LIMIT as "no limit" — silently returning the entire unbounded
    /// result set instead of erroring or falling back through code that says so explicitly.
    #[test]
    fn clamp_list_limit_rejects_limits_that_would_cast_negative_for_sqlite() {
        for hostile in [1u64 << 63, (1u64 << 63) + 12345, u64::MAX - 1] {
            assert_eq!(
                clamp_list_limit(Some(hostile)),
                None,
                "limit={hostile} would cast to a negative i64 in the SQL fast-path's LIMIT \
                 parameter; letting it through relies on SQLite's negative-LIMIT-means-unlimited \
                 convention instead of this function's own explicit unlimited fallback"
            );
        }
    }

    /// End-to-end proof that `list_sync` itself, not just the clamp helper, survives a
    /// `limit=u64::MAX` LIST: it must return the seeded objects, not an empty page.
    #[test]
    fn list_sync_limit_u64_max_returns_objects_not_an_empty_page() {
        let conn = Connection::open_in_memory().expect("conn");
        conn.execute_batch(
            "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
             revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
             CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL); \
             INSERT INTO meta (key, value) VALUES ('revision', '1'); \
             INSERT INTO objects (key, value, revision, ns, obj_name) VALUES \
             ('/registry/pods/default/foo', x'7b7d', 1, 'default', 'foo');",
        )
        .expect("schema");

        let resp = list_sync(
            &conn,
            "/registry/pods/",
            &ListOptions {
                limit: Some(u64::MAX),
                ..Default::default()
            },
        )
        .expect("list with limit=u64::MAX must not error");

        assert_eq!(
            resp.items.len(),
            1,
            "a client sending limit=u64::MAX (a hostile-but-plausible 'give me everything' \
             value) must get the seeded object back; before the fix the SQL fast-path's \
             `limit + 1` wraps to 0, producing `LIMIT 0` and an empty page forever"
        );
    }

    /// A freshly-created shard must not commit memory for slots no event has been pushed into
    /// yet.
    ///
    /// Why it matters: a conformance run creates dozens of shards (one per resource-type prefix
    /// touched), and most sit far below `RING_CAPACITY` for their entire lifetime — see
    /// `ring_capacity_is_pinned_to_512_and_evicts_oldest_first`'s doc for the measured
    /// justification of the constant. Eagerly reserving `RING_CAPACITY + 1` slots the instant a
    /// shard is created (rather than growing the ring as events actually arrive) commits that
    /// memory for every shard whether or not it is ever used, and it never shrinks back down —
    /// this fails on revert if `RingShard::new` goes back to
    /// `VecDeque::with_capacity(RING_CAPACITY + 1)`.
    #[test]
    fn fresh_ring_shard_does_not_preallocate_ring_capacity() {
        let shard = RingShard::new();
        let capacity = shard.ring.read().expect("ring poisoned").capacity();
        assert!(
            capacity < 100,
            "a brand-new shard's ring reserved {capacity} slots before a single event was \
             pushed into it (RING_CAPACITY is {RING_CAPACITY}); eager pre-allocation like this \
             commits dirty memory for every shard a conformance run creates, most of which \
             never come close to filling it"
        );
    }

    /// A write must reach exactly the shards whose prefix matches it — never a shard for a
    /// different namespace, and never a shard for a different resource type entirely.
    ///
    /// Why it matters: a mis-routed write means a watcher on the shard it should have reached
    /// silently misses the event (it never appears in that shard's ring, so a reconnecting watch
    /// never replays it), while a shard it should NOT have reached spuriously grows with events no
    /// watch on it will ever need. Both failure modes are silent — no error, just a watcher that
    /// never sees an update it was owed.
    #[test]
    fn matching_shards_write_reaches_every_prefix_match_and_nothing_else() {
        let mut shards: BTreeMap<String, Arc<RingShard>> = BTreeMap::new();
        shards.insert("/registry/pods/".into(), Arc::new(RingShard::new()));
        shards.insert("/registry/pods/default/".into(), Arc::new(RingShard::new()));
        // A different namespace's shard — must never match a "default" write.
        shards.insert(
            "/registry/pods/kube-system/".into(),
            Arc::new(RingShard::new()),
        );
        // A different resource type's shard — must never match a pods write.
        shards.insert("/registry/configmaps/".into(), Arc::new(RingShard::new()));

        let root = shard_key("/registry/pods/default/pod-a", Some("default"));
        let matched = matching_shards(&shards, &root, Some("default"));

        let mut matched_keys: Vec<&str> = matched.iter().map(|(k, _)| k.as_str()).collect();
        matched_keys.sort_unstable();
        assert_eq!(
            matched_keys,
            ["/registry/pods/", "/registry/pods/default/"],
            "a write to /registry/pods/default/pod-a must reach exactly the all-namespaces pods \
             shard and its own namespace's pods shard — routing it to the kube-system namespace \
             shard (wrong namespace) or the configmaps shard (wrong resource type), or dropping \
             the default shard match entirely, means some watcher silently misses the event"
        );
    }

    /// `matching_shards` must track the live shard set as watches open and close, not a snapshot
    /// taken once: a write after a new namespace-scoped watch opens must reach that watch's shard
    /// too, and a write after that shard is torn down (idle-GC) must stop reaching it.
    ///
    /// Why it matters: a mis-routed write here means either a newly-opened watch's ring never
    /// sees writes that happened after it opened (its owner silently stalls waiting for an event
    /// that already occurred), or a torn-down shard's Arc is kept alive and fed events forever,
    /// silently reintroducing the memory idle-GC was supposed to reclaim.
    #[test]
    fn matching_shards_reflects_shard_added_then_removed_between_writes() {
        let mut shards: BTreeMap<String, Arc<RingShard>> = BTreeMap::new();
        shards.insert("/registry/pods/".into(), Arc::new(RingShard::new()));
        let root = "/registry/pods/";

        // Before any namespace-scoped watch exists, only the root shard matches.
        let before: Vec<String> = matching_shards(&shards, root, Some("default"))
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            before,
            ["/registry/pods/"],
            "with no namespace-scoped shard yet, a write must match only the root shard"
        );

        // A namespace-scoped watch on "default" opens, creating its own shard.
        shards.insert("/registry/pods/default/".into(), Arc::new(RingShard::new()));
        let mut during: Vec<String> = matching_shards(&shards, root, Some("default"))
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        during.sort();
        assert_eq!(
            during,
            ["/registry/pods/", "/registry/pods/default/"],
            "a write after the namespace-scoped watch opens must reach BOTH shards, not just the \
             one that existed before it — otherwise the new watch's ring never sees writes that \
             happened after it opened"
        );

        // The namespace-scoped shard is torn down (idle-GC or CRD delete).
        shards.remove("/registry/pods/default/");
        let after: Vec<String> = matching_shards(&shards, root, Some("default"))
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            after,
            ["/registry/pods/"],
            "once the namespace-scoped shard is torn down, a later write must stop routing to it \
             — continuing to route to a removed shard would resurrect a stale Arc no live watch \
             can see, silently undoing the memory idle-GC was supposed to reclaim"
        );
    }

    /// `matching_shards` must stay fast regardless of how many unrelated shards exist store-wide
    /// — a real conformance run holds dozens of shards, one per resource type ever watched.
    ///
    /// Why it matters: this is a regression test for the O(shard-count) `.iter().filter(starts_with)`
    /// scan `matching_shards` used to run on every write. That scan's cost multiplies with both
    /// write rate and shard count — a linear cost applied to every single put/delete in the store.
    /// This asserts on wall-clock time rather than shard content because the whole point of the
    /// fix is CPU cost, not a different answer: a reverted linear scan returns the same matches,
    /// just after doing orders of magnitude more work to find them. Margins are generous (a
    /// two-`HashMap::get` lookup should take low single-digit milliseconds total) so this does not
    /// flake on a loaded CI runner, while still being far tighter than what a scan over tens of
    /// thousands of shards, run thousands of times, could ever complete within.
    #[test]
    fn matching_shards_stays_fast_with_many_unrelated_shards() {
        const DECOY_SHARDS: usize = 20_000;
        const WRITES: usize = 5_000;

        let mut shards: BTreeMap<String, Arc<RingShard>> = BTreeMap::new();
        for i in 0..DECOY_SHARDS {
            shards.insert(format!("/registry/decoy-{i}/"), Arc::new(RingShard::new()));
        }
        shards.insert("/registry/pods/".into(), Arc::new(RingShard::new()));
        shards.insert("/registry/pods/default/".into(), Arc::new(RingShard::new()));

        let root = "/registry/pods/";
        let started = std::time::Instant::now();
        for _ in 0..WRITES {
            let matched = matching_shards(&shards, root, Some("default"));
            assert_eq!(
                matched.len(),
                2,
                "sanity: must still find both real matches"
            );
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(300),
            "{WRITES} matching_shards calls against {DECOY_SHARDS} unrelated shards took \
             {elapsed:?}; an O(1) prefix lookup should complete this in low single-digit \
             milliseconds — this budget is only reachable by a linear starts_with scan if that \
             O(shard-count) cost has been reintroduced"
        );
    }

    /// `find_shard`/`find_shard_key` must resolve to the exact shard a watch's own prefix already
    /// has, fall back to the broader resource-type root only when it doesn't, and stop resolving
    /// to a shard the instant it is torn down.
    ///
    /// Why it matters: `SqliteStore::watch` uses these to decide whether to reuse an existing
    /// shard's retained history or start a brand-new (empty) one — a mis-resolve either throws
    /// away real history a watch should have inherited, or hands back a torn-down shard's stale
    /// `Arc` that no live watcher can see events through.
    #[test]
    fn find_shard_resolves_exact_then_falls_back_to_parent_across_add_and_remove() {
        let mut shards: BTreeMap<String, Arc<RingShard>> = BTreeMap::new();
        let root_prefix = "/registry/pods/";
        let ns_prefix = "/registry/pods/default/";

        assert!(
            find_shard(&shards, root_prefix).is_none(),
            "no shard exists yet — must not conjure one"
        );
        assert!(find_shard(&shards, ns_prefix).is_none());

        // An all-namespaces watch opens first, creating the root shard.
        let root_shard = Arc::new(RingShard::new());
        shards.insert(root_prefix.to_string(), Arc::clone(&root_shard));

        // A namespace-scoped watch on "default" has no shard of its own yet, so it must fall
        // back to the broader root shard rather than reporting "nothing exists".
        let (key, shard) =
            find_shard_key(&shards, ns_prefix).expect("root shard must be reused as fallback");
        assert_eq!(
            key, root_prefix,
            "the fallback's own key must be reported, not ns_prefix"
        );
        assert!(Arc::ptr_eq(&shard, &root_shard));

        // Its own, more specific shard is created afterward and must now take priority over the
        // broader root — reusing the root here would wrongly seed the ns watch off the root's
        // history instead of its own namespace-scoped shard.
        let ns_shard = Arc::new(RingShard::new());
        shards.insert(ns_prefix.to_string(), Arc::clone(&ns_shard));
        let (key, shard) = find_shard_key(&shards, ns_prefix).expect("ns shard now exists");
        assert_eq!(
            key, ns_prefix,
            "the exact ns match must win over the shorter root match"
        );
        assert!(Arc::ptr_eq(&shard, &ns_shard));

        // Tearing the ns shard down again must fall back to the root, not vanish or resurrect a
        // stale Arc for the removed entry.
        shards.remove(ns_prefix);
        assert!(
            Arc::ptr_eq(
                &find_shard(&shards, ns_prefix).expect("must fall back to root after removal"),
                &root_shard
            ),
            "once the ns shard is torn down, a later lookup must fall back to the root again — \
             continuing to resolve the removed key would be a use-after-teardown bug"
        );
    }

    /// `find_shard` must stay fast regardless of how many unrelated shards exist store-wide —
    /// every open watch calls it, so a real conformance run's dozens of live shards must not
    /// turn watch-open into a linear scan.
    ///
    /// Fails on revert: without the exact/parent two-key lookup, this reverts to the
    /// `.iter().filter(starts_with).max_by_key` scan `find_shard` used to run, whose cost scales
    /// with total shard count regardless of which resource type is being looked up.
    #[test]
    fn find_shard_stays_fast_with_many_unrelated_shards() {
        const DECOY_SHARDS: usize = 20_000;
        const LOOKUPS: usize = 5_000;

        let mut shards: BTreeMap<String, Arc<RingShard>> = BTreeMap::new();
        for i in 0..DECOY_SHARDS {
            shards.insert(format!("/registry/decoy-{i}/"), Arc::new(RingShard::new()));
        }
        shards.insert("/registry/pods/".into(), Arc::new(RingShard::new()));

        let ns_prefix = "/registry/pods/default/";
        let started = std::time::Instant::now();
        for _ in 0..LOOKUPS {
            assert!(
                find_shard(&shards, ns_prefix).is_some(),
                "sanity: must still find the root as a fallback match"
            );
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(300),
            "{LOOKUPS} find_shard calls against {DECOY_SHARDS} unrelated shards took {elapsed:?}; \
             an O(1) lookup should complete this in low single-digit milliseconds — this budget \
             is only reachable by a linear starts_with scan if that O(shard-count) cost has been \
             reintroduced"
        );
    }

    /// `evict_resource_type` must tear down EVERY shard rooted at a resource type, however many
    /// distinct namespaces happen to have their own shard for it — not just the first one, or a
    /// fixed small number.
    ///
    /// Why it matters: nothing stops separate watches on different namespaces of the same CRD
    /// from each getting their own shard entry (see `SqliteStore::watch`'s create-on-first-watch
    /// path). A CRD-delete eviction that only checked a fixed, small set of candidate keys — the
    /// same trick `find_shard`/`find_shard_key` use, which works there only because THEY are
    /// given one already-known namespace to check — would silently leave every namespace past
    /// the first one live: a deleted resource type's watch history would keep pinning ring
    /// memory forever, and a reconnecting watch on one of those stray shards would wrongly
    /// replay instead of getting the 410 Gone a deleted type must always return.
    #[tokio::test]
    async fn evict_resource_type_removes_every_namespace_scoped_shard_not_just_one() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let root = "/registry/widgets.example.com/widgets/";

        for ns in ["default", "kube-system", "tenant-a"] {
            let prefix = format!("{root}{ns}/");
            drop(
                store
                    .watch(&prefix, 0)
                    .await
                    .expect("namespace watch must succeed"),
            );
        }
        drop(
            store
                .watch(root, 0)
                .await
                .expect("cluster-scoped watch must succeed"),
        );

        assert_eq!(
            store.shards.read().expect("shards poisoned").len(),
            4,
            "sanity check on test setup: four distinct shards (root + 3 namespaces) must exist \
             before eviction runs"
        );

        store.evict_resource_type(root);

        assert!(
            store.shards.read().expect("shards poisoned").is_empty(),
            "every shard for this resource type — the root and all three namespace variants — \
             must be gone after eviction; any left behind pin ring memory forever and let a \
             reconnecting watcher on that stray shard replay instead of getting 410 Gone"
        );
    }

    /// `evict_resource_type` must stay fast regardless of how many OTHER resource types have
    /// live shards — a CRD delete must not pay for every other type's shard in the store just to
    /// find the handful (or one) that actually belong to the type being deleted.
    ///
    /// Fails on revert: without the `BTreeMap::range` prefix-seek, this reverts to the
    /// `.keys().filter(starts_with)` scan `evict_resource_type` used to run over the WHOLE
    /// `shards` map, whose cost scales with total shard count across every resource type in the
    /// store, not just the one being deleted.
    #[tokio::test]
    async fn evict_resource_type_stays_fast_with_many_unrelated_shards() {
        const DECOY_SHARDS: usize = 20_000;
        const EVICTIONS: usize = 5_000;

        let store = SqliteStore::new(":memory:").expect("in-memory store");
        {
            let mut guard = store.shards.write().expect("shards poisoned");
            for i in 0..DECOY_SHARDS {
                guard.insert(format!("/registry/decoy-{i}/"), Arc::new(RingShard::new()));
            }
        }
        let root = "/registry/widgets.example.com/widgets/";

        // Re-inserted before each call (evict_resource_type removes it every time) so the loop
        // amplifies the per-call scan cost the same way the matching_shards perf test amplifies
        // its own O(1)-vs-O(shard-count) lookup, instead of measuring a single call whose cost
        // is too small in absolute terms to distinguish O(1) from O(shard-count) reliably.
        let started = std::time::Instant::now();
        for _ in 0..EVICTIONS {
            store
                .shards
                .write()
                .expect("shards poisoned")
                .insert(root.to_string(), Arc::new(RingShard::new()));
            store.evict_resource_type(root);
        }
        let elapsed = started.elapsed();

        assert!(
            !store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(root),
            "sanity: the targeted shard must actually be gone after the final eviction"
        );
        assert!(
            elapsed < Duration::from_millis(300),
            "{EVICTIONS} evict_resource_type calls against {DECOY_SHARDS} unrelated shards took \
             {elapsed:?}; a BTreeMap range-seek should complete this in low single-digit \
             milliseconds — this budget is only reachable by a linear starts_with scan over \
             every shard in the store if that O(shard-count) cost has been reintroduced"
        );
    }

    /// The ring buffer must cap at exactly RING_CAPACITY entries and advance
    /// compaction_horizon to the revision of the new oldest entry every time it evicts.
    ///
    /// Why it matters: this invariant is what makes `RING_CAPACITY` mean anything at all, and it
    /// matters more the smaller that constant gets — at 512 the ring turns over continuously
    /// (11 shards sat at the cap for most of a conformance run), so eviction is the steady state
    /// rather than an edge case. If a future change to `push_event_locked` let the ring grow
    /// past RING_CAPACITY unboundedly, memory would grow without bound on a long-running
    /// server; if eviction fired but `compaction_horizon` failed to advance to match, watchers
    /// requesting an already-evicted resourceVersion would silently replay from a
    /// too-generous horizon instead of getting an immediate HTTP 410, and would miss events
    /// that were actually dropped.
    #[tokio::test]
    async fn ring_buffer_caps_at_ring_capacity_and_advances_horizon_on_evict() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Push exactly RING_CAPACITY + 1 events so eviction fires exactly once, on the final
        // push. Revisions are assigned 1..=RING_CAPACITY+1 in insertion order.
        for i in 0..=RING_CAPACITY as u64 {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/configmaps/default/cm-{i}"),
                    revision: i + 1,
                    value: Some(svc_value(&format!("cm-{i}"), i + 1)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        {
            let shard =
                store.shard_for_test("/registry/core/configmaps/default/cm-0", Some("default"));
            let guard = shard.ring.read().expect("ring poisoned");
            assert_eq!(
                guard.len(),
                RING_CAPACITY,
                "ring must cap at exactly RING_CAPACITY entries after RING_CAPACITY+1 pushes; \
                 growing past this means the RING_CAPACITY-entry retention budget (and its \
                 accompanying memory estimate, see the constant's doc comment) no longer holds, \
                 and the ring would grow unboundedly on a \
                 long-running server"
            );
        }

        assert_eq!(
            store.compaction_horizon(),
            2,
            "evicting the oldest entry (revision=1) must advance compaction_horizon to the \
             revision of the new oldest entry (revision=2); a stale horizon would let a watcher \
             request a resourceVersion whose event was actually evicted from the ring, causing \
             it to silently miss events instead of getting an immediate HTTP 410 telling it to \
             relist"
        );
    }

    /// RING_CAPACITY is 512, sized directly from `u7s_watch_replay_depth` rather than from a
    /// retention window: across a full conformance run the deepest replay any client actually
    /// needed was 25 events (2,359 watch opens, mean 0.10), and 512 clears that by ~20x. The
    /// run at 512 recorded zero revision-expiry 410s, zero compacted closes and zero Lagged
    /// recoveries, at 82 MB peak apiserver RSS versus 137 MB at the former 10_000.
    ///
    /// Why it matters: `ring_buffer_caps_at_ring_capacity_and_advances_horizon_on_evict` above
    /// asserts eviction purely in terms of the `RING_CAPACITY` symbol, so it passes unchanged
    /// no matter what value the constant holds — it cannot catch a drift back up toward 10_000
    /// or 100_000, which costs tens of MB of retained events for history nothing was ever
    /// measured asking for. This test pins the concrete value and independently confirms
    /// eviction drops exactly the overflow amount, oldest-first.
    #[tokio::test]
    async fn ring_capacity_is_pinned_to_512_and_evicts_oldest_first() {
        assert_eq!(
            RING_CAPACITY, 512,
            "RING_CAPACITY must stay at the measured-and-justified 512; if this fails, someone \
             changed the constant without updating this pinned assertion. Before adjusting it, \
             confirm the new value against a fresh u7s_watch_replay_depth capture — and note \
             that capture is only valid at a capacity where the shard never fills, since a \
             full ring censors the very tail being sized against"
        );

        let store = SqliteStore::new(":memory:").expect("in-memory store");

        const OVERFLOW: u64 = 100;
        for i in 0..(RING_CAPACITY as u64 + OVERFLOW) {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/configmaps/default/cm-{i}"),
                    revision: i + 1,
                    value: Some(svc_value(&format!("cm-{i}"), i + 1)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        let shard = store.shard_for_test("/registry/core/configmaps/default/cm-0", Some("default"));
        let guard = shard.ring.read().expect("ring poisoned");
        assert_eq!(
            guard.len(),
            RING_CAPACITY,
            "pushing RING_CAPACITY + 100 events must leave the ring at exactly RING_CAPACITY \
             entries — anything more means the reduced 10k cap no longer bounds memory as \
             intended"
        );
        assert_eq!(
            guard
                .front()
                .expect("ring must not be empty after pushes")
                .revision,
            OVERFLOW + 1,
            "the oldest surviving entry must be revision 101 — the first 100 pushed events \
             (revisions 1..=100) must have been evicted to make room; a lower revision here \
             means eviction fired too few times, silently growing the ring past its cap"
        );
    }

    /// deletion_log must NOT retain a tombstone after the deleted key is re-created via PUT.
    ///
    /// Why it matters: keeping a DELETED tombstone for a live key causes a watcher reconnecting
    /// after compaction to receive a spurious DELETED event for the current (live) incarnation
    /// of the key, making controllers believe the object was deleted and stop reconciling —
    /// an unbounded deletion_log also leaks one Arc<InternalEvent> (full object body) per
    /// ever-deleted key, growing without bound on a long-running server.
    #[tokio::test]
    async fn deletion_log_evicts_tombstone_on_recreate() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/namespaces/ns-a";
        let val =
            Bytes::from(r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-a"}}"#);

        // A shard (and therefore a deletion_log) now exists only once something watches this
        // resource type (see push_event_locked's doc) — held for the whole test so the shard
        // this test inspects below isn't idle-GC'd out from under it.
        let _watch = store
            .watch("/registry/core/namespaces/", 0)
            .await
            .expect("watch must succeed");

        // Create, then delete the key — tombstone enters deletion_log.
        store
            .put(key, val.clone(), None)
            .await
            .expect("put must succeed");
        store.delete(key, None).await.expect("delete must succeed");

        {
            let shard = store.shard_for_test(key, None);
            let guard = shard.deletion_log.read().expect("deletion_log poisoned");
            assert!(
                guard.by_key.contains_key(key),
                "deletion_log must contain tombstone for deleted key; test setup broken"
            );
        }

        // Re-create the key via PUT — tombstone must be evicted.
        store
            .put(key, val, None)
            .await
            .expect("recreate must succeed");

        {
            let shard = store.shard_for_test(key, None);
            let guard = shard.deletion_log.read().expect("deletion_log poisoned");
            assert!(
                !guard.by_key.contains_key(key),
                "deletion_log must NOT retain tombstone after key is re-created; retaining it \
                 causes watchers reconnecting after compaction to receive a spurious DELETED event \
                 for the live object, making controllers stop reconciling the re-created resource"
            );
        }
    }

    /// A deletion must record the tombstone's exact body size into
    /// `u7s_deletion_log_body_size_bytes`, by shard — the measurement a data-driven two-tier
    /// deletion_log tier-cap design needs to replace the estimated 1-6KB tombstone-size
    /// assumption it would otherwise be sized against with a real one. Fails on revert if
    /// `push_into_shard`'s `.observe()` call in the deletion branch were removed: the histogram
    /// would gain neither a sample nor any bytes for this delete, leaving `after` equal to
    /// `before` on both counts.
    #[tokio::test]
    async fn deletion_log_body_size_metric_observes_deleted_body_length() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        // A resource-type prefix unique to this test (not shared with any other test in this
        // file) — DELETION_LOG_BODY_SIZE_BYTES is a process-global Prometheus registry, so a
        // shared shard label would let another test's concurrent delete land an extra
        // observation between this test's before/after reads and make the exact-delta
        // assertion flaky under `cargo test`'s default parallel execution.
        let key = "/registry/deletion-log-body-size-metric-test/obj-1";
        let val = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-body-size"}}"#,
        );

        // A shard exists only once something watches this resource type (see
        // push_event_locked's doc) — held for the whole test so it isn't idle-GC'd.
        let _watch = store
            .watch("/registry/deletion-log-body-size-metric-test/", 0)
            .await
            .expect("watch must succeed");

        let shard_label = "/registry/deletion-log-body-size-metric-test/";
        let before_count = crate::metrics::DELETION_LOG_BODY_SIZE_BYTES
            .with_label_values(&[shard_label])
            .get_sample_count();
        let before_sum = crate::metrics::DELETION_LOG_BODY_SIZE_BYTES
            .with_label_values(&[shard_label])
            .get_sample_sum();

        store
            .put(key, val.clone(), None)
            .await
            .expect("put must succeed");
        store.delete(key, None).await.expect("delete must succeed");

        // The store round-trips the body through its own serialization before persisting (e.g.
        // stamping metadata.resourceVersion), so the tombstone's actual retained size can differ
        // from `val`'s literal length — read the real stored tombstone back instead of assuming
        // the input's byte count survives unchanged.
        let expected_len = {
            let shard = store.shard_for_test(key, None);
            let guard = shard.deletion_log.read().expect("deletion_log poisoned");
            match guard.by_key.get(key) {
                Some(DeletionLogEntry::Full(event)) => event
                    .deleted_body
                    .as_ref()
                    .expect("a real deletion must carry a deleted_body")
                    .len() as f64,
                other => panic!(
                    "tombstone for the just-deleted key must exist and still be in the Full \
                     tier (a single delete never crosses the Full-tier cap); got {other:?}"
                ),
            }
        };

        let after_count = crate::metrics::DELETION_LOG_BODY_SIZE_BYTES
            .with_label_values(&[shard_label])
            .get_sample_count();
        let after_sum = crate::metrics::DELETION_LOG_BODY_SIZE_BYTES
            .with_label_values(&[shard_label])
            .get_sample_sum();

        assert_eq!(
            after_count,
            before_count + 1,
            "deleting a key must record exactly one body-size observation for its shard; \
             before={before_count} after={after_count}"
        );
        assert_eq!(
            after_sum - before_sum,
            expected_len,
            "the recorded observation must equal the deleted object's exact byte length \
             ({expected_len}); a mismatch means the histogram is observing the wrong field \
             (e.g. the live value instead of deleted_body) or a stale/truncated body"
        );
    }

    /// deletion_log must retain tombstones for recently-deleted keys that have not been
    /// re-created, so a watcher reconnecting after compaction still receives DELETED events.
    ///
    /// Why it matters: evicting too aggressively drops DELETED events a watcher needs —
    /// a watcher that reconnects after the ring is compacted relies on deletion_log to
    /// receive tombstones for objects deleted during the compaction window; without them
    /// the watcher deadlocks waiting for a DELETED event that never arrives.
    #[tokio::test]
    async fn deletion_log_retains_tombstone_for_deleted_key_not_recreated() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // A shard (and therefore a deletion_log) now exists only once something watches this
        // resource type (see push_event_locked's doc) — held for the whole test so the shard
        // this test inspects below isn't idle-GC'd out from under it.
        let _watch = store
            .watch("/registry/core/namespaces/", 0)
            .await
            .expect("watch must succeed");

        // Delete several keys without re-creating them — all tombstones must survive.
        for i in 0..5u32 {
            let key = format!("/registry/core/namespaces/ns-{i}");
            let val = Bytes::from(format!(
                r#"{{"apiVersion":"v1","kind":"Namespace","metadata":{{"name":"ns-{i}"}}}}"#
            ));
            store.put(&key, val, None).await.expect("put must succeed");
            store.delete(&key, None).await.expect("delete must succeed");
        }

        // Perform additional writes (non-deletions) that do NOT touch the deleted keys.
        for i in 0..10u32 {
            let key = format!("/registry/core/configmaps/default/cm-{i}");
            let val = Bytes::from(format!(
                r#"{{"apiVersion":"v1","kind":"ConfigMap","metadata":{{"name":"cm-{i}","namespace":"default"}}}}"#
            ));
            store.put(&key, val, None).await.expect("put must succeed");
        }

        let shard = store.shard_for_test("/registry/core/namespaces/ns-0", None);
        let guard = shard.deletion_log.read().expect("deletion_log poisoned");
        for i in 0..5u32 {
            let key = format!("/registry/core/namespaces/ns-{i}");
            assert!(
                guard.by_key.contains_key(&key),
                "deletion_log must retain tombstone for ns-{i} (not re-created); evicting it \
                 would cause a reconnecting watcher to miss the DELETED event, deadlocking any \
                 controller waiting for the namespace deletion to complete"
            );
        }
    }

    /// Once a shard's Full-tier tombstone count exceeds RING_CAPACITY, the lowest-revision
    /// Full entry must be DOWNGRADED to Stripped (revision-only) — not evicted outright, and
    /// not left as Full forever.
    ///
    /// Why it matters: this downgrade is the entire memory-saving mechanism of the two-tier
    /// deletion_log design. If it silently stopped firing, every tombstone would stay
    /// full-body forever — reverting to the old flat, unbounded-per-tombstone-cost behavior,
    /// without any other test noticing (the entry would still be present in `by_key`, so
    /// evict-on-recreate and retain-until-recreated tests would keep passing). This test
    /// fails on that exact revert: with the downgrade step disabled,
    /// `guard.by_key.get(&victim_key)` still matches `Some(DeletionLogEntry::Full(_))` instead
    /// of `Stripped`, hitting the `panic!` branch below instead of the assertions.
    #[tokio::test]
    async fn deletion_log_downgrades_to_stripped_once_full_tier_cap_exceeded() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let victim_key = "/registry/core/namespaces/full-tier-victim".to_string();

        // The victim's own tombstone, at the lowest revision in this test.
        store.push_event(
            Arc::new(InternalEvent {
                key: victim_key.clone(),
                revision: 0,
                value: None,
                is_create: false,
                deleted_body: None,
            }),
            None,
        );

        // Push RING_CAPACITY more tombstones (all at higher revisions, well under
        // STRIPPED_TIER_CAP so outright eviction never fires in this test) so the Full tier
        // exceeds its cap exactly once, on the final insert, downgrading the victim — the
        // lowest-revision Full entry — to Stripped.
        for i in 0..RING_CAPACITY {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/namespaces/ns-{i}"),
                    revision: (i as u64) + 1,
                    value: None,
                    is_create: false,
                    deleted_body: None,
                }),
                None,
            );
        }

        let shard = store.shard_for_test(&victim_key, None);
        let guard = shard.deletion_log.read().expect("deletion_log poisoned");
        assert!(
            guard.by_key.contains_key(&victim_key),
            "downgrading to Stripped must NOT remove the key — a reconnecting watcher still \
             needs to know this key was deleted, just without the body"
        );
        match guard.by_key.get(&victim_key) {
            Some(DeletionLogEntry::Stripped { revision }) => assert_eq!(
                *revision, 0,
                "a downgraded entry must keep its original revision — replay's last_replayed \
                 tracking and eviction ordering both depend on it staying accurate"
            ),
            other => panic!(
                "the lowest-revision Full tombstone must be downgraded to Stripped once \
                 RING_CAPACITY newer deletions land; got {other:?} instead of Stripped"
            ),
        }
    }

    /// Outright eviction at the Stripped tier's cap must remove the tombstone with the
    /// globally lowest revision — not the first-inserted, last-inserted, or
    /// HashMap-iteration-order entry.
    ///
    /// Why it matters: eviction is driven by a `by_revision: BTreeMap<u64, String>`
    /// auxiliary index (`pop_first()`) instead of an O(n) `.iter().min_by_key()` scan over
    /// `by_key`, so the O(n) scan no longer runs while every concurrent writer is blocked on
    /// the global write lock. If that index were ever built from insertion order instead of
    /// `event.revision`, eviction would remove the wrong tombstone: an active watcher could
    /// lose the DELETED event for an object it is still waiting on (deadlock), while a
    /// tombstone for a key deleted long ago and needed by no one keeps consuming memory.
    ///
    /// This test plants the lowest-revision tombstone in the MIDDLE of the insertion
    /// sequence (not first or last), so it only passes if eviction genuinely orders by
    /// revision rather than by insertion order. It pushes past `STRIPPED_TIER_CAP` (not just
    /// the smaller Full-tier cap), so by the time eviction fires every survivor has already
    /// been downgraded to Stripped — this is the "Stripped tombstone evicted at
    /// STRIPPED_TIER_CAP" case the two-tier design's eviction policy must still get right.
    #[tokio::test]
    async fn deletion_log_eviction_evicts_lowest_revision_not_insertion_order() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        const STRIPPED_TIER_CAP: usize = 2 * RING_CAPACITY;
        let victim_key = "/registry/core/namespaces/victim".to_string();

        // Insert STRIPPED_TIER_CAP + 1 tombstones so the cap is exceeded exactly once, on
        // the final insert. The victim gets the lowest revision (0) but is inserted at the
        // MIDDLE index — an insertion-order-based (or desynced) eviction would pick a
        // different key.
        for i in 0..=STRIPPED_TIER_CAP {
            let (key, revision) = if i == STRIPPED_TIER_CAP / 2 {
                (victim_key.clone(), 0)
            } else {
                (format!("/registry/core/namespaces/ns-{i}"), (i as u64) + 1)
            };
            store.push_event(
                Arc::new(InternalEvent {
                    key,
                    revision,
                    value: None,
                    is_create: false,
                    deleted_body: None,
                }),
                None,
            );
        }

        let shard = store.shard_for_test(&victim_key, None);
        let guard = shard.deletion_log.read().expect("deletion_log poisoned");
        assert_eq!(
            guard.by_key.len(),
            STRIPPED_TIER_CAP,
            "deletion_log must shrink back to the cap after exactly one entry is evicted"
        );
        assert!(
            !guard.by_key.contains_key(&victim_key),
            "eviction must remove the globally lowest-revision tombstone (revision=0, planted \
             mid-sequence); if eviction instead used insertion order or a desynced index, a \
             different (wrong) tombstone would be evicted and this one would incorrectly survive"
        );
    }

    /// STRIPPED_TIER_CAP must stay at 2x RING_CAPACITY, not the old 8x: a full conformance
    /// run's busiest shard peaked at 870 live tombstones, so the extra 6x of cap bought
    /// ~656KB of pure index overhead per saturated shard that no real cluster traffic used.
    ///
    /// This test pushes exactly `2 * RING_CAPACITY + 1` tombstones — enough to trigger one
    /// eviction under the current (2x) cap, but nowhere near a reverted 8x cap. It fails on
    /// that revert: with an 8x cap, none of these inserts would evict anything, so the log
    /// would still hold all 1025 entries instead of having shrunk back to 1024.
    #[tokio::test]
    async fn deletion_log_stripped_tier_cap_is_bounded_at_two_times_ring_capacity() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key_prefix = "/registry/core/pods/";

        for i in 0..=(2 * RING_CAPACITY) {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("{key_prefix}pod-{i}"),
                    revision: i as u64,
                    value: None,
                    is_create: false,
                    deleted_body: None,
                }),
                None,
            );
        }

        let shard = store.shard_for_test(&format!("{key_prefix}pod-0"), None);
        let guard = shard.deletion_log.read().expect("deletion_log poisoned");
        assert_eq!(
            guard.by_key.len(),
            2 * RING_CAPACITY,
            "deletion_log must have evicted its oldest entry once it crossed 2x RING_CAPACITY \
             (={}); a length of {} instead means STRIPPED_TIER_CAP regressed back toward the \
             old, memory-wasteful 8x sizing that no measured shard's traffic ever needed",
            2 * RING_CAPACITY,
            2 * RING_CAPACITY + 1
        );
    }

    /// The evict-on-recreate path must remove a tombstone's entry from `by_key`, the
    /// `by_revision` index, AND `full_revisions` — not just `by_key`.
    ///
    /// Why it matters: eviction walks `by_revision` to find the lowest-revision victim in
    /// O(log n) (`pop_first()`). If evict-on-recreate only cleared `by_key` (forgetting
    /// `by_revision`), a stale revision->key entry for the recreated key would linger in
    /// `by_revision` forever at its old, no-longer-valid revision. Because that revision is
    /// typically far lower than any still-tombstoned key, the next cap eviction would keep
    /// picking that stale entry: `by_key.remove` on it would be a no-op, so the log would
    /// never actually shrink back under the cap (unbounded growth), and the real
    /// lowest-revision tombstone — which a reconnecting watcher may still need — would
    /// incorrectly survive instead of being evicted.
    #[tokio::test]
    async fn deletion_log_recreate_keeps_revision_index_in_sync_with_later_eviction() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let recreated_key = "/registry/core/namespaces/recreate-me".to_string();

        // 1. Tombstone "recreate-me" at the lowest possible revision (0).
        store.push_event(
            Arc::new(InternalEvent {
                key: recreated_key.clone(),
                revision: 0,
                value: None,
                is_create: false,
                deleted_body: None,
            }),
            None,
        );

        // 2. Recreate it — must evict the tombstone from both by_key and by_revision.
        store.push_event(
            Arc::new(InternalEvent {
                key: recreated_key.clone(),
                revision: 1,
                value: Some(Bytes::from(
                    r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"recreate-me"}}"#,
                )),
                is_create: true,
                deleted_body: None,
            }),
            None,
        );

        // 3. Push STRIPPED_TIER_CAP + 1 fresh tombstones, all at revisions strictly above the
        // stale revision=0 left behind by step 1 if the index were desynced. The lowest
        // revision among this fresh batch (revision=2, key "ns-0") is what a correctly
        // synced index must evict when the cap is exceeded on the final insert.
        const STRIPPED_TIER_CAP: usize = 2 * RING_CAPACITY;
        let true_victim = "/registry/core/namespaces/ns-0".to_string();
        for i in 0..=STRIPPED_TIER_CAP {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/namespaces/ns-{i}"),
                    revision: (i as u64) + 2,
                    value: None,
                    is_create: false,
                    deleted_body: None,
                }),
                None,
            );
        }

        let shard = store.shard_for_test(&true_victim, None);
        let guard = shard.deletion_log.read().expect("deletion_log poisoned");
        assert_eq!(
            guard.by_key.len(),
            STRIPPED_TIER_CAP,
            "deletion_log must shrink back to the cap after the cap-triggering insert; a stale \
             by_revision entry left behind by evict-on-recreate would make eviction a no-op \
             (removing a key that no longer exists in by_key), leaving the log permanently over \
             cap and growing without bound"
        );
        assert!(
            !guard.by_key.contains_key(&true_victim),
            "eviction must remove the tombstone with the lowest CURRENT revision (ns-0, \
             revision=2); if the recreate path left a stale, lower revision->key entry in \
             by_revision, eviction would instead try to evict the already-gone recreated key \
             (a no-op) and this tombstone would incorrectly survive"
        );
        assert!(
            !guard.by_key.contains_key(&recreated_key),
            "the recreated key must never re-appear as a tombstone in deletion_log; it is live"
        );
    }

    /// Batch namespace delete must emit a distinct watch DELETED event per object.
    ///
    /// Why it matters: before the fix, delete_namespace_sync incremented the global revision
    /// counter ONCE for the entire batch, so every deleted object shared the same revision.
    /// push_event broadcast N DELETED events all at the same rv. The watch stream's dedup check
    /// (`event.revision <= last_replayed`) yielded the first event (advancing last_replayed to
    /// that rv) and silently dropped every subsequent event at the same rv. Controllers watching
    /// /registry/endpoints/ received only ONE of the N endpoint DELETED events; their informer
    /// caches retained stale copies of the others. On the next reconcile the controller PUT
    /// with the stale rv, got 409 (object deleted → stored=0), and looped forever
    /// (EndpointSlice conformance failure).
    ///
    /// This test MUST fail if the per-object-revision change is reverted: shared rv → dedup
    /// drops all but the first DELETED event → watcher receives < N deletes → assert fails.
    #[tokio::test]
    async fn batch_namespace_delete_emits_distinct_watch_event_per_object() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let namespace = "endpointslice-test";

        // Subscribe BEFORE the creates: a shard (and therefore ring replay) now exists only
        // once something watches its resource type (see push_event_locked's doc), so unlike
        // before this test can no longer rely on replaying pre-watch writes from the ring —
        // it must observe them live instead, exactly as a real client-go informer's
        // LIST-then-WATCH would (the LIST call, not ring replay, is what covers objects that
        // existed before the WATCH opened).
        let prefix = format!("/registry/endpoints/{namespace}/");
        let stream = store.watch(&prefix, 0).await.expect("watch must succeed");
        futures_util::pin_mut!(stream);

        // Create 3 objects under /registry/endpoints/<namespace>/ to simulate the endpoints
        // the EndpointSlice controller creates for services in the namespace.
        let keys = [
            format!("/registry/endpoints/{namespace}/svc-a"),
            format!("/registry/endpoints/{namespace}/svc-b"),
            format!("/registry/endpoints/{namespace}/svc-c"),
        ];
        for key in &keys {
            let name = key.rsplit('/').next().unwrap_or("obj");
            let val = Bytes::from(format!(
                r#"{{"apiVersion":"v1","kind":"Endpoints","metadata":{{"name":"{name}","namespace":"{namespace}"}}}}"#
            ));
            store.put(key, val, None).await.expect("put must succeed");
        }

        // Consume the 3 live Added events emitted by the creates above.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let mut added_count = 0usize;
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Added(_))) => added_count += 1,
                Ok(Some(WatchEvent::Bookmark { .. })) => {}
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
            if added_count == keys.len() {
                break;
            }
        }
        assert_eq!(
            added_count,
            keys.len(),
            "watch must deliver Added for all {} pre-existing objects before the delete test begins",
            keys.len()
        );

        // Delete the namespace — this calls delete_namespace_resources internally.
        store
            .delete_namespace_resources(namespace)
            .await
            .expect("delete_namespace_resources must succeed");

        // Collect DELETED events for a short window. Each of the 3 objects must produce its own
        // DELETED event. If any share a revision, the dedup check drops all but the first and
        // the controller never learns about the others.
        let mut deleted_keys: Vec<String> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Deleted { key, .. })) => deleted_keys.push(key),
                Ok(Some(WatchEvent::Bookmark { .. })) => {}
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
            if deleted_keys.len() == keys.len() {
                break;
            }
        }

        assert_eq!(
            deleted_keys.len(),
            keys.len(),
            "batch namespace delete must emit a distinct watch event per object, else controllers \
             miss deletes and wedge in a 409-loop (EndpointSlice conformance); got {} DELETED \
             events, expected {}; missing: {:?}",
            deleted_keys.len(),
            keys.len(),
            keys.iter()
                .filter(|k| !deleted_keys.contains(k))
                .collect::<Vec<_>>(),
        );
        for key in &keys {
            assert!(
                deleted_keys.contains(key),
                "batch namespace delete must deliver DELETED event for {key}; a missing event \
                 leaves the controller's informer cache stale — the controller PUTs with the old \
                 rv, gets 409, and loops forever (EndpointSlice conformance failure)"
            );
        }
    }

    /// Concurrent writes to DIFFERENT keys under the SAME watch prefix must never cause a
    /// watcher to silently drop one of them.
    ///
    /// Why it matters: `put`/`delete` assign each write's revision under `write_conn`'s
    /// mutex (serialized), but the specific event's broadcast used to happen in the async
    /// continuation AFTER that mutex was released — unserialized across concurrent writers.
    /// The tokio scheduler does not guarantee a lower-revision writer's continuation resumes
    /// and broadcasts before a higher-revision writer's does. If a higher-revision event on
    /// the same prefix reaches a watcher first, `last_replayed` jumps ahead and the
    /// lower-revision event is silently dedup-skipped when it finally arrives. This is
    /// exactly how sonobuoy's "lifecycle of a Deployment" test's own DeleteCollection DELETED
    /// event could vanish under real conformance-suite write concurrency (many unrelated
    /// Deployment/ReplicaSet writes racing on the same prefix): the DELETE's own event
    /// arrived after another same-prefix write's higher revision had already been broadcast.
    ///
    /// The fix broadcasts from inside the `spawn_blocking` closure while still holding
    /// `write_conn`'s guard, so broadcast order structurally matches revision-assignment
    /// order — closing the race rather than relying on scheduling luck.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_same_prefix_writes_never_drop_a_watch_event() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let prefix = "/registry/deployments/race-ns/";

        // Subscribe before any writes so every write is observed as a live event.
        let stream = store.watch(prefix, 0).await.expect("watch must succeed");
        futures_util::pin_mut!(stream);

        const N: usize = 300;
        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let store = Arc::clone(&store);
            let key = format!("{prefix}dep-{i}");
            handles.push(tokio::spawn(async move {
                let val = Bytes::from(format!(
                    r#"{{"apiVersion":"apps/v1","kind":"Deployment","metadata":{{"name":"dep-{i}","namespace":"race-ns"}}}}"#
                ));
                store.put(&key, val, None).await.expect("put must succeed");
            }));
        }
        for h in handles {
            h.await.expect("writer task must not panic");
        }

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while seen.len() < N {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Added(obj))) => {
                    seen.insert(obj.key.clone());
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        assert_eq!(
            seen.len(),
            N,
            "all {N} concurrent same-prefix writes must be observed by the watcher; a \
             missing key means its event was dedup-skipped because an unrelated, \
             later-broadcast, higher-revision event on the same prefix advanced \
             last_replayed past it before it arrived (missing {} of {N})",
            N - seen.len()
        );
    }

    // Regression tests: Store::put must suppress no-op writes so kubelet's routine, unchanged
    // status re-PATCHes (every 10s, for every pod, forever) don't flood every watcher in the
    // cluster with phantom MODIFIED events — `kubectl get pods -w` must stay quiet for a
    // steady pod, matching real kube-apiserver's etcd3 GuaranteedUpdate byte-equality
    // short-circuit.

    /// A put() whose content is semantically identical to what's already stored (only
    /// `metadata.resourceVersion` differs, exactly as patch_pod_status re-sends the fetched
    /// object unchanged) must return the EXISTING revision, not write, not bump the revision,
    /// and not notify watchers.
    ///
    /// Why it matters: kubelet re-asserts a steady pod's status every 10s regardless of
    /// whether anything changed. Without this check, every one of those writes bumps the
    /// global revision and fires a watch/MODIFIED event, so `kubectl get pods -w` (and every
    /// controller's informer) sees a continuous stream of events with no real diff — at scale,
    /// this multiplies write/broadcast cost across every steady pod in the cluster forever.
    #[tokio::test]
    async fn put_with_unchanged_content_does_not_bump_revision_or_notify_watcher() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/pods/default/steady-pod";
        let initial = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"steady-pod","namespace":"default"},"status":{"phase":"Running"}}"#,
        );
        let rv1 = store
            .put(key, initial, None)
            .await
            .expect("create must succeed");

        let stream = store
            .watch("/registry/core/pods/", rv1)
            .await
            .expect("watch must succeed");
        futures_util::pin_mut!(stream);

        // Mimics patch_pod_status exactly: fetch the stored object (already carrying
        // resourceVersion=rv1), merge a patch that changes nothing, and write it back with
        // expected_revision = the rv it was read at.
        let stored = store.get(key).await.expect("get").expect("must exist");
        let rv2 = store
            .put(key, stored.value.clone(), Some(rv1))
            .await
            .expect("a no-op put must still report success to the caller, not error");

        assert_eq!(
            rv2, rv1,
            "an unchanged re-write must return the EXISTING revision unchanged; bumping it here \
             is exactly the bug that floods every pod watcher with meaningless MODIFIED events \
             every kubelet status-sync cycle (10s), indefinitely, for every steady pod"
        );

        let result = tokio::time::timeout(Duration::from_millis(200), stream.next()).await;
        assert!(
            result.is_err(),
            "no watch event may be emitted for a no-op write — a watcher observing an event \
             here (even just a Bookmark) means the flood this fix exists to prevent is still \
             happening"
        );
    }

    /// A put() with genuinely different content must still write, bump the revision, and
    /// notify watchers promptly — guards against the no-op check being too aggressive.
    ///
    /// Why it matters: if the equality check has a bug (e.g. comparing the wrong fields, or a
    /// false-positive match), real status transitions like Pending -> Running would become
    /// invisible to watchers, silently breaking every controller and `kubectl get -w` for
    /// actual state changes — a far worse failure than occasionally missing a no-op.
    #[tokio::test]
    async fn put_with_genuine_content_change_still_bumps_revision_and_notifies() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/pods/default/transitioning-pod";
        let pending = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"transitioning-pod","namespace":"default"},"status":{"phase":"Pending"}}"#,
        );
        let rv1 = store
            .put(key, pending, None)
            .await
            .expect("create must succeed");

        let stream = store
            .watch("/registry/core/pods/", rv1)
            .await
            .expect("watch must succeed");
        futures_util::pin_mut!(stream);

        let running = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"transitioning-pod","namespace":"default","resourceVersion":"1"},"status":{"phase":"Running"}}"#,
        );
        let rv2 = store
            .put(key, running, Some(rv1))
            .await
            .expect("genuine content change must succeed");

        assert!(
            rv2 > rv1,
            "a real status transition (Pending -> Running) must bump the revision — treating it \
             as a no-op would make the transition invisible to any watcher relying on \
             resourceVersion ordering"
        );

        let event = tokio::time::timeout(Duration::from_millis(200), stream.next())
            .await
            .expect(
                "a genuine content change must notify watchers promptly, not be swallowed \
                      by the no-op check",
            )
            .expect("stream must not end");
        match event {
            WatchEvent::Modified(obj) => {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&obj.value).expect("stored value must be valid JSON");
                assert_eq!(
                    parsed["status"]["phase"], "Running",
                    "the MODIFIED event must carry the new phase, not a stale/no-op body"
                );
            }
            other => panic!("expected Modified event for a genuine change, got {other:?}"),
        }
    }

    /// The FIRST write for a key (create) must never be treated as a no-op, even though there
    /// is no prior value to differ from.
    ///
    /// Why it matters: the no-op check only compares against an EXISTING stored value: if a
    /// future change to the check's `stored` handling accidentally treated "no prior value" as
    /// vacuously equal, every create would silently vanish — no revision, no Added event, no
    /// object ever actually stored. Every resource creation in the cluster would break.
    #[tokio::test]
    async fn put_first_write_for_new_key_is_never_treated_as_noop() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/pods/default/brand-new-pod";

        let stream = store
            .watch("/registry/core/pods/", 0)
            .await
            .expect("watch must succeed");
        futures_util::pin_mut!(stream);

        let value = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"brand-new-pod","namespace":"default"}}"#,
        );
        let rv = store
            .put(key, value, None)
            .await
            .expect("create must succeed");

        assert!(
            rv > 0,
            "a create must be assigned a real, positive revision — a no-op short-circuit \
             misfiring on a create would return revision 0 or an unwritten value"
        );

        let event = tokio::time::timeout(Duration::from_millis(200), stream.next())
            .await
            .expect(
                "a create must notify watchers — otherwise reflectors never learn the \
                      object exists",
            )
            .expect("stream must not end");
        assert!(
            matches!(event, WatchEvent::Added(_)),
            "the first write for a key must be delivered as Added, not silently dropped as a \
             (nonsensical) no-op"
        );

        let stored = store
            .get(key)
            .await
            .expect("get must not error")
            .expect("the object must actually be persisted, not skipped as a phantom no-op");
        assert_eq!(stored.revision, rv);
    }

    /// A precondition violation (`expected_revision` not matching the stored revision) must
    /// still return `RevisionMismatch`, even when the content being written would have been
    /// unchanged had the precondition passed.
    ///
    /// Why it matters: the CAS check protects against lost updates — it must run before, and
    /// take priority over, the no-op optimization. Real kube-apiserver's etcd3 store runs its
    /// precondition check in the registry layer strictly before GuaranteedUpdate's own
    /// byte-equality short-circuit ever compares data; letting a stale writer's
    /// content-appears-unchanged payload silently "succeed" here would mask real conflicts —
    /// e.g. patch_pod_status's RevisionMismatch retry loop depends on genuinely stale writes
    /// being rejected so it re-reads and re-applies against current state.
    #[tokio::test]
    async fn put_with_stale_expected_revision_errors_even_when_content_unchanged() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/pods/default/conflicted-pod";
        let value = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"conflicted-pod","namespace":"default"},"status":{"phase":"Running"}}"#,
        );
        let rv1 = store
            .put(key, value.clone(), None)
            .await
            .expect("create must succeed");

        // Same content the store already holds, but the caller's expected_revision is stale
        // (does not match the current stored revision) — a real optimistic-concurrency
        // conflict, independent of whether the payload happens to be content-identical.
        let result = store.put(key, value, Some(rv1 + 41)).await;

        assert!(
            matches!(
                result,
                Err(StoreError::RevisionMismatch { expected, current })
                    if expected == rv1 + 41 && current == rv1
            ),
            "a stale expected_revision must be rejected as RevisionMismatch even when the \
             content would have been unchanged — the no-op optimization must never mask a real \
             optimistic-concurrency conflict, got: {result:?}"
        );
    }

    // -- watch metrics: u7s_watch_broadcast_receivers / u7s_watch_broadcast_lagged_total --

    /// `watch_receiver_count` backs the `u7s_watch_broadcast_receivers` gauge — it must track
    /// the number of *currently open* watch streams, not just the number ever opened. Without
    /// this, an operator scraping /metrics could never tell "50 watches opened at startup and
    /// still open" from "50 watches opened and long since closed", which is the whole point of
    /// the gauge.
    #[tokio::test]
    async fn watch_receiver_count_reflects_open_streams_not_ever_opened() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        assert_eq!(
            store.watch_receiver_count(),
            0,
            "a fresh store must report zero active watch receivers"
        );

        let stream_a = store.watch("/registry/pods/", 0).await.expect("watch a");
        let stream_b = store.watch("/registry/pods/", 0).await.expect("watch b");
        assert_eq!(
            store.watch_receiver_count(),
            2,
            "two open watch streams must report receiver_count=2"
        );

        drop(stream_a);
        assert_eq!(
            store.watch_receiver_count(),
            1,
            "dropping one watch stream must decrement receiver_count back to 1 — a gauge that \
             only ever grows would tell an operator every watch that ever connected is still \
             open, hiding leaked or already-closed watchers"
        );

        drop(stream_b);
        assert_eq!(
            store.watch_receiver_count(),
            0,
            "dropping the last watch stream must bring receiver_count back to zero"
        );
    }

    /// A real `RecvError::Lagged(n)` must add exactly `n` to
    /// `u7s_watch_broadcast_lagged_total{prefix}` — this is the currently-discarded `_n` that
    /// motivated the metric: without counting it, an operator has no way to see that a watcher
    /// fell behind and silently missed events (recovered via ring-buffer catchup or a 410, but
    /// only after the fact).
    #[tokio::test]
    async fn broadcast_lag_increments_lagged_total_by_exact_missed_count() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/lag-test-events/";

        // Subscribe but do not poll the stream, so the receiver falls behind once the
        // broadcast channel fills past its capacity.
        let stream = store.watch(prefix, 0).await.expect("watch must succeed");
        futures_util::pin_mut!(stream);

        let before = super::metrics::WATCH_BROADCAST_LAGGED_TOTAL
            .with_label_values(&[prefix])
            .get();

        // Write one more than the broadcast capacity so the unpolled subscriber is guaranteed
        // to have missed at least one message once it is finally polled.
        let writes = BROADCAST_CAPACITY as u64 + 1;
        for i in 0..writes {
            let key = format!("{prefix}obj-{i}");
            store
                .put(&key, svc_value(&format!("obj-{i}"), i), None)
                .await
                .expect("put must succeed");
        }

        // Draining the ring buffer is not enough to observe Lagged — the ring buffer only
        // holds RING_CAPACITY entries, but the broadcast channel itself dropped messages for
        // this specific unpolled receiver once BROADCAST_CAPACITY was exceeded. Poll once to
        // surface the Lagged error the receiver accumulated while unread.
        let _ = tokio::time::timeout(Duration::from_millis(200), stream.next()).await;

        let after = super::metrics::WATCH_BROADCAST_LAGGED_TOTAL
            .with_label_values(&[prefix])
            .get();
        assert!(
            after > before,
            "a receiver that missed more than BROADCAST_CAPACITY messages must increment \
             u7s_watch_broadcast_lagged_total for its prefix once polled; before={before} after={after}"
        );
    }

    /// `u7s_watch_broadcast_lagged_total` must be labeled by `prefix_bucket`, not the raw
    /// (namespace-including) watch prefix — otherwise every namespace a long conformance run
    /// creates mints its own permanent, never-shrinking time series for this counter. Fails on
    /// revert if the label were switched back to the raw prefix: two different namespace-scoped
    /// watches under the same resource type would then land on two separate series instead of
    /// accumulating onto one.
    #[tokio::test]
    async fn broadcast_lag_total_buckets_by_resource_type_not_raw_namespace_prefix() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix_a = "/registry/lag-bucket-test/ns-a/";
        let prefix_b = "/registry/lag-bucket-test/ns-b/";
        let bucket = super::metrics::prefix_bucket(prefix_a);
        assert_eq!(
            bucket,
            super::metrics::prefix_bucket(prefix_b),
            "test setup invariant: both namespace-scoped prefixes must share one resource-type \
             bucket, or this test would not actually exercise the cardinality-bounding behavior"
        );

        // Neither stream is polled while this burst is written, so both fall behind the shared
        // broadcast channel — Lagged is a property of the receiver's own channel state, not of
        // which key each buffered event targets.
        let stream_a = store.watch(prefix_a, 0).await.expect("watch a");
        futures_util::pin_mut!(stream_a);
        let stream_b = store.watch(prefix_b, 0).await.expect("watch b");
        futures_util::pin_mut!(stream_b);

        let before = super::metrics::WATCH_BROADCAST_LAGGED_TOTAL
            .with_label_values(&[bucket])
            .get();

        let writes = BROADCAST_CAPACITY as u64 + 1;
        for i in 0..writes {
            let key = format!("/registry/lag-bucket-test/unrelated/obj-{i}");
            store
                .put(&key, svc_value(&format!("obj-{i}"), i), None)
                .await
                .expect("put must succeed");
        }
        let _ = tokio::time::timeout(Duration::from_millis(200), stream_a.next()).await;
        let _ = tokio::time::timeout(Duration::from_millis(200), stream_b.next()).await;

        let after = super::metrics::WATCH_BROADCAST_LAGGED_TOTAL
            .with_label_values(&[bucket])
            .get();
        assert!(
            after > before,
            "two different namespace-scoped watches under the same resource type must \
             accumulate onto the SAME prefix_bucket series; before={before} after={after}"
        );
    }

    /// A real `RecvError::Lagged` recovery must record a sample in
    /// `u7s_watch_lag_recovery_duration_seconds` under this watch's `prefix_bucket` — this is
    /// the metric an operator correlates against ring occupancy to confirm (or refute) whether a
    /// filling ring is making lag-recovery scans expensive enough to compound into further lag.
    /// Fails on revert if the `.observe()` call at the recovery-scan site were deleted: a real
    /// lag+recovery would leave this bucket permanently absent instead of gaining a sample.
    #[tokio::test]
    async fn lagged_recovery_records_a_duration_sample_for_its_prefix_bucket() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/lag-recovery-duration-test/";
        let bucket = super::metrics::prefix_bucket(prefix);

        let stream = store.watch(prefix, 0).await.expect("watch must succeed");
        futures_util::pin_mut!(stream);

        let before = super::metrics::WATCH_LAG_RECOVERY_DURATION_SECONDS
            .with_label_values(&[bucket])
            .get_sample_count();

        let writes = BROADCAST_CAPACITY as u64 + 1;
        for i in 0..writes {
            let key = format!("{prefix}obj-{i}");
            store
                .put(&key, svc_value(&format!("obj-{i}"), i), None)
                .await
                .expect("put must succeed");
        }
        let _ = tokio::time::timeout(Duration::from_millis(200), stream.next()).await;

        let after = super::metrics::WATCH_LAG_RECOVERY_DURATION_SECONDS
            .with_label_values(&[bucket])
            .get_sample_count();
        assert!(
            after > before,
            "a Lagged recovery scan on this prefix must record a duration sample under its \
             prefix_bucket; before={before} after={after}"
        );
    }

    /// Dropping the store that created a watch stream must not end that stream: `watch()`
    /// captures its own broadcast `Sender` clone (`tx_clone`, used for lag-recovery
    /// re-subscription) for the entire lifetime of the returned stream, so the channel's
    /// sender count can never reach zero while this same stream is the one polling
    /// `rx.recv()`. This pins down the invariant the `RecvError::Closed` match arm's
    /// `unreachable!()` relies on: if a future change to `tx_clone`'s capture strategy ever
    /// broke it, a real store shutdown would either panic every open watch task (loud, this
    /// test would start failing by panicking instead of timing out) or — if `unreachable!()`
    /// were also reverted back to a plain `return` — silently end every open watch stream
    /// clients still expect events from, instead of leaving them correctly pending forever
    /// (the actual behavior for as long as the apiserver process is alive).
    #[tokio::test]
    async fn watch_stream_stays_pending_after_originating_store_is_dropped() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let stream = store
            .watch("/registry/pods/", 0)
            .await
            .expect("watch must succeed");
        futures_util::pin_mut!(stream);

        // Drop the only handle to the store, including its own `tx` broadcast::Sender field.
        // The returned stream holds no reference back into `store` (its 'static bound
        // requires that), so this compiles — and is exactly what makes this a meaningful test:
        // it isolates whether losing the store's OWN Sender handle closes a stream opened
        // before the drop.
        drop(store);

        // If `tx_clone` did not exist (or were dropped along with the store), the next
        // rx.recv() would return RecvError::Closed and the stream would resolve — to `None`
        // before this fix, or by panicking inside `unreachable!()` after it — well within this
        // window instead of staying pending.
        let outcome = tokio::time::timeout(Duration::from_millis(200), stream.next()).await;
        assert!(
            outcome.is_err(),
            "a watch stream must remain pending after its originating store is dropped — \
             resolving here means the channel was observed as closed, which should be \
             structurally impossible while this stream holds its own Sender clone; got: \
             {outcome:?}"
        );
    }

    /// `create_if_namespace_active` must reject a create whose namespace is ALREADY
    /// Terminating at commit time — the base case the transactional guard exists for. Without
    /// it, a controller can keep injecting objects into a namespace mid-deletion, which is
    /// exactly the orphaned-content bug the transactional guard fixes.
    #[tokio::test]
    async fn create_if_namespace_active_rejects_terminating_namespace() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let ns_key = "/registry/namespaces/dying-ns";
        store
            .put(
                ns_key,
                Bytes::from(r#"{"status":{"phase":"Terminating"}}"#),
                None,
            )
            .await
            .expect("seed terminating namespace");

        let result = store
            .create_if_namespace_active(
                Some(ns_key),
                "/registry/core/configmaps/dying-ns/cm",
                Bytes::from(r#"{"metadata":{"name":"cm","namespace":"dying-ns"}}"#),
            )
            .await;
        assert!(
            matches!(result, Err(CreateNamespacedError::NamespaceTerminating)),
            "a create whose namespace is Terminating at commit time must be rejected with \
             NamespaceTerminating, not silently written — got {result:?}"
        );
        assert!(
            store
                .get("/registry/core/configmaps/dying-ns/cm")
                .await
                .unwrap()
                .is_none(),
            "the object must never be visible in the store when its namespace check failed"
        );
    }

    /// A namespace that does not exist at `ns_key` must be treated as active, not rejected —
    /// this method only closes the create-vs-delete race for namespaces that exist; it is not
    /// a namespace-existence check (that stays the caller's job, e.g. pods.rs's
    /// parse_namespace), matching the pre-existing behavior of the inline checks this method
    /// replaces (which also silently allowed the create when the namespace lookup found
    /// nothing).
    #[tokio::test]
    async fn create_if_namespace_active_allows_create_when_namespace_absent() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let result = store
            .create_if_namespace_active(
                Some("/registry/namespaces/never-created"),
                "/registry/core/configmaps/never-created/cm",
                Bytes::from(r#"{"metadata":{"name":"cm","namespace":"never-created"}}"#),
            )
            .await;
        assert!(
            result.is_ok(),
            "a missing namespace must not be treated as Terminating — got {result:?}"
        );
    }

    /// The namespace check and the object insert must be a single atomic unit: a concurrent
    /// write that flips the namespace to Terminating strictly AFTER this call's transaction
    /// has already committed the create must not retroactively fail it, and (the property that
    /// actually matters for correctness) the create must never observe a torn state where its
    /// own insert exists but the namespace phase it should have been gated on was never
    /// consulted at all.
    ///
    /// This exercises the same BEGIN IMMEDIATE / COMMIT boundary as `put_sync` and
    /// `delete_namespace_sync` — if the namespace-phase read and the object insert were ever
    /// split into two separate transactions (the bug this whole method exists to close), a
    /// `put` to `ns_key` issued by another task between them would sometimes win the race and
    /// sometimes lose it depending on scheduling, making this test flaky. Because `write_conn`
    /// serializes every write behind one mutex and `create_if_namespace_active_sync` never
    /// releases it between the read and the insert, running this many times must be
    /// deterministic every time.
    #[tokio::test]
    async fn create_if_namespace_active_check_and_insert_are_not_interleaved_by_concurrent_writes()
    {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let ns_key = "/registry/namespaces/busy-ns";
        store
            .put(
                ns_key,
                Bytes::from(r#"{"status":{"phase":"Active"}}"#),
                None,
            )
            .await
            .expect("seed active namespace");

        for i in 0..50 {
            let obj_key = format!("/registry/core/configmaps/busy-ns/cm-{i}");
            let create_store = Arc::clone(&store);
            let create_key = obj_key.clone();
            let create = tokio::spawn(async move {
                create_store
                    .create_if_namespace_active(
                        Some("/registry/namespaces/busy-ns"),
                        &create_key,
                        Bytes::from(r#"{"metadata":{"name":"cm","namespace":"busy-ns"}}"#),
                    )
                    .await
            });
            let flip_store = Arc::clone(&store);
            let flip = tokio::spawn(async move {
                flip_store
                    .put(
                        "/registry/namespaces/busy-ns",
                        Bytes::from(r#"{"status":{"phase":"Terminating"}}"#),
                        None,
                    )
                    .await
            });

            let (create_result, flip_result) = tokio::join!(create, flip);
            let create_result = create_result.expect("create task must not panic");
            flip_result
                .expect("flip task must not panic")
                .expect("flip put must succeed");

            // Whichever order the two writes actually landed in, the object's presence in the
            // store must agree with whether the create call reported success — there must be
            // no window where the create returned Ok but the object is absent (or vice versa),
            // which is what "check and insert happen in one transaction" guarantees.
            let stored = store.get(&obj_key).await.expect("get must not error");
            assert_eq!(
                create_result.is_ok(),
                stored.is_some(),
                "iteration {i}: create_if_namespace_active's return value and the object's \
                 actual presence in the store disagree — the namespace check and the insert \
                 must be one atomic unit, never a torn write"
            );

            // Reset the namespace to Active for the next iteration.
            store
                .put(
                    "/registry/namespaces/busy-ns",
                    Bytes::from(r#"{"status":{"phase":"Active"}}"#),
                    None,
                )
                .await
                .expect("reset namespace to active");
        }
    }

    /// `list_sync` runs many fallible queries between `BEGIN DEFERRED` and `COMMIT` (one per
    /// field-selector fast path, plus the snapshot-revision and remaining-count reads). If any
    /// of them errors out via `?` without rolling back, the connection is abandoned
    /// mid-transaction — frozen on whatever snapshot existed when the transaction opened.
    /// `Store::get()` happens to recover from this today via its stale-revision fallback to
    /// `write_conn`, but any future read path without that specific fallback would silently
    /// serve stale data forever from a wedged connection. This test forces list_sync's
    /// snapshot-revision read to fail (by deleting the `meta` revision row) after it has
    /// already opened the transaction, then checks the connection is back in autocommit mode —
    /// i.e. rolled back, not left open.
    #[test]
    fn list_sync_error_path_rolls_back_transaction() {
        let conn = Connection::open_in_memory().expect("conn");
        conn.execute_batch(
            "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
             revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
             CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);",
        )
        .expect("schema");
        // No 'revision' row in meta: list_sync's snapshot-revision query_row (which requires
        // exactly one row) fails with QueryReturnedNoRows partway through the transaction,
        // after the objects scan has already succeeded.

        let err = list_sync(&conn, "/registry/pods/", &ListOptions::default())
            .expect_err("a missing meta.revision row must surface as an error, not succeed");
        assert!(
            matches!(err, StoreError::Sqlite(_)),
            "expected list_sync's early return to be a sqlite error from the missing meta row, \
             got {err:?}"
        );

        assert!(
            conn.is_autocommit(),
            "list_sync's error path left the connection mid-transaction (BEGIN DEFERRED with \
             no matching ROLLBACK/COMMIT); a caller reusing this connection without \
             Store::get()'s stale-revision retry would be stuck reading a frozen snapshot from \
             the abandoned transaction"
        );
    }

    /// `put_sync` only issues an explicit ROLLBACK on named business-logic branches
    /// (AlreadyExists/RevisionMismatch/no-op); the revision-increment step is a bare
    /// `?`-propagated query with no matching ROLLBACK. Before the RAII transaction guard, a
    /// single transient failure there (disk I/O, SQLITE_BUSY/FULL) would leave the *shared*
    /// `write_conn` connection wedged mid-transaction for the life of the process — every
    /// subsequent put/delete/create/delete-namespace on the whole apiserver would then fail
    /// with "cannot start a transaction within a transaction" until restart.
    #[test]
    fn put_sync_error_path_rolls_back_transaction() {
        let conn = Connection::open_in_memory().expect("conn");
        conn.execute_batch(
            "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
             revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
             CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);",
        )
        .expect("schema");
        // No 'revision' row in meta: put_sync's revision-increment query_row fails with
        // QueryReturnedNoRows after the create-path checks have already passed.
        let last_written = AtomicU64::new(0);
        let err = put_sync(
            &conn,
            "/registry/pods/default/foo",
            Bytes::from(r#"{"metadata":{"name":"foo","namespace":"default"}}"#),
            None,
            &last_written,
        )
        .expect_err("a missing meta.revision row must surface as an error, not succeed");
        assert!(
            matches!(err, StoreError::Sqlite(_)),
            "expected put_sync's early return to be a sqlite error from the missing meta row, \
             got {err:?}"
        );
        assert!(
            conn.is_autocommit(),
            "put_sync's error path left the shared write connection mid-transaction — every \
             future write on the process would fail with 'cannot start a transaction within a \
             transaction' until restart; a single transient store error must not wedge the \
             whole apiserver's write path"
        );

        // Prove the connection actually recovered, not just that the flag looks right.
        conn.execute_batch("INSERT INTO meta (key, value) VALUES ('revision', '0')")
            .expect("seed revision");
        put_sync(
            &conn,
            "/registry/pods/default/bar",
            Bytes::from(r#"{"metadata":{"name":"bar","namespace":"default"}}"#),
            None,
            &last_written,
        )
        .expect("a subsequent write must succeed once the connection is no longer wedged");
    }

    /// Same wedge as `put_sync_error_path_rolls_back_transaction`, for `delete_sync`: the
    /// object lookup and concurrency check pass (the object exists), then the bare
    /// `?`-propagated revision-increment query fails with no matching ROLLBACK.
    #[test]
    fn delete_sync_error_path_rolls_back_transaction() {
        let conn = Connection::open_in_memory().expect("conn");
        conn.execute_batch(
            "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
             revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
             CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL); \
             INSERT INTO objects (key, value, revision, ns, obj_name) VALUES \
             ('/registry/pods/default/foo', x'7b7d', 1, 'default', 'foo');",
        )
        .expect("schema");
        let last_written = AtomicU64::new(0);
        let err = delete_sync(&conn, "/registry/pods/default/foo", None, &last_written)
            .expect_err("a missing meta.revision row must surface as an error, not succeed");
        assert!(
            matches!(err, StoreError::Sqlite(_)),
            "expected delete_sync's early return to be a sqlite error from the missing meta \
             row, got {err:?}"
        );
        assert!(
            conn.is_autocommit(),
            "delete_sync's error path left the shared write connection mid-transaction — every \
             future write on the process would fail with 'cannot start a transaction within a \
             transaction' until restart; a single transient store error must not wedge the \
             whole apiserver's write path"
        );

        conn.execute_batch("INSERT INTO meta (key, value) VALUES ('revision', '1')")
            .expect("seed revision");
        delete_sync(&conn, "/registry/pods/default/foo", None, &last_written)
            .expect("a subsequent write must succeed once the connection is no longer wedged");
    }

    /// Same wedge as above, for `create_if_namespace_active_sync`: the namespace-terminating
    /// check (skipped here via `ns_key: None`) and the already-exists check both pass, then
    /// the bare `?`-propagated revision-increment query fails with no matching ROLLBACK.
    #[test]
    fn create_if_namespace_active_sync_error_path_rolls_back_transaction() {
        let conn = Connection::open_in_memory().expect("conn");
        conn.execute_batch(
            "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
             revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
             CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);",
        )
        .expect("schema");
        let last_written = AtomicU64::new(0);
        let err = create_if_namespace_active_sync(
            &conn,
            None,
            "/registry/core/configmaps/default/cm",
            Bytes::from(r#"{"metadata":{"name":"cm","namespace":"default"}}"#),
            &last_written,
        )
        .expect_err("a missing meta.revision row must surface as an error, not succeed");
        assert!(
            matches!(err, CreateNamespacedError::Store(StoreError::Sqlite(_))),
            "expected create_if_namespace_active_sync's early return to be a sqlite error from \
             the missing meta row, got {err:?}"
        );
        assert!(
            conn.is_autocommit(),
            "create_if_namespace_active_sync's error path left the shared write connection \
             mid-transaction — every future write on the process would fail with 'cannot start \
             a transaction within a transaction' until restart; a single transient store error \
             must not wedge the whole apiserver's write path"
        );

        conn.execute_batch("INSERT INTO meta (key, value) VALUES ('revision', '0')")
            .expect("seed revision");
        create_if_namespace_active_sync(
            &conn,
            None,
            "/registry/core/configmaps/default/cm",
            Bytes::from(r#"{"metadata":{"name":"cm","namespace":"default"}}"#),
            &last_written,
        )
        .expect("a subsequent write must succeed once the connection is no longer wedged");
    }

    /// Same wedge as above, for `delete_namespace_sync`: the namespace scan finds one object
    /// (so the empty-namespace no-op rollback doesn't fire), then the bare `?`-propagated
    /// per-object revision-increment query inside the delete loop fails with no matching
    /// ROLLBACK.
    #[test]
    fn delete_namespace_sync_error_path_rolls_back_transaction() {
        let conn = Connection::open_in_memory().expect("conn");
        conn.execute_batch(
            "CREATE TABLE objects (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL, \
             revision INTEGER NOT NULL, ns TEXT, obj_name TEXT) WITHOUT ROWID; \
             CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL); \
             INSERT INTO objects (key, value, revision, ns, obj_name) VALUES \
             ('/registry/pods/dying-ns/foo', x'7b7d', 1, 'dying-ns', 'foo');",
        )
        .expect("schema");
        let last_written = AtomicU64::new(0);
        let err = delete_namespace_sync(&conn, "dying-ns", &last_written)
            .expect_err("a missing meta.revision row must surface as an error, not succeed");
        assert!(
            matches!(err, StoreError::Sqlite(_)),
            "expected delete_namespace_sync's early return to be a sqlite error from the \
             missing meta row, got {err:?}"
        );
        assert!(
            conn.is_autocommit(),
            "delete_namespace_sync's error path left the shared write connection \
             mid-transaction — every future write on the process would fail with 'cannot start \
             a transaction within a transaction' until restart; a single transient store error \
             must not wedge the whole apiserver's write path"
        );

        conn.execute_batch("INSERT INTO meta (key, value) VALUES ('revision', '1')")
            .expect("seed revision");
        let deleted = delete_namespace_sync(&conn, "dying-ns", &last_written)
            .expect("a subsequent write must succeed once the connection is no longer wedged");
        assert_eq!(
            deleted.len(),
            1,
            "the namespace's one object must still be deletable once the connection recovers"
        );
    }

    /// `list_namespace_objects` is the hottest LIST path in the conformance samply trace
    /// (ai/findings/samply-triage-2026-08-06.md) — it must reuse a cached prepared statement
    /// across calls instead of re-parsing the same SQL text from scratch on every request.
    ///
    /// This is checked via SQLite's per-statement `Run` status counter rather than timing:
    /// `prepare_cached` returns the *same* underlying `sqlite3_stmt` object on every call for
    /// identical SQL on the same connection, so its `Run` counter accumulates across calls and
    /// is still readable afterward by re-fetching that statement from the connection's cache.
    /// If the LIST path instead calls plain `conn.prepare`, every call compiles and finalizes
    /// its own one-off statement, nothing is ever left in the connection's cache, and
    /// re-fetching afterward hits a fresh statement with a `Run` counter of 0 — the fail mode
    /// this test exists to catch.
    #[tokio::test]
    async fn list_namespace_objects_reuses_cached_prepared_statement() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        for i in 0..3 {
            store
                .put(
                    &format!("/registry/services/default/svc-{i}"),
                    svc_value(&format!("svc-{i}"), 0),
                    None,
                )
                .await
                .expect("seed object");
        }

        const LIST_CALLS: i32 = 5;
        for _ in 0..LIST_CALLS {
            store
                .list_namespace_objects("default")
                .await
                .expect("list_namespace_objects");
        }

        // Re-fetch the statement list_namespace_objects prepares (identical SQL text, same
        // write_conn). With prepare_cached this pulls the exact statement object reused by
        // every call above; with plain prepare it would be a brand-new statement instead.
        let conn = store.write_conn.lock().await;
        let stmt = conn
            .prepare_cached("SELECT key, value, revision FROM objects WHERE ns = ?1")
            .expect("prepare_cached probe");
        let run_count = stmt.get_status(rusqlite::StatementStatus::Run);
        assert_eq!(
            run_count, LIST_CALLS,
            "expected the LIST path's prepared statement to still be sitting in write_conn's \
             statement cache with a Run count of {LIST_CALLS} (one per list_namespace_objects \
             call above); got {run_count} — this means list_namespace_objects is re-parsing \
             its SQL from scratch on every call instead of reusing a cached statement"
        );
    }

    /// A watcher on a quiet prefix still gets a global bookmark for a burst of writes on a
    /// completely different prefix (KCM's EnsureReady needs every informer's sync RV to
    /// eventually catch up to any write, not just writes on that informer's own resource
    /// type) — but the burst must cost this watcher one bookmark allocation, not one per
    /// write. Before debouncing, every open watch stream rendered one `WatchEvent::Bookmark`
    /// per write anywhere in the store, making allocation cost scale with cluster-wide write
    /// volume instead of the watcher's own prefix.
    #[tokio::test]
    async fn burst_of_writes_on_other_prefix_coalesces_into_one_bookmark() {
        tokio::time::pause();
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        let stream = store
            .watch("/registry/pods/", 0)
            .await
            .expect("watch failed");
        futures_util::pin_mut!(stream);

        let mut last_rv = 0u64;
        for i in 0..5 {
            last_rv = store
                .put(
                    &format!("/registry/services/default/svc-{i}"),
                    svc_value(&format!("svc-{i}"), 0),
                    None,
                )
                .await
                .expect("put must succeed");
        }

        // Collect whatever arrives up to one debounce window past the last write. Under a
        // paused clock, tokio auto-advances virtual time to the next pending timer once
        // nothing else is runnable, so this resolves promptly instead of sleeping for real.
        let deadline =
            tokio::time::Instant::now() + GLOBAL_BOOKMARK_DEBOUNCE + Duration::from_millis(50);
        let mut bookmarks: Vec<u64> = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Bookmark { revision })) => bookmarks.push(revision),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        assert_eq!(
            bookmarks,
            vec![last_rv],
            "5 writes on an unrelated prefix inside the debounce window must coalesce into \
             exactly one Bookmark at the last write's revision, not one per write — a per-write \
             bookmark makes every open watch's allocation rate scale with total cluster write \
             volume instead of its own prefix's activity"
        );
    }

    /// The debounced global bookmark must flush purely because its own timer elapsed, not
    /// because a later broadcast message happened to arrive and trigger a "check if it's time
    /// yet" flush. A quiescent cluster after a single burst of writes is the common case, not
    /// an edge case — if the flush needed a follow-up write to notice the deadline passed,
    /// every other watcher's informer sync RV would stay stuck below that burst's revision
    /// forever, and KCM's EnsureReady() would spin indefinitely.
    #[tokio::test]
    async fn debounced_bookmark_flushes_without_a_subsequent_write() {
        tokio::time::pause();
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        let stream = store
            .watch("/registry/pods/", 0)
            .await
            .expect("watch failed");
        futures_util::pin_mut!(stream);

        let written_rv = store
            .put(
                "/registry/services/default/svc-only",
                svc_value("svc-only", 0),
                None,
            )
            .await
            .expect("put must succeed");

        // No further writes occur anywhere in the store after this point.
        let deadline =
            tokio::time::Instant::now() + GLOBAL_BOOKMARK_DEBOUNCE + Duration::from_millis(50);
        let mut bookmark: Option<u64> = None;
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Bookmark { revision })) => {
                    bookmark = Some(revision);
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        assert_eq!(
            bookmark,
            Some(written_rv),
            "a single global bookmark update must still flush within the debounce window with \
             no follow-up write — a debounce that only flushes when the next event arrives \
             would leave this watcher's bookmark, and every other watcher's informer sync RV, \
             stuck below the burst's last write forever on a cluster that goes quiet afterward"
        );
    }

    /// A watcher whose own prefix is on the SAME shard as a write must receive exactly one
    /// Bookmark for that write — the trailing per-matched-event bookmark already delivers a
    /// bookmark at this revision immediately; the global-bookmark broadcast for this same
    /// shard carries no new information and must be suppressed before it can even enter the
    /// debounce timer above.
    ///
    /// Why it matters: without the dedup, every same-shard watcher pays for a second,
    /// identical-revision Bookmark allocation per write — doubling this watcher's allocation
    /// rate for zero client-visible benefit (client-go only cares that the RV advances, and
    /// it already has).
    #[tokio::test]
    async fn watcher_on_writing_shard_does_not_receive_redundant_global_bookmark() {
        tokio::time::pause();
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        let stream = store
            .watch("/registry/pods/", 0)
            .await
            .expect("watch failed");
        futures_util::pin_mut!(stream);

        let rv = store
            .put(
                "/registry/pods/default/foo",
                Bytes::from(
                    r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"foo","namespace":"default"}}"#,
                ),
                None,
            )
            .await
            .expect("put must succeed");

        // Collect whatever arrives up to one debounce window past the write, same idiom as
        // the cross-shard debounce tests above.
        let deadline =
            tokio::time::Instant::now() + GLOBAL_BOOKMARK_DEBOUNCE + Duration::from_millis(50);
        let mut bookmarks: Vec<u64> = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Bookmark { revision })) => bookmarks.push(revision),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        assert_eq!(
            bookmarks,
            vec![rv],
            "a same-shard watcher must see exactly one Bookmark per write, delivered by the \
             trailing per-matched-event path; a second Bookmark at the same revision means the \
             redundant same-shard global-bookmark was not suppressed and this watcher's \
             allocation rate has silently doubled again"
        );
    }

    /// A watcher on a DIFFERENT shard than the one just written to must still receive the
    /// global bookmark for that write — the same-shard dedup above must never widen to
    /// suppress this.
    ///
    /// Why it matters: KCM's ConsistencyStore.EnsureReady() requires every informer's sync RV
    /// to converge on ANY write in the cluster, not just writes to that informer's own
    /// resource type (e.g. a StatefulSet controller's informer must still advance after a pod
    /// write). If this cross-shard delivery ever regressed, EnsureReady would requeue forever.
    #[tokio::test]
    async fn watcher_on_different_shard_still_receives_global_bookmark() {
        tokio::time::pause();
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        let stream = store
            .watch("/registry/pods/", 0)
            .await
            .expect("watch failed");
        futures_util::pin_mut!(stream);

        let rv = store
            .put(
                "/registry/services/default/svc-1",
                svc_value("svc-1", 0),
                None,
            )
            .await
            .expect("put must succeed");

        let deadline =
            tokio::time::Instant::now() + GLOBAL_BOOKMARK_DEBOUNCE + Duration::from_millis(50);
        let mut bookmarks: Vec<u64> = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Bookmark { revision })) => bookmarks.push(revision),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        assert_eq!(
            bookmarks,
            vec![rv],
            "cross-shard watcher must still receive the global bookmark for a different \
             shard's write; if the same-shard dedup were widened to unconditionally suppress \
             the global bookmark, this watcher's sync RV would never converge and KCM's \
             EnsureReady would requeue forever"
        );
    }

    // --- Ring/deletion_log sharding by resource-type prefix ---
    //
    // A watch stream's *delivered* events are identical whether the ring is sharded or not:
    // both the old single-ring implementation and the new per-shard one filter every candidate
    // event by `e.key.starts_with(prefix)` before ever yielding it, so a pure "does the wrong
    // object show up in my watch stream" test cannot distinguish them — it would pass
    // unmodified even if this whole sharding pass were reverted. What sharding actually changes
    // is (a) which physical `RingShard` a write's event and eviction land in, and (b) how many
    // entries a watch-open/Lagged-recovery scan has to walk to find its own prefix's events.
    // The tests below target those two properties directly instead.

    /// Two different resource types' events must land in two distinct `RingShard` instances,
    /// each holding only its own resource type's events.
    ///
    /// Why it matters: the entire premise of per-resource-type retention isolation (a busy
    /// type's writes can no longer evict a quiet type's history) depends on writes for
    /// different resource types never sharing one physical ring. Fails on revert: unsharding
    /// (back to one global `ring` field) removes `SqliteStore::shards`/`RingShard` entirely, so
    /// this test would not even compile against the old design — and if instead the shard key
    /// were computed wrong (e.g. always the same string), `Arc::ptr_eq` below would trip and
    /// `pods_shard.ring`'s length would be 2, not 1.
    #[tokio::test]
    async fn writes_to_different_resource_types_land_in_different_shards() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // A shard now exists only once something watches its resource type (see
        // push_event_locked's doc) — held for the whole test so the two shards it inspects
        // below aren't idle-GC'd out from under it.
        let _pods_watch = store
            .watch("/registry/core/pods/", 0)
            .await
            .expect("watch must succeed");
        let _configmaps_watch = store
            .watch("/registry/core/configmaps/", 0)
            .await
            .expect("watch must succeed");

        store
            .put(
                "/registry/core/pods/default/pod-a",
                Bytes::from(
                    r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-a","namespace":"default"}}"#,
                ),
                None,
            )
            .await
            .expect("put pod-a");
        store
            .put(
                "/registry/core/configmaps/default/cm-a",
                Bytes::from(
                    r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm-a","namespace":"default"}}"#,
                ),
                None,
            )
            .await
            .expect("put cm-a");

        let pods_shard = store.shard_for_test("/registry/core/pods/default/pod-a", Some("default"));
        let configmaps_shard =
            store.shard_for_test("/registry/core/configmaps/default/cm-a", Some("default"));

        assert!(
            !Arc::ptr_eq(&pods_shard, &configmaps_shard),
            "Pods and ConfigMaps must resolve to two distinct RingShard instances; if both \
             prefixes hashed to the same shard key, this whole sharding pass would collapse \
             back into a single ring shared by every resource type"
        );

        let pods_ring = pods_shard.ring.read().expect("ring poisoned");
        assert_eq!(
            pods_ring.len(),
            1,
            "the Pods shard must contain exactly pod-a's own event; a length of 2 here would \
             mean cm-a's event also landed in this shard — i.e. the two resource types are \
             still sharing one physical ring"
        );
        assert_eq!(
            pods_ring.front().expect("must have an entry").key,
            "/registry/core/pods/default/pod-a"
        );
    }

    /// A busy resource type overflowing its own `RING_CAPACITY` must NOT evict a different,
    /// quiet resource type's events — each shard's capacity must be independent.
    ///
    /// Why it matters: this is the exact mechanism `RingShard`'s doc describes — before
    /// sharding, Pods (writing far more often than e.g. Namespaces) could push a Namespace's
    /// watch history out of a shared ring long before Namespaces itself ever came close to
    /// `RING_CAPACITY`. Fails on revert (shared capacity): pushing `RING_CAPACITY + 1` Pod
    /// events onto ONE shared ring that already held the Namespace event would evict that
    /// Namespace event on the very last push (global len exceeds `RING_CAPACITY`), and the
    /// assertion below (`quiet_ring.len() == 1`) would fail.
    #[tokio::test]
    async fn shard_capacity_is_independent_per_resource_type() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // One event on a quiet resource type (namespaces), pushed first.
        store.push_event(
            Arc::new(InternalEvent {
                key: "/registry/core/namespaces/quiet-ns".into(),
                revision: 1,
                value: Some(Bytes::from(
                    r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"quiet-ns"}}"#,
                )),
                is_create: true,
                deleted_body: None,
            }),
            None,
        );

        // A busy resource type (pods) alone overflows RING_CAPACITY.
        for i in 0..=RING_CAPACITY as u64 {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/pods/default/pod-{i}"),
                    revision: i + 2,
                    value: Some(svc_value(&format!("pod-{i}"), i + 2)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        let quiet_shard = store.shard_for_test("/registry/core/namespaces/quiet-ns", None);
        let quiet_ring = quiet_shard.ring.read().expect("ring poisoned");
        assert_eq!(
            quiet_ring.len(),
            1,
            "the namespaces shard must still hold its one event after the pods shard alone \
             absorbed RING_CAPACITY+1 writes; a length of 0 here means the pods writes evicted \
             it — i.e. the two resource types are still sharing one ring's eviction budget"
        );
    }

    /// Opening a watch must only ever read the ONE shard matching its own prefix — never the
    /// combined occupancy of every resource type in the store.
    ///
    /// Why it matters: `find_shard` resolves a watch's prefix to exactly one `Arc<RingShard>`
    /// before the replay scan runs (see `watch()`), and every `.iter()` call in the replay/
    /// Lagged-recovery paths only ever walks that one shard's `ring`. This test proves that
    /// path stays correct — and stays bounded by one small shard — even while five OTHER
    /// resource types combined hold 5x `RING_CAPACITY` events. Fails on revert (single global
    /// ring, prefix-filtered scan): `shard_for_test` (and `RingShard`/`shards` it depends on)
    /// would not exist, so this test would not compile; a real linear-scan revert would also
    /// have to walk all 50,005 entries below on every watch-open, the exact O(ring-size) cost
    /// this sharding pass exists to eliminate — this test's five busy resource types stand in
    /// for that combined occupancy.
    #[tokio::test]
    async fn watch_open_replay_only_scans_its_own_shard() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Five OTHER resource types, RING_CAPACITY events each — none of them share a shard
        // with the resource type this test actually watches.
        const OTHER_TYPES: u64 = 5;
        for t in 0..OTHER_TYPES {
            for i in 0..RING_CAPACITY as u64 {
                store.push_event(
                    Arc::new(InternalEvent {
                        key: format!("/registry/core/busytype{t}/default/obj-{i}"),
                        revision: t * RING_CAPACITY as u64 + i + 1,
                        value: Some(svc_value("obj", i + 1)),
                        is_create: true,
                        deleted_body: None,
                    }),
                    Some("default"),
                );
            }
        }

        // The watched resource type has only 5 events of its own.
        const QUIET_EVENTS: u64 = 5;
        let base_rev = OTHER_TYPES * RING_CAPACITY as u64;
        for i in 0..QUIET_EVENTS {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/quiettype/default/obj-{i}"),
                    revision: base_rev + i + 1,
                    value: Some(svc_value("obj", base_rev + i + 1)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        let quiet_shard =
            store.shard_for_test("/registry/core/quiettype/default/obj-0", Some("default"));
        let quiet_shard_len = quiet_shard.ring.read().expect("ring poisoned").len();
        assert_eq!(
            quiet_shard_len, QUIET_EVENTS as usize,
            "quiettype's own shard must hold exactly its own 5 events, decoupled from the \
             50_000 events pushed to the other five resource types"
        );

        let stream = store
            .watch("/registry/core/quiettype/", 0)
            .await
            .expect("watch must succeed");
        futures_util::pin_mut!(stream);

        let mut replayed = 0u64;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while replayed < QUIET_EVENTS {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Added(_))) => replayed += 1,
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        assert_eq!(
            replayed,
            QUIET_EVENTS,
            "watch-open replay on quiettype must deliver exactly its own 5 events even though \
             50_000 events exist for other resource types — proving the scan that produced them \
             was bounded by quiettype's own shard ({quiet_shard_len} entries), not the store's \
             combined occupancy ({} entries)",
            OTHER_TYPES * RING_CAPACITY as u64 + QUIET_EVENTS
        );
    }

    /// Finds the gathered `u7s_watch_ring_span_seconds` series for one shard label. Used instead
    /// of a direct `.get()` because this metric is a `HistogramVec`: it has no single "current
    /// value" to read back (see the metric's own doc for exactly why that was the defect this
    /// type change fixes) — tests must instead inspect the accumulated distribution.
    fn span_metric(shard_label: &str) -> prometheus::proto::Metric {
        let families = prometheus::gather();
        let family = families
            .iter()
            .find(|f| f.name() == "u7s_watch_ring_span_seconds")
            .expect(
                "u7s_watch_ring_span_seconds must appear in gathered metric families once a \
                 shard has recorded at least one push",
            );
        family
            .get_metric()
            .iter()
            .find(|m| {
                m.get_label()
                    .iter()
                    .any(|l| l.name() == "shard" && l.value() == shard_label)
            })
            .expect("gathered output must carry a series for the shard label that was observed")
            .clone()
    }

    /// Cumulative count for the bucket whose upper bound is exactly `upper_bound` (one of the
    /// fixed boundaries from `watch_ring_span_seconds_buckets`), e.g. `span_bucket_count(l, 1.0)`
    /// is how many observed spans on shard `l` have been <= 1 second — the low-bucket reading a
    /// ring-sizing decision actually needs, per the metric's own doc.
    fn span_bucket_count(shard_label: &str, upper_bound: f64) -> u64 {
        span_metric(shard_label)
            .get_histogram()
            .get_bucket()
            .iter()
            .find(|b| (b.upper_bound() - upper_bound).abs() < f64::EPSILON)
            .unwrap_or_else(|| {
                panic!("no bucket with upper_bound={upper_bound} for shard {shard_label}")
            })
            .cumulative_count()
    }

    /// `WATCH_RING_SPAN_SECONDS` must record how far back a shard's retained history actually
    /// reaches, in seconds, on every push — not merely that the shard holds N events.
    ///
    /// Why it matters: the ring is read exactly once, at watch open, to bridge
    /// `from_revision -> now`. A reconnecting client's watch survives iff the ring still covers
    /// the gap since it last saw an event, so the safety margin is a DURATION. Occupancy alone
    /// cannot distinguish 9,670 events meaning 8 seconds of cover from the same 9,670 meaning 8
    /// minutes, and those differ by whether a client that relists and re-watches gets expired
    /// again mid-round-trip and never reaches a streaming steady state. Any future decision to
    /// shrink `RING_CAPACITY` for memory is made against this number; if it silently reported
    /// the wrong thing we would size the ring off a fiction.
    ///
    /// Note the measured quantity is a SPAN between two push times (newest retained minus
    /// oldest retained), not the oldest entry's age against real "now" — see the metric's own
    /// doc. The pushes below therefore also stand in for the clock: the observation recorded by
    /// pushing at t=45 is 45 because the newest entry IS the t=45 one. Asserted via
    /// `sample_sum`/`sample_count` (a histogram's running total and observation count) rather
    /// than a single readback, since each push is now an independent observation, not an
    /// overwrite of one value.
    ///
    /// Fails on revert: if the push stamp stops being recorded every observation is 0 and
    /// `sample_sum` never advances past 0; if the subtraction is inverted it saturates to 0
    /// likewise.
    #[tokio::test]
    async fn ring_reports_retained_history_span_not_just_occupancy() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        // Unique resource-type root: the histogram lives in the process-global prometheus
        // registry, so sharing a shard label with another test would let them clobber each other.
        const SHARD: &str = "/registry/spantest-basic/";
        let push = |name: &str, rv: u64, at: u32| {
            store.push_event_at(
                Arc::new(InternalEvent {
                    key: format!("{SHARD}default/{name}"),
                    revision: rv,
                    value: Some(svc_value(name, rv)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
                at,
            );
        };

        push("a", 1, 0);
        let after_a = span_metric(SHARD).get_histogram().clone();
        assert_eq!(
            (after_a.get_sample_count(), after_a.get_sample_sum()),
            (1, 0.0),
            "a shard holding one just-written event has no history depth yet — observing \
             anything but 0 would overstate the replay cover available to a reconnecting watch"
        );

        push("b", 2, 30);
        let after_b = span_metric(SHARD).get_histogram().clone();
        assert_eq!(
            (after_b.get_sample_count(), after_b.get_sample_sum()),
            (2, 30.0),
            "with the oldest retained event pushed at t=0 and the newest at t=30, this push \
             must observe 30s of watch-replay history; occupancy (2) says nothing about that"
        );

        push("c", 3, 45);
        let after_c = span_metric(SHARD).get_histogram().clone();
        assert_eq!(
            (after_c.get_sample_count(), after_c.get_sample_sum()),
            (3, 75.0),
            "the span must be measured from the OLDEST retained event (t=0), not the gap \
             between the last two pushes — a watch reconnecting from 40s ago is still \
             serviceable and must not be judged against the most recent write, so this push \
             observes 45 (sum 30+45=75), not 15 (the t=30..t=45 gap)"
        );
    }

    /// Once eviction discards a shard's oldest entries, subsequent pushes must observe the new,
    /// shrunken span — not the stale one from before eviction.
    ///
    /// Why it matters: this is the case that decides whether the metric can be trusted as a
    /// safety signal at all. A ring at capacity is exactly when its cover is shrinking and when
    /// an operator most needs a true number; still observing spans measured from an event
    /// already evicted would claim the deepest history precisely when the least remains.
    ///
    /// Fails on revert: dropping the `secs_guard.pop_front()` that pairs with the ring's
    /// `pop_front` desynchronises the two deques, leaving a stale t=0 stamp at the front — the
    /// final push would then observe 100 again instead of 0, and the low-bucket assertion below
    /// would see 512 (unchanged) instead of 513.
    #[tokio::test]
    async fn ring_span_falls_when_eviction_discards_the_oldest_events() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        const SHARD: &str = "/registry/spantest-evict/";
        let push = |i: u64, at: u32| {
            store.push_event_at(
                Arc::new(InternalEvent {
                    key: format!("{SHARD}default/obj-{i}"),
                    revision: i,
                    value: Some(svc_value("obj", i)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
                at,
            );
        };

        // Exactly fill the ring at t=0, so nothing has been evicted yet: RING_CAPACITY
        // observations, all of value 0, all falling in the le=1 bucket (buckets are cumulative
        // "<=" boundaries starting at 1 — see `watch_ring_span_seconds_buckets`'s doc).
        for i in 0..RING_CAPACITY as u64 {
            push(i + 1, 0);
        }
        assert_eq!(
            span_bucket_count(SHARD, 1.0),
            RING_CAPACITY as u64,
            "ring filled entirely at t=0 spans no time on every one of those pushes — test \
             setup broken"
        );

        // One more push at t=100 forces the first eviction: the oldest t=0 entry goes, but
        // RING_CAPACITY-1 more t=0 entries remain, so this push still observes 100, not 0.
        push(RING_CAPACITY as u64 + 1, 100);
        assert_eq!(
            span_bucket_count(SHARD, 1.0),
            RING_CAPACITY as u64,
            "one eviction leaves the remaining t=0 entries as the oldest, so cover is still \
             100s for this push — the le=1 (spans-no-time) bucket must not have grown"
        );
        assert_eq!(
            span_bucket_count(SHARD, 128.0),
            RING_CAPACITY as u64 + 1,
            "the 100s observation must land in the bucket that covers it (le=128, since \
             64 < 100 <= 128), on top of every earlier <=1s observation counted cumulatively"
        );

        // Overwrite the ring at t=100 one push short of RING_CAPACITY: exactly enough to evict
        // every remaining t=0 entry, so the LAST of these pushes is the one where the ring turns
        // fully homogeneous at t=100 and its own observation must be 0 (newest and oldest both
        // t=100), not 100. (One push earlier already evicted the very first t=0 entry, leaving
        // RING_CAPACITY-1 t=0 entries to clear here.)
        for i in 0..RING_CAPACITY as u64 - 1 {
            push(RING_CAPACITY as u64 + 2 + i, 100);
        }
        assert_eq!(
            span_bucket_count(SHARD, 1.0),
            RING_CAPACITY as u64 + 1,
            "after a full turnover the push that completes it observes 0s of history — a \
             metric still recording 100 for that push would be describing events the ring has \
             already discarded, i.e. claiming replay cover that no longer exists"
        );
    }

    /// `u7s_watch_ring_span_seconds` must expose the WORST-CASE (minimum) span a shard has ever
    /// produced, not whatever its most recent push happened to be — because the worst case is
    /// the only reading a `RING_CAPACITY` sizing decision can safely be made against, and it is
    /// exactly what an external Prometheus poller reliably misses.
    ///
    /// Why it matters: a hot shard's per-push span oscillates between a long
    /// steady-state value and brief near-zero dips whenever the ring fully turns over — measured
    /// in production as ~2s dips lasting a single push, surrounded by spans of 10s-500s. The
    /// PRE-FIX gauge was `.set()` on every push and read by a poller sampling every 30s: at
    /// RING_CAPACITY=512 that caught the sub-10s dip on only 3 of 51 samples, and at
    /// RING_CAPACITY=1500 it never did, reporting a reassuring ~74s "minimum" that was almost
    /// certainly single-digit in reality — wrong in the dangerous direction for a safety signal.
    /// A test that reads a gauge immediately after a masking push cannot tell "we never dipped
    /// low" from "we dipped low and then moved on," which is the exact blind spot being fixed
    /// here — so this test does not read a single value at all; it inspects the accumulated
    /// distribution, which is what actually changed.
    ///
    /// This test reproduces that shape directly: fill a shard, fully turn it over (which forces
    /// exactly one push, the one that completes the turnover, to observe a near-zero span — see
    /// `ring_span_falls_when_eviction_discards_the_oldest_events` for why only that one push
    /// does), then immediately push one far-future event that makes the very next observation
    /// huge. A single "current value" reading taken after all of this — the only thing the old
    /// gauge could ever offer a poller — would show the huge value and hide that the shard had
    /// just spanned under a second. The low bucket must still show that dip regardless.
    ///
    /// Fails on revert: reverting `WATCH_RING_SPAN_SECONDS` to an `IntGaugeVec` does not compile
    /// against this test (no buckets to inspect) — the type change IS the fix, because a gauge
    /// has no way to retain a value it already overwrote.
    #[tokio::test]
    async fn watch_ring_span_seconds_reports_worst_case_replay_cover_not_last_polled_value() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        const SHARD: &str = "/registry/spantest-worstcase/";
        let push = |i: u64, at: u32| {
            store.push_event_at(
                Arc::new(InternalEvent {
                    key: format!("{SHARD}default/obj-{i}"),
                    revision: i,
                    value: Some(svc_value("obj", i)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
                at,
            );
        };

        // Fill the ring at t=0 — every one of these RING_CAPACITY pushes trivially observes 0
        // (a fresh/growing ring's oldest entry is always its own newest so far), which is why the
        // baseline count below is RING_CAPACITY, not 0.
        for i in 0..RING_CAPACITY as u64 {
            push(i + 1, 0);
        }
        // Fully turn it over at t=3: every push here observes 3s EXCEPT the very last one, which
        // completes the turnover and observes 0s — the ~2s-wide dip this bug is about. Exactly
        // one MORE push beyond the fill's baseline ever records a value <=1s.
        for i in 0..RING_CAPACITY as u64 {
            push(RING_CAPACITY as u64 + 1 + i, 3);
        }
        // Immediately mask it: one push far in the future makes the NEXT (and from here on,
        // every subsequent) observation huge, exactly as a poller landing after this instant
        // would see if it could only ever read "the current value".
        push(2 * RING_CAPACITY as u64 + 1, 1000);

        assert_eq!(
            span_bucket_count(SHARD, 1.0),
            RING_CAPACITY as u64 + 1,
            "the fill's RING_CAPACITY trivial zero-spans plus the one turnover-completing dip \
             must both still be visible in the low bucket even after the masking push — a \
             gauge's 'current value' at this point would show only the masking push's huge \
             span, with no way to tell that a <=1s span had ever occurred at all"
        );

        let total_pushes = 2 * RING_CAPACITY as u64 + 1;
        assert_eq!(
            span_metric(SHARD).get_histogram().get_sample_count(),
            total_pushes,
            "every push must be observed, not merely occasionally sampled — this is the actual \
             mechanism fix: a histogram records every write's span permanently, so a narrow \
             worst-case window can never simply go unseen the way it did under external polling"
        );
    }

    /// Opening a watch must record how many events it had to replay.
    ///
    /// Why it matters: replay depth is the only measurement we have of what clients actually
    /// NEED from the ring, as opposed to what the ring happens to hold. Every decision about
    /// `RING_CAPACITY` — including shrinking it to recover memory — is made against the tail of
    /// this distribution. If the instrumentation silently stops firing, the histogram reports an
    /// empty series, which is indistinguishable from the genuinely-desired state of "no watch
    /// ever needed a replay" — so a broken metric would read as a safe one, and we would size
    /// the ring off nothing at all.
    ///
    /// Drives a real `watch()` open rather than poking the metric directly, because the
    /// regression being guarded against is the `.observe()` call being dropped from the watch
    /// path, not the metric definition disappearing.
    ///
    /// Fails on revert: removing the observe leaves sample_count at 0.
    #[tokio::test]
    async fn watch_open_records_the_number_of_events_it_replayed() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        // Unique resource-type root: the histogram lives in the process-global prometheus
        // registry, so sharing a bucket label with another test would let them clobber each other.
        const BUCKET: &str = "/registry/replaydepth-test/";
        const EVENTS: u64 = 7;

        for i in 0..EVENTS {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("{BUCKET}default/obj-{i}"),
                    revision: i + 1,
                    value: Some(svc_value("obj", i + 1)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        let handle = crate::metrics::WATCH_REPLAY_DEPTH.with_label_values(&[BUCKET]);
        assert_eq!(
            handle.get_sample_count(),
            0,
            "test setup broken: this bucket must be untouched before the watch opens"
        );

        // The observation happens inside watch() before the stream is constructed, so awaiting
        // the open is enough — no need to poll any events out.
        let _stream = store.watch(BUCKET, 0).await.expect("watch must succeed");

        assert_eq!(
            handle.get_sample_count(),
            1,
            "one watch open must record exactly one replay-depth observation — a silently \
             uninstrumented histogram looks identical to 'nothing ever needed replaying'"
        );
        assert_eq!(
            handle.get_sample_sum(),
            EVENTS as f64,
            "the recorded depth must be the number of events actually replayed ({EVENTS}), not \
             the shard's occupancy or a constant — sizing RING_CAPACITY against a wrong \
             magnitude here would under- or over-provision the ring by whatever the error is"
        );
    }

    /// A watch on a quiet resource type must survive a busy resource type's eviction.
    ///
    /// Why it matters: expiry used to be decided against one process-wide `compaction_horizon`
    /// advanced by `fetch_max` from EVERY shard's eviction. Because a fast-churning shard retains
    /// only recent events, its oldest-retained revision is the HIGHEST of any shard, so the
    /// store-wide maximum tracked whichever resource type churned hardest and was then applied to
    /// all of them. A watch on a quiet type whose ring still held every event it ever saw would be
    /// told "too old resource version". The client relists and re-watches; if the busy type is
    /// still churning the horizon has moved again by then, so it can fail to ever re-establish —
    /// a relist loop that looks like controllers falling behind while the resource
    /// being watched is entirely intact.
    ///
    /// Fails on revert: restoring the global read makes the quiet watch yield
    /// `WatchEvent::Compacted` instead of replaying, and the explicit precondition assertion
    /// below documents exactly why (the store-wide horizon sits far above this watch's rv).
    #[tokio::test]
    async fn quiet_shard_watch_survives_a_busy_shard_eviction() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Quiet type: five low-revision events, far too few to ever evict.
        const QUIET_EVENTS: u64 = 5;
        for i in 0..QUIET_EVENTS {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/f8ziu-quiet/default/obj-{i}"),
                    revision: 10 + i,
                    value: Some(svc_value("obj", 10 + i)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        // Busy type: overflow its ring so it evicts and raises a high floor.
        for i in 0..(RING_CAPACITY as u64 + 1_000) {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/f8ziu-busy/default/obj-{i}"),
                    revision: 1_000 + i,
                    value: Some(svc_value("obj", 1_000 + i)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        // Precondition: the store-wide maximum is now far above the quiet watch's rv. This is
        // the value the old code expired against, and is what makes this test meaningful.
        let global = store.compaction_horizon();
        assert!(
            global > 5,
            "test setup broken: the busy shard must have evicted and pushed the store-wide \
             horizon ({global}) above the quiet watch's from_revision (5)"
        );
        assert_eq!(
            store.compaction_horizon_for("/registry/core/f8ziu-quiet/"),
            0,
            "the quiet shard never evicted, so its own floor must still be 0 — if this reports \
             the busy shard's floor the per-shard resolution is not working"
        );

        let stream = store
            .watch("/registry/core/f8ziu-quiet/", 5)
            .await
            .expect("watch must succeed");
        futures_util::pin_mut!(stream);

        let mut replayed = 0u64;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while replayed < QUIET_EVENTS {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(WatchEvent::Compacted { requested, horizon })) => panic!(
                    "quiet shard's watch was expired (requested rv {requested}, horizon \
                     {horizon}) even though its own ring still holds all {QUIET_EVENTS} of its \
                     events — the horizon was resolved store-wide instead of per-shard"
                ),
                Ok(Some(_)) => replayed += 1,
                Ok(None) => panic!("stream ended before replaying the quiet shard's events"),
                Err(_) => panic!(
                    "timed out after replaying {replayed} of {QUIET_EVENTS} quiet-shard events"
                ),
            }
        }
    }

    /// The inverse of the above: a watch below a shard's OWN floor must still be expired.
    ///
    /// Why it matters: the per-shard fix must not be implemented by weakening expiry generally.
    /// Silently serving a revision whose events this shard has genuinely evicted is strictly
    /// worse than the spurious-410 bug it replaces — the client would receive an incomplete
    /// replay and believe it had caught up, missing writes with no error anywhere.
    ///
    /// Fails on revert: an implementation that always returns 0 (e.g. never wiring the shard's
    /// floor on eviction) passes the sibling test above but fails here.
    #[tokio::test]
    async fn busy_shard_still_expires_a_watch_below_its_own_floor() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        for i in 0..(RING_CAPACITY as u64 + 1_000) {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/f8ziu-busy2/default/obj-{i}"),
                    revision: 1_000 + i,
                    value: Some(svc_value("obj", 1_000 + i)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        let own_floor = store.compaction_horizon_for("/registry/core/f8ziu-busy2/");
        assert!(
            own_floor > 1_000,
            "test setup broken: the busy shard must have evicted and set its own floor, got \
             {own_floor}"
        );

        let stream = store
            .watch("/registry/core/f8ziu-busy2/", 1_001)
            .await
            .expect("watch must succeed");
        futures_util::pin_mut!(stream);

        match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
            Ok(Some(WatchEvent::Compacted { .. })) => {}
            other => panic!(
                "a watch from rv 1001, below this shard's own floor of {own_floor}, must be \
                 expired with Compacted — anything else silently serves an incomplete replay as \
                 though it were the full history. Got: {other:?}"
            ),
        }
    }

    /// The shared `compaction_horizon` atomic must use `fetch_max`, not a plain `store`, when a
    /// shard evicts — otherwise a quieter shard's later, lower-revision eviction would regress
    /// the horizon backward after a busier shard already advanced it past that point.
    ///
    /// Why it matters: `compaction_horizon()` is intentionally one process-wide value shared by
    /// every shard (see its field doc on `SqliteStore`) — the HTTP layer's eager pre-watch 410
    /// check reads it before it knows which shard a watch belongs to. If it could regress, a
    /// client could be told a resourceVersion is still valid ("not expired") after the shard
    /// that actually holds it has already evicted it from its ring, so a subsequent replay would
    /// silently skip events instead of correctly returning `WatchEvent::Compacted`.
    ///
    /// Fails on revert (plain `.store()`): quiettype's first-ever eviction below evicts its own
    /// revision=1 event — far below the horizon the busy shard already set — and a plain store
    /// would overwrite the horizon back down to that low value.
    #[tokio::test]
    async fn compaction_horizon_never_regresses_when_a_quieter_shard_evicts_after_a_busier_one() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // 1. A quiet resource type gets a handful of low-revision events first — well under
        //    RING_CAPACITY, so none of them are evicted yet.
        const QUIET_SEED: u64 = 100;
        for i in 0..QUIET_SEED {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/quiettype/default/obj-{i}"),
                    revision: i + 1,
                    value: Some(svc_value("obj", i + 1)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
        }

        // 2. A busy resource type then fills past 2x RING_CAPACITY, evicting repeatedly and
        //    advancing compaction_horizon to a revision far higher than quiettype's own
        //    still-unevicted revision=1.
        let mut next_rev = QUIET_SEED + 1;
        for _ in 0..=(2 * RING_CAPACITY as u64) {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/busytype/default/obj-{next_rev}"),
                    revision: next_rev,
                    value: Some(svc_value("obj", next_rev)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
            next_rev += 1;
        }
        let horizon_after_busy_shard = store.compaction_horizon();
        assert!(
            horizon_after_busy_shard > QUIET_SEED,
            "test setup: the busy shard must have advanced the horizon well past quiettype's \
             still-unevicted revisions (1..={QUIET_SEED})"
        );

        // 3. The quiet resource type NOW overflows RING_CAPACITY for the first time, evicting
        //    its own oldest entry (revision=1) — far below the horizon already established.
        for _ in 0..(RING_CAPACITY as u64 - QUIET_SEED + 1) {
            store.push_event(
                Arc::new(InternalEvent {
                    key: format!("/registry/core/quiettype/default/obj-{next_rev}"),
                    revision: next_rev,
                    value: Some(svc_value("obj", next_rev)),
                    is_create: true,
                    deleted_body: None,
                }),
                Some("default"),
            );
            next_rev += 1;
        }

        assert!(
            store.compaction_horizon() >= horizon_after_busy_shard,
            "compaction_horizon must never regress below a value it already reached \
             ({horizon_after_busy_shard}); quiettype's own first eviction (of its revision=1 \
             event, far below that value) must not overwrite it — a plain `.store()` instead of \
             `fetch_max` would let this quieter shard's low-revision eviction silently un-expire \
             revisions the busy shard's ring has already discarded"
        );
    }

    // --- Ring shard lifecycle: create-on-first-watch, idle-GC after RING_SHARD_IDLE_GRACE ---
    //
    // A shard now exists only because a watch is or recently was open on its
    // resource type, not because something was written to it (see push_event_locked's and
    // SqliteStore::watch's doc comments). The five tests below guard each half of that
    // lifecycle plus the two races the design has to survive.

    /// A watch opened against a resource type with zero prior writes must create that type's
    /// shard immediately, not leave it absent until some future write.
    ///
    /// Why it matters: if watch-open stopped creating a shard, this watch would have no ring to
    /// reconnect into — a client that briefly disconnects (a pod restart, a network blip) would
    /// get no replay at all instead of the RING_SHARD_IDLE_GRACE window this whole lifecycle
    /// exists to provide, silently degrading every reconnect into a full relist.
    #[tokio::test]
    async fn watch_open_creates_shard_when_no_writes_yet() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/core/widgets/";

        assert!(
            !store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(prefix),
            "test setup: no shard should exist before anything has watched or written this type"
        );

        let _stream = store.watch(prefix, 0).await.expect("watch must succeed");

        assert!(
            store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(prefix),
            "watching a resource type with zero prior writes must create its shard immediately \
             — otherwise this watch has no ring to fall back on if it has to reconnect a moment \
             later"
        );
    }

    /// A write to a resource type nobody is watching must NOT create a shard — but must still
    /// be fully durable via sqlite.
    ///
    /// Why it matters: this is the entire memory-frugality point of the redesign
    /// — every ephemeral CRD type ever written otherwise ratchets the shard count up for
    /// the rest of the process's life, even though nothing is or will be watching most of them.
    /// If a write started creating shards again, that regression would be invisible from a
    /// client's point of view (reads still work) and would only show up as unbounded memory
    /// growth over a long-running process's lifetime.
    #[tokio::test]
    async fn write_without_watch_does_not_create_shard() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let key = "/registry/core/widgets/default/widget-a";
        let val = Bytes::from(
            r#"{"apiVersion":"v1","kind":"Widget","metadata":{"name":"widget-a","namespace":"default"}}"#,
        );

        let written_rv = store.put(key, val, None).await.expect("put must succeed");

        assert!(
            store.shards.read().expect("shards poisoned").is_empty(),
            "a write to a resource type with no open watch must not create a shard — doing so \
             would silently reintroduce the unbounded, monotonically-growing shard count this \
             whole lifecycle change exists to fix"
        );

        let fetched = store
            .get(key)
            .await
            .expect("get must not error")
            .expect("object must still be readable via sqlite even with no shard");
        assert_eq!(
            fetched.revision, written_rv,
            "sqlite remains the source of truth regardless of ring/shard state — the revision \
             put() returned must be exactly what a subsequent get() reads back"
        );

        let listed = store
            .list("/registry/core/widgets/", ListOptions::default())
            .await
            .expect("list must not error");
        assert_eq!(
            listed.items.len(),
            1,
            "list must still see the written object via sqlite even though no shard exists to \
             fan out a live event for it"
        );
    }

    /// A shard with zero attached watchers must survive until RING_SHARD_IDLE_GRACE elapses,
    /// then be torn down.
    ///
    /// Why it matters: tearing a shard down immediately on disconnect would defeat the whole
    /// point of the grace period — a client that reconnects a moment later (the common case;
    /// real client-go reconnects usually inside 5s) would find no ring to replay from and be
    /// forced into a full relist on every transient disconnect. Not tearing it down at all would
    /// silently reintroduce the unbounded shard growth this lifecycle exists to fix.
    #[tokio::test]
    async fn watch_disconnect_gc_after_grace_period() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/core/widgets/";

        let stream = store.watch(prefix, 0).await.expect("watch must succeed");
        drop(stream);

        assert!(
            store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(prefix),
            "the shard must survive immediately after disconnect — the grace period exists \
             precisely so a reconnect a moment later still has a ring to replay from"
        );

        tokio::time::sleep(RING_SHARD_IDLE_GRACE * 3).await;

        assert!(
            !store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(prefix),
            "a shard with zero watchers for longer than RING_SHARD_IDLE_GRACE must be torn down \
             — otherwise every resource type anything ever watched, even once and briefly, keeps \
             its shard for the rest of the process's life, which is the exact unbounded-growth \
             failure mode this lifecycle change exists to fix"
        );
    }

    /// A watch that reconnects with a stale `from_revision` after idle-GC has already reclaimed
    /// its shard must be told 410 Expired, not silently served an empty or fabricated replay.
    ///
    /// Why it matters: watch clients reconnecting with a stale RV after 120s idle-GC MUST
    /// receive 410 Expired, not a silent-empty or synthetic-ADDED replay that pretends to be
    /// gap-free history — else long-running controllers drift from apiserver truth and never
    /// know. `set_compaction_horizon_for_test` seeds a floor the shard had ALREADY earned by
    /// evicting real history before idle-GC ever touches it, so this exercises the ordinary
    /// "busy resource type" path, not the edge case the sibling test below covers.
    ///
    /// Fails on revert: reverting `tear_down_shard`/idle-GC's removal to a plain
    /// `HashMap::remove` (today's behavior) drops the floor along with the shard, so
    /// `compaction_horizon_for` falls back to 0 and the internal expiry check inside `watch()`
    /// never fires — the reconnect below would instead get a live (empty) stream.
    #[tokio::test]
    async fn watch_reconnect_after_idle_gc_reclaim_gets_expired_not_silent_replay() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/core/widgets-reclaim-busy/";

        // Give this shard a real, already-evicted floor before it is ever reclaimed — simulates
        // a resource type that churned enough to compact on its own, independent of idle-GC.
        store.set_compaction_horizon_for_test(prefix, 50);

        let stream = store.watch(prefix, 0).await.expect("watch must succeed");
        drop(stream);

        tokio::time::sleep(RING_SHARD_IDLE_GRACE * 3).await;

        assert!(
            !store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(prefix),
            "test setup broken: idle-GC must have reclaimed the shard for the reconnect below \
             to be a meaningful test of the reclaimed-vs-never-written distinction"
        );

        let reconnect = store.watch(prefix, 10).await.expect(
            "reconnect itself must succeed at the transport level — the 410 arrives as \
             a WatchEvent on the stream, not an Err from watch()",
        );
        futures_util::pin_mut!(reconnect);

        match tokio::time::timeout(Duration::from_millis(500), reconnect.next()).await {
            Ok(Some(WatchEvent::Compacted { .. })) => {}
            other => panic!(
                "watch clients reconnecting with a stale RV after 120s idle-GC MUST receive 410 \
                 Expired, not a silent-empty or synthetic-ADDED replay that pretends to be \
                 gap-free history — else long-running controllers drift from apiserver truth \
                 and never know. Got: {other:?}"
            ),
        }
    }

    /// A shard that never evicted anything (its own `horizon` floor stays 0 for its whole life)
    /// must still correctly expire a stale reconnect once idle-GC reclaims it — the preserved
    /// floor must come from the highest revision the ring ever actually held, not from the
    /// eviction-floor field alone.
    ///
    /// Why it matters: a quiet CRD whose entire history fit in the ring still holds real events
    /// a reconnecting client could be behind on once the ring is gone — the reclamation floor
    /// must reflect what was actually served, not just what was evicted. An implementation that
    /// carries forward only `shard.horizon` (0 here, since this shard never overflowed) would
    /// pass the sibling busy-shard test above yet still let this exact bug through.
    ///
    /// Fails on revert: without reading the ring's own highest-held revision at teardown, the
    /// preserved floor is 0 for this shard, `compaction_horizon_for` reports "not expired", and
    /// the reconnect below gets a live stream instead of Compacted.
    #[tokio::test]
    async fn watch_reconnect_after_idle_gc_reclaim_of_never_evicted_shard_gets_expired() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/core/widgets-reclaim-quiet/";

        // Two events only — nowhere near RING_CAPACITY, so this shard's own `horizon` (the
        // eviction floor) never advances past 0.
        store.push_event(
            Arc::new(InternalEvent {
                key: format!("{prefix}default/widget-a"),
                revision: 5,
                value: Some(svc_value("widget-a", 5)),
                is_create: true,
                deleted_body: None,
            }),
            Some("default"),
        );
        store.push_event(
            Arc::new(InternalEvent {
                key: format!("{prefix}default/widget-b"),
                revision: 10,
                value: Some(svc_value("widget-b", 10)),
                is_create: true,
                deleted_body: None,
            }),
            Some("default"),
        );

        assert_eq!(
            store.compaction_horizon_for(prefix),
            0,
            "test setup broken: this shard must never have evicted anything — otherwise this \
             test is indistinguishable from the sibling busy-shard test and cannot prove the \
             fix reads the ring's own history rather than just the eviction floor"
        );

        let stream = store.watch(prefix, 0).await.expect("watch must succeed");
        drop(stream);

        tokio::time::sleep(RING_SHARD_IDLE_GRACE * 3).await;

        assert!(
            !store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(prefix),
            "test setup broken: idle-GC must have reclaimed the shard for the reconnect below \
             to be a meaningful test"
        );

        // Behind the shard's highest-ever-held revision (10) but above its (always-0) eviction
        // floor — only a fix that reads the ring's own history at teardown expires this.
        let reconnect = store.watch(prefix, 7).await.expect(
            "reconnect itself must succeed at the transport level — the 410 arrives as \
             a WatchEvent on the stream, not an Err from watch()",
        );
        futures_util::pin_mut!(reconnect);

        match tokio::time::timeout(Duration::from_millis(500), reconnect.next()).await {
            Ok(Some(WatchEvent::Compacted { .. })) => {}
            other => panic!(
                "a quiet CRD whose entire history fit in the ring still holds real events a \
                 reconnecting client could be behind on once the ring is gone — the \
                 reclamation floor must reflect what was actually served, not just what was \
                 evicted. Got: {other:?}"
            ),
        }
    }

    /// A watch that reconnects to the same prefix DURING the grace window must cancel the
    /// pending teardown — the shard must still exist after the original grace deadline passes.
    ///
    /// Why it matters: this is the mechanism that makes the grace period actually useful rather
    /// than just a fixed delay before eviction happens anyway. Without this re-check, a client
    /// that reconnects at, say, 90s into a 120s grace window would still lose its ring at the
    /// 120s mark even though it is actively watching again — turning every reconnect race into a
    /// coin flip between "ring survives" and "ring evicted out from under an active watcher."
    #[tokio::test]
    async fn watch_reconnect_during_grace_window_cancels_gc() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/core/widgets/";

        let first = store.watch(prefix, 0).await.expect("watch must succeed");
        drop(first);

        // Reconnect well within the grace window.
        tokio::time::sleep(RING_SHARD_IDLE_GRACE / 4).await;
        let second = store
            .watch(prefix, 0)
            .await
            .expect("reconnect during grace window must succeed");

        // Wait past the FIRST watch's own grace deadline (measured from its own disconnect).
        tokio::time::sleep(RING_SHARD_IDLE_GRACE).await;

        assert!(
            store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(prefix),
            "a watch that reconnected during the grace window must have cancelled the pending \
             teardown — losing the shard here means idle-GC evicted it while a client was \
             actively watching it again, not merely 'nobody watched for a while'"
        );

        drop(second);
    }

    /// Churning far more abandoned namespace-scoped prefixes than `MAX_RECLAIMED_HORIZONS` must
    /// keep `reclaimed_horizons.entries` bounded WITHOUT making a still-relevant reconnect see
    /// horizon 0 for one of the evicted prefixes.
    ///
    /// Why it matters: a namespace-scoped watch prefix is, by construction, never reused (each
    /// ephemeral test/CI namespace gets a fresh name), so nothing short of an explicit cap keeps
    /// this map bounded — that unbounded growth is a memory leak scaling with namespace churn.
    /// But a cap that just discards the entry it evicts would make `compaction_horizon_for` (and
    /// `get_or_create_shard`'s reseed-on-recreate) report 0 — "no horizon known" — for that
    /// prefix, and a watch reconnecting there with a genuinely stale from_revision would then be
    /// silently told it is already caught up instead of getting 410 Expired, skipping every event
    /// it should have replayed.
    ///
    /// Fails on revert: reverting `preserve_reclaimed_horizon` back to an unbounded insert leaves
    /// every one of the 4,596 entries below alive individually, which the length assertion
    /// catches. Reverting to a cap that discards instead of folds the evicted entry into
    /// `overflow` makes `ns-0`'s horizon come back as 0 below instead of > 1, and the final
    /// reconnect gets a live stream instead of `Compacted`.
    #[tokio::test]
    async fn reclaimed_horizons_bounded_and_evicted_prefix_still_gets_correct_nonzero_horizon() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let root = "/registry/core/widgets-churn/";

        // Horizons increase with `i`, mirroring the store's own globally-increasing revision
        // counter — `ns-0`'s floor (1) is the smallest and so the first eviction candidate.
        let churn = MAX_RECLAIMED_HORIZONS + 500;
        for i in 0..churn {
            let prefix = format!("{root}ns-{i}/");
            store.set_compaction_horizon_for_test(&prefix, (i + 1) as u64);
            tear_down_shard(&store.shards, &store.reclaimed_horizons, &prefix);
        }

        let len = store
            .reclaimed_horizons
            .read()
            .expect("reclaimed_horizons poisoned")
            .entries
            .len();
        assert!(
            len <= MAX_RECLAIMED_HORIZONS,
            "reclaimed_horizons.entries must stay bounded regardless of how many distinct \
             namespace prefixes have ever been abandoned — {churn} torn-down prefixes left {len} \
             entries behind, which is unbounded growth by another name"
        );

        let evicted_prefix = format!("{root}ns-0/");
        assert!(
            !store
                .reclaimed_horizons
                .read()
                .expect("reclaimed_horizons poisoned")
                .entries
                .contains_key(&evicted_prefix),
            "test setup broken: ns-0 (lowest horizon, so the first eviction candidate) must \
             actually have been evicted for the rest of this test to prove the overflow-fallback \
             path works, rather than trivially passing because its exact entry survived"
        );

        // Every eviction past the cap folds a HIGHER horizon into the shared `overflow` atomic
        // via fetch_max (see `preserve_reclaimed_horizon`'s doc), so the aggregate must exceed
        // ns-0's own original floor of 1 — this also rules out the eviction/fold logic silently
        // stopping after the first fold.
        let horizon = store.compaction_horizon_for(&evicted_prefix);
        assert!(
            horizon > 1,
            "ns-0's own entry was evicted under the cap, but its floor must still be \
             recoverable (as a lower bound, via the process-wide overflow atomic) — a plain \
             discard-on-evict cap would report 0 here, wrongly telling a reconnecting watch it \
             is already caught up. Got horizon={horizon}"
        );

        // from_revision=1 is stale relative to `horizon` (>1) — a client that saw nothing past
        // revision 1 before this prefix went quiet and everything after was discarded.
        let reconnect = store.watch(&evicted_prefix, 1).await.expect(
            "reconnect itself must succeed at the transport level — the 410 arrives as a \
             WatchEvent on the stream, not an Err from watch()",
        );
        futures_util::pin_mut!(reconnect);
        match tokio::time::timeout(Duration::from_millis(500), reconnect.next()).await {
            Ok(Some(WatchEvent::Compacted { .. })) => {}
            other => panic!(
                "a watch reconnecting with a stale from_revision on a prefix whose own entry \
                 was evicted under the cap must get 410 Expired, not a live stream that \
                 silently starts from scratch as if nothing had ever been discarded. \
                 Got: {other:?}"
            ),
        }
    }

    /// Evicting far more distinct CHILDLESS resource-type roots (no namespace child ever created
    /// for any of them) than `MAX_RECLAIMED_HORIZONS` must keep `entries` bounded the same way,
    /// and a later query for a namespace under one of those evicted roots that has NEVER been
    /// seen before must still get a correct, nonzero floor.
    ///
    /// Why it matters: this is exactly the shape that broke every prior fold-to-a-parent-map-key
    /// design (three attempts). Each root here also gets its OWN unique group segment, so
    /// its `parent_prefix` fold target is a NOVEL key every single time — under a design that
    /// folds an evicted victim into that parent key, an unconditional insert of a novel key
    /// leaves the map's net size unchanged (not -1), so it never shrinks back under the cap. This
    /// design has no such failure mode because the fold destination is a single atomic, which can
    /// never be a "novel key" the map has to grow to hold.
    ///
    /// Fails on revert: reverting `preserve_reclaimed_horizon`'s fold-to-atomic back to
    /// fold-to-parent-map-key (the prior design's shape) leaves `entries.len()` growing by
    /// roughly one per churned root below instead of staying capped, which the length assertion
    /// catches. Reverting to a cap that discards instead of folds makes `horizon` below come back
    /// as 0 and the final reconnect get a live stream instead of `Compacted`.
    #[tokio::test]
    async fn reclaimed_horizons_evicted_childless_root_still_gets_correct_nonzero_horizon() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");

        // Seeded from i+2 (not i+1): from_revision=0 is treated by `watch()` as "fresh, no
        // history claimed" and skips the expiry check entirely, so the reconnect below needs a
        // from_revision that is both > 0 AND strictly less than root-churn-0's own floor —
        // impossible if that floor were exactly 1.
        let churn = MAX_RECLAIMED_HORIZONS + 10;
        for i in 0..churn {
            let root = format!("/registry/group-{i}/root-churn-{i}/");
            store.set_compaction_horizon_for_test(&root, (i + 2) as u64);
            tear_down_shard(&store.shards, &store.reclaimed_horizons, &root);
        }

        let len = store
            .reclaimed_horizons
            .read()
            .expect("reclaimed_horizons poisoned")
            .entries
            .len();
        assert!(
            len <= MAX_RECLAIMED_HORIZONS,
            "reclaimed_horizons.entries must stay bounded even when every evicted victim's \
             parent_prefix fold target is a novel key — {churn} torn-down childless roots left \
             {len} entries behind, which is unbounded growth by another name (this is the exact \
             shape that broke the prior fold-to-parent-key design)"
        );

        let evicted_root = "/registry/group-0/root-churn-0/";
        assert!(
            !store
                .reclaimed_horizons
                .read()
                .expect("reclaimed_horizons poisoned")
                .entries
                .contains_key(evicted_root),
            "test setup broken: root-churn-0 (lowest horizon, so the first eviction candidate) \
             must actually have been evicted — a CHILDLESS root, unlike the sibling test's \
             namespace leaves — for the rest of this test to prove the childless-root fold path"
        );

        // A namespace under root-churn-0's resource type that has never been seen before — no
        // exact entry for it could possibly exist, and root-churn-0 itself is also gone (evicted
        // above), so this can only recover a nonzero floor via the overflow fallback.
        let fresh_namespace_prefix = format!("{evicted_root}never-seen-ns/");
        let horizon = store.compaction_horizon_for(&fresh_namespace_prefix);
        assert!(
            horizon >= 2,
            "root-churn-0's own entry was evicted (a childless root has no namespace child to \
             special-case around), but a floor at least as high as its true value of 2 must \
             still be reachable from a brand-new namespace query under the SAME resource type — \
             0 here would silently tell a reconnecting watch on that namespace it is already \
             caught up, even though this resource type's own history was discarded. \
             Got horizon={horizon}"
        );

        let reconnect = store.watch(&fresh_namespace_prefix, 1).await.expect(
            "reconnect itself must succeed at the transport level — the 410 arrives as a \
             WatchEvent on the stream, not an Err from watch()",
        );
        futures_util::pin_mut!(reconnect);
        match tokio::time::timeout(Duration::from_millis(500), reconnect.next()).await {
            Ok(Some(WatchEvent::Compacted { .. })) => {}
            other => panic!(
                "a watch on a brand-new namespace under a resource type whose childless ROOT was \
                 evicted under the cap must still get 410 Expired for a stale from_revision, not \
                 a live stream that silently starts from scratch as if this resource type had no \
                 history at all. Got: {other:?}"
            ),
        }
    }

    /// A namespace-scoped CHILD shard created for the first time AFTER its all-namespaces ROOT
    /// sibling was torn down (with a real, un-evicted floor still sitting in
    /// `reclaimed_horizons.entries`) must inherit that floor at creation — not seed 0 — because
    /// `compaction_horizon_for` reads a LIVE shard's own `horizon` field directly once the shard
    /// exists (see that method's doc), never consulting `reclaimed_horizons` again for the rest
    /// of that shard's life.
    ///
    /// Why it matters: a shard seeded at 0 tells every future reconnect on that namespace it is
    /// already caught up regardless of how stale its `from_revision` really is — the exact
    /// silent event loss `reclaimed_horizons` exists to prevent, just triggered by the ONE path
    /// (shard creation, not lookup) that used a narrower exact-match-only chain than
    /// `find_reclaimed_horizon`'s own exact/parent/overflow chain.
    ///
    /// Fails on revert: reverting `get_or_create_shard`'s reseed to exact-match-then-overflow
    /// (skipping the one parent hop) makes `horizon` below come back as 0 instead of the root's
    /// true floor of 100, since neither the exact child key nor `overflow` (never bumped here —
    /// the root's single entry never exceeded the cap) carries it.
    #[tokio::test]
    async fn get_or_create_shard_reseeds_child_from_torn_down_root_parent_entry() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let root = "/registry/core/widgets/";
        let child = "/registry/core/widgets/default/";

        // A real, nonzero floor whose entry survives (the cap is 4096, and this is the only
        // entry ever inserted) — exactly the "un-evicted parent record" shape the review
        // reproduced, ruling out the already-correct overflow fallback from covering for a
        // missing parent hop here.
        store.set_compaction_horizon_for_test(root, 100);
        tear_down_shard(&store.shards, &store.reclaimed_horizons, root);

        // from_revision=0 means "no history claimed" (see `watch()`'s own doc), so this always
        // opens live rather than 410ing — the shard for `child` is created for the first time
        // right here, via `get_or_create_shard`'s reseed path. The returned stream must be kept
        // alive: dropping it would release `ShardWatcherGuard` and let idle-GC race the
        // assertion below.
        let watch = store
            .watch(child, 0)
            .await
            .expect("fresh watch with from_revision=0 must always open live, never 410");

        let horizon = store.compaction_horizon_for(child);
        assert!(
            horizon >= 100,
            "child's own resource-type root was torn down with a real floor of 100 that is \
             still an un-evicted entry in reclaimed_horizons — the child shard's reseed must \
             recover it via the same parent-hop find_reclaimed_horizon uses, not silently seed \
             0 and tell every future reconnect on this namespace it is already caught up. \
             Got horizon={horizon}"
        );

        drop(watch);
    }

    /// A shard idle-GC teardown racing against a concurrent write to the same prefix must never
    /// panic and must never lose the write — sqlite persistence, not ring survival, is the
    /// correctness bar.
    ///
    /// Why it matters: this is the write-vs-teardown race the redesign's correctness analysis
    /// depends on being safe — teardown removes a shard under `shards`' write lock, while a
    /// concurrent write reads `shards` to find shards to fan out to. If those two operations
    /// were not mutually exclusive (e.g. a write read a shard reference, teardown dropped the
    /// last OTHER reference concurrently, and the write then touched freed memory), this would
    /// be a use-after-free; if the locking were merely sloppy rather than unsound, it could still
    /// silently drop the shard's own copy of an event without falling back to sqlite. Hammering
    /// real concurrent writes against repeated real teardown calls on the same shard is what
    /// would expose either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn race_write_vs_teardown_does_not_lose_broadcast() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let prefix = "/registry/core/racers/";

        // Create the shard the way a real watch would; kept open for the whole test so the
        // stream itself never becomes a confounding variable in this race.
        let stream = store.watch(prefix, 0).await.expect("watch must succeed");
        futures_util::pin_mut!(stream);

        const N: usize = 200;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));

        let writer_store = Arc::clone(&store);
        let writer_barrier = Arc::clone(&barrier);
        let writer = tokio::spawn(async move {
            writer_barrier.wait().await;
            for i in 0..N {
                let key = format!("{prefix}racer-{i}");
                let val = Bytes::from(format!(
                    r#"{{"apiVersion":"v1","kind":"Racer","metadata":{{"name":"racer-{i}"}}}}"#
                ));
                writer_store
                    .put(&key, val, None)
                    .await
                    .expect("put must succeed even if its own shard is concurrently torn down");
            }
        });

        let teardown_shards = Arc::clone(&store.shards);
        let teardown_reclaimed_horizons = Arc::clone(&store.reclaimed_horizons);
        let teardown_barrier = Arc::clone(&barrier);
        let teardown = tokio::spawn(async move {
            teardown_barrier.wait().await;
            // Simulates idle-GC's teardown firing repeatedly mid-write-burst. Unconditional (the
            // shard's watcher count is irrelevant here) — this test exercises the write path's
            // locking under concurrent removal, which is exactly what tear_down_shard performs
            // for real idle-GC too, just without the surrounding idle re-check.
            for _ in 0..N {
                tear_down_shard(&teardown_shards, &teardown_reclaimed_horizons, prefix);
            }
        });

        writer.await.expect("writer task must not panic");
        teardown.await.expect("teardown task must not panic");

        // Sqlite, not the ring, is the source of truth: every write must be durably persisted
        // regardless of whether its own shard survived the race against teardown.
        let listed = store
            .list(prefix, ListOptions::default())
            .await
            .expect("list must not error");
        assert_eq!(
            listed.items.len(),
            N,
            "every one of {N} concurrent writes must be durably persisted via sqlite even under \
             a shard being repeatedly torn down mid-burst — losing one here means the write path \
             lost data instead of merely losing ring/replay history"
        );
    }

    /// A create-then-delete on a resource type nobody has ever watched, followed LATER by a
    /// watch that asks for history starting at the create's own revision, must still observe
    /// the delete — exactly the "list/watch/create/delete" priming sequence upstream's CRD e2e
    /// fixtures use (`isWatchCachePrimed`) to warm a fresh watch cache before relying on it.
    ///
    /// Why it matters: create-on-first-watch's backfill (`SqliteStore::watch`'s `created_fresh`
    /// branch) reconstructs a brand-new shard's history from `list()`'s CURRENT state, which by
    /// definition cannot include an object that has already been deleted. If neither the create
    /// nor the delete ever touched a shard (because nobody was watching yet), the delete is
    /// unrecoverable — a watch opened afterward asking for it waits forever. This is the exact
    /// "gave up waiting for watch event" failure blocking CustomResourceDefinition Watch and
    /// every FieldValidation/AggregatedDiscovery test that creates a CRD through the shared
    /// `CreateNewV1CustomResourceDefinition` fixture.
    #[tokio::test]
    async fn delete_before_any_watch_is_still_observed_by_a_later_historical_watch() {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let prefix = "/registry/mygroup.example.com/widgets/";
        let key = "/registry/mygroup.example.com/widgets/default/setup-instance";
        let val = Bytes::from(
            r#"{"apiVersion":"mygroup.example.com/v1","kind":"Widget","metadata":{"name":"setup-instance","namespace":"default"}}"#,
        );

        assert!(
            store.shards.read().expect("shards poisoned").is_empty(),
            "test setup: nothing has watched or written this resource type yet"
        );

        let created_rv = store
            .put(key, val, None)
            .await
            .expect("create must succeed");
        let (deleted_rv, _) = store
            .delete(key, Some(created_rv))
            .await
            .expect("delete must succeed");
        assert!(
            deleted_rv > created_rv,
            "delete must bump the revision past the create it is deleting"
        );

        // Opened only NOW — strictly after both the create and the delete completed, with zero
        // watchers ever attached in between. Requests history starting at the create's own
        // revision, exactly like a client that already observed the create and now wants
        // everything since.
        let stream = store
            .watch(prefix, created_rv)
            .await
            .expect("watch must succeed");
        futures_util::pin_mut!(stream);

        let event = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect(
                "a watch requesting history from the create's own revision must observe the \
                 delete that happened before it ever opened — timing out here means the delete \
                 was silently lost because no shard existed to record it",
            )
            .expect("stream must not end");
        match event {
            WatchEvent::Deleted {
                key: deleted_key, ..
            } => {
                assert_eq!(
                    deleted_key, key,
                    "the observed delete must be for the object that was actually deleted"
                );
            }
            other => panic!("expected a Deleted event, got {other:?}"),
        }
    }

    /// A caller that only knows `S: Store` (exactly how `handlers/watch.rs`'s
    /// `watch_generic_impl<S: Store>` reaches the store) must see the same per-shard value a
    /// caller holding a concrete `SqliteStore` sees — never the trait's cross-shard-max default.
    fn compaction_horizon_for_via_store_bound<S: Store>(store: &S, prefix: &str) -> u64 {
        store.compaction_horizon_for(prefix)
    }

    /// Fails on revert: if `impl Store for SqliteStore` does not override `compaction_horizon_for`,
    /// a generic `S: Store` bound resolves the call to the trait's default method (cross-shard
    /// max) instead of `SqliteStore`'s inherent per-shard method — Rust generic dispatch has no
    /// visibility into a type's inherent impls once code is compiled against only a trait bound,
    /// so this is invisible to every OTHER test in this file, which all call through a concrete
    /// `SqliteStore` value and therefore resolve to the inherent method regardless of whether the
    /// override exists.
    ///
    /// Why it matters: the eager pre-stream 410 check in `handlers/watch.rs` is generic-bounded
    /// on `S: Store`; if `impl Store for SqliteStore` silently inherits the cross-shard-max
    /// default, a fresh watch on shard X gets its `from_revision` compared against the max
    /// horizon across ALL shards, spuriously firing 410 Gone whenever any other resource type has
    /// advanced its horizon — reintroducing the exact per-shard-vs-cross-shard ambiguity the
    /// `compaction_horizon_for` inherent method exists to resolve.
    #[tokio::test]
    async fn compaction_horizon_for_via_generic_store_bound_matches_per_shard_not_cross_shard_max()
    {
        let store = SqliteStore::new(":memory:").expect("in-memory store");
        let busy_prefix = "/registry/core/ghp6f-busy/";
        let quiet_prefix = "/registry/core/ghp6f-quiet/";

        // Busy shard: a real, high floor that would leak into the quiet shard's answer if the
        // generic-bound call resolved to the cross-shard-max default instead of the per-shard
        // inherent method.
        store.set_compaction_horizon_for_test(busy_prefix, 500);

        // Quiet shard: never evicted anything, then reclaimed by idle-GC — its per-shard floor
        // comes from `reclaimed_horizons`, a second code path the fix must also cover, not just
        // the still-live-shard path `busy_prefix` exercises above.
        store.push_event(
            Arc::new(InternalEvent {
                key: format!("{quiet_prefix}default/widget-a"),
                revision: 7,
                value: Some(svc_value("widget-a", 7)),
                is_create: true,
                deleted_body: None,
            }),
            Some("default"),
        );
        let stream = store
            .watch(quiet_prefix, 0)
            .await
            .expect("watch must succeed");
        drop(stream);
        tokio::time::sleep(RING_SHARD_IDLE_GRACE * 3).await;
        assert!(
            !store
                .shards
                .read()
                .expect("shards poisoned")
                .contains_key(quiet_prefix),
            "test setup broken: idle-GC must have reclaimed the quiet shard for this test to \
             exercise the reclaimed-horizon fallback, not the still-live-shard path"
        );

        let via_concrete = store.compaction_horizon_for(quiet_prefix);
        assert_eq!(
            via_concrete, 7,
            "test setup broken: the quiet shard's own floor must be its highest-ever-held \
             revision (7), not the busy shard's (500) — otherwise this test cannot distinguish \
             per-shard from cross-shard-max"
        );

        let via_bound = compaction_horizon_for_via_store_bound(&store, quiet_prefix);
        assert_eq!(
            via_bound, via_concrete,
            "a generic `S: Store` caller (handlers/watch.rs's watch_generic_impl) must see the \
             SAME per-shard floor a concrete-type caller sees; if `impl Store for SqliteStore` \
             does not override `compaction_horizon_for`, this call falls through to the trait's \
             cross-shard-max default and returns 500 (the busy shard's floor) instead of 7 (this \
             shard's own floor), spuriously 410-ing a watch reconnect that is nowhere near \
             expired"
        );
    }
}
