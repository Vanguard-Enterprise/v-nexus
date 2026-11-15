//! The agent's outbound queue for one connection, with the flow control rules of
//! `docs/agent-protocol.md` (Acknowledgements and flow control):
//!
//! - Snapshot messages (`snapshot_start`, its `upsert` messages, `snapshot_end`,
//!   `snapshot_abort`) and `collection_error` stay in order and are never merged.
//! - Watch events coalesce per collection and UID, but only after the collection's
//!   latest `snapshot_end`, and never across a snapshot message of the same collection:
//!   a newer event replaces the pending one in place, and a `delete` replaces a pending
//!   `upsert`.
//! - A new snapshot of a collection drops the unsent remainder of the previous one and
//!   sends `snapshot_abort` for it, unless its `snapshot_start` was never sent either.
//!
//! So memory holds at most one snapshot's items per collection plus one pending change
//! per resource, however fast events arrive. The connection takes messages from the
//! front only while its acknowledgement window has room.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use uuid::Uuid;
use vn_core::agent_protocol::{Message, SnapshotAbort};
use vn_core::inventory::Collection;

/// A message ready to send: its type and its body, already encoded as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub kind: &'static str,
    pub body: String,
}

impl Outgoing {
    pub fn new<M: Message>(body: &M) -> Self {
        Self {
            kind: M::TYPE,
            body: serde_json::to_string(body).expect("message bodies serialize to JSON"),
        }
    }

    /// The text frame of this message as message `seq`.
    pub fn frame(&self, seq: u64) -> String {
        let kind = serde_json::to_string(self.kind).expect("strings serialize");
        format!(r#"{{"type":{kind},"seq":{seq},"body":{}}}"#, self.body)
    }

    /// The frame's size in bytes for any `seq`, at most.
    pub fn frame_len(&self) -> usize {
        // `{"type":"","seq":,"body":}` plus the type and a 20-digit seq.
        26 + self.kind.len() + 20 + self.body.len()
    }
}

#[derive(Debug)]
enum Slot {
    /// A message outside inventory, such as an `error` answer.
    Control(Outgoing),
    /// A snapshot message or `collection_error`: ordered, never merged.
    Ordered {
        snapshot: Option<Uuid>,
        is_start: bool,
        message: Outgoing,
    },
    /// A watch event. Its current content is in [`Queue::watch`] under the key.
    Watch(WatchKey),
}

/// Watch events coalesce under the same key. `segment` changes with every ordered
/// message of the collection, so events never merge across one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WatchKey {
    collection: Collection,
    uid: String,
    segment: u64,
}

#[derive(Debug, Clone, Copy)]
struct CurrentSnapshot {
    id: Uuid,
    ended: bool,
}

/// The queue's state. [`SyncQueue`] shares it between the collectors and the connection.
#[derive(Debug, Default)]
pub struct Queue {
    slots: VecDeque<Slot>,
    watch: HashMap<WatchKey, Outgoing>,
    segments: HashMap<Collection, u64>,
    current: HashMap<Collection, CurrentSnapshot>,
    /// Gives uncoalescable watch events distinct keys.
    next_unique: u64,
}

impl Queue {
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The next message to send.
    pub fn pop(&mut self) -> Option<Outgoing> {
        loop {
            let message = match self.slots.pop_front()? {
                Slot::Control(message) | Slot::Ordered { message, .. } => Some(message),
                Slot::Watch(key) => self.watch.remove(&key),
            };
            if message.is_some() {
                return message;
            }
        }
    }

    /// Queues a message outside inventory.
    pub fn control(&mut self, message: Outgoing) {
        self.slots.push_back(Slot::Control(message));
    }

    /// Starts snapshot `id` of `collection` with its `snapshot_start`, abandoning the
    /// previous snapshot if it has unsent messages or has not ended.
    pub fn begin_snapshot(&mut self, collection: Collection, id: Uuid, start: Outgoing) {
        self.abandon(collection, "replaced");
        self.current
            .insert(collection, CurrentSnapshot { id, ended: false });
        self.ordered(collection, Some(id), true, start);
    }

    /// Queues an item or the end of the collection's current snapshot `id`.
    pub fn snapshot_message(
        &mut self,
        collection: Collection,
        id: Uuid,
        message: Outgoing,
        end: bool,
    ) {
        if end && let Some(current) = self.current.get_mut(&collection) {
            current.ended = true;
        }
        self.ordered(collection, Some(id), false, message);
    }

    /// Abandons the collection's current snapshot: drops its unsent messages and, if its
    /// `snapshot_start` was already sent, queues `snapshot_abort` with `reason`. Does
    /// nothing when the snapshot ended and was sent completely.
    pub fn abandon(&mut self, collection: Collection, reason: &str) {
        let Some(current) = self.current.remove(&collection) else {
            return;
        };
        let mut unsent = false;
        let mut start_unsent = false;
        self.slots.retain(|slot| match slot {
            Slot::Ordered {
                snapshot: Some(id),
                is_start,
                ..
            } if *id == current.id => {
                unsent = true;
                start_unsent |= *is_start;
                false
            }
            _ => true,
        });
        if current.ended && !unsent {
            return;
        }
        if !start_unsent {
            let abort = Outgoing::new(&SnapshotAbort {
                snapshot_id: current.id,
                reason: reason.to_owned(),
            });
            self.ordered(collection, Some(current.id), false, abort);
        }
    }

    /// Queues an ordered message of `collection` that belongs to no snapshot, such as
    /// `collection_error`.
    pub fn collection_message(&mut self, collection: Collection, message: Outgoing) {
        self.ordered(collection, None, false, message);
    }

    /// Queues a watch event for the object `uid`, replacing a pending event for it when
    /// the rules allow.
    pub fn watch_event(&mut self, collection: Collection, uid: &str, message: Outgoing) {
        let coalesce = self.current.get(&collection).is_none_or(|s| s.ended);
        let segment = if coalesce {
            self.segments.get(&collection).copied().unwrap_or(0)
        } else {
            // Not after a `snapshot_end`: give the event a key nothing else shares. The
            // high bit keeps these apart from segment numbers.
            self.next_unique += 1;
            self.next_unique | (1 << 63)
        };
        let key = WatchKey {
            collection,
            uid: uid.to_owned(),
            segment,
        };
        if let Some(pending) = self.watch.get_mut(&key) {
            *pending = message;
            return;
        }
        self.watch.insert(key.clone(), message);
        self.slots.push_back(Slot::Watch(key));
    }

    fn ordered(
        &mut self,
        collection: Collection,
        snapshot: Option<Uuid>,
        is_start: bool,
        message: Outgoing,
    ) {
        *self.segments.entry(collection).or_default() += 1;
        self.slots.push_back(Slot::Ordered {
            snapshot,
            is_start,
            message,
        });
    }
}

/// A [`Queue`] shared by the collectors, which add to it, and the connection, which
/// sends from it. Cloning shares the same queue.
#[derive(Debug, Clone, Default)]
pub struct SyncQueue {
    queue: Arc<Mutex<Queue>>,
    ready: Arc<Notify>,
}

impl SyncQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Changes the queue and wakes the connection.
    pub fn update<R>(&self, change: impl FnOnce(&mut Queue) -> R) -> R {
        let result = change(&mut self.lock());
        self.ready.notify_one();
        result
    }

    /// The next message to send, if any.
    pub fn pop(&self) -> Option<Outgoing> {
        self.lock().pop()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Resolves after the queue changed. A change while nobody waits is remembered, so
    /// none is missed.
    pub async fn changed(&self) {
        self.ready.notified().await;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const NODES: Collection = Collection::Nodes;
    const DEPLOYMENTS: Collection = Collection::Deployments;

    /// A message whose type and body name it, for readable assertions.
    fn msg(kind: &'static str, body: Value) -> Outgoing {
        Outgoing {
            kind,
            body: body.to_string(),
        }
    }

    fn drain(queue: &mut Queue) -> Vec<(String, Value)> {
        std::iter::from_fn(|| queue.pop())
            .map(|m| (m.kind.to_owned(), serde_json::from_str(&m.body).unwrap()))
            .collect()
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn frames_are_envelopes() {
        let message = msg("upsert", json!({"uid": "a"}));
        let frame = message.frame(7);
        assert_eq!(frame, r#"{"type":"upsert","seq":7,"body":{"uid":"a"}}"#);
        assert!(message.frame_len() >= message.frame(u64::MAX).len());
    }

    #[test]
    fn snapshot_messages_stay_in_order_and_unmerged() {
        let mut q = Queue::default();
        q.begin_snapshot(NODES, id(1), msg("snapshot_start", json!(1)));
        q.snapshot_message(
            NODES,
            id(1),
            msg("upsert", json!({"uid": "a", "v": 1})),
            false,
        );
        q.snapshot_message(
            NODES,
            id(1),
            msg("upsert", json!({"uid": "a", "v": 2})),
            false,
        );
        q.snapshot_message(NODES, id(1), msg("snapshot_end", json!(1)), true);
        let sent = drain(&mut q);
        assert_eq!(
            sent.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            ["snapshot_start", "upsert", "upsert", "snapshot_end"]
        );
    }

    #[test]
    fn watch_events_coalesce_per_uid_after_the_snapshot_end() {
        let mut q = Queue::default();
        q.begin_snapshot(NODES, id(1), msg("snapshot_start", json!(1)));
        q.snapshot_message(NODES, id(1), msg("snapshot_end", json!(1)), true);
        q.watch_event(NODES, "a", msg("upsert", json!({"uid": "a", "v": 1})));
        q.watch_event(NODES, "b", msg("upsert", json!({"uid": "b", "v": 1})));
        q.watch_event(NODES, "a", msg("upsert", json!({"uid": "a", "v": 2})));
        q.watch_event(NODES, "b", msg("delete", json!({"uid": "b"})));
        // Another collection's events and UIDs are separate.
        q.watch_event(DEPLOYMENTS, "a", msg("upsert", json!({"uid": "a", "d": 1})));
        let sent = drain(&mut q);
        assert_eq!(
            sent,
            vec![
                ("snapshot_start".into(), json!(1)),
                ("snapshot_end".into(), json!(1)),
                ("upsert".into(), json!({"uid": "a", "v": 2})),
                ("delete".into(), json!({"uid": "b"})),
                ("upsert".into(), json!({"uid": "a", "d": 1})),
            ]
        );
    }

    #[test]
    fn watch_events_never_merge_across_a_snapshot_message() {
        let mut q = Queue::default();
        q.watch_event(NODES, "a", msg("upsert", json!({"v": 1})));
        q.collection_message(NODES, msg("collection_error", json!("e")));
        q.watch_event(NODES, "a", msg("upsert", json!({"v": 2})));
        q.watch_event(NODES, "a", msg("upsert", json!({"v": 3})));
        assert_eq!(
            drain(&mut q),
            vec![
                ("upsert".into(), json!({"v": 1})),
                ("collection_error".into(), json!("e")),
                ("upsert".into(), json!({"v": 3})),
            ]
        );
        // A sent event is no longer pending, so the next one for the UID queues anew.
        q.watch_event(NODES, "b", msg("upsert", json!({"v": 1})));
        assert_eq!(q.pop().unwrap().body, json!({"v": 1}).to_string());
        q.watch_event(NODES, "b", msg("delete", json!({"v": 2})));
        assert_eq!(drain(&mut q), vec![("delete".into(), json!({"v": 2}))]);
    }

    #[test]
    fn a_new_snapshot_replaces_the_unsent_remainder_of_the_previous_one() {
        let mut q = Queue::default();
        q.begin_snapshot(NODES, id(1), msg("snapshot_start", json!(1)));
        q.snapshot_message(NODES, id(1), msg("upsert", json!("a")), false);
        q.snapshot_message(NODES, id(1), msg("upsert", json!("b")), false);
        q.begin_snapshot(DEPLOYMENTS, id(9), msg("snapshot_start", json!(9)));
        // The start and one item were sent.
        assert_eq!(q.pop().unwrap().kind, "snapshot_start");
        assert_eq!(q.pop().unwrap().body, json!("a").to_string());
        q.begin_snapshot(NODES, id(2), msg("snapshot_start", json!(2)));
        let sent = drain(&mut q);
        assert_eq!(
            sent,
            vec![
                ("snapshot_start".into(), json!(9)),
                (
                    "snapshot_abort".into(),
                    json!({"snapshot_id": id(1), "reason": "replaced"})
                ),
                ("snapshot_start".into(), json!(2)),
            ]
        );
    }

    #[test]
    fn a_snapshot_never_started_on_the_wire_is_dropped_silently() {
        let mut q = Queue::default();
        q.begin_snapshot(NODES, id(1), msg("snapshot_start", json!(1)));
        q.snapshot_message(NODES, id(1), msg("upsert", json!("a")), false);
        q.begin_snapshot(NODES, id(2), msg("snapshot_start", json!(2)));
        assert_eq!(drain(&mut q), vec![("snapshot_start".into(), json!(2))]);
    }

    #[test]
    fn a_completely_sent_snapshot_is_not_aborted() {
        let mut q = Queue::default();
        q.begin_snapshot(NODES, id(1), msg("snapshot_start", json!(1)));
        q.snapshot_message(NODES, id(1), msg("snapshot_end", json!(1)), true);
        drain(&mut q);
        q.begin_snapshot(NODES, id(2), msg("snapshot_start", json!(2)));
        assert_eq!(drain(&mut q), vec![("snapshot_start".into(), json!(2))]);
        // An ended snapshot whose end is unsent is replaced: its end never arrives.
        q.snapshot_message(NODES, id(2), msg("snapshot_end", json!(2)), true);
        q.begin_snapshot(NODES, id(3), msg("snapshot_start", json!(3)));
        assert_eq!(
            drain(&mut q),
            vec![
                (
                    "snapshot_abort".into(),
                    json!({"snapshot_id": id(2), "reason": "replaced"})
                ),
                ("snapshot_start".into(), json!(3)),
            ]
        );
    }

    #[test]
    fn abandoning_an_open_snapshot_aborts_it() {
        let mut q = Queue::default();
        q.begin_snapshot(NODES, id(1), msg("snapshot_start", json!(1)));
        drain(&mut q);
        q.abandon(NODES, "list_failed");
        q.abandon(NODES, "list_failed");
        assert_eq!(
            drain(&mut q),
            vec![(
                "snapshot_abort".into(),
                json!({"snapshot_id": id(1), "reason": "list_failed"})
            )]
        );
    }

    #[tokio::test]
    async fn the_shared_queue_wakes_the_sender() {
        let queue = SyncQueue::new();
        let sender = queue.clone();
        let waiter = tokio::spawn(async move {
            sender.changed().await;
            sender.pop()
        });
        queue.update(|q| q.control(msg("error", json!({}))));
        let popped = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(popped.unwrap().kind, "error");
        assert!(queue.is_empty());
    }
}
