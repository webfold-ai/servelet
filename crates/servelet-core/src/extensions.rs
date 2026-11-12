// -- Extensions: TypeId-keyed type-map (mirrors the real `http` crate's `Extensions`) ----

/// A type-erased value that can still be cloned — the standard "clone_box" pattern, needed
/// because `Extensions` must itself be `Clone` (both `Request` and `Response` derive `Clone`)
/// even though it stores arbitrary `dyn Any` values.
///
/// Found by a reproduced bug (downcast always failing, even for the type just inserted): calling
/// `b.as_any()` where `b: &Box<dyn CloneAny>` does NOT dispatch to the boxed value's own impl —
/// `Box<dyn CloneAny>` is itself `'static`, so it ALSO satisfies the blanket impl's own bound
/// below, and Rust's method resolution tries the receiver type (`Box<dyn CloneAny>`) before
/// auto-deref'ing into its contents, silently picking the WRONG (box-level, recursive) impl
/// instance instead of the concrete stored type's. The fix is forcing dispatch through the
/// unsized `dyn CloneAny` place directly — every call site below double-derefs (`(**b)`) rather
/// than calling `.as_any()` on the `&Box<..>` reference itself.
trait CloneAny: std::any::Any + Send + Sync {
    fn clone_box(&self) -> Box<dyn CloneAny>;
    fn as_any(&self) -> &dyn std::any::Any;
}
impl<T: std::any::Any + Clone + Send + Sync> CloneAny for T {
    fn clone_box(&self) -> Box<dyn CloneAny> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl Clone for Box<dyn CloneAny> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

fn type_id_coord(id: std::any::TypeId) -> u64 {
    // `TypeId` isn't a string/int `Coord` covers directly — hash it through its own `Hash` impl
    // into a u64, same shape as this file's own `header_coord` for `HeaderName`.
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut hasher);
    hasher.finish()
}

/// A type-map carried alongside a `Request`/`Response` — mirrors the real `http` crate's
/// `Extensions` exactly (`insert<T: Clone+Send+Sync+'static>`/`get<T>`/`remove<T>`): middleware
/// stashes arbitrary typed data (a parsed auth identity, a request id, a trace span) for
/// downstream handlers/layers to read back by type, without a bespoke field on `Request`/
/// `Response` for every such use — exactly what `axum`'s `Extension<T>` extractor and `actix-web`
/// equivalents both build on. Honest gap vs. the real crate: no `get_mut` — hashtrinity's
/// `Table` has no `get_mut` to build it on; every other operation (`get`/`insert`/`remove`, the
/// shapes `FromRequestParts`-style extractors and middleware actually use) is exact.
///
/// Uses `wirefold::Table` (the exact-key-storing variant), NOT `CoordMap` — `CoordMap`
/// ("the address regenerates the key... stores nothing") is for keys that ARE their own
/// collision-free coordinate (small dense integers, direct addressing); a `TypeId` hashed
/// through `DefaultHasher` is an OPAQUE 64-bit value with no such guarantee, so two unrelated
/// types whose hashes happened to collide would have silently overwritten each other's slot —
/// found via a reproduced test failure (a second `insert` of a different type corrupted the
/// first), root-caused to exactly this mismatch. `Table` stores the key and resolves collisions
/// by real comparison, which is what a type-map's correctness actually depends on.
#[derive(Clone)]
pub struct Extensions {
    map: wirefold::Table<u64, Box<dyn CloneAny>>,
}

impl Default for Extensions {
    fn default() -> Self {
        Extensions::new()
    }
}

impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extensions").finish_non_exhaustive()
    }
}

impl Extensions {
    pub fn new() -> Self {
        Extensions { map: wirefold::Table::new() }
    }

    /// Insert a value, returning whatever was previously stored for this exact type `T`.
    pub fn insert<T: Clone + Send + Sync + 'static>(&mut self, val: T) -> Option<T> {
        let key = type_id_coord(std::any::TypeId::of::<T>());
        let prev = self.map.remove(&key).and_then(|b| (*b).as_any().downcast_ref::<T>().cloned());
        self.map.put(key, Box::new(val));
        prev
    }

    pub fn get<T: 'static>(&self) -> Option<&T> {
        let key = type_id_coord(std::any::TypeId::of::<T>());
        self.map.get(&key).and_then(|b| (**b).as_any().downcast_ref::<T>())
    }

    pub fn remove<T: Clone + 'static>(&mut self) -> Option<T> {
        let key = type_id_coord(std::any::TypeId::of::<T>());
        self.map.remove(&key).and_then(|b| (*b).as_any().downcast_ref::<T>().cloned())
    }
}

