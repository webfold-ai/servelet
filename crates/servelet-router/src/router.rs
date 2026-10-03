use super::*;

// -- Axum face: router/handler -----------------------------------------

type HandlerFuture = Pin<Box<dyn Future<Output = Response> + Send>>;
pub type BoxHandler = Arc<dyn Fn(Request) -> HandlerFuture + Send + Sync>;

/// One segment of a route pattern — a literal path component, or a `:name` capture. Dynamic
/// routing (`/users/:id`) needs this because `CoordMap` (the `routes` fast path below) hashes a
/// path to its address and stores nothing recoverable — a `:id` segment has no fixed string to
/// hash against, so it can't live in that structure at all; it needs actual segment-by-segment
/// matching.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathSegment {
    Literal(String),
    Param(String),
    /// `*name` — actix's `{name:.*}` catch-all (e.g. Swagger UI's static-asset server, `/docs/
    /// {_:.*}`): matches every remaining path segment (zero or more), joined back with `/` into
    /// one captured value. Only meaningful as the LAST segment of a pattern; `parse_pattern`
    /// doesn't enforce that (a wildcard elsewhere just never matches anything after it, since
    /// `match_pattern` always treats it as consuming the rest of the path).
    Wildcard(String),
}

fn parse_pattern(path: &str) -> Vec<PathSegment> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            if let Some(name) = seg.strip_prefix('*') {
                PathSegment::Wildcard(name.to_string())
            } else if let Some(name) = seg.strip_prefix(':') {
                PathSegment::Param(name.to_string())
            } else {
                PathSegment::Literal(seg.to_string())
            }
        })
        .collect()
}

fn match_pattern(pattern: &[PathSegment], path: &str) -> Option<Vec<(String, String)>> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let has_wildcard = matches!(pattern.last(), Some(PathSegment::Wildcard(_)));
    if !has_wildcard && parts.len() != pattern.len() {
        return None;
    }
    if has_wildcard && parts.len() < pattern.len() - 1 {
        return None;
    }
    // A `Vec`, not a `HashMap` -- preserves the pattern's left-to-right declaration order, which
    // `AsTerm for String`/`AsTerm for (String, String)` (positional, name-blind) rely on for
    // `Path<String>`/`Path<(String, String)>`-style extraction; `Path<T>`'s named-struct case
    // (`#[derive(Term)]`) doesn't care about order, so this is a superset, not a tradeoff.
    let mut params = Vec::with_capacity(pattern.len());
    let fixed_len = if has_wildcard { pattern.len() - 1 } else { pattern.len() };
    for (seg, part) in pattern[..fixed_len].iter().zip(parts.iter()) {
        match seg {
            PathSegment::Literal(l) => {
                if l != part {
                    return None;
                }
            }
            PathSegment::Param(name) => {
                params.push((name.clone(), part.to_string()));
            }
            PathSegment::Wildcard(_) => unreachable!("wildcard is never in the fixed prefix"),
        }
    }
    if let Some(PathSegment::Wildcard(name)) = pattern.last() {
        params.push((name.clone(), parts[fixed_len..].join("/")));
    }
    Some(params)
}

/// Path parameters extracted by a dynamic-route match, stashed in the request's `Extensions` —
/// what `crate::httpsrv::actix::Path` reads back out. Order-preserving (see `match_pattern`) so both named
/// (`Path<SomeStruct>`) and positional (`Path<String>`/`Path<(String, String)>`) extraction work
/// from the same capture.
#[derive(Clone, Debug, Default)]
pub struct PathParams(Vec<(String, String)>);

impl PathParams {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Captured values in pattern-declaration order, names dropped — what positional extraction
    /// (`Path<String>`, `Path<(String, String)>`) reads.
    pub fn ordered_values(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(_, v)| v.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// One registered route, retaining its original (method, path) string — needed by `nest`/
/// `merge` to re-key routes under a new prefix, which the `routes` `CoordMap` alone can't do
/// (it has no way to enumerate what it holds).
#[derive(Clone)]
struct RouteEntry {
    method: Method,
    path: String,
    pattern: Vec<PathSegment>,
    handler: BoxHandler,
}

#[derive(Clone)]
pub struct Router {
    routes: Arc<CoordMap<u64, BoxHandler>>,
    entries: Arc<Vec<RouteEntry>>,
    fallback: Option<BoxHandler>,
    /// Handler-wrapping middleware, applied at dispatch time in registration order — axum's
    /// `middleware::from_fn` shape (a function transforming the handler), not an arbitrary
    /// `service.rs::Layer<Router>` (which would change Router's own type on application; this
    /// stays `Router`-typed, a deliberate, stated scope choice).
    middlewares: Arc<Vec<Arc<dyn Fn(BoxHandler) -> BoxHandler + Send + Sync>>>,
    /// Extra state injected into every request's `Extensions` before dispatch — `with_state`.
    state_injectors: Arc<Vec<Arc<dyn Fn(&mut Extensions) + Send + Sync>>>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("routes", &self.routes.len())
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl Router {
    pub fn new() -> Self {
        Router {
            routes: Arc::new(CoordMap::coordinate()),
            entries: Arc::new(Vec::new()),
            fallback: None,
            middlewares: Arc::new(Vec::new()),
            state_injectors: Arc::new(Vec::new()),
        }
    }

    fn register(&mut self, method: Method, path: String, handler: BoxHandler) {
        let pattern = parse_pattern(&path);
        // A pattern with no Param segments is exactly a literal path -- still gets the fast
        // CoordMap lookup too, so static routes pay zero cost for dynamic routing existing.
        if !pattern.iter().any(|s| matches!(s, PathSegment::Param(_) | PathSegment::Wildcard(_))) {
            let key = route_coord(&method, &path);
            Arc::make_mut(&mut self.routes).put(key, handler.clone());
        }
        Arc::make_mut(&mut self.entries).push(RouteEntry { method, path, pattern, handler });
    }

    pub fn route<H, F>(mut self, method: Method, path: impl Into<String>, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        let h: BoxHandler = Arc::new(move |req| Box::pin(handler(req)));
        self.register(method, path.into(), h);
        self
    }

    pub fn route_sync<H>(mut self, method: Method, path: impl Into<String>, handler: H) -> Self
    where
        H: Fn(Request) -> Response + Send + Sync + 'static,
    {
        let h: BoxHandler = Arc::new(move |req| Box::pin(std::future::ready(handler(req))));
        self.register(method, path.into(), h);
        self
    }

    pub fn get<H, F>(self, path: impl Into<String>, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.route(Method::GET, path, handler)
    }

    pub fn post<H, F>(self, path: impl Into<String>, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.route(Method::POST, path, handler)
    }

    /// Mount every route of `other` under `prefix` — axum's `nest`. Re-keys each of `other`'s
    /// ROUTES (not `other`'s own fallback/middleware, which stay local to `other` and are not
    /// carried over — a stated scope reduction, not a hidden one).
    pub fn nest(mut self, prefix: impl Into<String>, other: Router) -> Self {
        let prefix = prefix.into();
        let prefix = prefix.strip_suffix('/').unwrap_or(&prefix);
        for entry in other.entries.iter() {
            let new_path = format!("{prefix}{}", entry.path);
            self.register(entry.method.clone(), new_path, entry.handler.clone());
        }
        self
    }

    /// Combine every route of `other` into `self` at the SAME paths — axum's `merge`. A route
    /// registered in both routers for the same (method, path) is resolved last-write-wins
    /// (`other`'s copy replaces `self`'s), the same rule a single router's own re-registration
    /// already follows. If `other` carries a fallback service (e.g. a router produced by
    /// `.layered(...)`), that fallback is preserved so the merged router still serves it.
    pub fn merge(mut self, other: Router) -> Self {
        for entry in other.entries.iter() {
            self.register(entry.method.clone(), entry.path.clone(), entry.handler.clone());
        }
        // Preserve a fallback from the other router. Layered routers store their wrapped service
        // as a fallback with no entries; without this their routes would silently vanish on merge.
        if self.fallback.is_none() || other.fallback.is_some() {
            self.fallback = other.fallback.clone();
        }
        self
    }

    /// A catch-all handler for any request no route (exact or dynamic) matches — axum's
    /// `fallback`, replacing the default bare 404.
    pub fn fallback<H, F>(mut self, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.fallback = Some(Arc::new(move |req| Box::pin(handler(req))));
        self
    }

    /// Inject `state` into every request's `Extensions` before dispatch — axum's `with_state`.
    /// Read it back with `Request::app_data<T>` (`req.extensions().get::<Arc<S>>()`), the same
    /// mechanism `Data::inject` uses per-request; this applies it router-wide instead.
    pub fn with_state<S: Clone + Send + Sync + 'static>(mut self, state: S) -> Self {
        let state = Arc::new(state);
        Arc::make_mut(&mut self.state_injectors).push(Arc::new(move |ext: &mut Extensions| {
            ext.insert(state.clone());
        }));
        self
    }

    /// Apply a handler-wrapping middleware to EVERY route, dispatch-time (registration order
    /// doesn't matter — this covers every route regardless of when `.layer()` was called
    /// relative to `.route()`). axum's `middleware::from_fn` shape: a function from one handler
    /// to another. For an arbitrary `service.rs::Layer<Router>` (`RateLimitLayer`, `CorsLayer`,
    /// a hand-implemented `tower`-shaped layer), see `layered` below.
    pub fn layer<F>(mut self, f: F) -> Self
    where
        F: Fn(BoxHandler) -> BoxHandler + Send + Sync + 'static,
    {
        Arc::make_mut(&mut self.middlewares).push(Arc::new(f));
        self
    }

    /// Wrap this WHOLE router through a real `service.rs::Layer<Router>` — `tower::Layer`
    /// composition (`router.layered(RateLimitLayer::new(100, Duration::from_secs(1)))`), not
    /// `layer`'s handler-wrapping-closure shape. `Router` already implements `servelet_core::Service`
    /// (`impl Service<Request> for Router` in `service.rs`), so any `L: Layer<Router>` whose
    /// resulting `L::Service` also serves `Request -> Response` composes here directly.
    ///
    /// The wrapped service is boxed back down into a `BoxHandler` and installed as this
    /// router's fallback (with an empty route table) — axum's own `Router::layer` plays the
    /// same trick (wrapping each route's inner service, then re-boxing to a common `Route`
    /// type) so the RESULT stays a plain `Router` that can still be `.merge`d, `.nest`ed, or
    /// passed to `serve` — the wrapped service's own concrete type never leaks into `Router`'s
    /// type. The tradeoff, stated honestly: once wrapped, the original route table is no longer
    /// directly introspectable via `contains_route` — dispatch still happens, just indirected
    /// through the opaque layered service, same as any real tower `Layer` composition.
    pub fn layered<L>(self, layer: L) -> Self
    where
        L: servelet_core::Layer<Router>,
        L::Service: servelet_core::Service<Request, Response = Response, Error = servelet_core::Error> + Send + Sync + 'static,
    {
        let wrapped = Arc::new(tokio::sync::Mutex::new(layer.wrap(self)));
        let handler: BoxHandler = Arc::new(move |req: Request| {
            let wrapped = wrapped.clone();
            Box::pin(async move {
                let mut svc = wrapped.lock().await;
                // tower's own contract: `ready` gates `serve` (rate limiting, circuit breaking,
                // etc. live in `ready`, e.g. `RateLimitService::ready`) -- calling `serve` alone
                // would silently skip every layer that enforces itself there.
                if let Err(e) = servelet_core::Service::ready(&mut *svc).await {
                    return Response::new(StatusCode::SERVICE_UNAVAILABLE, e.to_string());
                }
                match servelet_core::Service::serve(&mut *svc, req).await {
                    Ok(resp) => resp,
                    Err(e) => Response::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
                }
            }) as HandlerFuture
        });
        Router {
            routes: Arc::new(CoordMap::coordinate()),
            entries: Arc::new(Vec::new()),
            fallback: Some(handler),
            middlewares: Arc::new(Vec::new()),
            state_injectors: Arc::new(Vec::new()),
        }
    }

    pub async fn handle(&self, req: Request) -> Response {
        let span = tracing::info_span!("http.request", method = %req.method(), path = %req.path(), status = tracing::field::Empty);
        let _entered = span.enter();
        let resp = self.handle_inner(req).await;
        span.record("status", resp.status().as_u16());
        resp
    }

    async fn handle_inner(&self, mut req: Request) -> Response {
        for inject in self.state_injectors.iter() {
            inject(req.extensions_mut());
        }

        let key = route_coord(req.method(), req.path());
        let found = if let Some(handler) = self.routes.get(&key) {
            Some(handler.clone())
        } else {
            // Fast path missed -- fall back to walking the dynamic-pattern entries (only those
            // with at least one Param segment; literal-only entries would have hit the CoordMap
            // above if they existed at all).
            let path = req.path().to_string();
            self.entries.iter().find_map(|e| {
                if e.method != *req.method() || !e.pattern.iter().any(|s| matches!(s, PathSegment::Param(_) | PathSegment::Wildcard(_))) {
                    return None;
                }
                match_pattern(&e.pattern, &path).map(|params| {
                    req.extensions_mut().insert(PathParams(params));
                    e.handler.clone()
                })
            })
        };

        let resp = match found.or_else(|| self.fallback.clone()) {
            Some(handler) => {
                let wrapped = self.middlewares.iter().fold(handler, |h, mw| mw(h));
                wrapped(req).await
            }
            None => {
                eprintln!("DEBUG  target=bedrock::router");  // was: DEBUG target: "bedrock::router", "no route matched"
                Response::not_found()
            }
        };
        
        resp
    }

    pub fn contains_route(&self, method: &Method, path: &str) -> bool {
        self.routes.get(&route_coord(method, path)).is_some()
    }
}

impl Default for Router {
    fn default() -> Self {
        Router::new()
    }
}

fn route_coord(method: &Method, path: &str) -> u64 {
    method_coord(method).wrapping_mul(PHI) ^ path.coord()
}

fn method_coord(method: &Method) -> u64 {
    match method {
        Method::GET => 1,
        Method::POST => 2,
        Method::PUT => 3,
        Method::DELETE => 4,
        Method::PATCH => 5,
        Method::HEAD => 6,
        Method::OPTIONS => 7,
        Method::CONNECT => 8,
        Method::TRACE => 9,
        Method::Other(s) => s.coord(),
    }
}
