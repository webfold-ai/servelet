//! The router tests moved out of `biota/http-server`'s `kernel.rs` `mod tests` (rev `4ce2dcd`),
//! verbatim: the tracing-span test (4088-4146, now in `tracing_span.rs`, see the note there), the exact-path dispatch test (4138-4146),
//! `extensions_survive_a_real_request_through_the_router` (4213-4236), and the route-matching
//! block (4358-4502) plus `router_layered_composes_an_arbitrary_layer` (4957-4981).
//!
//! The only edits are reach-ins that pointed at modules outside this extraction:
//!   * `use crate::platform::service::RateLimitLayer` -> `use servelet_core::RateLimitLayer`
//!     (that module moved into `servelet-core`; see its `service.rs` for why).
//!   * the `Data<T>` doc reference in `router_with_state_...` is prose only.
//!
//! NOT MOVED, with the reason (docs/SPINE.md): `public_surface_covers_client_router_proxy_and_relationships`
//! is a single test over four subsystems — this file keeps the router half of it verbatim as
//! `router_public_surface_dispatches_and_reports_contains_route`. `actix_path_extractor_reads_
//! router_extracted_params` exercises the actix masquerade's `Path` extractor
//! (`crate::httpsrv::actix::to_handler1`), which is a later unit; the `PathParams` it reads is
//! already covered here by `router_matches_dynamic_path_params`.

use std::sync::Arc;

use servelet_core::{Extensions, Method, Request, Response, StatusCode};
use servelet_router::{BoxHandler, PathParams, Router};

#[tokio::test]
async fn router_handles_exact_method_path() {
    let router = Router::new().get("/", |_req| async { Response::ok("alive") });
    let req = Request::new(Method::GET, "/".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "alive");
}

/// End-to-end: a value stashed in `Request::extensions_mut()` by (simulated) middleware,
/// read back by the handler — the exact `axum::Extension<T>`/actix `ReqData<T>` shape.
#[tokio::test]
async fn extensions_survive_a_real_request_through_the_router() {
    #[derive(Clone, Debug, PartialEq)]
    struct AuthUser(String);

    let router = Router::new().get("/whoami", |req: Request| async move {
        match req.extensions().get::<AuthUser>() {
            Some(u) => Response::ok(u.0.clone()),
            None => Response::new(StatusCode::UNAUTHORIZED, "no user"),
        }
    });

    let mut req = Request::new(Method::GET, "/whoami".parse().unwrap());
    req.extensions_mut().insert(AuthUser("clay".into()));
    let resp = router.handle(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "clay");

    // No extension inserted this time -- handler must not find a stale one.
    let req = Request::new(Method::GET, "/whoami".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The router half of biota's `public_surface_covers_client_router_proxy_and_relationships`,
/// moved verbatim. The client/proxy/relationships halves are not in this unit.
#[tokio::test]
async fn router_public_surface_dispatches_and_reports_contains_route() {
    let router = Router::new()
        .route_sync(Method::GET, "/health", |_req| Response::ok("ok"))
        .post("/echo", |req| async move { Response::ok(req.into_body()) });
    assert!(router.contains_route(&Method::GET, "/health"));
    assert!(!router.contains_route(&Method::DELETE, "/health"));

    let health = router
        .handle(Request::new(Method::GET, "/health".parse().unwrap()))
        .await;
    assert_eq!(health.status(), StatusCode::OK);

    let echo = router
        .handle(Request::new(Method::POST, "/echo".parse().unwrap()).with_body("ping"))
        .await;
    assert_eq!(echo.text().await.unwrap(), "ping");
}

/// prefix still wins over the pattern via the fast exact-match path -- proving static routes
/// aren't slowed or shadowed by a dynamic one sharing a prefix.
#[tokio::test]
async fn router_matches_dynamic_path_params() {
    let router = Router::new()
        .route_sync(Method::GET, "/users/me", |_req| Response::ok("current-user"))
        .route_sync(Method::GET, "/users/:id", |req| {
            let params = req.extensions().get::<PathParams>().cloned().unwrap();
            Response::ok(format!("user:{}", params.get("id").unwrap()))
        });

    let req = Request::new(Method::GET, "/users/42".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.text().await.unwrap(), "user:42");

    // The literal route must still win at its own exact path, not fall through to the
    // pattern (which would also technically match "/users/me" with id="me").
    let req = Request::new(Method::GET, "/users/me".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.text().await.unwrap(), "current-user");

    let req = Request::new(Method::GET, "/users/42/extra".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "a differing segment count must not match");
}

/// Real proof of multi-segment dynamic routes: `/orgs/:org/repos/:repo` with two captures.
#[tokio::test]
async fn router_matches_multi_segment_dynamic_path() {
    let router = Router::new().route_sync(Method::GET, "/orgs/:org/repos/:repo", |req| {
        let p = req.extensions().get::<PathParams>().cloned().unwrap();
        Response::ok(format!("{}/{}", p.get("org").unwrap(), p.get("repo").unwrap()))
    });
    let req = Request::new(Method::GET, "/orgs/anthropic/repos/claude-code".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.text().await.unwrap(), "anthropic/claude-code");
}

/// Real proof of a wildcard/catch-all route (`*tail`, actix's `{_:.*}` equivalent — Swagger
/// UI's static-asset server is the real caller): matches ANY number of trailing segments
/// (including a nested path, and zero segments), captured as one `/`-joined string, while a
/// literal route at the SAME prefix still wins over the wildcard for its own exact path.
#[tokio::test]
async fn router_matches_wildcard_catch_all_route() {
    let router = Router::new()
        .route_sync(Method::GET, "/docs/openapi.json", |_req| Response::ok("the-openapi-doc"))
        .route_sync(Method::GET, "/docs/*tail", |req| {
            let p = req.extensions().get::<PathParams>().cloned().unwrap();
            Response::ok(format!("tail:{}", p.get("tail").unwrap()))
        });

    let req = Request::new(Method::GET, "/docs/openapi.json".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.text().await.unwrap(), "the-openapi-doc", "a literal route must still win at its own exact path");

    let req = Request::new(Method::GET, "/docs/index.html".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.text().await.unwrap(), "tail:index.html");

    let req = Request::new(Method::GET, "/docs/assets/swagger-ui.css".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.text().await.unwrap(), "tail:assets/swagger-ui.css", "a nested path must be captured whole, joined by /");

    let req = Request::new(Method::GET, "/docs".parse().unwrap());
    let resp = router.handle(req).await;
    assert_eq!(resp.text().await.unwrap(), "tail:", "zero trailing segments must still match, with an empty capture");
}

/// Real proof of `nest`: an inner router's routes become reachable under a prefix on the
/// outer router, including a DYNAMIC route inside the nested router.
#[tokio::test]
async fn router_nest_mounts_inner_routes_under_a_prefix() {
    let inner = Router::new()
        .route_sync(Method::GET, "/", |_req| Response::ok("api-root"))
        .route_sync(Method::GET, "/items/:id", |req| {
            let p = req.extensions().get::<PathParams>().cloned().unwrap();
            Response::ok(format!("item:{}", p.get("id").unwrap()))
        });
    let outer = Router::new().nest("/api", inner);

    let resp = outer.handle(Request::new(Method::GET, "/api/".parse().unwrap())).await;
    assert_eq!(resp.text().await.unwrap(), "api-root");

    let resp = outer.handle(Request::new(Method::GET, "/api/items/7".parse().unwrap())).await;
    assert_eq!(resp.text().await.unwrap(), "item:7");
}

/// Real proof of `merge`: routes from two independently-built routers are both reachable
/// after merging, at their original (un-prefixed) paths.
#[tokio::test]
async fn router_merge_combines_two_routers() {
    let a = Router::new().route_sync(Method::GET, "/a", |_req| Response::ok("from-a"));
    let b = Router::new().route_sync(Method::GET, "/b", |_req| Response::ok("from-b"));
    let combined = a.merge(b);

    assert_eq!(combined.handle(Request::new(Method::GET, "/a".parse().unwrap())).await.text().await.unwrap(), "from-a");
    assert_eq!(combined.handle(Request::new(Method::GET, "/b".parse().unwrap())).await.text().await.unwrap(), "from-b");
}

/// Real proof of `fallback`: an unmatched request hits the custom fallback, not the bare
/// default 404.
///
/// It asserts BOTH directions on purpose. Asserting only the fallback half (as this test did at
/// `bf34eca`) leaves the registered route unpinned, so renaming it — which `scripts/mutation.sh`
/// does — leaves the suite green and proves nothing. A fallback test has to show that the known
/// route still resolves AND that the unknown one does not, or it cannot tell "the fallback fired"
/// from "the router matched nothing at all".
#[tokio::test]
async fn router_fallback_catches_unmatched_requests() {
    let router = Router::new()
        .route_sync(Method::GET, "/known", |_req| Response::ok("known"))
        .fallback(|_req| async { Response::new(StatusCode::NOT_FOUND, "custom-fallback") });

    // The registered route must still be served — this half is what a renamed route breaks.
    let hit = router.handle(Request::new(Method::GET, "/known".parse().unwrap())).await;
    assert_eq!(hit.status(), StatusCode::OK);
    assert_eq!(hit.text().await.unwrap(), "known");

    // And an unregistered path must reach the custom fallback, not the bare default 404.
    let resp = router.handle(Request::new(Method::GET, "/unknown".parse().unwrap())).await;
    assert_eq!(resp.text().await.unwrap(), "custom-fallback");
}

/// Real proof of `with_state`: every request sees the injected state via `Request::app_data<T>`,
/// without the handler needing the state passed any other way.
#[tokio::test]
async fn router_with_state_injects_shared_state_into_every_request() {
    #[derive(Clone)]
    struct AppState {
        label: String,
    }
    let router = Router::new()
        .with_state(AppState { label: "shared".to_string() })
        .route_sync(Method::GET, "/state", |req| {
            let state = req.extensions().get::<Arc<AppState>>().cloned().unwrap();
            Response::ok(state.label.clone())
        });

    let resp = router.handle(Request::new(Method::GET, "/state".parse().unwrap())).await;
    assert_eq!(resp.text().await.unwrap(), "shared");
}

/// Real proof of `layer`: a middleware wrapping every handler actually runs, observable via
/// a real header it adds to the response.
#[tokio::test]
async fn router_layer_wraps_every_handler() {
    let router = Router::new()
        .route_sync(Method::GET, "/", |_req| Response::ok("plain"))
        .layer(|inner: BoxHandler| -> BoxHandler {
            Arc::new(move |req| {
                let inner = inner.clone();
                Box::pin(async move { inner(req).await.with_header("x-middleware", "ran") })
            })
        });

    let resp = router.handle(Request::new(Method::GET, "/".parse().unwrap())).await;
    assert_eq!(resp.headers().get("x-middleware").unwrap().to_str().unwrap(), "ran");
    assert_eq!(resp.text().await.unwrap(), "plain");
}

/// Real proof `Router::layered` composes an ARBITRARY `service::Layer<Router>` — not
/// just the handler-wrapping-closure shape `layer` already covered. `RateLimitLayer` is a
/// real, independently-defined `Layer` (not written for this test): its enforcement lives
/// in `Service::ready`, so this also proves `layered`'s adapter genuinely calls `ready`
/// before `serve` (tower's own contract), not `serve` alone.
#[tokio::test]
async fn router_layered_composes_an_arbitrary_layer() {
    use servelet_core::RateLimitLayer;

    let router = Router::new()
        .route_sync(Method::GET, "/limited", |_req| Response::ok("ok"))
        .layered(RateLimitLayer::new(2, std::time::Duration::from_secs(60)));

    let r1 = router.handle(Request::new(Method::GET, "/limited".parse().unwrap())).await;
    assert_eq!(r1.status(), StatusCode::OK, "request 1 of 2 must pass");
    let r2 = router.handle(Request::new(Method::GET, "/limited".parse().unwrap())).await;
    assert_eq!(r2.status(), StatusCode::OK, "request 2 of 2 must pass");

    let r3 = router.handle(Request::new(Method::GET, "/limited".parse().unwrap())).await;
    assert_eq!(r3.status(), StatusCode::SERVICE_UNAVAILABLE, "request 3 must be rejected by the real RateLimitLayer, wired through `layered`");
}