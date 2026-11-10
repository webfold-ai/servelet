//! `servelet-core` — the data model every servelet crate speaks.
//!
//! `Method`, `StatusCode`, `Version`, `Uri`, `HeaderMap`/`HeaderName`/`HeaderValue`,
//! `Extensions`, `Request`, `Response`, `Error`/`Result`, `ConnectionInfo`, and the two
//! composition traits (`Service`, `Layer`) pieces meet at.
//!
//! No tokio. No reactor, no runtime, no sockets. This crate builds and runs inside a
//! synchronous `main`, a `#[test]`, or any executor a caller picks.
//!
//! Moved byte-for-byte from `biota/http-server`'s `kernel.rs` at rev `4ce2dcd`
//! (lines 60-1063) and `kernel/platform.rs` (`service`, lines 353-420 and 484-573).
//! Every deviation is listed, with its reason, in `docs/SPINE.md`.

#![forbid(unsafe_code)]

use std::io;
use std::str;
use std::str::FromStr;
use std::sync::Arc;

// Re-used by `types.rs` (HeaderMap's store and coordinate hash) and `extensions.rs`
// (the exact-key table). See docs/SPINE.md "Dependencies" for why these three names and no
// others.
use wirefold::{CoordMap, PHI};

mod error;
mod extensions;
mod message;
mod service;
mod types;

pub use error::{Error, Result};
pub use extensions::Extensions;
pub use message::{ConnectionInfo, Request, Response};
pub use service::{oneshot, Layer, RateLimitLayer, RateLimitService, Service, Stack};
pub use types::*;