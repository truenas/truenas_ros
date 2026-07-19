//! The shared io_uring engine: the raw UAPI surface ([`sys`]), the mmap'd
//! ring ([`ring`]), SQE staging with in-flight accounting and the
//! cancel-everything teardown ([`engine`]), the wake eventfd and cross-thread
//! loop flags ([`wake`]), the generation-guarded slot entry ([`slots`]), the
//! `user_data` routing codec ([`user_data`]), and opcode-support probing
//! ([`probe`]).
//!
//! Domain stacks build on this — `net` (the stream server/client roles)
//! today, the async fs reactor next — each bringing its own op-tag vocabulary
//! and completion dispatch. The engine deliberately knows neither: tags and
//! per-completion policy are passed in ([`engine::Engine::arm_wake`],
//! [`engine::Engine::cancel_and_reap_all`]), so one ring can serve several
//! domains' ops on a shared submission batch.

// Like `sys`, the engine keeps a deliberate superset surface: which items a
// build uses depends on the enabled domains (a lone role — or the engine
// feature by itself — leaves shared primitives unused, and domain tag space
// is declared before its domain lands). That asymmetry is expected, not dead
// code to prune.
#![allow(dead_code)]

pub(crate) mod engine;
pub(crate) mod probe;
pub(crate) mod ring;
pub(crate) mod slots;
pub(crate) mod sys;
pub(crate) mod user_data;
pub(crate) mod wake;
