//! 条带复原舱 (Stripe Recovery Pod).
//!
//! Offline review of erasure-coded object fragments: import manifests and
//! shards with per-block digests, enumerate feasible candidate sets under
//! generation/object-digest/stripe constraints, reconstruct missing shards
//! on GF(256), commit stripes atomically and publish verified exports.

pub mod demo;
pub mod digest;
pub mod engine;
pub mod export;
pub mod gf256;
pub mod importer;
pub mod model;
pub mod recovery;
pub mod rs;
pub mod store;
pub mod web;

pub use digest::{object_bytes as build_object_bytes, object_data_digest, sha256_hex};
pub use gf256::Gf256;
pub use model::{ImportBundle, Manifest, ReceiptInput};
pub use rs::{encode as rs_encode, CodecVersion};
pub use store::Store;
