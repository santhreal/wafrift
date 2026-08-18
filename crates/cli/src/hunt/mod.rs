//! Hunt campaign: automated bypass discovery, exploitation, and genome banking.
//!
//! Modules:
//! - [`hunt_cmd`]: top-level `wafrift hunt` campaign orchestrator
//! - [`harvest_cmd`]: harvest bypasses from a running campaign
//! - [`exploit_cmd`]: exploit discovered bypasses for proof-of-concept
//! - [`distill_cmd`]: distill a corpus to its minimal failing subset
//! - [`info_gain_sched`]: information-gain-driven probe scheduling
//! - [`corpus_cmd`]: corpus management subcommands
//! - [`corpus_recorder`]: record probe outcomes into a corpus
//! - [`equiv_engine`]: equivalence-class CEGIS engine (the flagship)
//! - [`seed`]: seed payload generation
//! - [`bank`]: gene bank (bypass genome storage)
//! - [`bank_registry`]: gene bank signing-key registry

pub mod bank;
pub mod bank_registry;
pub mod corpus_cmd;
pub mod corpus_recorder;
pub mod distill_cmd;
pub mod equiv_engine;
pub mod exploit_cmd;
pub mod harvest_cmd;
pub mod hunt_cmd;
pub mod info_gain_sched;
pub mod seed;
