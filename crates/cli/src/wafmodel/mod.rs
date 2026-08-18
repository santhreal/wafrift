//! WAF model decompilation, evasion, and sanitizer analysis.
//!
//! Modules:
//! - [`wafmodel_cmd`]: `wafrift wafmodel` — L* WAF decompiler driver
//! - [`model_evade_cmd`]: `wafrift model-evade` — evade a decompiled WAF model
//! - [`sanitizer_decompile_cmd`]: `wafrift sanitizer-decompile` — client sanitizer decompiler

pub mod model_evade_cmd;
pub mod sanitizer_decompile_cmd;
pub mod wafmodel_cmd;
