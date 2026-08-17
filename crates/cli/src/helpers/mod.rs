//! Shared CLI helper functions, split by domain.
//!
//! Submodules:
//! - [`shell`]: shell quoting primitives
//! - [`curl`]: curl command rendering for probe reproducers
//! - [`url`]: URL and form-parsing utilities
//! - [`http`]: HTTP response parsing and error-walking
//! - [`runtime`]: runtime, IO, and process-exit utilities
//! - [`variant`]: strategy selection, confidence scoring, variant building

pub mod curl;
pub mod http;
pub mod runtime;
pub mod shell;
pub mod url;
pub mod variant;

// Re-export so existing `helpers::foo` call sites compile unchanged.
// The `helpers` module is `mod helpers` (not `pub mod`), so all re-exports
// are effectively crate-internal regardless of the `pub` keyword here.
pub use curl::*;
pub use http::*;
pub use runtime::*;
pub use shell::*;
pub use url::*;
pub use variant::*;
