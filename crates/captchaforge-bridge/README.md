# wafrift-captchaforge-bridge

Optional adapter. captchaforge is retired. This crate waits for a lurien
engine cookie write (`cf_clearance` / `_abck` / `ak_bmsc` / `aws-waf-token`).
It does not call `auto_solve`, CapSolver, or a page sidecar.

`--captchaforge` on `wafrift-proxy` fails loud. Live challenges belong to
lurien (`software/browser`).

## License

MIT OR Apache-2.0.
