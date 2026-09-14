<!-- meta:title Integration Testing -->
<!-- meta:description Running live end-to-end tests against a real CrowdStrike Falcon tenant. -->
<!-- meta:section development -->
<!-- meta:link-base /falcon-mcp/ -->

Live end-to-end tests exercise the real falcon-mcp server against a real CrowdStrike Falcon tenant.

They are excluded from `make test` and never run in CI. See [`test/e2e/README.md`](https://github.com/CrowdStrike/falcon-mcp/blob/main/test/e2e/README.md) for credentials, labels, and how to run a subset:

```bash
export FALCON_CLIENT_ID=...
export FALCON_CLIENT_SECRET=...

make test-e2e
```
