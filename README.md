# cacheisolate

**Multi-tenant prefix-cache side-channel auditor.**

Reproduce prefix-cache timing leakage and compare shared, tenant-isolated, and selectively isolated serving policies.

![cacheisolate cover](demo/cover.png)

![cacheisolate workbench](demo/dashboard.png)

## What ships

- Ordered multi-tenant request simulation with explicit cache ownership
- Shared, fully isolated, and sensitivity-aware selective policies
- Attacker probe inference, cross-tenant hit, latency-gap, and reuse reporting
- CLI, JSON API, visual timeline, Docker, tests, and GitHub Actions

## Run it end to end

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -e .
cacheisolate demo
cacheisolate serve
```

Open <http://127.0.0.1:8090>.

## Demo result

A victim primes one private prefix. Three attacker candidates reveal the correct value through an 86 ms hit/miss gap under a shared cache. Tenant isolation blocks the leak but removes public reuse; selective isolation blocks the private leak while preserving the cross-tenant public-system-prefix hit.

## Current basis

- [Prompt Leakage via KV-Cache Sharing in Multi-Tenant LLM Serving, NDSS 2025](https://www.ndss-symposium.org/wp-content/uploads/2025-1772-paper.pdf)
- [CacheSolidarity](https://arxiv.org/abs/2603.10726)

## Scope

This deterministic harness establishes the attack mechanism. Production results depend on network jitter, continuous batching, scheduler behavior, routing, quantization, and the serving engine.

## Test

```bash
python -m unittest discover -s tests -v
```

MIT licensed.
