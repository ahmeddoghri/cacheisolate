from __future__ import annotations

import hashlib


DEMO = {
    "hit_latency_ms": 18,
    "miss_latency_ms": 104,
    "events": [
        {"tenant": "clinic-a", "prefix": "private|patient=alice|diagnosis=alpha", "sensitive": True, "role": "victim"},
        {"tenant": "clinic-a", "prefix": "public|system=medical-assistant-v3", "sensitive": False, "role": "normal"},
        {"tenant": "attacker", "prefix": "private|patient=alice|diagnosis=beta", "sensitive": True, "role": "probe", "candidate": "beta"},
        {"tenant": "attacker", "prefix": "private|patient=alice|diagnosis=alpha", "sensitive": True, "role": "probe", "candidate": "alpha"},
        {"tenant": "attacker", "prefix": "private|patient=alice|diagnosis=gamma", "sensitive": True, "role": "probe", "candidate": "gamma"},
        {"tenant": "clinic-b", "prefix": "public|system=medical-assistant-v3", "sensitive": False, "role": "normal"},
    ],
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _cache_key(event: dict, policy: str) -> str:
    prefix = str(event["prefix"])
    tenant = str(event["tenant"])
    if policy == "shared":
        namespace = "shared"
    elif policy == "tenant_isolated":
        namespace = tenant
    elif policy == "selective":
        namespace = tenant if event.get("sensitive", True) else "public"
    else:
        raise ValueError(f"unknown policy: {policy}")
    return _digest(f"{namespace}|{prefix}")


def simulate(events: list[dict], policy: str, hit_latency_ms: float, miss_latency_ms: float) -> dict:
    cache: dict[str, str] = {}
    timeline = []
    cross_tenant_hits = 0
    safe_shared_hits = 0
    probe_results = []
    for index, event in enumerate(events):
        key = _cache_key(event, policy)
        owner = cache.get(key)
        hit = owner is not None
        cross_tenant = hit and owner != event["tenant"]
        latency = hit_latency_ms if hit else miss_latency_ms
        if cross_tenant:
            cross_tenant_hits += 1
            if not event.get("sensitive", True):
                safe_shared_hits += 1
        timeline.append({
            "index": index,
            "tenant": event["tenant"],
            "role": event.get("role", "normal"),
            "candidate": event.get("candidate"),
            "sensitive": bool(event.get("sensitive", True)),
            "hit": hit,
            "cross_tenant": cross_tenant,
            "latency_ms": latency,
        })
        if event.get("role") == "probe":
            probe_results.append({"candidate": event.get("candidate"), "latency_ms": latency, "hit": hit})
        cache[key] = str(event["tenant"])
    inferred = None
    if probe_results:
        minimum = min(item["latency_ms"] for item in probe_results)
        winners = [item["candidate"] for item in probe_results if item["latency_ms"] == minimum]
        if len(winners) == 1 and minimum < miss_latency_ms:
            inferred = winners[0]
    return {
        "policy": policy,
        "requests": len(events),
        "cache_hits": sum(item["hit"] for item in timeline),
        "cross_tenant_hits": cross_tenant_hits,
        "safe_shared_hits": safe_shared_hits,
        "inferred_private_value": inferred,
        "leak_detected": inferred is not None,
        "timeline": timeline,
    }


def analyze(payload: dict) -> dict:
    events = list(payload["events"])
    hit_latency = float(payload.get("hit_latency_ms", 20))
    miss_latency = float(payload.get("miss_latency_ms", 100))
    if hit_latency <= 0 or miss_latency <= hit_latency:
        raise ValueError("miss latency must be greater than positive hit latency")
    policies = [simulate(events, policy, hit_latency, miss_latency) for policy in ("shared", "tenant_isolated", "selective")]
    shared, isolated, selective = policies
    return {
        "request_count": len(events),
        "latency_gap_ms": round(miss_latency - hit_latency, 3),
        "shared_cache_leaks": shared["leak_detected"],
        "shared_inference": shared["inferred_private_value"],
        "isolated_cache_leaks": isolated["leak_detected"],
        "selective_cache_leaks": selective["leak_detected"],
        "selective_safe_reuse": selective["safe_shared_hits"],
        "selective_reuse_vs_shared": round(selective["cache_hits"] / max(1, shared["cache_hits"]), 3),
        "recommended_policy": "selective" if not selective["leak_detected"] and selective["safe_shared_hits"] else "tenant_isolated",
        "policies": policies,
        "scope": "Deterministic timing-side-channel harness; production evaluation must include jitter, batching, routing, and the actual serving engine.",
    }
