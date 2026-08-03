import unittest

from cacheisolate.core import DEMO, _cache_key, analyze


class DelimiterInjectionTest(unittest.TestCase):
    """_cache_key hashed f"{namespace}|{prefix}" with an unescaped "|"
    separator. A tenant id containing "|" could shift the boundary between
    namespace and prefix, colliding with a different tenant's cache key even
    under the "tenant_isolated" policy -- completely defeating the isolation
    the policy is supposed to provide."""

    def _victim_and_attacker(self):
        victim = {"tenant": "victim", "prefix": "private|patient=alice|diagnosis=alpha"}
        attacker = {"tenant": "victim|private", "prefix": "patient=alice|diagnosis=alpha"}
        return victim, attacker

    def test_crafted_tenant_id_no_longer_collides_under_isolation(self):
        victim, attacker = self._victim_and_attacker()
        self.assertNotEqual(_cache_key(victim, "tenant_isolated"), _cache_key(attacker, "tenant_isolated"))

    def test_crafted_tenant_id_no_longer_leaks_private_value(self):
        events = [
            {"tenant": "victim", "prefix": "private|patient=alice|diagnosis=alpha", "sensitive": True, "role": "victim"},
            {"tenant": "victim|private", "prefix": "patient=alice|diagnosis=beta", "sensitive": True, "role": "probe", "candidate": "beta"},
            {"tenant": "victim|private", "prefix": "patient=alice|diagnosis=alpha", "sensitive": True, "role": "probe", "candidate": "alpha"},
            {"tenant": "victim|private", "prefix": "patient=alice|diagnosis=gamma", "sensitive": True, "role": "probe", "candidate": "gamma"},
        ]
        result = analyze({"events": events, "hit_latency_ms": 18, "miss_latency_ms": 104})
        self.assertFalse(result["isolated_cache_leaks"])

    def test_prefix_containing_delimiter_still_distinguished(self):
        # A prefix with an embedded "|" must not collide with a different
        # tenant/prefix split that happens to concatenate to the same string.
        event_a = {"tenant": "a", "prefix": "b|c"}
        event_b = {"tenant": "a|b", "prefix": "c"}
        self.assertNotEqual(_cache_key(event_a, "shared"), _cache_key(event_b, "shared"))

    def test_demo_output_unaffected(self):
        result = analyze(DEMO)
        self.assertEqual(result["latency_gap_ms"], 86.0)
        self.assertTrue(result["shared_cache_leaks"])
        self.assertEqual(result["shared_inference"], "alpha")
        self.assertFalse(result["isolated_cache_leaks"])
        self.assertFalse(result["selective_cache_leaks"])
        self.assertEqual(result["selective_safe_reuse"], 1)
        self.assertEqual(result["recommended_policy"], "selective")


if __name__ == "__main__":
    unittest.main()
