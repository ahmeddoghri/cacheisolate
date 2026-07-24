import unittest

from cacheisolate.core import DEMO, analyze, simulate


class CacheIsolateTests(unittest.TestCase):
    def test_shared_cache_leaks_candidate(self):
        result = analyze(DEMO)
        self.assertTrue(result["shared_cache_leaks"])
        self.assertEqual(result["shared_inference"], "alpha")

    def test_full_isolation_blocks_cross_tenant_hits(self):
        result = analyze(DEMO)
        isolated = next(item for item in result["policies"] if item["policy"] == "tenant_isolated")
        self.assertEqual(isolated["cross_tenant_hits"], 0)
        self.assertFalse(isolated["leak_detected"])

    def test_selective_policy_preserves_public_reuse(self):
        result = analyze(DEMO)
        self.assertFalse(result["selective_cache_leaks"])
        self.assertEqual(result["selective_safe_reuse"], 1)
        self.assertEqual(result["recommended_policy"], "selective")

    def test_invalid_latency_model_fails(self):
        with self.assertRaisesRegex(ValueError, "latency"):
            analyze({**DEMO, "hit_latency_ms": 100, "miss_latency_ms": 20})


if __name__ == "__main__":
    unittest.main()
