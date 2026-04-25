import unittest

from latentguard.interceptor import ReverseProxyInterceptor
from latentguard.normalizer import RequestNormalizer
from latentguard.rule_engine import RuleEngine
from latentguard.contracts import RequestContext


class FirstThreeModulesTests(unittest.TestCase):
    def test_module_1_reverse_proxy_interception_extracts_metadata(self) -> None:
        interceptor = ReverseProxyInterceptor()
        req = interceptor.intercept(
            {
                "method": "post",
                "path": "https://example.com/login?next=%2Fdashboard",
                "headers": {"X-Forwarded-For": "203.0.113.11, 10.0.0.1"},
                "body": {"username": "alice"},
            }
        )
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.path, "/login")
        self.assertEqual(req.query, "next=%2Fdashboard")
        self.assertEqual(req.source_ip, "203.0.113.11")
        self.assertIn("username", req.body)

    def test_module_2_normalization_and_feature_extraction(self) -> None:
        normalizer = RequestNormalizer()
        req = RequestContext(
            method="GET",
            path="/search%2Fitems",
            query="q=hello%20world",
            headers={"Host": "example.com"},
            body="payload%3D1",
            source_ip="198.51.100.10",
        )
        norm = normalizer.normalize(req)
        self.assertEqual(norm.canonical_path, "/search/items")
        self.assertEqual(norm.canonical_query, "q=hello world")
        self.assertEqual(norm.canonical_body, "payload=1")
        self.assertIn("entropy", norm.features)
        self.assertIn("special_ratio", norm.features)

    def test_module_3_rule_filtering_blocks_threat_intel_ip(self) -> None:
        engine = RuleEngine(deny_ips={"198.51.100.99"})
        req = RequestContext(
            method="GET",
            path="/products",
            query="id=1",
            headers={"Host": "example.com"},
            body="",
            source_ip="198.51.100.99",
        )
        norm = RequestNormalizer().normalize(req)
        evaluation = engine.evaluate(req, norm)
        self.assertEqual(evaluation.action, "block")
        self.assertIn("threatintel.ip", evaluation.matched_rules)


if __name__ == "__main__":
    unittest.main()
