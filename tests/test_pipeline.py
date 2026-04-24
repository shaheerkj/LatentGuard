import tempfile
import unittest

from latentguard.pipeline import LatentGuardPipeline


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.pipeline = LatentGuardPipeline(data_path=self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_blocks_known_attack(self) -> None:
        result = self.pipeline.process_request(
            {
                "method": "GET",
                "path": "/search",
                "query": "q=1 UNION SELECT password FROM users",
                "headers": {"Host": "example.com"},
                "source_ip": "198.51.100.2",
            }
        )
        self.assertEqual(result["decision"]["action"], "block")
        self.assertFalse(result["forward_to_backend"])

    def test_ml_failure_falls_back_to_safe_mode(self) -> None:
        self.pipeline.ml.set_fail_mode(True)
        result = self.pipeline.process_request(
            {
                "method": "GET",
                "path": "/products",
                "query": "page=1",
                "headers": {"Host": "example.com"},
                "source_ip": "198.51.100.3",
            }
        )
        self.assertTrue(result["decision"]["fallback_used"])
        self.assertTrue(result["safe_mode"])

    def test_ml_recovery_after_safe_mode_disabled(self) -> None:
        self.pipeline.ml.set_fail_mode(True)
        _ = self.pipeline.process_request(
            {
                "method": "GET",
                "path": "/products",
                "query": "page=1",
                "headers": {"Host": "example.com"},
                "source_ip": "198.51.100.30",
            }
        )
        self.assertTrue(self.pipeline.safe_mode)

        self.pipeline.safe_mode = False
        self.pipeline.ml.set_fail_mode(False)
        recovered = self.pipeline.process_request(
            {
                "method": "GET",
                "path": "/products",
                "query": "page=2",
                "headers": {"Host": "example.com"},
                "source_ip": "198.51.100.31",
            }
        )
        self.assertFalse(recovered["decision"]["fallback_used"])
        self.assertFalse(recovered["safe_mode"])

    def test_generates_rules_from_blocked_logs(self) -> None:
        self.pipeline.process_request(
            {
                "method": "GET",
                "path": "/login",
                "query": "cmd=../../etc/passwd",
                "headers": {"Host": "example.com"},
                "source_ip": "198.51.100.4",
            }
        )
        gen = self.pipeline.generate_rules()
        self.assertGreaterEqual(gen["patterns_found"], 1)

    def test_updates_consensus_config(self) -> None:
        cfg = self.pipeline.set_consensus_config(
            {
                "weight_m4": 0.5,
                "weight_m5": 0.2,
                "weight_rules": 0.3,
                "block_threshold": 0.7,
            }
        )
        self.assertAlmostEqual(cfg["weight_m4"], 0.5)
        self.assertAlmostEqual(cfg["block_threshold"], 0.7)


if __name__ == "__main__":
    unittest.main()
