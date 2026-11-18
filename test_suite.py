import unittest
import tempfile
from pathlib import Path
from checks.secret_scanner import scan_single_file, scan_multiple_paths
from checks.port_checker import parse_port_spec
from checks.exceptions import ConfigurationError

class TestSecuritySuite(unittest.TestCase):
    def test_secret_scanner_detects_leaks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dirty_file = Path(tmpdir) / "app.env"
            dirty_file.write_text("DB_HOST=localhost\nAWS_KEY=AKIAIOSFODNN7EXAMPLEKEY\n", encoding="utf-8")

            findings = scan_single_file(dirty_file)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "CRITICAL")
            self.assertIn("AWS/Cloud Access Key", findings[0]["detail"])

    def test_secret_scanner_clean_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_file = Path(tmpdir) / "clean.ini"
            clean_file.write_text("[APP]\nenv = production\ntimeout = 30\n", encoding="utf-8")

            findings = scan_single_file(clean_file)
            self.assertEqual(len(findings), 0)

    def test_secret_scanner_recursive_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sub = Path(tmpdir) / "nested"
            sub.mkdir()
            (sub / "secret.conf").write_text("password = SuperSecretPass123\n", encoding="utf-8")
            (Path(tmpdir) / "safe.yaml").write_text("port: 8080\n", encoding="utf-8")

            findings = scan_multiple_paths([tmpdir])
            self.assertEqual(len(findings), 1)

    def test_port_spec_parser(self):
        ports = parse_port_spec("22, 80, 1430-1432, 443")
        self.assertEqual(ports, [22, 80, 443, 1430, 1431, 1432])

    def test_port_spec_invalid_range_raises(self):
        with self.assertRaises(ConfigurationError):
            parse_port_spec("9000-8000")

if __name__ == "__main__":
    unittest.main()