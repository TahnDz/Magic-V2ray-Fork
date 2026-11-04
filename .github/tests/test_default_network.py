"""Run the production detector against netd rule fixtures; no device changes.

Run: python3 -m unittest discover -s .github/tests
"""
import base64
from pathlib import Path
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest


class DefaultNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (Path(__file__).resolve().parents[2] / "service.sh").read_text()
        start = source.index("detect_auto_table() {\n")
        end = source.index("\n}", start) + len("\n}")
        cls.detector = source[start:end]

    def detect(self, rules):
        # Only the detector is evaluated, so service startup/iptables never run.
        script = "fixture_ip() { cat; }\nip=fixture_ip\n" + self.detector + "\ndetect_auto_table\n"
        result = subprocess.run(
            [shutil.which("sh"), "-c", script], input=rules,
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_full_range_wifi_default(self):
        rules = "29998: from all fwmark 0x0/0xffff iif lo uidrange 0-2147483647 lookup wlan0 \n"
        self.assertEqual(self.detect(rules), "wlan0")

    def test_full_range_mobile_default(self):
        rules = "29998: from all fwmark 0x0/0xffff iif lo uidrange 0-2147483647 lookup rmnet_data2\n"
        self.assertEqual(self.detect(rules), "rmnet_data2")

    def test_narrow_uid_routes_do_not_override_global_default(self):
        rules = (
            "29040: from all fwmark 0x0/0xffff iif lo uidrange 10147-10147 lookup other0\n"
            "29040: from all fwmark 0x0/0xffff iif lo uidrange 10000-19999 lookup tun0\n"
            "29998: from all fwmark 0x0/0xffff iif lo uidrange 0-2147483647 lookup wlan0\n"
        )
        self.assertEqual(self.detect(rules), "wlan0")

    def test_legacy_default_with_trailing_whitespace(self):
        rules = "31000: from all fwmark 0x0/0xffff iif lo lookup wlan0 \t\n"
        self.assertEqual(self.detect(rules), "wlan0")

    def test_numeric_table_is_returned_for_existing_resolver(self):
        rules = "29998: from all fwmark 0x0/0xffff iif lo uidrange 0-2147483647 lookup 1026\n"
        self.assertEqual(self.detect(rules), "1026")

    def test_only_narrow_uid_routes_yield_no_default(self):
        rules = "29040: from all fwmark 0x0/0xffff iif lo uidrange 10147-10147 lookup tun0\n"
        self.assertEqual(self.detect(rules), "")

    def test_unrelated_marks_are_ignored(self):
        rules = (
            "15998: from all fwmark 0x10064/0x1ffff iif lo uidrange 0-2147483647 lookup other0\n"
            "29998: from all fwmark 0x0/0xffff iif lo uidrange 0-2147483647 lookup wlan0\n"
        )
        self.assertEqual(self.detect(rules), "wlan0")

    def test_empty_rules_yield_no_default(self):
        self.assertEqual(self.detect(""), "")


class NetworkModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (Path(__file__).resolve().parents[2] / "service.sh").read_text()

        def function(name):
            start = source.index(name + "() {\n")
            end = source.index("\n}", start) + len("\n}")
            return source[start:end]

        cls.mobile_detector = function("is_mobile_data_iface")
        cls.mode_detector = function("network_mode_allows_interface")

    def allows(self, mode, iface):
        script = (
            "query_settings() { printf '%s\\n' \"$NETWORK_MODE\"; }\n"
            + self.mobile_detector
            + "\n"
            + self.mode_detector
            + "\nnetwork_mode_allows_interface \"$TEST_IFACE\"\n"
        )
        env = os.environ.copy()
        env["NETWORK_MODE"] = str(mode)
        env["TEST_IFACE"] = iface
        return subprocess.run(
            [shutil.which("sh"), "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        ).returncode == 0

    def test_mobile_only_allows_rmnet(self):
        self.assertTrue(self.allows(2, "rmnet_data2"))

    def test_mobile_only_bypasses_wifi(self):
        self.assertFalse(self.allows(2, "wlan0"))

    def test_wifi_only_bypasses_mobile(self):
        self.assertFalse(self.allows(1, "rmnet_data2"))

    def test_wifi_only_allows_ethernet(self):
        self.assertTrue(self.allows(1, "wlan0"))


class SettingsDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (Path(__file__).resolve().parents[2] / "service.sh").read_text()

        def function(name):
            start = source.index(name + "() {\n")
            end = source.index("\n}", start) + len("\n}")
            return source[start:end]

        cls.decoder = function("decode_settings")
        cls.query = function("query_settings")

    def query_mode(self, payload, double_encoded=False):
        encoded = base64.b64encode(payload.encode())
        if double_encoded:
            encoded = base64.b64encode(encoded)
        with tempfile.TemporaryDirectory() as data_dir:
            Path(data_dir, "settings.base64").write_bytes(encoded)
            script = (
                "DATADIR=" + shlex.quote(data_dir) + "\n"
                + self.decoder + "\n"
                + self.query + "\n"
                + "query_settings networkMode\n"
            )
            result = subprocess.run(
                [shutil.which("sh"), "-c", script],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

    def test_current_settings_decode_once(self):
        self.assertEqual(self.query_mode('{"networkMode":2}'), "2")

    def test_legacy_double_encoded_settings_are_read(self):
        self.assertEqual(self.query_mode('{"networkMode":2}', double_encoded=True), "2")


if __name__ == "__main__":
    unittest.main()
