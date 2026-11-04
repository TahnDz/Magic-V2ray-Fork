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
        cls.sub_filter = function("mobile_iface_matches_selected_sub")
        cls.mode_detector = function("network_mode_allows_interface")
        cls.effective_mode = function("effective_network_mode")
        cls.effective_sub = function("effective_mobile_data_sub_id")
        cls.trigger_enabled = function("network_trigger_enabled")

    def allows(self, mode, iface, selected_sub="auto", trigger_mode="", trigger_sub="", trigger_enabled="false"):
        script = (
            "query_settings() { case \"$1\" in networkMode) printf '%s\\n' \"$NETWORK_MODE\" ;; mobileDataSubId) printf '%s\\n' \"$MOBILE_SUB\" ;; esac; }\n"
            + "query_trigger_settings() { case \"$1\" in enabled) printf '%s\\n' \"$TRIGGER_ENABLED\" ;; networkMode) printf '%s\\n' \"$TRIGGER_MODE\" ;; mobileDataSubId) printf '%s\\n' \"$TRIGGER_SUB\" ;; esac; }\n"
            + "TRIGGER_FILE=\"$TRIGGER_PATH\"; if [ \"$TRIGGER_PRESENT\" != 1 ]; then TRIGGER_FILE=/dev/null; fi\n"
            + self.mobile_detector
            + "\n"
            + self.sub_filter
            + "\n"
            + self.trigger_enabled
            + "\n"
            + self.effective_mode
            + "\n"
            + self.effective_sub
            + "\n"
            + "mobile_iface_sub_id() { case \"$1\" in rmnet_data1) printf '4\\n' ;; rmnet_data2) printf '1\\n' ;; *) printf '\\n' ;; esac; }\n"
            + self.mode_detector
            + "\nnetwork_mode_allows_interface \"$TEST_IFACE\"\n"
        )
        env = os.environ.copy()
        env["NETWORK_MODE"] = str(mode)
        env["TEST_IFACE"] = iface
        env["MOBILE_SUB"] = selected_sub
        env["TRIGGER_MODE"] = trigger_mode
        env["TRIGGER_SUB"] = trigger_sub
        env["TRIGGER_ENABLED"] = trigger_enabled
        env["TRIGGER_PRESENT"] = "1" if trigger_mode else "0"
        with tempfile.TemporaryDirectory() as trigger_dir:
            env["TRIGGER_PATH"] = str(Path(trigger_dir) / "trigger.base64")
            if trigger_mode:
                Path(env["TRIGGER_PATH"]).write_text("{}")
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

    def test_mobile_only_can_select_sim_subscription(self):
        self.assertTrue(self.allows(2, "rmnet_data1", "4"))
        self.assertFalse(self.allows(2, "rmnet_data2", "4"))

    def test_standalone_trigger_network_overrides_legacy_setting(self):
        self.assertTrue(self.allows(0, "rmnet_data1", "auto", "2", "4", "true"))
        self.assertFalse(self.allows(0, "rmnet_data2", "auto", "2", "4", "true"))

    def test_disabled_trigger_does_not_restrict_manual_network(self):
        self.assertTrue(self.allows(2, "wlan0", "4", "2", "4", "false"))


class SettingsDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (Path(__file__).resolve().parents[2] / "service.sh").read_text()

        def function(name):
            start = source.index(name + "() {\n")
            end = source.index("\n}", start) + len("\n}")
            return source[start:end]

        cls.decoder = function("decode_json_file")
        cls.query = function("query_json_file")

    def query_mode(self, payload, storage="base64"):
        encoded = payload.encode()
        if storage == "base64":
            encoded = base64.b64encode(encoded)
        elif storage == "double-base64":
            encoded = base64.b64encode(base64.b64encode(encoded))
        elif storage != "plain":
            raise ValueError(storage)
        with tempfile.TemporaryDirectory() as data_dir:
            Path(data_dir, "settings.base64").write_bytes(encoded)
            script = (
                "DATADIR=" + shlex.quote(data_dir) + "\n"
                + self.decoder + "\n"
                + self.query + "\n"
                + "query_json_file \"$DATADIR/settings.base64\" networkMode\n"
            )
            result = subprocess.run(
                [shutil.which("sh"), "-c", script],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

    def test_plain_json_settings_are_read(self):
        self.assertEqual(self.query_mode('{"networkMode":2}', storage="plain"), "2")

    def test_legacy_base64_settings_are_read(self):
        self.assertEqual(self.query_mode('{"networkMode":2}'), "2")

    def test_legacy_double_encoded_settings_are_read(self):
        self.assertEqual(self.query_mode('{"networkMode":2}', storage="double-base64"), "2")


if __name__ == "__main__":
    unittest.main()
