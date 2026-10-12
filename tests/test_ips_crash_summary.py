import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from ips_crash_summary import summarize_report


PC = 0x122400000
REPORT = {
    "bug_type": "309", "procName": "FixtureApp", "pid": 42,
    "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGKILL"},
    "termination": {"namespace": "CODESIGNING", "code": 2, "indicator": "Invalid Page"},
    "faultingThread": 1,
    "threads": [
        {"threadState": {"pc": {"value": 1234}}},
        {"triggered": True, "frames": [], "threadState": {
            "pc": {"value": PC}, "far": {"value": PC}, "lr": {"value": 0xCAFEBABE},
            "esr": {"description": "(Instruction Abort) Permission fault"},
        }},
    ],
    "vmRegionInfo": "--->  VM_ALLOCATE  122400000-122404000 [   16K] r--/rw- SM=PRV",
    "usedImages": [{"name": "FixtureApp", "base": 0x100000000, "size": 0x10000}],
}


class IpsCrashSummaryTests(unittest.TestCase):
    def summarize(self, report=None):
        return summarize_report(json.dumps(REPORT if report is None else report).encode())

    def test_two_record_ips_and_exact_byte_hash(self):
        data = (json.dumps({"bug_type": "309", "app_name": "FixtureApp"}) +
                "\n" + json.dumps(REPORT)).encode()
        summary = summarize_report(data, "fixture.ips")
        self.assertEqual(summary["process"]["pid"], 42)
        self.assertEqual(summary["report_name"], "fixture.ips")
        self.assertEqual(summary["report_sha256"], hashlib.sha256(data).hexdigest())

    def test_faulting_thread_and_mapping_are_observations(self):
        summary = self.summarize()
        self.assertEqual(summary["faulting_thread"]["index"], 1)
        self.assertEqual(summary["registers"]["pc"], PC)
        self.assertTrue(summary["observations"]["instruction_permission_fault"])
        self.assertTrue(summary["observations"]["pc_equals_far"])
        mapping = summary["fault_mapping"]
        self.assertEqual(mapping["size_bytes"], 16384)
        self.assertEqual((mapping["protection"], mapping["maximum_protection"]), ("r--", "rw-"))
        self.assertTrue(mapping["contains_pc"])

    def test_image_absence_does_not_establish_root_cause_or_fix(self):
        summary = self.summarize()
        self.assertFalse(summary["observations"]["image_name_presence"]["frida-agent"])
        self.assertEqual(summary["underlying_compatibility_defect"], "not_established_by_crash_report")
        self.assertEqual(summary["fix_verification"], "not_assessed")

    def test_absent_image_inventory_is_unknown(self):
        for inventory in (None, [], [None]):
            with self.subTest(inventory=inventory):
                report = copy.deepcopy(REPORT)
                report["usedImages"] = inventory
                observations = self.summarize(report)["observations"]
                self.assertIsNone(observations["image_name_presence"]["frida-agent"])
                self.assertIsNone(observations["pc_in_reported_image"])

    def test_incomplete_image_ranges_do_not_prove_pc_is_outside_images(self):
        report = copy.deepcopy(REPORT)
        report["usedImages"].append({"name": "unknown-range"})
        self.assertIsNone(self.summarize(report)["observations"]["pc_in_reported_image"])
        report["usedImages"].append({"name": "frida-agent.dylib", "base": PC, "size": 16384})
        observations = self.summarize(report)["observations"]
        self.assertTrue(observations["pc_in_reported_image"])
        self.assertTrue(observations["image_name_presence"]["frida-agent"])

    def test_image_ranges_are_half_open(self):
        report = copy.deepcopy(REPORT)
        report["usedImages"] = [{"base": PC - 1, "size": 1}]
        self.assertFalse(self.summarize(report)["observations"]["pc_in_reported_image"])

    def test_absolute_symbol_record_is_not_a_missing_image_range(self):
        report = copy.deepcopy(REPORT)
        report["usedImages"].append({"source": "A", "base": 0, "size": 0})
        self.assertFalse(self.summarize(report)["observations"]["pc_in_reported_image"])
        report["usedImages"] = [{"source": "A", "base": 0, "size": 0}]
        self.assertIsNone(self.summarize(report)["observations"]["pc_in_reported_image"])

    def test_missing_registers_and_faulting_thread_are_unknown(self):
        report = copy.deepcopy(REPORT)
        report["threads"] = []
        summary = self.summarize(report)
        self.assertIsNone(summary["faulting_thread"]["index"])
        self.assertIsNone(summary["observations"]["pc_equals_far"])
        self.assertIsNone(summary["observations"]["instruction_permission_fault"])
        self.assertIsNone(summary["fault_mapping"]["contains_pc"])

    def test_invalid_faulting_index_does_not_use_another_thread(self):
        for index in (-1, 99, True, "invalid", None):
            with self.subTest(index=index):
                report = copy.deepcopy(REPORT)
                report["faultingThread"] = index
                self.assertIsNone(self.summarize(report)["registers"]["pc"])

    def test_triggered_thread_fallback_requires_one_candidate(self):
        report = copy.deepcopy(REPORT)
        del report["faultingThread"]
        self.assertEqual(self.summarize(report)["faulting_thread"]["selected_by"], "triggered")
        report["threads"][0]["triggered"] = True
        self.assertIsNone(self.summarize(report)["registers"]["pc"])

    def test_hexadecimal_registers_and_lowercase_vm_field(self):
        report = copy.deepcopy(REPORT)
        report["threads"][1]["threadState"]["pc"]["value"] = hex(PC)
        report["vmregioninfo"] = report.pop("vmRegionInfo")
        self.assertEqual(self.summarize(report)["registers"]["pc"], PC)
        self.assertEqual(self.summarize(report)["fault_mapping"]["size_bytes"], 16384)

    def test_unrelated_memory_crash_is_not_codesigning(self):
        report = copy.deepcopy(REPORT)
        report["termination"] = {"namespace": "SIGNAL", "code": 11}
        report["threads"][1]["threadState"]["esr"]["description"] = "(Data Abort) Translation fault"
        observations = self.summarize(report)["observations"]
        self.assertFalse(observations["codesigning_invalid_page"])
        self.assertFalse(observations["instruction_permission_fault"])

    def test_incomplete_termination_is_unknown(self):
        for termination in ({}, {"code": 2}, {"namespace": "CODESIGNING"}):
            with self.subTest(termination=termination):
                report = copy.deepcopy(REPORT)
                report["termination"] = termination
                self.assertIsNone(self.summarize(report)["observations"]["codesigning_invalid_page"])

    def test_invalid_or_missing_mapping_is_unknown(self):
        for region in (None, "", "---> VM_ALLOCATE 122404000-122400000 [16K] r--/rw-", "unknown format"):
            with self.subTest(region=region):
                report = copy.deepcopy(REPORT)
                report["vmRegionInfo"] = region
                self.assertIsNone(self.summarize(report)["fault_mapping"])

    def test_mapping_does_not_implicitly_cover_the_program_counter(self):
        report = copy.deepcopy(REPORT)
        report["threads"][1]["threadState"]["pc"]["value"] += 16384
        mapping = self.summarize(report)["fault_mapping"]
        self.assertFalse(mapping["contains_pc"])
        self.assertTrue(mapping["contains_far"])

    def test_malformed_and_unsupported_reports_are_rejected(self):
        for data in (b"", b"[]", b"{}", b"{", b'{} trailing',
                     json.dumps(REPORT).encode() + b"\n{}\n{}",
                     b"{}\n" + json.dumps(REPORT).encode(),
                     json.dumps(REPORT).encode() + b"\n" + json.dumps(REPORT).encode(),
                     b'{"bug_type":"210","procName":"kernel","termination":{}}'):
            with self.subTest(data=data[:60]):
                with self.assertRaises(ValueError):
                    summarize_report(data)

    def test_cli_reads_existing_file_without_changing_it(self):
        script = pathlib.Path(__file__).with_name("ips_crash_summary.py")
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "fixture.ips"
            data = json.dumps(REPORT).encode()
            path.write_bytes(data)
            result = subprocess.run([sys.executable, str(script), str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["report_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(path.read_bytes(), data)
            path.write_bytes(b"truncated report")
            result = subprocess.run([sys.executable, str(script), str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
