import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m"

class DyldTaskMetadataPolicyTests(unittest.TestCase):
    def test_policy_preserves_all_task_flags_except_dyld_finalization(self):
        with tempfile.TemporaryDirectory(prefix="dyld-task-metadata-") as directory:
            binary = pathlib.Path(directory) / "policy"
            result = subprocess.run([
                "xcrun", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                str(ROOT / "tests/dyld_task_metadata_policy_tests.c"), "-o", str(binary),
            ], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(binary)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("6 checks passed", result.stdout)

    def test_ios26_publication_uses_target_flags_not_magic_auxiliary_pattern(self):
        source = SOURCE.read_text()
        start = source.index("static int task_set_dyld_info_internal")
        end = source.index("\nint task_set_dyld_info(", start)
        implementation = source[start:end]
        self.assertIn("__builtin_available(iOS 26.0, *)", implementation)
        self.assertIn("task_dyld_flags_address_from_pair(snapshot.pairAddress)", implementation)
        self.assertIn("task_dyld_flags_for_replacement", implementation)
        self.assertIn("snapshot.hasFlags", implementation)
        target_policy = implementation.split("uint64_t launchdTask", 1)[1]
        ios26 = target_policy.split("if (__builtin_available(iOS 26.0, *))", 1)[1].split("\n    else {", 1)[0]
        self.assertNotIn("expectedInfo", ios26)

if __name__ == "__main__":
    unittest.main()
