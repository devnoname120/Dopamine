import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class ExecPatchRegistrationTests(unittest.TestCase):
    def test_registration_is_published_before_kevent_and_rolled_back_on_failure(self):
        implementation = function_source(
            "BaseBin/libjailbreak/src/roothider/exec_patch.m", "spawnExecPatchAdd"
        )
        with tempfile.TemporaryDirectory(prefix="exec-patch-registration-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation,
                "tests/exec_patch_registration_tests.m",
                ("-fobjc-arc", "-fblocks", "-framework", "Foundation"),
            )
            for scenario in ("visible", "rollback"):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, scenario)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
