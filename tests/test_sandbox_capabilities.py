import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class SandboxCapabilityTests(unittest.TestCase):
    def test_watchdog_trace_brackets_sandbox_reacquire(self):
        implementation = function_source(
            "BaseBin/systemhook/src/main.c",
            "sandbox_apply_hook",
        )
        phases = (
            'systemhook_trace_phase("sandbox-apply-enter")',
            'systemhook_trace_phase("sandbox-apply-original-returned")',
            'systemhook_trace_result("sandbox-apply-extensions-returned"',
        )
        positions = [implementation.find(phase) for phase in phases]
        self.assertTrue(all(position >= 0 for position in positions), implementation)
        self.assertEqual(positions, sorted(positions))

    def test_dyld_and_systemhook_require_complete_consumption(self):
        for path in ("BaseBin/dyldhook/src/main.c", "BaseBin/systemhook/src/main.c"):
            with self.subTest(path=path):
                implementation = function_source(path, "consume_tokenized_sandbox_extensions")
                with tempfile.TemporaryDirectory(prefix="sandbox-consume-") as directory:
                    executable = compile_fixture(
                        pathlib.Path(directory), implementation, "tests/sandbox_capability_consume_tests.c"
                    )
                    for scenario in ("success", "empty", "short", "empty-token", "long", "fail-first", "fail-second", "fail-third"):
                        with self.subTest(path=path, scenario=scenario):
                            result = run_fixture(executable, scenario)
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_server_rejects_missing_or_untransportable_extension_sets(self):
        implementation = function_source(
            "BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c",
            "validate_sandbox_extensions_for_checkin",
        )
        with tempfile.TemporaryDirectory(prefix="sandbox-server-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/sandbox_capability_server_tests.c"
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
