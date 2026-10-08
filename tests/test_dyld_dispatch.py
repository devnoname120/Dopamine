import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class DyldDispatchTests(unittest.TestCase):
    """Validate 23A341 dispatch code and keep loader tables read-only."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="roothide-dyld-dispatch-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = pathlib.Path(cls.directory.name) / "dispatch_tests"
        result = subprocess.run(
            ["xcrun", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-Ddlsym=dispatch_test_dlsym",
             "-Ddlopen=dispatch_test_dlopen",
             "-Ddlclose=dispatch_test_dlclose",
             "-Wno-unused-variable", "-I", str(ROOT / "BaseBin/systemhook/src"),
             "-I", str(ROOT / "BaseBin/_external/modules/litehook/src"),
             str(ROOT / "tests/dyld_dispatch_tests.c"),
             str(ROOT / "BaseBin/systemhook/src/dyld_dispatch.c"),
             "-o", str(cls.binary)], text=True, capture_output=True,
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_all_five_captured_stubs_preserve_argument_setup(self):
        self.run_case("captured")

    def test_changed_or_truncated_stubs_are_not_patched(self):
        self.run_case("changed")

    def test_wrong_global_salt_and_invalid_arguments_are_rejected(self):
        self.run_case("invalid")

    def test_runtime_patcher_keeps_the_table_readonly(self):
        self.run_case("runtime")

    def test_backend_errors_propagate_with_a_valid_original(self):
        self.run_case("backend-failure")

    def test_public_exports_do_not_require_private_local_symbols(self):
        self.run_case("exports-only")

    def test_public_export_lookup_ignores_vroot_default_symbol_shadowing(self):
        self.run_case("shadowed-export")

    def test_dlsym_uses_the_same_dispatch_backend(self):
        source = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        self.assertIn('dyld_hook_dispatch(gAPIsPtr, "_dlsym", 2, 16,', source)
        self.assertIn('(void **)&dyld_dlsym_orig, 0x839D)', source)

    def test_dlsym_watchdog_trace_precedes_special_case_and_forwarding(self):
        source = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        start = source.index("void *dyld_dlsym_hook(")
        end = source.index("static int init_dlsym_hook", start)
        hook = source[start:end]

        trace = hook.index("systemhook_trace_dlsym(name, handle);")
        special_case = hook.index('handle == gLibSandboxHandle && !strcmp(name, "sandbox_apply")')
        forwarding = hook.index("__attribute__((musttail)) return dyld_dlsym_orig")
        self.assertLess(trace, special_case)
        self.assertLess(trace, forwarding)

        helper_start = source.index("static void systemhook_trace_dlsym(")
        helper_end = source.index("\n}", helper_start)
        helper = source[helper_start:helper_end]
        self.assertIn("systemhook_trace_comparison_target()", helper)
        self.assertIn("__atomic_fetch_add", helper)
        self.assertIn("systemhook dlsym", helper)

    def test_watchdog_comparison_trace_includes_healthy_controls(self):
        source = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        helper_start = source.index("static bool systemhook_trace_comparison_target(")
        helper_end = source.index("\n}", helper_start)
        helper = source[helper_start:helper_end]

        self.assertIn("_NSGetExecutablePath", helper)

        for name in (
            "backboardd",
            "audiomxd",
            "thermalmonitord",
            "CommCenter",
            "logd",
            "runningboardd",
            "wifid",
            "configd",
        ):
            self.assertIn(f'"{name}"', helper)

        phase_start = source.index("static void systemhook_trace_phase(")
        phase_end = source.index("\n}", phase_start)
        self.assertIn(
            "systemhook_trace_comparison_target()",
            source[phase_start:phase_end],
        )

    def test_watchdog_comparison_trace_is_opt_in(self):
        source = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        enabled_start = source.index("static bool systemhook_trace_enabled(")
        enabled_end = source.index("\n}", enabled_start)
        enabled = source[enabled_start:enabled_end]
        self.assertIn('getenv("ROOTHIDE_SYSTEMHOOK_PHASE_TRACE")', enabled)

        for helper_name in (
            "systemhook_trace_phase",
            "systemhook_trace_result",
            "systemhook_trace_dlsym",
        ):
            helper_start = source.index(f"static void {helper_name}(")
            helper_end = source.index("\n}", helper_start)
            helper = source[helper_start:helper_end]
            self.assertIn("if (!systemhook_trace_enabled()) return;", helper)


if __name__ == "__main__":
    unittest.main()
