import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TraceGatingTests(unittest.TestCase):
    def test_launchd_xpcproxy_trace_is_explicitly_opt_in(self):
        source = (ROOT / "BaseBin/launchdhook/src/roothider.m").read_text()
        self.assertIn('const char *xpcProxyTraceEnabled = getenv("ROOTHIDE_XPCPROXY_TRACE")', source)
        self.assertRegex(source, r'bool\s+traceXpcProxy\s*=\s*path\s*&&\s*strcmp\(path,\s*"/usr/libexec/xpcproxy"\)\s*==\s*0\s*&&\s*xpcProxyTraceEnabled\s*&&\s*strcmp\(xpcProxyTraceEnabled,\s*"1"\)\s*==\s*0')

    def test_patchproc_xpcproxy_trace_is_explicitly_opt_in(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/common.m").read_text()
        self.assertIn('const char *xpcProxyTraceEnabled = getenv("ROOTHIDE_XPCPROXY_TRACE")', source)
        self.assertRegex(source, r'bool\s+traceXpcProxy\s*=\s*procPath\s*&&\s*strcmp\(procPath,\s*"/usr/libexec/xpcproxy"\)\s*==\s*0\s*&&\s*xpcProxyTraceEnabled\s*&&\s*strcmp\(xpcProxyTraceEnabled,\s*"1"\)\s*==\s*0')

    def test_systemhook_loader_trace_is_explicitly_opt_in(self):
        source = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()
        helper = source[source.index("static void roothide_loader_trace") : source.index("//export for PatchLoader")]
        self.assertIn('getenv("ROOTHIDE_LOADER_TRACE")', helper)
        self.assertIn('strcmp(traceEnabled, "1") != 0', helper)
        self.assertLess(helper.index('getenv("ROOTHIDE_LOADER_TRACE")'), helper.index("getprogname()"))
        self.assertIn('strcmp(name, "Sileo") == 0', helper)
        self.assertNotIn("diagnosticSshd", helper)

    def test_systemhook_phase_trace_can_target_sileo_but_stays_opt_in(self):
        source = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        trace_target = source[source.index("static bool systemhook_trace_comparison_target") : source.index("static bool systemhook_trace_enabled")]
        trace_gate = source[source.index("static bool systemhook_trace_enabled") : source.index("static void systemhook_trace_phase")]
        self.assertIn('"Sileo"', trace_target)
        self.assertIn('getenv("ROOTHIDE_SYSTEMHOOK_PHASE_TRACE")', trace_gate)
        self.assertIn("enabled[0] == '1' && enabled[1] == '\\0'", trace_gate)

    def test_sileo_constructor_trace_is_build_opt_in_and_child_scoped(self):
        source = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()
        makefile = (ROOT / "BaseBin/systemhook/Makefile").read_text()

        self.assertRegex(makefile, r"(?m)^SILEO_CONSTRUCTOR_TRACE\s*\?=\s*0$")
        self.assertIn("-DROOTHIDE_SILEO_CONSTRUCTOR_TRACE=$(SILEO_CONSTRUCTOR_TRACE)", makefile)

        helper_start = source.index("static void arm_sileo_constructor_trace")
        helper_end = source.index("\n}", helper_start) + 2
        helper = source[helper_start:helper_end]
        self.assertIn("#if ROOTHIDE_SILEO_CONSTRUCTOR_TRACE", helper)
        self.assertIn('string_has_suffix(path, "/Applications/Sileo.app/Sileo")', helper)
        self.assertIn('envbuf_setenv(envc, "ROOTHIDE_SYSTEMHOOK_PHASE_TRACE", "1")', helper)
        self.assertIn('envbuf_setenv(envc, "ROOTHIDE_LOADER_TRACE", "1")', helper)
        self.assertNotIn('setenv("ROOTHIDE_SYSTEMHOOK_PHASE_TRACE"', helper)
        self.assertNotIn('setenv("ROOTHIDE_LOADER_TRACE"', helper)

        spawn_start = source.index("int roothide_systemhook___posix_spawn_posthook")
        spawn_end = source.index("int roothide_systemhook___execve_prehook", spawn_start)
        spawn = source[spawn_start:spawn_end]
        self.assertIn("arm_sileo_constructor_trace(path, &envc);", spawn)

        exec_start = source.index("int roothide_systemhook___execve_posthook")
        exec_end = source.index("void* (*dyld_dlopen_orig)", exec_start)
        exec_posthook = source[exec_start:exec_end]
        self.assertIn("arm_sileo_constructor_trace(path, &envc);", exec_posthook)

    def test_sileo_constructor_trace_self_arms_in_final_image(self):
        main = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        roothider = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()

        phase_gate = main[
            main.index("static bool systemhook_trace_enabled") :
            main.index("static void systemhook_trace_phase")
        ]
        self.assertIn("#if ROOTHIDE_SILEO_CONSTRUCTOR_TRACE", phase_gate)
        self.assertRegex(
            phase_gate,
            r'(?s)getprogname\(\).*?strcmp\([^\n]*"Sileo"\).*?return true',
        )

        loader = roothider[
            roothider.index("static void roothide_loader_trace") :
            roothider.index("static void arm_sileo_constructor_trace")
        ]
        self.assertIn("#if ROOTHIDE_SILEO_CONSTRUCTOR_TRACE", loader)
        self.assertRegex(
            loader,
            r'(?s)getprogname\(\).*?strcmp\([^\n]*"Sileo"\)',
        )

    def test_temporary_constructor_boundary_trace_is_removed(self):
        source = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        roothider = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()
        header = (ROOT / "BaseBin/systemhook/src/roothider.h").read_text()

        self.assertNotIn("roothide_loader_trace_boundary", header)
        self.assertNotIn("roothide_loader_trace_boundary", roothider)
        self.assertNotIn("roothide_loader_trace_boundary", source)

    def test_build59_sshd_auth_diagnostic_is_removed(self):
        source = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()
        makefile = (ROOT / "BaseBin/systemhook/Makefile").read_text()
        self.assertNotIn("ROOTHIDE_SSH_AUTH_DIAGNOSTICS", makefile)
        self.assertNotIn("ROOTHIDE_SSH_AUTH_DIAGNOSTICS", source)


if __name__ == "__main__":
    unittest.main()
