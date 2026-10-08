import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SYSTEMHOOK_MAIN = ROOT / "BaseBin/systemhook/src/main.c"


class ForkfixLoadPolicyTests(unittest.TestCase):
    def test_arm64e_forkfix_load_requires_process_fork_permission(self):
        source = SYSTEMHOOK_MAIN.read_text()
        load = source.index('JBROOT_PATH("/basebin/forkfix.dylib")')
        start = source.rfind("#ifdef __arm64e__", 0, load)
        end = source.index("#endif", load)
        block = source[start:end]

        self.assertIn('JBROOT_PATH("/basebin/forkfix.dylib")', block)
        self.assertIn('dlopen(', block)
        self.assertIn(
            'int forkSandboxResult = sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL);',
            block,
        )
        self.assertIn(
            'systemhook_trace_result("process-fork-sandbox-check", forkSandboxResult);',
            block,
        )
        gate = block.index("if (forkSandboxResult == 0) {")
        forkfix_path = block.index('const char *forkfixPath = JBROOT_PATH("/basebin/forkfix.dylib");')
        self.assertLess(gate, forkfix_path)

    def test_required_forkfix_is_not_blocked_by_optional_external_hook_setup(self):
        source = SYSTEMHOOK_MAIN.read_text()
        initializer = source.index("__attribute__((constructor)) static void initializer")
        external = source.index("init_hookd_external_support()", initializer)
        forkfix = source.index('JBROOT_PATH("/basebin/forkfix.dylib")', initializer)

        self.assertLess(forkfix, external)
        external_window = source[external - 80: external + 160]
        self.assertNotRegex(external_window, r"init_hookd_external_support\(\)\s*!=\s*0\)\s*return")


if __name__ == "__main__":
    unittest.main()
