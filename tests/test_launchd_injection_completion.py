import unittest

from port_review_test_support import ROOT, function_source


class LaunchdInjectionCompletionTests(unittest.TestCase):
    def test_opainject_propagates_pac_and_rop_failures(self):
        main = (ROOT / "BaseBin/opainject/main.m").read_text()
        header = (ROOT / "BaseBin/opainject/rop_inject.h").read_text()
        rop = (ROOT / "BaseBin/opainject/rop_inject.m").read_text()

        self.assertIn("int spawnPacChild(int argc, char *argv[])", main)
        self.assertIn("return spawnPacChild(argc, argv);", main)
        self.assertIn("int injectResult = injectDylibViaRop", main)
        self.assertIn("return injectResult;", main)
        self.assertIn("extern int injectDylibViaRop", header)

        inject = function_source("BaseBin/opainject/rop_inject.m", "injectDylibViaRop")
        self.assertRegex(inject, r"if\s*\(kr != KERN_SUCCESS")
        self.assertIn("if (!sandboxFixup", inject)
        self.assertIn("if (!dlopenAddr || !dlerrorAddr)", inject)
        self.assertIn("if (!remoteDylibPath)", inject)
        self.assertIn("if (kr != KERN_SUCCESS || !dlopenRet)", inject)
        self.assertIn("mach_port_deallocate", inject)
        self.assertRegex(inject, r"return\s+result;")

        arb_start = rop.index("kern_return_t arbCall(")
        arb_end = rop.index("\nvoid prepareForMagic", arb_start)
        arb = rop[arb_start:arb_end]
        self.assertIn("cleanup:", arb)
        self.assertIn("resume_threads_except_for", arb[arb.index("cleanup:"):])
        self.assertNotIn("failed to wait for thread to finish: %s\\n\", mach_error_string(kr));\n\t\t\treturn kr;", arb)
        restore = arb.index("thread_restore_state_arm64(targetThread, origThreadFullState)")
        cleanup_free = arb.index("free(origThreadFullState);", restore)
        self.assertIn("origThreadFullState = NULL;", arb[restore:cleanup_free])

    def test_app_owns_receiver_until_bounded_completion(self):
        app = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text()
        method_start = app.index("- (NSError *)injectLaunchdHook")
        method_end = app.index("\n/*", method_start)
        method = app[method_start:method_end]

        self.assertNotIn("pthread_detach", method)
        self.assertIn("pthread_join", method)
        self.assertIn("mach_port_destroy", method)
        self.assertIn("dispatch_time(DISPATCH_TIME_NOW", method)
        self.assertNotIn("DISPATCH_TIME_FOREVER", method)
        self.assertIn("WEXITSTATUS(status) != 0", method)
        self.assertIn("boomerangCancelled", app)


if __name__ == "__main__":
    unittest.main()
