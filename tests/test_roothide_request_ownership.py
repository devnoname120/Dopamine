import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class RootHideRequestOwnershipTests(unittest.TestCase):
    def test_requests_and_replies_are_released_on_every_outcome(self):
        implementation = function_source("BaseBin/libjailbreak/src/jbclient_xpc.c", "jbserver_xpc_send")
        path = "BaseBin/libjailbreak/src/jbclient_roothide.c"
        for name in ("jbclient_roothide_jailbroken", "jbclient_palehide_present",
                     "jbclient_blacklist_check_pid", "jbclient_blacklist_check_path_checked",
                     "jbclient_blacklist_check_path",
                     "jbclient_blacklist_check_bundle", "jbclient_dyld_patch_enabled",
                     "jbclient_set_dyld_patch"):
            implementation += "\n" + function_source(path, name)
        with tempfile.TemporaryDirectory(prefix="port-request-ownership-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation,
                                         "tests/roothide_request_ownership_tests.c", ["-fblocks"])
            for mode in ("success", "transport-failure", "server-failure"):
                with self.subTest(mode=mode):
                    result = run_fixture(executable, mode)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("7 request ownership paths, 0 live objects", result.stdout)


if __name__ == "__main__":
    unittest.main()
