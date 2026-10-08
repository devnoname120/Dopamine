import pathlib
import tempfile
import unittest

from port_review_test_support import compile_fixture, function_source, run_fixture


class BoomerangDoneDispatchTests(unittest.TestCase):
    def test_done_is_handled_before_generic_unknown_action_reply(self):
        implementation = function_source(
            "BaseBin/libjailbreak/src/jbserver_boomerang.c",
            "jbserver_received_boomerang_xpc_message",
        )
        with tempfile.TemporaryDirectory(prefix="boomerang-done-dispatch-") as temporary:
            executable = compile_fixture(
                pathlib.Path(temporary),
                implementation,
                "tests/boomerang_done_dispatch_tests.c",
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
