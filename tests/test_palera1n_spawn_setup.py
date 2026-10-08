import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class Palera1nSpawnSetupTests(unittest.TestCase):
    def test_long_running_helper_spawn_setup_is_checked_and_collision_safe(self):
        path = "Application/Dopamine/Exploits/palera1n/palera1n.m"
        source = (ROOT / path).read_text()
        implementation = ""
        helper = re.search(r"^static int palera1n_make_pipe\([^;]*?\n\{.*?^\}", source, re.MULTILINE | re.DOTALL)
        if helper:
            implementation += helper.group(0) + "\n"
        implementation += function_source(path, "spawn_server")
        with tempfile.TemporaryDirectory(prefix="palera1n-spawn-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), implementation, "tests/palera1n_spawn_setup_tests.m",
                ("-fblocks", "-fobjc-arc"),
            )
            for scenario in ("success", "collision", "attr-init", "persona", "actions-init", "pipe", "add-action", "spawn"):
                with self.subTest(scenario=scenario):
                    result = run_fixture(executable, scenario)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
