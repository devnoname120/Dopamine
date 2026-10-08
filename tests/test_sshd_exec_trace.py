import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SshdExecTraceTests(unittest.TestCase):
    def test_launchd_no_longer_marks_openssh_xpcproxy_children(self):
        source = (ROOT / "BaseBin/launchdhook/src/roothider.m").read_text()
        self.assertNotIn("ROOTHIDE_SSHD_EXEC_TRACE", source)
        self.assertNotIn("traceSshdExec", source)

    def test_systemhook_sshd_exec_trace_is_removed(self):
        source = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()
        for marker in (
            "ROOTHIDE_SSHD_EXEC_TRACE",
            "roothide_sshd_exec_trace",
            "sshd-spawn",
            "sshd-argv",
            "sshd-env",
            "sshd-path",
        ):
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
