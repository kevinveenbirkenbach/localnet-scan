import unittest
from unittest.mock import patch, MagicMock
import subprocess

import utils

class TestUtils(unittest.TestCase):
    @patch("shutil.which", return_value=None)
    def test_which_none(self, m):
        self.assertIsNone(utils.which("no-such-cmd"))

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep", "10"], timeout=1))
    def test_run_timeout(self, m):
        rc, out, err = utils.run(["sleep", "10"], timeout=1)
        self.assertEqual(rc, 124)
        self.assertEqual(out, "")
        self.assertEqual(err, "timeout")
