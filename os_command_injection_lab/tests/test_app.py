import unittest
from unittest.mock import patch
import subprocess

import app as lab


class CommandInjectionLabTests(unittest.TestCase):
    def setUp(self):
        lab.app.config.update(TESTING=True)
        self.client = lab.app.test_client()

    @patch("app.subprocess.run")
    def test_vulnerable_route_uses_shell(self, mocked_run):
        mocked_run.return_value = subprocess.CompletedProcess(
            args="getent hosts 127.0.0.1; id", returncode=0, stdout="demo output", stderr=""
        )
        response = self.client.post(
            "/run/vulnerable", data={"target": "127.0.0.1; id"}
        )
        self.assertEqual(response.status_code, 200)
        kwargs = mocked_run.call_args.kwargs
        self.assertTrue(kwargs["shell"])
        self.assertIn("127.0.0.1; id", mocked_run.call_args.args[0])

    @patch("app.subprocess.run")
    def test_secure_route_passes_input_as_one_argument(self, mocked_run):
        mocked_run.return_value = subprocess.CompletedProcess(
            args=["getent", "hosts", "127.0.0.1; id"],
            returncode=2,
            stdout="",
            stderr="invalid target",
        )
        response = self.client.post(
            "/run/secure", data={"target": "127.0.0.1; id"}
        )
        self.assertEqual(response.status_code, 200)
        args = mocked_run.call_args.args[0]
        kwargs = mocked_run.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertEqual(args[-1], "127.0.0.1; id")
        self.assertEqual(args.count("id"), 0)

    def test_target_length_is_bounded(self):
        response = self.client.post("/run/secure", data={"target": "x" * 129})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
