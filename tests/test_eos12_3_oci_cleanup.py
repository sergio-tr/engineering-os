"""Offline regression tests for verified OCI container cleanup."""

import io
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from engineering_os.infrastructure.runtime.oci.oci_process import SubprocessOciHandle


CONTAINER_ID = "a" * 64
REMOVE = ["podman", "rm", "-f", CONTAINER_ID]
EXISTS = ["podman", "container", "exists", CONTAINER_ID]


class OciCleanupTests(unittest.TestCase):
    def start_fixture(self, cid=CONTAINER_ID):
        proc = Mock(stdout=io.StringIO(), stderr=io.StringIO())
        proc.poll.return_value = 0
        proc.wait.return_value = 0

        def spawn(argv, **kwargs):
            self.assertEqual(argv[:3], ["podman", "run", "--cidfile"])
            if cid is not None:
                Path(argv[3]).write_text(cid + "\n", encoding="ascii")
            return proc

        with patch.object(subprocess, "Popen", side_effect=spawn):
            handle, argv = SubprocessOciHandle.start_podman(
                ["podman", "run", "--name", "fixture", "image"],
                container_name="fixture",
            )
        return handle, Path(argv[3])

    def test_removal_and_absence_are_independently_verified(self):
        handle, cidfile = self.start_fixture()
        handle.runner = Mock(side_effect=[
            SimpleNamespace(returncode=0),
            SimpleNamespace(returncode=1),
        ])
        result = handle.cleanup()
        self.assertEqual(handle.container_id, CONTAINER_ID)
        self.assertTrue(result["cleanup_requested"])
        self.assertTrue(result["removal_succeeded"])
        self.assertTrue(result["cleaned_up"])
        self.assertTrue(result["cleanup_verified"])
        self.assertEqual(result["container_presence"], {
            "container_id": CONTAINER_ID, "state": "absent", "returncode": 1,
        })
        self.assertFalse(cidfile.parent.exists())
        self.assertEqual(handle.cleanup(), result)
        self.assertEqual(handle.runner.call_args_list, [call(REMOVE, 10.0), call(EXISTS, 10.0)])

    def test_unsuccessful_or_indeterminate_removal(self):
        for response, error in (
            (SimpleNamespace(returncode=125), "container_removal_failed"),
            (OSError("unavailable"), "OSError"),
            (SimpleNamespace(), "missing_returncode"),
        ):
            with self.subTest(error=error):
                handle, _ = self.start_fixture()
                handle.runner = Mock(side_effect=[response])
                result = handle.cleanup()
                self.assertTrue(result["cleanup_requested"])
                self.assertFalse(result["removal_succeeded"])
                self.assertFalse(result["cleaned_up"])
                self.assertFalse(result["cleanup_verified"])
                self.assertEqual(result["container_presence"]["state"], "unknown")
                self.assertEqual(result["error"], error)
                handle.runner.assert_called_once_with(REMOVE, 10.0)

    def test_presence_verification_fails_closed(self):
        for response, state, error in (
            (SimpleNamespace(returncode=0), "present", "container_presence_present"),
            (None, "unknown", "missing_returncode"),
            (subprocess.TimeoutExpired(EXISTS, 10), "unknown", "TimeoutExpired"),
            (OSError("unavailable"), "unknown", "OSError"),
            (SimpleNamespace(returncode=125), "unknown", "container_presence_unknown"),
        ):
            with self.subTest(response=response, error=error):
                handle, _ = self.start_fixture()
                handle.runner = Mock(side_effect=[SimpleNamespace(returncode=0), response])
                result = handle.cleanup()
                self.assertTrue(result["removal_succeeded"])
                self.assertFalse(result["cleaned_up"])
                self.assertFalse(result["cleanup_verified"])
                self.assertEqual(result["container_presence"]["state"], state)
                self.assertEqual(result["error"], error)
                self.assertEqual(handle.runner.call_args_list, [call(REMOVE, 10.0), call(EXISTS, 10.0)])

    def test_missing_or_invalid_cid_never_falls_back_to_container_name(self):
        for cid in (None, "", "fixture", CONTAINER_ID + "extra"):
            with self.subTest(cid=cid):
                handle, _ = self.start_fixture(cid)
                handle.runner = Mock()
                result = handle.cleanup()
                self.assertFalse(result["cleaned_up"])
                self.assertFalse(result["cleanup_verified"])
                self.assertEqual(result["error"], "container_identity_unavailable")
                self.assertEqual(handle.cleanup(), result)
                handle.runner.assert_not_called()

    def test_interrupted_cleanup_cannot_fall_back_to_local_process_success(self):
        handle, cidfile = self.start_fixture()
        handle.runner = Mock(side_effect=KeyboardInterrupt)
        with self.assertRaises(KeyboardInterrupt):
            handle.cleanup()

        self.assertFalse(cidfile.parent.exists())
        result = handle.cleanup()
        self.assertFalse(result["cleaned_up"])
        self.assertFalse(result["cleanup_verified"])
        self.assertEqual(result["error"], "container_identity_unavailable")
        handle.runner.assert_called_once_with(REMOVE, 10.0)
