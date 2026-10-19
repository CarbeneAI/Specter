"""Exercise the foreground launcher with disposable processes, never real services."""

import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
STUB = r'''#!/usr/bin/env python3
import json, os, signal, sys, time
from pathlib import Path

state = Path(os.environ["STUB_STATE"])
name = Path.cwd().name
def stop(signum, frame):
    (state / (name + ".stopped")).touch()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
record = state / (name + ".pending")
record.write_text(json.dumps({
    "pid": os.getpid(), "cwd": os.getcwd(), "args": sys.argv[1:],
    "marker": os.environ.get("LAUNCHER_TEST_MARKER"),
}))
record.rename(state / (name + ".json"))
while True:
    request = state / (name + ".exit")
    if request.exists():
        sys.exit(int(request.read_text()))
    time.sleep(0.02)
'''


class LauncherFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="specter launcher ")
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "checkout with spaces"
        for name in ("server", "client"):
            (self.checkout / "apps" / name).mkdir(parents=True)
        shutil.copy2(ROOT / "start-specter.sh", self.checkout)
        self.state = self.root / "state"
        self.state.mkdir()
        self.home = self.root / "home with spaces"
        self.home.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.make_bun(self.bin)
        self.make_node()
        self.env = {
            "HOME": str(self.home),
            "PATH": str(self.bin) + ":/usr/bin:/bin",
            "STUB_STATE": str(self.state),
        }
        self.process = None
        self.log = open(self.root / "launcher.log", "w+")

    def tearDown(self):
        if self.process is not None:
            # Only the process group created by this test; never match real Bun PIDs.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=5)
        self.log.close()
        self.tmp.cleanup()

    def make_bun(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        stub = directory / "bun"
        stub.write_text(STUB)
        stub.chmod(0o755)

    def make_node(self, version="v22.22.2", status=0):
        stub = self.bin / "node"
        stub.write_text(STUB.replace('state = Path',
            f'if sys.argv[1:] == ["--version"]: print({version!r}); sys.exit({status})\nstate = Path'))
        stub.chmod(0o755)

    def launch(self):
        self.process = subprocess.Popen(
            ["/bin/bash", str(self.checkout / "start-specter.sh")],
            cwd=self.root, env=self.env, start_new_session=True,
            stdout=self.log, stderr=subprocess.STDOUT, text=True,
        )

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            if self.process.poll() is not None:
                output = self.output()
                self.fail(f"launcher exited {self.process.returncode}: {output}")
            time.sleep(0.02)
        self.fail("timed out waiting for stub processes: " + self.output())

    def ready(self):
        self.wait_for(lambda: all((self.state / (name + ".json")).exists()
                                  for name in ("server", "client")))

    def record(self, name):
        return json.loads((self.state / (name + ".json")).read_text())

    def output(self):
        self.log.seek(0)
        return self.log.read()

    def finish(self, expected):
        self.process.wait(timeout=5)
        self.assertEqual(self.process.returncode, expected, self.output())

    def request_exit(self, name, status):
        request = self.state / (name + ".requested")
        request.write_text(str(status))
        request.rename(self.state / (name + ".exit"))


class LauncherTests(LauncherFixture):
    def test_checkout_and_environment_with_spaces(self):
        (self.checkout / ".env").write_text(
            "LAUNCHER_TEST_MARKER='loaded from checkout'\nCLIENT_PORT=5317\nSPECTER_CLIENT_HOST=::1\n"
        )
        self.launch()
        self.ready()
        for name in ("server", "client"):
            self.assertEqual(self.record(name)["cwd"], str((self.checkout / "apps" / name).resolve()))
            self.assertEqual(self.record(name)["marker"], "loaded from checkout")
        self.assertEqual(self.record("server")["args"], ["--watch", "src/index.ts"])
        self.assertEqual(self.record("client")["args"],
                         ["./node_modules/vite/bin/vite.js", "--port", "5317", "--host", "::1"])
        self.process.terminate()
        self.finish(0)
        for name in ("server", "client"):
            self.assertTrue((self.state / (name + ".stopped")).exists())

    def test_default_port_and_bun_in_service_users_home(self):
        (self.bin / "bun").unlink()
        self.make_bun(self.home / ".bun" / "bin")
        self.launch()
        self.ready()
        self.assertIn("5173", self.record("client")["args"])
        self.assertEqual(self.record("client")["args"][-2:], ["--host", "127.0.0.1"])
        self.process.terminate()
        self.finish(0)

    def test_custom_bun_install_from_env(self):
        (self.bin / "bun").unlink()
        install = self.root / "custom bun install"
        self.make_bun(install / "bin")
        (self.checkout / ".env").write_text(f"BUN_INSTALL='{install}'\n")
        self.launch()
        self.ready()
        self.process.terminate()
        self.finish(0)

    def test_missing_bun_starts_neither_child(self):
        (self.bin / "bun").unlink()
        self.launch()
        self.finish(127)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_unavailable_node_starts_neither_child(self):
        self.make_node(status=127)
        self.launch()
        self.finish(127)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_old_node_starts_neither_child(self):
        self.make_node(version="v20.0.0")
        self.launch()
        self.finish(1)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_invalid_env_starts_neither_child(self):
        (self.checkout / ".env").write_text("CLIENT_PORT='unterminated\n")
        self.launch()
        self.process.wait(timeout=5)
        self.assertNotEqual(self.process.returncode, 0, self.output())
        self.assertEqual(list(self.state.iterdir()), [])

    def test_missing_app_directory_starts_neither_child(self):
        (self.checkout / "apps" / "client").rmdir()
        self.launch()
        self.finish(1)
        self.assertEqual(list(self.state.iterdir()), [])

    def assert_child_failure(self, failed, sibling):
        self.launch()
        self.ready()
        self.request_exit(failed, 7)
        self.finish(7)
        self.assertTrue((self.state / (sibling + ".stopped")).exists())

    def test_server_failure_stops_client_and_preserves_status(self):
        self.assert_child_failure("server", "client")

    def test_client_failure_stops_server_and_preserves_status(self):
        self.assert_child_failure("client", "server")

    def test_clean_child_exit_is_a_service_failure(self):
        self.launch()
        self.ready()
        self.request_exit("server", 0)
        self.finish(1)
        self.assertTrue((self.state / "client.stopped").exists())

    def test_immediate_child_failure_is_not_missed(self):
        self.request_exit("server", 9)
        self.launch()
        self.finish(9)

    def test_cleanup_leaves_unrelated_process_running(self):
        sentinel = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
        try:
            self.launch()
            self.ready()
            self.process.terminate()
            self.finish(0)
            self.assertIsNone(sentinel.poll())
        finally:
            sentinel.terminate()
            sentinel.wait(timeout=5)

    def test_interrupt_stops_both_children_successfully(self):
        self.launch()
        self.ready()
        self.process.send_signal(signal.SIGINT)
        self.finish(0)
        for name in ("server", "client"):
            self.assertTrue((self.state / (name + ".stopped")).exists())


class ManagerConfigTests(LauncherFixture):
    def setUp(self):
        super().setUp()
        shutil.copy2(ROOT / "manage.sh", self.checkout)

    def run_manager(self, command):
        return subprocess.run(["/bin/bash", str(self.checkout / "manage.sh"), command],
                              cwd=self.root, env=self.env, capture_output=True, text=True, timeout=5)

    def test_unavailable_node_starts_neither_child(self):
        self.make_node(status=127)
        result = self.run_manager("start")
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_old_node_starts_neither_child(self):
        self.make_node(version="v20.0.0")
        result = self.run_manager("start")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_failing_node_version_starts_neither_child(self):
        self.make_node(status=2)
        result = self.run_manager("start")
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_root_env_ports_and_ipv6_status_urls(self):
        (self.checkout / ".env").write_text(
            "PORT=4801\nCLIENT_PORT=5417\nSPECTER_API_HOST=::1\nSPECTER_CLIENT_HOST='[::1]'\n")
        lsof = self.bin / "lsof"
        lsof.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$STUB_STATE/lsof-args"\nexit 0\n')
        lsof.chmod(0o755)
        result = self.run_manager("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("http://[::1]:4801", result.stdout)
        self.assertIn("http://[::1]:5417", result.stdout)
        self.assertIn(":4801", (self.state / "lsof-args").read_text())


class ServiceTemplateTests(LauncherFixture):
    def test_service_templates_accept_checkout_paths_with_spaces(self):
        for template in ("specter.service", "deploy/specter.service"):
            with self.subTest(template=template):
                content = (ROOT / template).read_text()
                content = content.replace("%h/Specter", str(self.checkout))
                content = content.replace("/path/to/Specter", str(self.checkout))
                content = content.replace("/home/YOUR_USERNAME", str(self.home))
                content = content.replace("YOUR_USERNAME", pwd.getpwuid(os.getuid()).pw_name)
                unit = self.root / "specter.service"
                unit.write_text(content)
                result = subprocess.run(
                    ["systemd-analyze", "verify", str(unit)],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
