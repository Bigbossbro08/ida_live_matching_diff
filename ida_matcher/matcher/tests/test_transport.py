"""Tests for the matcher transport endpoint resolution."""

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ida_matcher.matcher import transport


class _Listener:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TestTransport(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("IDA_CLI_INSTANCES_DIR")
        self._old_url = os.environ.get("IDA_MATCHER_URL")
        os.environ.pop("IDA_MATCHER_URL", None)
        self.tmp = Path(tempfile.mkdtemp(prefix="matcher_transport_"))
        self.instances = self.tmp / "instances"
        self.instances.mkdir(parents=True, exist_ok=True)
        os.environ["IDA_CLI_INSTANCES_DIR"] = str(self.instances)
        transport._cache["url"] = None
        transport._cache["ts"] = 0.0
        self._listeners = []

    def tearDown(self):
        for listener in self._listeners:
            listener.close()
        if self._old_env is None:
            os.environ.pop("IDA_CLI_INSTANCES_DIR", None)
        else:
            os.environ["IDA_CLI_INSTANCES_DIR"] = self._old_env
        if self._old_url is None:
            os.environ.pop("IDA_MATCHER_URL", None)
        else:
            os.environ["IDA_MATCHER_URL"] = self._old_url
        transport._cache["url"] = None
        transport._cache["ts"] = 0.0
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _listener(self):
        listener = _Listener()
        self._listeners.append(listener)
        return listener

    def test_env_override_wins(self):
        with mock.patch.dict(os.environ, {"IDA_MATCHER_URL": "http://127.0.0.1:28123/"}):
            self.assertEqual(transport.base_url(), "http://127.0.0.1:28123")

    def test_default_when_nothing_running(self):
        self.assertEqual(transport.base_url(), transport.DEFAULT_BASE_URL)

    def test_discovers_live_instance(self):
        listener = self._listener()
        (self.instances / ("ida_%d_%d_x.json" % (os.getpid(), listener.port))).write_text(
            json.dumps({"pid": os.getpid(), "port": listener.port, "last_heartbeat": 5}),
            encoding="utf-8",
        )
        self.assertEqual(transport.base_url(), f"http://127.0.0.1:{listener.port}")

    def test_corrupt_descriptor_ignored(self):
        (self.instances / "ida_1_28100_bad.json").write_bytes(b"\x00" * 64)
        self.assertEqual(transport.base_url(), transport.DEFAULT_BASE_URL)

    def test_url_joins_path(self):
        with mock.patch.dict(os.environ, {"IDA_MATCHER_URL": "http://127.0.0.1:28123"}):
            transport._cache["url"] = None
            self.assertEqual(transport.url("/health"), "http://127.0.0.1:28123/health")

    def test_fallback_warns_once(self):
        transport._cache.pop("warned_fallback", None)
        transport._cache["url"] = None
        transport._cache["ts"] = 0.0
        self.assertEqual(transport.base_url(), transport.DEFAULT_BASE_URL)
        self.assertTrue(transport._cache.get("warned_fallback"))

    def _two_instances(self):
        a, b = self._listener(), self._listener()
        for name, lst in (("a", a), ("b", b)):
            (self.instances / ("ida_%d_%d_%s.json" % (os.getpid(), lst.port, name))).write_text(
                json.dumps({"pid": os.getpid(), "port": lst.port, "last_heartbeat": lst.port}),
                encoding="utf-8",
            )
        return a, b

    def test_multiple_instances_picks_newest_by_default(self):
        self._two_instances()
        transport._cache.update({"url": None, "ts": 0.0})
        url = transport.base_url()
        self.assertTrue(url.startswith("http://127.0.0.1:"))

    def test_multiple_instances_strict_raises(self):
        self._two_instances()
        transport._cache.update({"url": None, "ts": 0.0})
        with mock.patch.dict(os.environ, {"IDA_MATCHER_AMBIGUITY_ERROR": "1"}):
            with self.assertRaises(transport.AmbiguousInstanceError):
                transport.base_url()


class TestFetchDataChunking(unittest.TestCase):
    def test_many_data_chunks_and_retries(self):
        from ida_matcher.matcher import match_core

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"results": {"a": {"bytes": "aa"}, "b": {"bytes": "aa"}}}'

        with mock.patch.object(match_core.transport, "url", return_value="http://x/datas"), \
             mock.patch("urllib.request.urlopen", return_value=_Resp()):
            res = match_core.fetch_many_data_from_ida(["a", "b"])
        self.assertEqual(set(res.keys()), {"a", "b"})


if __name__ == "__main__":
    unittest.main()
