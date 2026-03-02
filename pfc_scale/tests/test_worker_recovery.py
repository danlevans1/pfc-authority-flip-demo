from __future__ import annotations

import unittest

from pfc_scale.worker import maybe_inject_crash, reclaim_pending_messages


class FakeRedis:
    def __init__(self):
        self.calls: list[tuple[str, object]] = []

    def xautoclaim(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("xautoclaim", kwargs))
        return ["0-0", [(b"1-0", {b"intent": b"{}"})], []]


class WorkerRecoveryTests(unittest.TestCase):
    def test_reclaim_pending_uses_xautoclaim(self) -> None:
        fake = FakeRedis()
        claimed = reclaim_pending_messages(fake, "pfc:intents", "pfc:workers", "worker-1", min_idle_ms=60000, count=50)  # type: ignore[arg-type]
        self.assertEqual(len(claimed), 1)
        self.assertEqual(fake.calls[0][0], "xautoclaim")
        kwargs = fake.calls[0][1]
        assert isinstance(kwargs, dict)
        self.assertEqual(kwargs["name"], "pfc:intents")
        self.assertEqual(kwargs["groupname"], "pfc:workers")
        self.assertEqual(kwargs["consumername"], "worker-1")
        self.assertEqual(kwargs["min_idle_time"], 60000)
        self.assertEqual(kwargs["count"], 50)

    def test_crash_after_invokes_exit(self) -> None:
        events: list[int] = []
        flushed = {"v": False}

        def flush() -> None:
            flushed["v"] = True

        def fake_exit(code: int) -> None:
            events.append(code)
            raise SystemExit(code)

        with self.assertRaises(SystemExit):
            maybe_inject_crash(3, 3, "run-test", flush, exit_fn=fake_exit)
        self.assertTrue(flushed["v"])
        self.assertEqual(events, [137])


if __name__ == "__main__":
    unittest.main()
