import unittest

from features.ztp.core import activity_log


class ZtpActivityLogTests(unittest.TestCase):
    def setUp(self):
        activity_log.clear()

    def tearDown(self):
        activity_log.clear()

    def test_record_returns_incrementing_ids(self):
        first = activity_log.record("sftp", "hello")
        second = activity_log.record("dhcp", "world")
        self.assertLess(first["id"], second["id"])

    def test_recent_returns_oldest_first(self):
        activity_log.record("sftp", "one")
        activity_log.record("sftp", "two")
        activity_log.record("sftp", "three")

        events = activity_log.recent()
        self.assertEqual([e["message"] for e in events], ["one", "two", "three"])

    def test_recent_since_id_only_returns_newer_events(self):
        activity_log.record("sftp", "one")
        checkpoint = activity_log.record("sftp", "two")
        activity_log.record("sftp", "three")

        events = activity_log.recent(since_id=checkpoint["id"])
        self.assertEqual([e["message"] for e in events], ["three"])

    def test_recent_respects_limit(self):
        for i in range(10):
            activity_log.record("sftp", f"event {i}")

        events = activity_log.recent(limit=3)
        # limit keeps the MOST RECENT entries, not the oldest --
        # a UI tailing a feed wants "what just happened", not
        # "what happened first".
        self.assertEqual([e["message"] for e in events], ["event 7", "event 8", "event 9"])

    def test_clear_empties_the_feed(self):
        activity_log.record("sftp", "one")
        activity_log.clear()
        self.assertEqual(activity_log.recent(), [])

    def test_esn_and_level_are_carried_through(self):
        event = activity_log.record("syslog", "boom", esn="ESN123", level="error")
        self.assertEqual(event["esn"], "ESN123")
        self.assertEqual(event["level"], "error")

    def test_default_level_is_info(self):
        event = activity_log.record("dhcp", "started")
        self.assertEqual(event["level"], "info")

    def test_feed_is_bounded(self):
        # _MAX_EVENTS caps the deque -- verify old events actually get
        # evicted rather than growing memory forever across a long
        # ZTP session with many retry cycles.
        for i in range(activity_log._MAX_EVENTS + 50):
            activity_log.record("sftp", f"event {i}")
        events = activity_log.recent(limit=None)
        self.assertEqual(len(events), activity_log._MAX_EVENTS)
        # the oldest 50 should have been evicted
        self.assertEqual(events[0]["message"], "event 50")


if __name__ == "__main__":
    unittest.main()
