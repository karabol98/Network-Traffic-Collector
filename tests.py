import unittest
from datetime import datetime, timedelta
from collector import BucketManager  # Assuming your BucketManager is in collector.py

MAX_BUCKETS = 1  # Only expect one bucket for each index
MAX_BUCKET_SIZE = 100  # Example size limit for bucket rotation based on size (in bytes)

class TestBucketManager(unittest.TestCase):

    # Test if bucket rotation works by the number of open buckets
    def test_bucket_rotation_by_open_buckets(self):
        manager = BucketManager(max_buckets=1, max_bucket_size=3)

        # Process 5 events, we expect them to stay within 1 bucket
        for i in range(5):
            event = {"_time": datetime.now().isoformat(), "data": f"event {i}"}
            manager.process_event("index_1", event)

        # Get the bucket count for the index
        bucket_count = manager.get_bucket_count("index_1")

        # Assert that the bucket count does not exceed MAX_BUCKETS
        self.assertLessEqual(bucket_count, 1, f"Bucket count exceeds {MAX_BUCKETS} after processing events.")

    # Test if bucket size rotation works (when size limit is exceeded)
    def test_bucket_size_rotation(self):
        manager = BucketManager(max_buckets=MAX_BUCKETS, max_bucket_size=MAX_BUCKET_SIZE)

        # Process enough events to exceed the bucket size limit
        events = [
            {"_time": datetime.now().isoformat(), "data": "event 1"},
            {"_time": datetime.now().isoformat(), "data": "event 2"},
            {"_time": datetime.now().isoformat(), "data": "event 3"},
        ]

        for event in events:
            manager.process_event("index_1", event)

        # After processing, the number of buckets should be more than 1 if size limit exceeded
        bucket_count = manager.get_bucket_count("index_1")
        self.assertGreater(bucket_count, 1, "Buckets should rotate when size limit is exceeded.")

    # Test if the max number of open buckets is respected
    def test_bucket_rotation_by_max_open_buckets(self):
        manager = BucketManager(max_buckets=MAX_BUCKETS, max_bucket_size=MAX_BUCKET_SIZE)

        # Process events, exceeding the max number of open buckets
        events = [
            {"_time": datetime.now().isoformat(), "data": "event 1"},
            {"_time": datetime.now().isoformat(), "data": "event 2"},
            {"_time": datetime.now().isoformat(), "data": "event 3"},
            {"_time": datetime.now().isoformat(), "data": "event 4"},  # This should trigger rotation
        ]

        for event in events:
            manager.process_event("index_1", event)

        # Verify if the number of open buckets doesn't exceed the max allowed
        bucket_count = manager.get_bucket_count("index_1")
        self.assertLessEqual(bucket_count, MAX_BUCKETS, f"Bucket count exceeds {MAX_BUCKETS} after processing events.")

    # Test the event processing functionality
    def test_process_event(self):
        manager = BucketManager(max_buckets=MAX_BUCKETS, max_bucket_size=MAX_BUCKET_SIZE)

        event = {
            "_time": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "msg": "Test event"
        }

        # Simulate processing an event for index "test-index"
        manager.process_event("test-index", event)

        # Check if the bucket is created
        self.assertEqual(len(manager.buckets["test-index"]), 1)
        bucket = manager.buckets["test-index"][0]
        self.assertEqual(bucket.index, "test-index")
        self.assertEqual(bucket.size_in_bytes, len(str(event).encode("utf-8")))

    # Test if the bucket limit is respected per index
    def test_limit_open_buckets(self):
        manager = BucketManager(max_buckets=MAX_BUCKETS, max_bucket_size=MAX_BUCKET_SIZE)

        event = {
            "_time": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "msg": "Test event"
        }

        for i in range(7):  # Assume MAX_BUCKETS = 5
            manager.process_event("test-index", event)

        # Check if only 1 bucket exists
        self.assertEqual(len(manager.buckets["test-index"]), 1)

    # Test if the oldest bucket is closed when the limit is exceeded
    def test_close_oldest_bucket(self):
        manager = BucketManager(max_buckets=MAX_BUCKETS, max_bucket_size=MAX_BUCKET_SIZE)

        event = {
            "_time": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "msg": "Test event"
        }

        for i in range(7):  # Assume MAX_BUCKETS = 5
            manager.process_event("test-index", event)

        # Check that the oldest bucket is closed (removed from the list)
        self.assertEqual(len(manager.buckets["test-index"]), 1)
        self.assertNotIn("test-index", [bucket.index for bucket in manager.buckets["test-index"]])

if __name__ == '__main__':
    unittest.main()
