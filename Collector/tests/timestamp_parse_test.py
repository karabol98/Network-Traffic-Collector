import pytest
from datetime import datetime
import sys
import os
from timestamp import smart_strptime

from timestamp import python_format
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bucket_manager import BucketManager
from datetime import timezone

class TestBucketManager:
    def setup_method(self):
        pass

    def test_smart_strptime_none_timeformat(self):
        """Test when timeformat is None"""
        result = smart_strptime("2022-01-01", None)
        expected = datetime(2022, 1, 1, 0, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_smart_strptime_empty_timeformat(self):
        """Test when timeformat is empty"""
        result = smart_strptime("2022-01-01", "")
        expected = datetime(2022, 1, 1, 0, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_smart_strptime_unix(self):
        """Test unix timestamp format"""
        # Unix timestamp for 2022-01-01 00:00:00 UTC
        timestamp = 1640995200
        result = smart_strptime(str(timestamp), "unix")
        expected = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        assert result == expected

    def test_smart_strptime_unix_ms(self):
        """Test unix timestamp in milliseconds format"""
        # Unix timestamp in milliseconds for 2022-01-01 00:00:00 UTC
        timestamp_ms = 1640995200000
        result = smart_strptime(str(timestamp_ms), "unix_ms")
        expected = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
        assert result == expected

    def test_smart_strptime_iso_format(self):
        """Test ISO format"""
        date_str = "2022-01-01 12:30:45"
        result = smart_strptime(date_str, "%Y-%m-%d %H:%M:%S")
        expected = datetime(2022, 1, 1, 12, 30, 45, tzinfo=timezone.utc)
        assert result == expected

    def test_smart_strptime_custom_format(self):
        """Test custom date format"""
        date_str = "01/15/2022"
        result = smart_strptime(date_str, "%m/%d/%Y")
        expected = datetime(2022, 1, 15, tzinfo=timezone.utc)
        assert result == expected

    def test_smart_strptime_invalid_value(self):
        """Test with invalid date value"""
        result = smart_strptime("not-a-date", "%Y-%m-%d")
        assert result is None

    def test_smart_strptime_invalid_format(self):
        """Test with mismatched format"""
        result = smart_strptime("2022-01-01", "%m/%d/%Y")
        assert result is None

    def test_smart_strptime_different_formats(self):
        """Test various datetime formats"""
        formats = [
            ("2022-01-01", "%Y-%m-%d", datetime(2022, 1, 1, tzinfo=timezone.utc)),
            ("01/15/2022 14:30", "%m/%d/%Y %H:%M", datetime(2022, 1, 15, 14, 30, tzinfo=timezone.utc)),
            ("20220101", "%Y%m%d", datetime(2022, 1, 1, tzinfo=timezone.utc)),
            ("20220101", "YYYYMMDD", datetime(2022, 1, 1, tzinfo=timezone.utc)),
            ("Jan 15, 2022", "%b %d, %Y", datetime(2022, 1, 15, tzinfo=timezone.utc)),
            ("15-Jan-2022", "%d-%b-%Y", datetime(2022, 1, 15, tzinfo=timezone.utc))
        ]

        for date_str, fmt, expected in formats:
            fmt = python_format(fmt)
            result = smart_strptime(date_str, fmt)
            assert result == expected
