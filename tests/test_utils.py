# -----------------------------------------------------------------------
# OpenXenManager
#
# Copyright (C) 2014 Daniel Lintott <daniel@serverb.co.uk>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# -----------------------------------------------------------------------
"""Tests for OXM utility functions."""

import pytest


class TestHumanizeTime:
    """Test the humanize_time utility function."""

    def test_zero_seconds(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.humanize_time(0)
        assert "00 days" in result
        assert "00 hours" in result
        assert "00 minutes" in result

    def test_exact_minutes(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.humanize_time(120)  # 2 minutes
        assert "02 minutes" in result

    def test_exact_hours(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.humanize_time(3600)  # 1 hour
        assert "01 hours" in result

    def test_days_and_hours(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.humanize_time(90061)  # 1 day, 1 hour, 1 min, 1 sec
        assert "01 days" in result
        assert "01 hours" in result
        assert "01 minutes" in result

    def test_large_duration(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.humanize_time(366161)  # ~4 days, 2 hours, 2 min
        assert "04 days" in result


class TestConvertBytes:
    """Test the convert_bytes utility function."""

    def test_bytes(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.convert_bytes(500)
        assert result == "500"

    def test_kilobytes(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.convert_bytes(1024)
        assert result == "1.00K"

    def test_megabytes(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.convert_bytes(1024 * 1024)
        assert result == "1.00M"

    def test_gigabytes(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.convert_bytes(1024**3)
        assert result == "1.00G"

    def test_terabytes(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.convert_bytes(1024**4)
        assert result == "1.00T"

    def test_large_gigabytes(self):
        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.convert_bytes(5 * 1024**3)
        assert result == "5.00G"


class TestFormatDate:
    """Test date formatting utility."""

    def test_basic_format(self):
        from datetime import datetime

        from OXM.oxcSERVER import oxcSERVER

        result = oxcSERVER.format_date("20240115T103000Z")
        assert isinstance(result, datetime)
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 10
        assert result.minute == 30


class TestFilterFunctions:
    """Test template filtering functions."""

    def test_filter_custom_template_no_template(self):
        from OXM.oxcSERVER import oxcSERVER

        item = {"is_a_template": False, "name_label": "test", "last_booted_record": ""}
        assert oxcSERVER.filter_custom_template(item) is False

    def test_filter_custom_template_gui_prefix(self):
        from OXM.oxcSERVER import oxcSERVER

        item = {
            "is_a_template": True,
            "name_label": "__gui__test",
            "last_booted_record": "",
        }
        assert oxcSERVER.filter_custom_template(item) is False

    def test_filter_custom_template_no_last_boot(self):
        from OXM.oxcSERVER import oxcSERVER

        item = {
            "is_a_template": True,
            "name_label": "MyTemplate",
            "last_booted_record": "",
        }
        assert oxcSERVER.filter_custom_template(item) is False

    def test_filter_custom_template_valid(self):
        from OXM.oxcSERVER import oxcSERVER

        item = {
            "is_a_template": True,
            "name_label": "MyTemplate",
            "last_booted_record": "something",
        }
        assert oxcSERVER.filter_custom_template(item) is True

    def test_filter_normal_template_no_template(self):
        from OXM.oxcSERVER import oxcSERVER

        item = {"is_a_template": False, "name_label": "test", "last_booted_record": ""}
        assert oxcSERVER.filter_normal_template(item) is False

    def test_filter_normal_template_gui_prefix(self):
        from OXM.oxcSERVER import oxcSERVER

        item = {
            "is_a_template": True,
            "name_label": "__gui__test",
            "last_booted_record": "",
        }
        assert oxcSERVER.filter_normal_template(item) is False

    def test_filter_normal_template_valid(self):
        from OXM.oxcSERVER import oxcSERVER

        item = {
            "is_a_template": True,
            "name_label": "BaseTemplate",
            "last_booted_record": "",
        }
        assert oxcSERVER.filter_normal_template(item) is True


class TestBytesToGb:
    """Test byte-to-GB conversion utility."""

    def test_exact_gb(self):
        from OXM.utils import bytes_to_gb

        result = bytes_to_gb(1073741824)  # 1 GB
        assert abs(result - 1.0) < 0.001

    def test_half_gb(self):
        from OXM.utils import bytes_to_gb

        result = bytes_to_gb(536870912)  # 0.5 GB
        assert abs(result - 0.5) < 0.001

    def test_zero(self):
        from OXM.utils import bytes_to_gb

        assert bytes_to_gb(0) == 0


class TestOxcUIHelpersSearch:
    """Test search helper methods."""

    def test_filter_vbd_uuid_found(self, fake_oxc):
        fake_oxc["VBD"] = {
            "ref1": {"uuid": "test-uuid"},
            "ref2": {"uuid": "other-uuid"},
        }
        result = fake_oxc._ui_helpers.filter_vbd_uuid("test-uuid")
        assert result == "ref1"

    def test_filter_vbd_uuid_not_found(self, fake_oxc):
        fake_oxc["VBD"] = {
            "ref1": {"uuid": "test-uuid"},
        }
        result = fake_oxc._ui_helpers.filter_vbd_uuid("missing")
        assert result is None


class TestOxcBackupImportMethods:
    """Test backup/import method signatures exist."""

    def test_has_restore_server(self, fake_oxc):
        assert hasattr(fake_oxc, "restore_server")

    def test_has_backup_server(self, fake_oxc):
        assert hasattr(fake_oxc, "backup_server")

    def test_has_import_vm(self, fake_oxc):
        assert hasattr(fake_oxc, "import_vm")

    def test_has_pool_backup_database(self, fake_oxc):
        assert hasattr(fake_oxc, "pool_backup_database")


class TestOxcPerformanceMethods:
    """Test performance module methods exist."""

    def test_has_update_performance(self, fake_oxc):
        assert hasattr(fake_oxc._performance, "update_performance")

    def test_has_stop_performance(self, fake_oxc):
        assert hasattr(fake_oxc._performance, "stop_performance")


class TestOxcEventTaskMethods:
    """Test event/task module methods exist."""

    def test_has_thread_event_next(self, fake_oxc):
        assert hasattr(fake_oxc, "thread_event_next")

    def test_has_cancel_task(self, fake_oxc):
        assert hasattr(fake_oxc, "cancel_task")
