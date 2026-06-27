# -----------------------------------------------------------------------
# OpenXenManager
#
# Copyright (C) 2014 Daniel Lintott <daniel@serverb.co.uk>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# -----------------------------------------------------------------------
"""PyGI/GTK mocking utilities for unit testing without a display server."""

import sys
from unittest import mock

import pytest


def setup_gtk_mock():
    """Mock PyGObject to run tests without X11/GTK environment.

    This must be called before importing any GTK modules.
    """
    # Block actual GI imports
    gi_stub = mock.MagicMock()
    sys.modules["gi"] = gi_stub
    sys.modules["gi.repository"] = mock.MagicMock()

    # Stub GdkPixbuf
    pixbuf_mock = mock.MagicMock()
    pixbuf_mock.Pixbuf.new_from_file.return_value = mock.MagicMock()
    sys.modules["gi.repository.GdkPixbuf"] = pixbuf_mock

    # Stub Gtk
    gtk_mock = mock.MagicMock()
    sys.modules["gi.repository.Gtk"] = gtk_mock


def setup_test_environment():
    """Set up the full test environment with GTK mocking and logging config."""
    setup_gtk_mock()

    # Ensure OXM logging config exists (non-functional without GTK)
    try:
        from OXM import logging_config  # noqa: F401
    except ImportError:
        pass


def create_mock_wine():
    """Create a mock oxcWindow ('wine') for testing oxcSERVER methods."""
    wine = mock.MagicMock()
    wine.selected_ip = "127.0.0.1"
    wine.selected_name = "test-host"
    wine.selected_host = "OpaqueRef:fake-host"
    wine.selected_ref = "OpaqueRef:fake-vm"
    wine.pathconfig = "/tmp"

    # Mock builder with get_object returning mocked widgets
    builder_mock = mock.MagicMock()
    widget_mock = mock.MagicMock()
    widget_mock.get_child.return_value = None
    widget_mock.add = mock.MagicMock()
    widget_mock.show_all = mock.MagicMock()
    builder_mock.get_object.return_value = widget_mock
    wine.builder = builder_mock

    # Mock treestore and tree operations
    treestore_mock = mock.MagicMock()
    wine.treestore = treestore_mock
    wine.treesearch = mock.MagicMock()

    return wine


def create_mock_connection():
    """Create a mock XenAPI/XML-RPC connection."""
    conn = mock.MagicMock()

    # Set up common return values for XenAPI calls
    conn.VM.get_all_records.return_value = {"Value": {}}
    conn.host.get_all_records.return_value = {"Value": {}}
    conn.pool.get_all_records.return_value = {"Value": {}}
    conn.SR.get_all_records.return_value = {"Value": {}}
    conn.VDI.get_all_records.return_value = {"Value": {}}
    conn.VIF.get_all_records.return_value = {"Value": {}}
    conn.VBD.get_all_records.return_value = {"Value": {}}
    conn.PIF.get_all_records.return_value = {"Value": {}}
    conn.PBD.get_all_records.return_value = {"Value": {}}
    conn.task.create.return_value = {"Value": "OpaqueRef:fake-task"}
    conn.session.logout.return_value = None

    # Event registration
    conn.event.register.return_value = None

    return conn


def create_oxcserver_instance(host="127.0.0.1", **kwargs):
    """Create an oxcSERVER instance with mocked dependencies.

    The instance cannot actually connect (no GTK/X11), but its methods
    can be tested for logic correctness.
    """
    # We need a real oxcWindow to pass in — create a minimal mock chain
    wine = create_mock_wine()

    # Import after GTK is mocked
    from OXM.oxcSERVER import oxcSERVER

    server = oxcSERVER(
        host=host,
        user="root",
        password="fake",
        wine=wine,
        use_ssl=False,
        verify_ssl=True,  # Use verified context for tests
        port=80,
    )

    # Inject mock connection and state
    server.connection = create_mock_connection()
    server.session_uuid = "OpaqueRef:fake-session"
    server.all = {
        "vms": {},
        "host": {},
        "pool": {},
        "SR": {},
        "VDI": {},
        "VIF": {},
        "VBD": {},
        "PIF": {},
        "PBD": {},
        "network": {},
        "task": {},
        "host_metrics": {},
        "VM_metrics": {},
        "VM_guest_metrics": {},
    }
    server.hostroot = {}
    server.poolroot = None

    return server


@pytest.fixture
def fake_oxc():
    """Provide a minimal oxcSERVER-like object for helper method tests."""

    class FakeOxc:
        def __init__(self):
            from OXM.oxc_backup_import import OxcBackupImport
            from OXM.oxc_performance import OxcPerformance
            from OXM.oxc_ui_helpers import OxcUIHelpers

            self._ui_helpers = OxcUIHelpers()
            self._backup_import = OxcBackupImport()
            self._performance = OxcPerformance()
            self.all = {
                "vms": {},
                "VBD": {},
                "VDI": {},
                "SR": {},
                "PIF": {},
                "PBD": {},
                "network": {},
                "host": {},
            }
            self.wine = create_mock_wine()
            self.connection = create_mock_connection()
            self.session_uuid = "OpaqueRef:fake"

    return FakeOxc()
