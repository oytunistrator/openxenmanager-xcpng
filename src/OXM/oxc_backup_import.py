# -----------------------------------------------------------------------
# OpenXenManager
#
# Copyright (C) 2009 Alberto Gonzalez Rodriguez alberto@pesadilla.org
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
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.
# -----------------------------------------------------------------------
"""Backup, restore, import and export operations for OXC Server."""

import os

from . import logging_config

log = logging_config.log


class OxcBackupImport:
    """Handles backup/restore/import/export operations that require file I/O."""

    def get_dmesg(self, ref):
        return self.connection.host.dmesg(self.session_uuid, ref)["Value"]

    def save_screenshot(self, ref, filename):
        url = (
            "https://"
            + self.wine.selected_ip
            + "/vncsnapshot?session_id=%s&ref=%s" % (self.session_uuid, ref)
        )
        import urllib.request

        urllib.request.urlretrieve(url, filename)

    def pool_backup_database(self, ref, filename, name):
        task_uuid = self.connection.task.create(
            self.session_uuid,
            "Backup Pool database",
            "Backing up database pool " + name,
        )
        self.track_tasks[task_uuid["Value"]] = "Backup.Pool"
        url = (
            "https://"
            + self.wine.selected_ip
            + "/pool/xmldbdump?session_id=%s&task_id=%s"
            % (self.session_uuid, task_uuid["Value"])
        )
        import urllib.request

        urllib.request.urlretrieve(url, filename)

    def pool_restore_database(self, ref, filename, name, dry_run="true"):
        task_uuid = self.connection.task.create(
            self.session_uuid,
            "Restore Pool database",
            "Restoring database pool " + filename,
        )
        self.track_tasks[task_uuid["Value"]] = "Restore.Pool"

        size = os.path.getsize(filename)
        url = self.wine.selected_ip
        fp = open(filename, "r")
        try:
            from . import put

            put.putfile(
                fp,
                "https://"
                + url
                + "/pool/xmldbdump?session_id=%s&task_id=%s&dry_run=%s"
                % (self.session_uuid, task_uuid["Value"], dry_run),
            )
        except Exception as exc:
            log.error("Failed to restore pool database: %s", exc)
            raise
        finally:
            fp.close()

    def host_download_logs(self, ref, filename, name):
        task_uuid = self.connection.task.create(
            self.session_uuid,
            "Downloading host logs",
            "Downloading logs from host " + name,
        )
        self.track_tasks[task_uuid["Value"]] = "Download.Logs"
        url = (
            "https://"
            + self.wine.selected_ip
            + "/host_logs_download?session_id=%s&sr_id=%s&task_id=%s"
            % (self.session_uuid, ref, task_uuid["Value"])
        )
        import urllib.request

        urllib.request.urlretrieve(url, filename)

    def host_download_status_report(self, ref, refs, filename, name):
        task_uuid = self.connection.task.create(
            self.session_uuid,
            "Downloading status report",
            "Downloading status report from host " + name,
        )
        self.track_tasks[task_uuid["Value"]] = self.host_vm[ref][0]
        url = (
            "https://"
            + self.wine.selected_ip
            + "/system-status?session_id=%s&entries=%s&task_id=%s"
            "&output=tar" % (self.session_uuid, refs, task_uuid["Value"])
        )
        import urllib.request

        urllib.request.urlretrieve(url, filename)

    def backup_server(self, ref, filename, name):
        task_uuid = self.connection.task.create(
            self.session_uuid, "Backup Server", "Backing up server " + name
        )
        self.track_tasks[task_uuid["Value"]] = "Backup.Server"
        url = (
            "https://"
            + self.wine.selected_ip
            + "/host_backup?session_id=%s&sr_id=%s&task_id=%s"
            % (self.session_uuid, ref, task_uuid["Value"])
        )
        import urllib.request

        urllib.request.urlretrieve(url, filename)

    def restore_server(self, ref, filename, name):
        """Restore a server from backup file."""
        try:
            task_uuid = self.connection.task.create(
                self.session_uuid,
                "Restoring Server",
                "Restoring Server %s from %s " % (name, filename),
            )
            self.track_tasks[task_uuid["Value"]] = "Restore.Server"

            fp = open(filename, "rb")
            try:
                url = self.wine.selected_ip
                from . import put

                put.putfile(
                    fp,
                    "https://"
                    + url
                    + "/host_restore?session_id=%s&task_id=%s&dry_run=true"
                    % (self.session_uuid, task_uuid["Value"]),
                )
            finally:
                fp.close()
        except FileNotFoundError:
            log.error("Backup file not found: %s", filename)
            raise
        except Exception as exc:
            log.error("Failed to restore server: %s", exc)
            raise

    def import_vm(self, ref, filename):
        """Import a VM from an XVA file."""
        try:
            task_uuid = self.connection.task.create(
                self.session_uuid, "Importing VM", "Importing VM " + filename
            )
            self.track_tasks[task_uuid["Value"]] = "Import.VM"

            size = os.stat(filename)[6]
            url = self.wine.selected_ip
            fp = open(filename, "r")
            try:
                from . import put

                put.putfile(
                    fp,
                    "https://"
                    + url
                    + "/import?session_id=%s&sr_id=%s&task_id=%s"
                    % (self.session_uuid, ref, task_uuid["Value"]),
                )
            finally:
                fp.close()
        except FileNotFoundError:
            log.error("Import file not found: %s", filename)
            raise
