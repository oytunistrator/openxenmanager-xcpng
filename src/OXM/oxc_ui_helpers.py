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
"""UI helper functions for OXC Server (log display, search, tree ops)."""

import time
from threading import Thread

from gi.repository import Gdk, Gtk

from . import utils
from .messages import get_msg


class OxcUIHelpers:
    """Helper methods for UI manipulation (logs, trees, search)."""

    # -- Task cancellation -----------------------------------------------

    def cancel_task(self, widget, data=None):
        self.connection.task.cancel(self.session_uuid, Gtk.Buildable.get_name(widget))
        widget.hide()
        wid = Gtk.Buildable.get_name(widget)
        self.vboxchildprogress[wid].set_label("Cancelled")
        self.vboxchildprogressbar[wid].hide()
        self.wine.push_alert("Task cancelled")

    # -- Log box helpers -------------------------------------------------

    def fill_vm_log(self, uuid, tree=None, list=None, thread=False):
        """Populate the VM log view with tasks and messages."""
        self.filter_uuid = uuid
        self.filter_ref = self.wine.selected_ref

        container = self.wine.builder.get_object("vmtablelog")
        for child in container.get_children():
            Gtk.Container.remove(container, child)

        i = 0
        for task_ref in filter(self.task_filter_uuid, self.tasks):
            task = self.all["task"][task_ref]
            if "snapshot" in task:
                self.add_box_log(
                    task["snapshot"]["name_label"],
                    str(task["snapshot"]["created"]),
                    "%s %s"
                    % (
                        task["snapshot"]["name_label"],
                        self.all["vms"]
                        .get(self.track_tasks[task["ref"]], {})
                        .get("name_label", ""),
                    ),
                    str(task["snapshot"]["created"]),
                    task["ref"],
                    task,
                    float(task["snapshot"]["progress"]),
                    i % 2,
                )
            else:
                if "ref" in task:
                    self.add_box_log(
                        task["name_label"],
                        str(task["created"]),
                        "%s %s"
                        % (
                            task["name_label"],
                            self.all["vms"]
                            .get(self.track_tasks[task["ref"]], {})
                            .get("name_label", ""),
                        ),
                        str(task["created"]),
                        self.get_task_ref_by_uuid(task["uuid"]),
                        task,
                        float(task["progress"]),
                        i % 2,
                    )
                else:
                    self.add_box_log(
                        task["name_label"],
                        str(task["created"]),
                        "%s %s" % (task["name_label"], task["name_description"]),
                        str(task["created"]),
                        task_ref,
                        task,
                        float(task["progress"]),
                        i % 2,
                    )
                i += 1

        for log in sorted(
            filter(self.log_filter_uuid, self.all_messages.values()),
            key=lambda x: x["timestamp"],
            reverse=True,
        ):
            timestamp = str(log["timestamp"])
            if thread:
                Gtk.Gdk.threads_enter()
                self.add_box_log(
                    log["name"],
                    timestamp,
                    log["body"],
                    str(log["timestamp"]),
                    alt=i % 2,
                )
                Gtk.Gdk.threads_leave()
            else:
                self.add_box_log(
                    log["name"],
                    timestamp,
                    log["body"],
                    str(log["timestamp"]),
                    alt=i % 2,
                )
            i += 1

    def add_box_log(
        self, title, date, description, time_text, id=None, task=None, progress=0, alt=0
    ):
        """Create a visual log entry box."""
        date_formatted = str(self.format_date(date))
        vboxframe = Gtk.Frame()
        if task:
            vboxframe.set_size_request(900, 100)
        else:
            vboxframe.set_size_request(900, 80)

        vboxchild = Gtk.Fixed()
        vboxevent = Gtk.EventBox()
        vboxevent.add(vboxchild)
        vboxframe.add(vboxevent)

        vboxchildlabel1 = Gtk.Label()
        vboxchildlabel1.set_selectable(True)
        vboxchildlabel2 = Gtk.Label()
        vboxchildlabel2.set_selectable(True)
        vboxchildlabel3 = Gtk.Label()
        vboxchildlabel3.set_selectable(True)
        vboxchildlabel3.set_size_request(-1, -1)
        vboxchildlabel3.set_line_wrap(True)
        vboxchildlabel4 = Gtk.Label()
        vboxchildlabel4.set_selectable(True)

        vboxchildlabel2.set_label(date_formatted)
        msg = get_msg(title)
        if msg:
            vboxchildlabel1.set_label(msg["header"])
            vboxchildlabel3.set_label(msg["detail"] % self.wine.selected_name)
        else:
            vboxchildlabel1.set_label(title)
            vboxchildlabel3.set_label(description)

        vboxchild.put(vboxchildlabel1, 25, 12)
        vboxchild.put(vboxchildlabel2, 600, 12)
        vboxchild.put(vboxchildlabel3, 25, 32)
        vboxchild.put(vboxchildlabel4, 25, 52)

        # Active task progress UI
        if task:
            self.vboxchildcancel[id] = Gtk.Button()
            self.vboxchildcancel[id].connect("clicked", self.cancel_task)
            self.vboxchildcancel[id].set_name(str(id))
            self.vboxchildprogressbar[id] = Gtk.ProgressBar()
            self.vboxchildprogress[id] = Gtk.Label()
            self.vboxchildprogress[id].set_selectable(True)
            self.vboxchildprogressbar[id].set_size_request(500, 20)
            self.vboxchildprogressbar[id].set_fraction(progress)

            task_status = None
            if "snapshot" in task:
                task_status = task["snapshot"].get("status", "")
            else:
                task_status = task.get("status", "")

            is_active = (
                (task_status not in ("failure", "success")) if task_status else True
            )

            if is_active:
                vboxchild.put(self.vboxchildcancel[id], 500, 32)
                self.vboxchildcancel[id].set_label("Cancel")
                self.vboxchildprogress[id].set_label("Progress: ")
                vboxchild.put(self.vboxchildprogressbar[id], 100, 72)
                vboxchild.put(self.vboxchildprogress[id], 25, 72)

                if task_status == "failure":
                    self.vboxchildcancel[id].hide()
                    self.vboxchildprogressbar[id].hide()
                    _rgba_err = Gdk.RGBA()
                    _rgba_err.parse("#FF0000")
                    try:
                        self.vboxchildprogress[id].modify_fg(
                            Gtk.StateFlags.NORMAL, _rgba_err
                        )
                    except (TypeError, AttributeError):
                        pass
                    if "snapshot" in task:
                        self.vboxchildprogress[id].set_label(
                            "Error: %s" % task["snapshot"].get("error_info", "")
                        )
                    else:
                        self.vboxchildprogress[id].set_label(
                            "Error: %s" % task.get("error_info", "")
                        )

            if task_status == "success":
                if "snapshot" in task and task["snapshot"]["status"] == "success":
                    self.vboxchildcancel[id].hide()
                    self.vboxchildprogressbar[id].hide()
                elif task.get("status") == "success":
                    self.vboxchildcancel[id].hide()
                    self.vboxchildprogressbar[id].hide()

        if "finished" in task:
            finished_str = "Finished: %s" % str(self.format_date(str(task["finished"])))
            vboxchildlabel4.set_label(finished_str)

        # Alternating row colors
        _rgba_blue = Gdk.RGBA()
        _rgba_green = Gdk.RGBA()
        _rgba_blue.parse("#d5e5f7")
        _rgba_green.parse("#BAE5D3")
        bg_color = _rgba_blue if alt else _rgba_green
        try:
            vboxevent.modify_bg(Gtk.StateFlags.NORMAL, bg_color)
        except (TypeError, AttributeError):
            pass  # GTK4 compatibility

        container = self.wine.builder.get_object("vmtablelog")
        container.add(vboxframe)
        container.show_all()

    # -- Search helpers --------------------------------------------------

    def thread_host_search(self, ref, list):
        Thread(target=self.fill_host_search, args=(ref, list)).start()
        return True

    def search_ref(self, model, path, iter_ref, user_data):
        if self.treestore.get_value(iter_ref, 6) == user_data:
            self.found_iter = iter_ref

    # -- UUID filter helpers ---------------------------------------------

    def log_filter_uuid(self, item):
        return item["obj_uuid"] == self.filter_uuid

    def task_filter_uuid(self, item_ref):
        if item_ref in self.all["task"]:
            item = self.all["task"][item_ref]
            if item_ref in self.track_tasks:
                if self.track_tasks[item_ref] in self.all["vms"]:
                    return (
                        self.all["vms"][self.track_tasks[item_ref]]["uuid"]
                        == self.filter_uuid
                    )
            if (
                "ref" in item
                and item["ref"] in self.track_tasks
                and self.track_tasks[item["ref"]] in self.all["vms"]
            ):
                return (
                    self.all["vms"][self.track_tasks[item["ref"]]]["uuid"]
                    == self.filter_uuid
                )
            else:
                if "resident_on" in item:
                    return item["resident_on"] == self.filter_ref
                if "uuid" in item:
                    self.get_task_ref_by_uuid(item["uuid"])
            return False

    def get_task_ref_by_uuid(self, uuid):
        for task in self.tasks.keys():
            if "uuid" in self.tasks[task]:
                if uuid == self.tasks[task]["uuid"]:
                    return task
        return None

    def filter_vif_ref(self, item):
        return item["VM"] == self.filter_ref

    def filter_vbd_ref(self, item):
        return item["VM"] == self.filter_ref

    def filter_vbd_uuid(self, uuid):
        for vbd in self.all["VBD"]:
            if self.all["VBD"][vbd]["uuid"] == uuid:
                return vbd
        return None

    def filter_vm_uuid(self, item):
        return item["uuid"] == self.filter_uuid

    def vm_filter_uuid(self, uuid):
        for vm in self.all["vms"]:
            if self.all["vms"][vm]["uuid"] == uuid:
                return vm
        return None

    def storage_filter_uuid(self):
        for stg in self.all["SR"]:
            if self.all["SR"][stg]["uuid"] == self.filter_uuid:
                return stg
        return None

    def host_filter_uuid(self):
        for host in self.all["host"]:
            if self.all["host"][host]["uuid"] == self.filter_uuid:
                return host
        return None

    @staticmethod
    def filter_custom_template(item):
        if not item["is_a_template"]:
            return False
        if item["name_label"][:7] == "__gui__":
            return False
        if item["last_booted_record"] != "":
            return True
        return False

    @staticmethod
    def filter_normal_template(item):
        if not item["is_a_template"]:
            return False
        elif item["name_label"][:7] == "__gui__":
            return False
        elif item["last_booted_record"] == "":
            return True
        return False

    def filter_vdi_ref(self):
        for vdi in self.all["VDI"].keys():
            if vdi == self.filter_vdi:
                return vdi
        return None

    @staticmethod
    def search_in_liststore(list, ref, field):
        """Search a list store for an entry matching ref in the given field."""
        for i in range(list.__len__()):
            iter_ref = list.get_iter((i,))
            if ref == list.get_value(iter_ref, field):
                return iter_ref
        return None
