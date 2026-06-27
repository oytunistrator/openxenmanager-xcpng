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
"""Task tracking and event loop processing for OXC Server."""

import time
import traceback
import xml.dom.minidom
from threading import Thread

from gi.repository import Gdk, GLib, Gtk

from . import utils


class OxcEventTask:
    """Handles XenServer event loop processing and task tracking."""

    halt = False  # Main loop exit flag (also used by other modules)
    halt_search = False  # Search thread exit flag

    def thread_event_next(self):
        """Start the event processing loop in a background thread."""
        Thread(target=self.event_next, args=()).start()
        return True

    # -- event processing -------------------------------------------------

    def event_next(self):
        """Main XenServer event loop. Runs in a background thread."""

        import logging

        from . import logging_config as _lc

        log = _lc.log

        def push_alert(msg):
            GLib.idle_add(lambda: self.wine.push_alert(msg))

        while not self.halt:
            try:
                eventn = self.connection_events.event.next(self.session_events_uuid)
                if "Value" in eventn:
                    for event in eventn["Value"]:
                        self._handle_event(event)
            except OSError as msg:
                self.halt = True
                log.error("Event loop interrupted by OS error: %s", msg)
            except Exception:
                log.exception("Event loop -- unexpected error")

        log.info("Exiting event loop")

    def _handle_event(self, event):
        """Dispatch an individual XenServer event to the appropriate handler."""
        evt_class = event.get("class", "") or event.get("cls", "")

        # -- VM events --------------------------------------------------
        if evt_class == "vm":
            self._handle_vm_event(event)
        elif evt_class == "task":
            self._handle_task_event(event)
        elif evt_class == "vm_guest_metrics":
            self.all["VM_guest_metrics"][event["ref"]] = (
                self.connection.VM_guest_metrics.get_record(
                    self.session_uuid, event["ref"]
                )
            )
        elif evt_class == "vdi":
            self.all["VDI"][event["ref"]] = event["snapshot"]
            self._refresh_storage_tabs("local")
            self._refresh_storage_tabs("vm")
        elif evt_class == "vbd":
            self.all["VBD"][event["ref"]] = event["snapshot"]
        elif evt_class == "pif":
            self.all["PIF"][event["ref"]] = event["snapshot"]
            if self.wine.selected_tab == "HOST_Nics":
                GLib.idle_add(lambda: self.wine.update_tab_host_nics() and False)
        elif evt_class == "bond":
            if event["operation"] == "del":
                del self.all["Bond"][event["ref"]]
            else:
                self.all["Bond"][event["ref"]] = event["snapshot"]
            if self.wine.selected_tab == "HOST_Nics":
                GLib.idle_add(lambda: self.wine.update_tab_host_nics() and False)
        elif evt_class == "vif":
            if event["operation"] == "del":
                del self.all["VIF"][event["ref"]]
            else:
                if event["operation"] == "add":
                    self.connection.VIF.plug(self.session_uuid, event["ref"])
                self.all["VIF"][event["ref"]] = event["snapshot"]
        elif evt_class == "sr":
            self.filter_uuid = event["snapshot"]["uuid"]
            self.all["SR"][event["ref"]] = event["snapshot"]
            GLib.idle_add(
                lambda: self.treestore.foreach(self.update_storage_status, "") and False
            )
            if event["operation"] == "del":
                GLib.idle_add(
                    lambda: self.treestore.foreach(self.delete_storage, "") and False
                )
            elif event["operation"] == "add":
                sr = event["ref"]
                host = list(self.all["host"].keys())[0]
                if self.poolroot:
                    parent = self.poolroot
                else:
                    parent = self.hostroot.get(host)
                if parent is not None:
                    GLib.idle_add(
                        lambda sr=sr, p=parent: self._add_storage_to_tree(sr, p)
                    )
        elif evt_class == "pool":
            self._handle_pool_event(event)
        elif evt_class == "message":
            self._handle_message_event(event)
        elif evt_class == "network":
            if event["operation"] == "del":
                del self.all["network"][event["ref"]]
            else:
                self.all["network"][event["ref"]] = event["snapshot"]
            if self.wine.selected_tab == "HOST_Network":
                GLib.idle_add(lambda: self.wine.update_tab_host_network() and False)
        elif evt_class == "vlan":
            if event["operation"] == "del":
                if event["ref"] in self.all.get("vlan", {}):
                    del self.all["vlan"][event["ref"]]
            self.all["vlan"][event["ref"]] = event["snapshot"]
        elif evt_class == "host":
            self._handle_host_event(event)
        elif evt_class == "pif_metrics":
            self.all["PIF_metrics"][event["ref"]] = event["snapshot"]
        elif evt_class == "host_metrics":
            self.all["host_metrics"][event["ref"]] = event["snapshot"]
        elif evt_class == "vbd_metrics":
            self.all["VBD_metrics"][event["ref"]] = event["snapshot"]
        elif evt_class == "vif_metrics":
            self.all["VIF_metrics"][event["ref"]] = event["snapshot"]
        elif evt_class == "vm_metrics":
            self.all["VM_metrics"][event["ref"]] = event["snapshot"]
        elif evt_class == "console":
            self.all["console"][event["ref"]] = event["snapshot"]
        elif evt_class == "host_patch":
            if event["operation"] == "del":
                del self.all["host_patch"][event["ref"]]
            else:
                self.all["host_patch"][event["ref"]] = event["snapshot"]
        elif evt_class == "pool_patch":
            if event["operation"] == "del":
                del self.all["pool_patch"][event["ref"]]
            else:
                self.all["pool_patch"][event["ref"]] = event["snapshot"]
        elif evt_class == "host_cpu":
            self.all["host_cpu"][event["ref"]] = event["snapshot"]
        elif evt_class == "pbd":
            self.all["PBD"][event["ref"]] = event["snapshot"]
            if event["operation"] == "add":
                sr = event["snapshot"]["SR"]
                host = event["snapshot"]["host"]
                GLib.idle_add(
                    lambda sr=sr, p=self.hostroot.get(host), it=self.last_storage_iter: (
                        self._insert_pbd_after_tree(p, it, sr)
                    )
                )
        else:
            print(event["class"] + " => ", event)

    # -- VM event handler -----------------------------------------------

    def _handle_vm_event(self, event):
        if event["operation"] == "add":
            self.all["vms"][event["ref"]] = event["snapshot"]
            if not self.all["vms"][event["ref"]]["is_a_snapshot"]:
                GLib.idle_add(lambda: self.add_vm_to_tree(event["ref"]) and False)
            else:
                GLib.idle_add(
                    lambda: (
                        self.fill_vm_snapshots(
                            self.wine.selected_ref,
                            self.wine.builder.get_object("treevmsnapshots"),
                            self.wine.builder.get_object("listvmsnapshots"),
                        )
                        and False
                    )
                )

            GLib.idle_add(lambda: self.wine.modelfilter.clear_cache() and False)
            GLib.idle_add(lambda: self.wine.modelfilter.refilter() and False)
            self._update_task_refs(event["ref"], "Import.VM")
            self._update_task_refs(event["ref"], "Backup.Server")
            self._update_task_refs(event["ref"], "Restore.Server")
            self._update_task_refs(event["ref"], "Backup.Pool")
            self._update_task_refs(event["ref"], "Restore.Pool")
            self._update_task_refs(event["ref"], "Upload.Patch")

            self.wine.builder.get_object("wprogressimportvm").hide()
            self.import_ref = event["ref"]

        elif event["operation"] == "del":
            if not self.all["vms"][event["ref"]]["is_a_snapshot"]:
                self.found_iter = None
                self.treestore.foreach(self.search_ref, event["ref"])
                if self.found_iter:
                    GLib.idle_add(
                        lambda: self.treestore.remove(self.found_iter) and False
                    )
                del self.all["vms"][event["ref"]]
            else:
                GLib.idle_add(
                    lambda: (
                        self.fill_vm_snapshots(
                            self.wine.selected_ref,
                            self.wine.builder.get_object("treevmsnapshots"),
                            self.wine.builder.get_object("listvmsnapshots"),
                        )
                        and False
                    )
                )
                del self.all["vms"][event["ref"]]

        else:  # update
            filter_uuid = event["snapshot"]["uuid"]
            vm_id = self.vm_filter_uuid(filter_uuid)
            if vm_id:
                if (
                    event["snapshot"]["is_a_template"]
                    != self.all["vms"][vm_id]["is_a_template"]
                ):
                    self.all["vms"][vm_id] = event["snapshot"]
                    self.found_iter = None
                    self.treestore.foreach(self.search_ref, event["ref"])
                    if self.found_iter and event["snapshot"]["is_a_template"]:
                        GLib.idle_add(
                            lambda iter_ref=self.found_iter: self._set_vm_tree_icon(
                                iter_ref, "user_template_16.png"
                            )
                        )
                        GLib.idle_add(lambda: self.wine.update_tabs() and False)
                else:
                    if (
                        event["snapshot"]["resident_on"]
                        != self.all["vms"][vm_id]["resident_on"]
                    ):
                        self.found_iter = None
                        GLib.idle_add(
                            lambda: (
                                self.treestore.foreach(self.search_ref, event["ref"])
                                and False
                            )
                        )
                        if self.found_iter:
                            GLib.idle_add(
                                lambda: self.treestore.remove(self.found_iter) and False
                            )
                            self.all["vms"][vm_id] = event["snapshot"]
                            GLib.idle_add(
                                lambda: self.add_vm_to_tree(event["ref"]) and False
                            )

                    if (
                        event["snapshot"]["affinity"]
                        != self.all["vms"][vm_id]["affinity"]
                    ):
                        pass  # Log or handle migration events later

                    self.all["vms"][vm_id] = event["snapshot"]
            else:
                if event["ref"] in self.track_tasks:
                    self.all["vms"][self.track_tasks[event["ref"]]] = event["snapshot"]
                else:
                    self.all["vms"][event["ref"]] = event["snapshot"]

            self.all["vms"][event["ref"]] = event["snapshot"]
            self.treestore.foreach(self.update_vm_status, filter_uuid)
            GLib.idle_add(lambda: self.wine.update_memory_tab() and False)

    def _update_task_refs(self, ref, task_type):
        """Update task tracking dict for a given task type."""
        for track in list(self.track_tasks.keys()):
            if self.track_tasks[track] == task_type:
                self.track_tasks[track] = ref

    # -- Task event handler ----------------------------------------------

    def _handle_task_event(self, event):
        snapshot = event["snapshot"]
        task_ref = event["ref"]
        self.all["task"][task_ref] = snapshot

        if snapshot["status"] == "success":
            if task_ref in self.vboxchildprogressbar:
                self.vboxchildprogress[task_ref].hide()
                self.vboxchildprogressbar[task_ref].hide()
                self.vboxchildcancel[task_ref].hide()

            # Error handling before the success checks below
            if snapshot["error_info"]:
                if task_ref in self.track_tasks:
                    vm_ref = self.track_tasks[task_ref]
                    if vm_ref in self.all["vms"]:
                        GLib.idle_add(
                            lambda err=snapshot["error_info"], vm=self.all["vms"][vm_ref], name=snapshot["name_label"]: (
                                self.wine.push_error_alert(
                                    "%s %s %s" % (name, vm["name_label"], err)
                                )
                            )
                        )
                        eref = task_ref
                        if eref in self.vboxchildcancel:
                            self.vboxchildcancel[eref].hide()
                            self.vboxchildprogressbar[eref].hide()
                            self.vboxchildprogress[eref].set_label(
                                str(snapshot["error_info"])
                            )
                            _rgba_err = Gdk.RGBA()
                            _rgba_err.parse("#FF0000")
                            try:
                                self.vboxchildprogress[eref].modify_fg(
                                    Gtk.StateFlags.NORMAL, _rgba_err
                                )
                            except (TypeError, AttributeError):
                                pass
                    else:
                        self.wine.builder.get_object("wprogressimportvm").hide()
                        self.wine.builder.get_object("tabboximport").set_current_page(2)
                        GLib.idle_add(
                            lambda desc=snapshot["name_description"], err=snapshot["error_info"]: (
                                self.wine.push_error_alert("%s: %s" % (desc, err))
                            )
                        )

        # Task completion events
        if snapshot["status"] == "success":
            name = snapshot["name_label"]

            # VIF create → plug
            if name == "Async.VIF.create":
                dom = xml.dom.minidom.parseString(snapshot["result"])
                nodes = dom.getElementsByTagName("value")
                vif_ref = nodes[0].childNodes[0].data
                self.connection.VIF.plug(self.session_uuid, vif_ref)
                if self.wine.selected_tab == "VM_Network":
                    GLib.idle_add(
                        lambda: (
                            self.fill_vm_network(
                                self.wine.selected_ref,
                                self.wine.builder.get_object("treevmnetwork"),
                                self.wine.builder.get_object("listvmnetwork"),
                            )
                            and False
                        )
                    )

            # VM revert → start
            elif name == "Async.VM.revert":
                if task_ref in self.track_tasks:
                    self.start_vm(self.track_tasks[task_ref])

            # Clone/copy → set description
            elif name in ("Async.VM.clone", "Async.VM.copy"):
                dom = xml.dom.minidom.parseString(snapshot["result"])
                nodes = dom.getElementsByTagName("value")
                vm_ref = nodes[0].childNodes[0].data
                if task_ref in self.set_descriptions:
                    self.connection.VM.set_name_description(
                        self.session_uuid, vm_ref, self.set_descriptions[task_ref]
                    )

            # Provision/clone/copy → update VBD/VIF/allowed_ops
            elif name in ("Async.VM.provision", "Async.VM.clone", "Async.VM.copy"):
                filter_uuid = snapshot["uuid"]
                vm_id = self.vm_filter_uuid(filter_uuid)
                if (
                    task_ref in self.track_tasks
                    and self.track_tasks[task_ref] in self.all["vms"]
                ):
                    src = self.track_tasks[task_ref]
                    for vbd in self.all["vms"][src]["VBDs"]:
                        rec = self.connection.VBD.get_record(self.session_uuid, vbd)
                        if "Value" in rec:
                            self.all["SR"][vbd] = rec["Value"]
                    for vif in self.all["vms"][src]["VIFs"]:
                        rec = self.connection.VIF.get_record(self.session_uuid, vif)
                        if "Value" in rec:
                            self.all["VIF"][vif] = rec["Value"]

                if vm_id is not None:
                    ops = self.connection.VM.get_allowed_operations(
                        self.session_uuid, vm_id
                    )["Value"]
                    self.all["vms"][vm_id]["allowed_operations"] = ops
                elif task_ref in self.track_tasks:
                    target = self.track_tasks[task_ref]
                    ops = self.connection.VM.get_allowed_operations(
                        self.session_uuid, target
                    )["Value"]
                    self.all["vms"][target]["allowed_operations"] = ops

                    # Auto-start if configured
                    if "start" in ops and target in self.autostart:
                        host_start = self.autostart[target]
                        res = self.connection.Async.VM.start_on(
                            self.session_uuid, target, host_start, False, False
                        )
                        if "Value" in res:
                            self.track_tasks[res["Value"]] = target
                        else:
                            print(res)

            # Snapshot created → update snapshot list
            elif name == "Async.VM.snapshot":
                self.filter_uuid = snapshot["uuid"]
                if task_ref in self.track_tasks:
                    vm_uuid = self.track_tasks[task_ref]
                    dom = xml.dom.minidom.parseString(snapshot["result"])
                    nodes = dom.getElementsByTagName("value")
                    snap_ref = nodes[0].childNodes[0].data
                    rec = self.connection.VM.get_record(self.session_uuid, snap_ref)
                    if "Value" in rec:
                        self.all["vms"][snap_ref] = rec["Value"]
                        for vbd in self.all["vms"][snap_ref]["VBDs"]:
                            vrec = self.connection.VBD.get_record(
                                self.session_uuid, vbd
                            )
                            if "Value" in vrec:
                                self.all["VBD"][vbd] = vrec["Value"]

                    if (
                        self.track_tasks[task_ref] == self.wine.selected_ref
                        and self.wine.selected_tab == "VM_Snapshots"
                    ):
                        GLib.idle_add(
                            lambda: (
                                self.fill_vm_snapshots(
                                    self.wine.selected_ref,
                                    self.wine.builder.get_object("treevmsnapshots"),
                                    self.wine.builder.get_object("listvmsnapshots"),
                                )
                                and False
                            )
                        )

            elif name == "VM.Async.snapshot":
                if (
                    self.track_tasks.get(task_ref) == self.wine.selected_ref
                    and self.wine.selected_tab == "VM_Snapshots"
                ):
                    GLib.idle_add(
                        lambda: (
                            self.fill_vm_snapshots(
                                self.wine.selected_ref,
                                self.wine.builder.get_object("treevmsnapshots"),
                                self.wine.builder.get_object("listvmsnapshots"),
                            )
                            and False
                        )
                    )

            elif name == "Importing VM":
                if self.import_start and task_ref in self.track_tasks:
                    self.start_vm(self.track_tasks[task_ref])
                if self.import_make_into_template and task_ref in self.track_tasks:
                    self.make_into_template(self.track_tasks[task_ref])

            elif name == "VM.destroy":
                if self.wine.selected_tab == "VM_Snapshots":
                    GLib.idle_add(
                        lambda: (
                            self.fill_vm_snapshots(
                                self.wine.selected_ref,
                                self.wine.builder.get_object("treevmsnapshots"),
                                self.wine.builder.get_object("listvmsnapshots"),
                            )
                            and False
                        )
                    )

            elif name in ("VIF.destroy", "VIF.plug"):
                if self.wine.selected_tab == "VM_Network":
                    GLib.idle_add(
                        lambda: (
                            self.fill_vm_network(
                                self.wine.selected_ref,
                                self.wine.builder.get_object("treevmnetwork"),
                                self.wine.builder.get_object("listvmnetwork"),
                            )
                            and False
                        )
                    )

            elif name in ("VBD.create", "VBD.destroy"):
                if self.wine.selected_tab == "VM_Storage":
                    GLib.idle_add(
                        lambda: (
                            self.fill_vm_storage(
                                self.wine.selected_ref,
                                self.wine.builder.get_object("listvmstorage"),
                            )
                            and False
                        )
                    )

            elif name in ("VDI.create", "VDI.destroy"):
                if self.wine.selected_tab == "Local_Storage":
                    GLib.idle_add(
                        lambda: (
                            self.fill_local_storage(
                                self.wine.selected_ref,
                                self.wine.builder.get_object("liststg"),
                            )
                            and False
                        )
                    )

            elif name in ("network.create", "network.destroy"):
                if self.wine.selected_tab == "HOST_Network":
                    GLib.idle_add(lambda: self.wine.update_tab_host_network() and False)

            elif name in (
                "Async.Bond.create",
                "Bond.create",
                "Async.Bond.destroy",
                "Bond.destroy",
            ):
                if self.wine.selected_tab == "HOST_Nics":
                    GLib.idle_add(lambda: self.wine.update_tab_host_nics() and False)

        # Progress updates
        if task_ref in self.vboxchildprogressbar:
            self.vboxchildprogressbar[task_ref].set_fraction(
                float(snapshot["progress"])
            )

        if task_ref in self.track_tasks:
            self.tasks[task_ref] = event
            if (
                self.track_tasks[task_ref] == self.wine.selected_ref
                and self.wine.selected_tab == "VM_Logs"
                and task_ref not in self.vboxchildprogressbar
            ):
                GLib.idle_add(
                    lambda: (
                        self.fill_vm_log(self.wine.selected_uuid, thread=True) and False
                    )
                )

        elif snapshot["name_label"] == "Exporting VM":
            if task_ref not in self.vboxchildprogressbar:
                self.track_tasks[task_ref] = self.wine.selected_ref
                self.tasks[task_ref] = event
                GLib.idle_add(
                    lambda: (
                        self.fill_vm_log(self.wine.selected_uuid, thread=True) and False
                    )
                )

    # -- Pool/Host/Message events ----------------------------------------

    def _handle_pool_event(self, event):
        if (
            self.all["pool"][event["ref"]]["name_label"]
            != event["snapshot"]["name_label"]
        ):
            if self.poolroot:
                GLib.idle_add(lambda: self.treestore.remove(self.poolroot) and False)
            else:
                for hr in self.hostroot.keys():
                    GLib.idle_add(
                        lambda h=hr: self.treestore.remove(self.hostroot[h]) and False
                    )
            self.sync()

        if (
            self.all["pool"][event["ref"]]["default_SR"]
            != event["snapshot"]["default_SR"]
        ):
            GLib.idle_add(
                lambda old=self.all["pool"][event["ref"]]["default_SR"], new=event["snapshot"]["default_SR"]: (
                    self.treestore.foreach(self.update_default_sr, [old, new])
                )
            )

        self.all["pool"][event["ref"]] = event["snapshot"]
        if self.wine.selected_type == "pool":
            self.update_tab_pool_general(self.wine.selected_ref, self.wine.builder)

    def _handle_message_event(self, event):
        if event["operation"] == "del":
            del self.all_messages[event["ref"]]
        elif event["operation"] == "add":
            self.all_messages[event["ref"]] = event["snapshot"]
            self.add_alert(event["snapshot"], event["ref"], self.wine.listalerts)
            if hasattr(self.wine, "update_n_alerts"):
                self.wine.update_n_alerts()

    def _handle_host_event(self, event):
        if event["operation"] == "del":
            self.filter_uuid = event["snapshot"]["uuid"]
            self.treestore.foreach(self.delete_host, "")
            del self.all["host"][event["ref"]]
        elif event["operation"] == "add":
            self.all["host"][event["ref"]] = event["snapshot"]
            self.wine.show_error_dlg("Host added, please reconnect for sync all info")
        else:
            self.filter_uuid = event["snapshot"]["uuid"]
            self.all["host"][event["ref"]] = event["snapshot"]
            self.treestore.foreach(self.update_host_status, "")

    # -- Storage tree helpers ---------------------------------------------

    def _add_storage_to_tree(self, sr, parent):
        GLib.idle_add(
            lambda s=sr, p=parent: (
                self.treestore.append(
                    p,
                    [
                        GdkPixbuf.Pixbuf.new_from_file(
                            utils.image_path("storage_shaped_16.png")
                        ),
                        self.all["SR"][s]["name_label"],
                        self.all["SR"][s]["uuid"],
                        "storage",
                        None,
                        self.host,
                        s,
                        self.all["SR"][s]["allowed_operations"],
                        None,
                    ],
                )
                and False
            )
        )

    def _insert_pbd_after_tree(self, parent, iter_ref, sr):
        if parent is not None and iter_ref is not None:
            GLib.idle_add(
                lambda p=parent, i=iter_ref, s=sr: (
                    self.treestore.insert_after(
                        p,
                        i,
                        [
                            GdkPixbuf.Pixbuf.new_from_file(
                                utils.image_path("storage_shaped_16.png")
                            ),
                            self.all["SR"][s]["name_label"],
                            self.all["SR"][s]["uuid"],
                            "storage",
                            None,
                            self.host,
                            s,
                            self.all["SR"][s]["allowed_operations"],
                            None,
                        ],
                    )
                    and False
                )
            )

    def _refresh_storage_tabs(self, tab_type):
        """Refresh storage-related UI tabs."""
        if tab_type == "local" and self.wine.selected_tab == "Local_Storage":
            GLib.idle_add(
                lambda: (
                    self.fill_local_storage(
                        self.wine.selected_ref, self.wine.builder.get_object("liststg")
                    )
                    and False
                )
            )
        elif tab_type == "vm" and self.wine.selected_tab == "VM_Storage":
            GLib.idle_add(
                lambda: (
                    self.fill_vm_storage(
                        self.wine.selected_ref,
                        self.wine.builder.get_object("listvmstorage"),
                    )
                    and False
                )
            )

    def _set_vm_tree_icon(self, iter_ref, icon_name):
        GLib.idle_add(
            lambda i=iter_ref, ic=icon_name: self.treestore.set_value(
                i, 0, GdkPixbuf.Pixbuf.new_from_file(utils.image_path(ic))
            )
        )
