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
"""Performance charting (RRD data) for OXC Server."""

import os
import time
import urllib.request

from gi.repository import GLib, Gtk

from . import rrd as _rrd_module
from . import rrdinfo as _rrdinfo_module
from . import utils
from .oxcSERVER import line_chart


class OxcPerformance:
    """Handles performance data collection and chart rendering."""

    halt_performance = False  # Controlled by caller's stop_perf() method

    def update_performance(self, uuid, ref, ip, host=False, period=5):
        """Fetch RRD data and render CPU/Memory/Network/Disk charts.

        This method runs in a background thread; it uses GLib.idle_add to
        update the GTK UI safely.
        """
        self.halt_performance = False

        if host:
            data_sources = self.connection.host.get_data_sources(self.session_uuid, ref)
        else:
            data_sources = self.connection.VM.get_data_sources(self.session_uuid, ref)

        if "Value" not in data_sources:
            return
        data_sources = data_sources["Value"]

        # Collect enabled data sources grouped by 3-char prefix
        ds = {}
        for data_source in data_sources:
            if data_source["enabled"]:
                name = data_source["name_label"]
                desc = data_source["name_description"]
                key = name[:3]
                if key not in ds:
                    ds[key] = []
                entry = [name, desc]
                if entry not in ds[key]:
                    excluded_names = (
                        "memory_internal_free",
                        "xapi_free_memory_kib",
                        "xapi_memory_usage_kib",
                        "xapi_live_memory_kib",
                    )
                    if name not in excluded_names and name[:6] != "pif___":
                        ds[key].append(entry)

        # Download RRD file
        if host:
            rrd_file = os.path.join(self.wine.pathconfig, "host_rrds.rrd")
            url = "https://%s/host_rrds?session_id=%s" % (ip, self.session_uuid)
        else:
            rrd_file = os.path.join(self.wine.pathconfig, "vm_rrds.rrd")
            url = "https://%s/vm_rrds?session_id=%s&uuid=%s" % (
                ip,
                self.session_uuid,
                uuid,
            )

        if os.path.exists(rrd_file):
            os.unlink(rrd_file)
        urllib.request.urlretrieve(url, rrd_file)
        rrd = _rrd_module.RRD(rrd_file)
        rrdinfo = rrd.get_data(period)

        # Time tick formatter for X-axis
        def show_tic(value):
            if time.strftime("%S", time.localtime(value)) == "00":
                return time.strftime("%H:%M", time.localtime(value))
            return ""

        # Chart container
        chart = {}
        graph = {}
        for name in ["cpu", "vbd", "vif", "mem"]:
            chart[name] = line_chart.LineChart()
            chart[name].xaxis.set_show_tics(True)
            chart[name].xaxis.set_tic_format_function(show_tic)
            chart[name].yaxis.set_position(7)
            chart[name].connect("datapoint-hovered", self._perf_hover_handler)
            chart[name].legend.set_visible(True)
            chart[name].legend.set_position(line_chart.POSITION_RIGHT)
            chart[name].set_padding(0)
            chart[name].yaxis.set_label("kBps")

        chart["cpu"].yaxis.set_label("%")
        chart["mem"].yaxis.set_label("MB")

        # --- CPU graph ---
        chart["cpu"].set_yrange((0, 100))
        for key in rrdinfo.keys():
            if key[:3] == "cpu":
                data = rrdinfo[key]["values"]
                for i in range(len(data)):
                    data[i][1] *= 100
                graph[key] = line_chart.Graph(key, key, data)
                graph[key].set_show_title(False)
                chart["cpu"].add_graph(graph[key])

        if "data" in locals() and data:
            chart["cpu"].set_size_request(len(data) * 20, 250)

        def add_cpu():
            w = self.wine.builder.get_object("scrwin_cpuusage")
            child = w.get_child()
            if child:
                w.remove(child)
            w.add(chart["cpu"])
            w.show_all()

        GLib.idle_add(add_cpu)

        # --- Memory graph ---
        memory_available = False
        if "memory_internal_free" in rrdinfo and "memory" in rrdinfo:
            chart["mem"].set_yrange(
                (0, int(rrdinfo["memory"]["max_value"]) / 1024 / 1024)
            )
            data = rrdinfo["memory"]["values"]
            data2 = rrdinfo["memory_internal_free"]["values"]
            for i in range(len(data2)):
                data[i][1] = (data[i][1] - data2[i][1] * 1024) / 1024 / 1024
            memory_available = True
        elif "memory_total_kib" in rrdinfo and "xapi_free_memory_kib" in rrdinfo:
            chart["mem"].set_yrange(
                (0, int(rrdinfo["memory_total_kib"]["max_value"]) / 1024 / 1024)
            )
            data = rrdinfo["memory_total_kib"]["values"]
            data2 = rrdinfo["xapi_free_memory_kib"]["values"]
            for i in range(len(data2)):
                data[i][1] = (data[i][1] - data2[i][1] * 1024) / 1024 / 1024
            memory_available = True

        if memory_available:
            graph["mem"] = line_chart.Graph("Memory used", "Memory used", data)
            graph["mem"].set_show_title(False)
            chart["mem"].add_graph(graph["mem"])
            chart["mem"].set_size_request(len(data) * 20, 250)

            def add_mem():
                w = self.wine.builder.get_object("scrwin_memusage")
                child = w.get_child()
                if child:
                    w.remove(child)
                w.add(chart["mem"])
                w.show_all()

            GLib.idle_add(add_mem)
        else:

            def add_mem_label():
                w = self.wine.builder.get_object("scrwin_memusage")
                child = w.get_child()
                if child:
                    w.remove(child)
                label = Gtk.Label()
                label.set_markup("<b>No data available</b>")
                w.add(label)
                w.show_all()

            GLib.idle_add(add_mem_label)

        # --- Network graph ---
        max_value = 0
        net_data = None
        for key in rrdinfo.keys():
            if key[:3] == "vif" or key[:3] == "pif":
                net_data = rrdinfo[key]["values"]
                for i in range(len(net_data)):
                    net_data[i][1] /= 1024
                    if net_data[i][1] > max_value:
                        max_value = net_data[i][1]
                graph[key] = line_chart.Graph(key, key, net_data)
                graph[key].set_show_title(False)
                chart["vif"].add_graph(graph[key])

        if net_data:
            chart["vif"].set_yrange((0, max_value))
            chart["vif"].set_size_request(len(net_data) * 20, 250)

            def add_net():
                w = self.wine.builder.get_object("scrwin_netusage")
                child = w.get_child()
                if child:
                    w.remove(child)
                w.add(chart["vif"])
                w.show_all()

            GLib.idle_add(add_net)
        else:

            def add_net_label():
                w = self.wine.builder.get_object("scrwin_netusage")
                child = w.get_child()
                if child:
                    w.remove(child)
                label = Gtk.Label()
                label.set_markup("<b>No data available</b>")
                w.add(label)
                w.show_all()

            GLib.idle_add(add_net_label)

        # --- Disk graph (VM only) ---
        disk_available = False
        if not host:
            max_value = 0
            disk_data = None
            for key in rrdinfo.keys():
                if key[:3] == "vbd":
                    disk_data = rrdinfo[key]["values"]
                    for i in range(len(disk_data)):
                        disk_data[i][1] /= 1024
                    graph[key] = line_chart.Graph(key, key, disk_data)
                    graph[key].set_show_title(False)
                    chart["vbd"].add_graph(graph[key])
                    if rrdinfo[key]["max_value"] / 1024 > max_value:
                        max_value = rrdinfo[key]["max_value"] / 1024

            if disk_data:
                chart["vbd"].set_yrange((0, max_value))
                chart["vbd"].set_size_request(len(disk_data) * 20, 250)
                disk_available = True

                def add_disk():
                    w = self.wine.builder.get_object("scrwin_diskusage")
                    child = w.get_child()
                    if child:
                        w.remove(child)
                    w.add(chart["vbd"])
                    w.show_all()

                GLib.idle_add(add_disk)

        # --- Live update loop (background thread) ---
        if not disk_available and max_value == 0:
            max_value = 1

        time.sleep(5)
        while not self.halt_performance:
            update_rrd = os.path.join(self.wine.pathconfig, "update.rrd")
            if os.path.exists(update_rrd):
                os.unlink(update_rrd)

            # Use rrdinfo.RRDUpdates if available
            try:
                updates_url = (
                    "https://%s/rrd_updates?session_id=%s&start=%d"
                    "&cf=AVERAGE&interval=5&vm_uuid=%s"
                    % (ip, self.session_uuid, int(time.time()) - 10, uuid)
                )
                urllib.request.urlretrieve(updates_url, update_rrd)
                rrd2 = _rrd_module.XPORT(update_rrd)
                rrdinfo = rrd2.get_data()
            except Exception:
                break

            for key in rrdinfo:
                if key in graph and rrdinfo[key]["values"]:
                    data = rrdinfo[key]["values"]
                    if key[:3] == "cpu":
                        for i in range(len(data)):
                            data[i][1] *= 100
                        graph[key].add_data(data)
                        chart[key[:3]].queue_draw()
                    elif key[:3] == "vif":
                        for i in range(len(data)):
                            data[i][1] /= 1024
                        graph[key].add_data(data)
                        chart[key[:3]].queue_draw()
                    elif key[:3] == "vbd" and disk_available:
                        for i in range(len(data)):
                            data[i][1] /= 1024
                        graph[key].add_data(data)
                        chart[key[:3]].queue_draw()

            if memory_available and "memory_internal_free" in rrdinfo:
                data = rrdinfo["memory"]["values"]
                data2 = rrdinfo["memory_internal_free"]["values"]
                for i in range(len(data2)):
                    data[i][1] = (data[i][1] - data2[i][1] * 1024) / 1024 / 1024
                graph["mem"].add_data(data)
                chart["mem"].queue_draw()

            for _i in range(5):
                if not self.halt_performance:
                    time.sleep(1)

    def stop_performance(self):
        """Signal the performance update loop to stop."""
        self.halt_performance = True

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _perf_hover_handler(chart, graph, xy):
        """Dummy hover handler (was previously printing data)."""
        pass  # No-op; hover tooltips can be re-added later
