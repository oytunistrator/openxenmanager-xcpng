from __future__ import print_function
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
#
# -----------------------------------------------------------------------
import xmlrpc.client
import http.client
import socket
import sys
from threading import Thread
from gi.repository import GObject as gobject


class oxcSERVERaddserver(gobject.GObject):
    __gsignals__ = {
        "connect-success": (gobject.SIGNAL_RUN_FIRST, None, ()),
        "connect-failure": (gobject.SIGNAL_RUN_FIRST, None, (str,)),
        "sync-progress": (gobject.SIGNAL_RUN_FIRST, None, (str,)),
        "sync-success": (gobject.SIGNAL_RUN_FIRST, None, ()),
        "sync-failure": (gobject.SIGNAL_RUN_FIRST, None, (str,))
    }

    connectThread = None

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.all = {}

    # Helper transports to allow per-ServerProxy socket timeouts on Python 3
    class _TimeoutTransport(xmlrpc.client.Transport):
        def __init__(self, timeout=None, use_datetime=False):
            super().__init__(use_datetime=use_datetime)
            self.timeout = timeout

        def make_connection(self, host):
            # host may include ':port'
            host_only, sep, port = host.partition(":")
            if port:
                try:
                    port = int(port)
                except Exception:
                    port = None
            if port:
                return http.client.HTTPConnection(host_only, port, timeout=self.timeout)
            else:
                return http.client.HTTPConnection(host_only, timeout=self.timeout)

    class _TimeoutSafeTransport(xmlrpc.client.SafeTransport):
        def __init__(self, timeout=None, use_datetime=False):
            super().__init__(use_datetime=use_datetime)
            self.timeout = timeout

        def make_connection(self, host):
            host_only, sep, port = host.partition(":")
            if port:
                try:
                    port = int(port)
                except Exception:
                    port = None
            if port:
                return http.client.HTTPSConnection(host_only, port, timeout=self.timeout)
            else:
                return http.client.HTTPSConnection(host_only, timeout=self.timeout)

    def connect_server_async(self):
        # begin connecting
        self.connectThread = Thread(target=self.connect_server)
        self.connectThread.start()

    def connect_server(self):
        protocol = ["http", "https"][self.ssl]
        self.url = "%s://%s:%d" % (protocol, self.host, self.port)
        print(self.url)
        # Choose transport depending on scheme
        if self.url.startswith('https://'):
            transport = self._TimeoutSafeTransport(timeout=30)
        else:
            transport = self._TimeoutTransport(timeout=30)
        self.connection = xmlrpc.client.ServerProxy(self.url, transport=transport)
        self.connection_events = xmlrpc.client.ServerProxy(self.url, transport=transport)
        try:
            self.session = self.connection.session.login_with_password(
                self.user, self.password)
            if self.session['Status'] == "Success":
                self.is_connected = True
                self.session_uuid = self.session['Value']
                self.session_events = \
                    self.connection_events.session.login_with_password(
                        self.user, self.password)
                self.session_events_uuid = self.session_events['Value']
                self.connection_events.event.register(
                    self.session_events_uuid, ["*"])
                # tell the controller that we've finished
                self.emit("connect-success")
            else:
                self.emit("connect-failure",
                          self.session['ErrorDescription'][2])
        except:
            self.emit("connect-failure", sys.exc_info()[1])

    def thread_event_next(self):
        Thread(target=self.event_next, args=()).start()
        return True

    def fill_alerts(self, list):
        # FIXME priority: 1 info 5 alert
        self.all_messages = self.connection.message.get_all_records(
            self.session_uuid)['Value']
        relacion = {}
        for ref in self.all_messages.keys():
            relacion[self.get_seconds(
                str(self.all_messages[ref]['timestamp']))] = ref
        rkeys = sorted(relacion.keys())
        for ref in rkeys:
            message = self.all_messages[relacion[ref]]
            self.add_alert(message, relacion[ref], list)

    def sync(self):
        try:
            # What to get during the synchronisation
            props = {'host': 'hosts',
                     'pool': 'pools',
                     'SR': 'SRs',
                     'task': 'task',
                     'VBD': 'VBDs',
                     'VBD_metrics': 'VBD metrics',
                     'VDI': 'VDIs',
                     'network': 'networks',
                     'PIF': 'PIFs',
                     'PIF_metrics': 'PIF metrics',
                     'PBD': 'PBDs',
                     'VIF': 'VIFs',
                     'VIF_metrics': 'VIF metrics',
                     'Bond': 'NIC Bonds',
                     'VM_guest_metrics': 'VM guest metrics',
                     'VM_metrics': 'VM metrics',
                     'host_metrics': 'host metrics',
                     'host_cpu': 'host CPUs',
                     'pool_patch': 'pool patches',
                     'host_patch': 'host patches',
                     'console': 'consoles',
                     'subject': 'subjects',
                     'role': 'roles'}

            # Get all vm records
            self.emit("sync-progress", "Retrieving VMs")
            result = self.connection.VM.get_all_records(self.session_uuid)
            if "Value" not in result:
                if "HOST_IS_SLAVE" in result["ErrorDescription"]:
                    # TODO: csun: automatically connect instead
                    error = "The host server \"%s\" is a slave in a pool; " \
                            "please connect to the master server at \"%s\"." \
                            % (self.host, result["ErrorDescription"][1])
                    self.emit("sync-failure", error)
                    return
                else:
                    error = "Unknown error:\n%s" % \
                            str(result["ErrorDescription"])
                self.emit("sync-failure", error)
                return
            else:
                self.all['vms'] = result.get('Value')

            for key, desc in props.items():
                self.emit('sync-progress', 'Retrieving %s' % desc)
                func = getattr(self.connection, key)
                self.all[key] = func.get_all_records(
                    self.session_uuid).get('Value')

            # DEBUG
            for ref in self.all['host']:
                version = (["%s" % (self.all['host'][ref]['software_version'].get(x))
                            for x in ('product_brand', 'product_version', 'xapi')] +
                           [self.all['host'][ref]['license_params'].get(
                               'sku_marketing_name')])
                print("Server version is %s" % version)

            for task in self.all['task'].keys():
                self.tasks[task] = self.all['task'][task]

            # FIXME: all['VIF_metrics'] == all['VLAN']?
            self.all['vlan'] = self.all['VIF_metrics']
        except:
            self.emit("sync-failure", "An unknown error occurred. See log "
                                      "output in terminal for details.")
            print("Synchronisation error:\n")
            import traceback
            traceback.print_exc()
        else:
            print("sync-success")
            self.emit("sync-success")
