from __future__ import print_function
# -----------------------------------------------------------------------
# OpenXenManager
#
# Copyright (C) 2009 Alberto Gonzalez Rodriguez alberto@pesadilla.org
# Copyright (C) 2011 Cheng Sun <chengsun9@gmail.com>
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
from . import xtea
import re
from .oxcSERVER import *
from os import path
from . import utils
import gi
from gi.repository import GLib, GdkPixbuf, Gdk


def get_combo_active_text(widget):
    if widget.get_has_entry():
        return widget.get_child().get_text()
    else:
        model = widget.get_model()
        iter = widget.get_active_iter()
        if iter is not None:
            return model.get_value(iter, 0)
        return ""


def idle(func):
    return lambda *args, **kwargs: GLib.idle_add(lambda: func(*args, **kwargs) and False)


class AddServer(object):
    def __init__(self, main, host=None, user=None, password=None,
                 use_ssl=None, verify_ssl=None, port=None):
        self.main = main
        self.builder = main.builder
        self.treestore = main.treestore
        self.xc_servers = main.xc_servers
        self.dialog = self.builder.get_object('addserver')
        self.dialog.connect("key-press-event", self.on_addserver_key_press)
        self.details = {'host': host,
                        'port': port,
                        'user': user,
                        'password': password,
                        'use_ssl': use_ssl,
                        'verify_ssl': verify_ssl}

    def show_dialog(self, grab_widget=None):
        if self.details['host']:
            self.builder.get_object(
                'addserver_hostname').get_child().set_text(
                self.details['host'])
        if self.details['port'] is not None:
            self.builder.get_object('addserverport').set_text(
                self.details['port'])
        if self.details['user'] is not None:
            self.builder.get_object('addserverusername').set_text(
                self.details['user'])
        if self.details['password'] is not None:
            self.builder.get_object('addserverpassword').set_text(
                self.details['password'])
        if self.details['use_ssl'] is not None:
            self.builder.get_object('checksslconnection').set_active(
                self.details['use_ssl'])
        if self.details['verify_ssl'] is not None:
            self.builder.get_object('check_verifyssl').set_active(
                self.details['verify_ssl'])
        self.dialog.show_all()
        if grab_widget is not None:
            self.builder.get_object(grab_widget).grab_focus()

    def on_addserver_hostname_changed(self, widget):
        """
        Function called when hostname/ip text field is changed
        """
        btn_connect = self.builder.get_object("connect_addserver")
        hostname = get_combo_active_text(widget)
        if re.match(r"^[a-zA-Z0-9\-_.]+?$", hostname):
            # If is valid, enable the button
            btn_connect.set_sensitive(True)
            # If hostname is in saved servers, fill in the details
            if hostname in self.main.config_hosts:
                saved = self.main.config_hosts[hostname]
                self.builder.get_object("addserverusername").set_text(saved[0])
                # Decrypt password if master password is set
                if self.main.password:
                    try:
                        import binascii
                        encrypted = saved[1]
                        if encrypted:
                            encrypted_bytes = binascii.unhexlify(encrypted)
                            decrypted = xtea.crypt(encrypted_bytes, "X" * (16-len(self.main.password)) + self.main.password, self.main.iv)
                            if isinstance(decrypted, bytes):
                                decrypted = decrypted.decode('latin1')
                            self.builder.get_object("addserverpassword").set_text(decrypted)
                        else:
                            self.builder.get_object("addserverpassword").set_text("")
                    except Exception:
                        # If decryption fails, leave password empty
                        self.builder.get_object("addserverpassword").set_text("")
                else:
                    self.builder.get_object("addserverpassword").set_text("")
                self.builder.get_object("checksslconnection").set_active(saved[2] == "True")
                self.builder.get_object("check_verifyssl").set_active(saved[3] == "True")
        else:
            # If is invalid, disable the button
            btn_connect.set_sensitive(False)

    def on_addserver_ssl_toggled(self, widget):
        """
        Function called when "SSL connection" checkbox is toggled
        """
        connect_port = self.builder.get_object("addserverport")
        # set the default port number
        ports = ["80", "443"]   # for unencrypted and encrypted respectively
        if (not connect_port.get_text() or
                connect_port.get_text() == ports[not widget.get_active()]):
            connect_port.set_text(ports[widget.get_active()])

    def on_cancel_addserver_clicked(self, widget):
        """
        Function called when you press the "cancel" button on "add server"
        dialog
        """
        self.builder.get_object("addserver").hide()

    def on_connect_addserver_clicked(self, widget):
        """
        Function called when you press the "connect" button
        """
        # Get host, username and password
        self.details = {
            'host': get_combo_active_text(self.builder.get_object(
                "addserver_hostname")),
            'port': self.builder.get_object("addserverport").get_text(),
            'user': self.builder.get_object("addserverusername").get_text(),
            'password': self.builder.get_object(
                "addserverpassword").get_text(),
            'use_ssl': self.builder.get_object(
                "checksslconnection").get_active(),
            'verify_ssl': self.builder.get_object(
                "check_verifyssl").get_active()}

        # Validate required fields before hiding dialog / attempting connect
        main = getattr(self, 'main', self)
        try:
            port_val = int(self.details['port'])
        except Exception:
            main.show_error_dlg("Please enter a valid port number.", "Invalid input")
            return

        if not self.details['host']:
            main.show_error_dlg("Host is required.", "Missing input")
            return
        if not self.details['user']:
            main.show_error_dlg("Username is required.", "Missing input")
            return
        if not self.details['password']:
            main.show_error_dlg("Password is required.", "Missing input")
            return

        # convert port back to int now that it's validated
        self.details['port'] = port_val

        self.builder.get_object("addserver").hide()

        # Call to "add_server" function with params
        # This function try connect to server and authenticate
        self.connect_server()

    def on_addserver_key_press(self, widget, event):
        """
        Function called when a key is pressed in the add server dialog
        """
        if event.keyval == Gdk.KEY_Return or event.keyval == Gdk.KEY_KP_Enter:
            # Trigger the connect button
            self.on_connect_addserver_clicked(widget)
            return True
        return False

    def connect_server(self):
        """
        Function used to connect to server
        """

        main = getattr(self, 'main', self)

        # Defensive: if dialog was cancelled before we began, abort
        if getattr(self, 'cancelled', False):
            return

        # check that we are not already connected
        # FIXME: csun: should be better done when we have controllers
        found = []

        def add_helper(model, path, iter):
            if self.treestore.get(iter, 3, 5) == ("host", self.details['host']):
                found.append(self.treestore.get(iter, 1)[0])
                return True
            return False
        self.treestore.foreach(add_helper)

        if len(found):
            # Show an alert dialog showing error
            main.show_error_dlg("'%s' is already connected as '%s'"
                                 % (self.details['host'], found[0]), "Error")
            return

        # Show a dialog with a progress bar.. it should be do better
        self.builder.get_object("wprogressconnect").show()

        # Create a new oxcSERVER object
        self.builder.get_object("lblprogessconnect").set_label(
            "Connecting to %s..." % self.details['host'])
        # Pass the main window object (self.main) to oxcSERVER so that
        # oxcSERVER can access window-level attributes (selected_ref, pathconfig, etc.)
        server = oxcSERVER(self.details['host'],
                   self.details['user'],
                   self.details['password'],
                   main,
                   self.details['use_ssl'],
                   self.details['verify_ssl'],
                   self.details['port'])

        self.xc_servers[self.details['host']] = server
        # connect the signal handlers
        server.connect("connect-success", idle(self.server_connect_success))
        server.connect("connect-failure", idle(self.server_connect_failure))
        server.connect("sync-progress", idle(self.server_sync_progress))
        server.connect("sync-success", idle(self.server_sync_update_tree))
        server.connect("sync-failure", idle(self.server_sync_failure))
        # begin async connection
        server.connect_server_async()
        # begin UI animation
        Thread(target=self.update_connect_status, args=(server,)).start()

    def update_connect_status(self, server):
        """
        Animates the progress bar during connection.
        """
        while server.connectThread.is_alive():
            self.builder.get_object("progressconnect").pulse()
            server.connectThread.join(1)
        # TODO: what does this variable do?
        main = getattr(self, 'main', self)
        if main.selected_host is None:
            main.selected_host = server.host

    def server_connect_success(self, server):
        """
        Callback when a server connects successfully.

        We begin "synchronising", where the server object downloads data
        about the server, and then we query it to update our UI
        """
        # Hide "add server" window
        main = getattr(self, 'main', self)
        self.builder.get_object("addserver").hide()
        # Append to historical host list on "add server" window
        self.builder.get_object("listaddserverhosts").append([server.host])
        # Fill left tree and get all data (pool, vm, storage, template..)
        Thread(target=server.sync).start()

        # If we use a master password then save the password
        # Password is saved encrypted with XTEA
        encrypted_password = ""
        if main.password:
            x = xtea.crypt("X" * (16-len(main.password)) + main.password,
                           server.password, main.iv)
            # Python3: use binascii.hexlify for bytes -> hex string
            try:
                import binascii
                if isinstance(x, bytes):
                    encrypted_password = binascii.hexlify(x).decode('ascii')
                else:
                    # if x is str (unlikely), keep as-is
                    encrypted_password = x
            except Exception:
                try:
                    encrypted_password = x.encode("hex")
                except Exception:
                    encrypted_password = ""
        main.config_hosts[server.host] = [server.user, encrypted_password,
                                          server.ssl, server.verify_ssl]
        main.config['servers']['hosts'] = main.config_hosts
        # Save relation host/user/passwords to configuration
        main.config.write()

    def server_connect_failure(self, server, msg):
        """
        Method called if connection fails
        """
        # Show add server dialog again
        main = getattr(self, 'main', self)
        self.builder.get_object("addserver").show()
        # And hide progress bar
        self.builder.get_object("wprogressconnect").hide()
        # Show an alert dialog showing error
        main.show_error_dlg("%s" % msg, "Error connecting")

    def server_sync_progress(self, server, msg):
        print("Server sync progress %s" % msg)
        self.builder.get_object("progressconnect").pulse()
        self.builder.get_object("lblprogessconnect").set_text(
            "Synchronizing...\n%s" % msg)

    def server_sync_finish(self, server):
        """
        Method called when server sync has finished
        """
        # Hide window progress
        self.builder.get_object("wprogressconnect").hide()

        # Setting again the modelfiter it will be refresh internal
        # path/references
        main = getattr(self, 'main', self)
        main.treeview.set_model(main.modelfilter)
        main.treeview.expand_all()

    def server_sync_failure(self, server, msg):
        """
        Method called when server sync failed
        """
        server.logout()
        main = getattr(self, 'main', self)
        main.show_error_dlg(msg)
        self.server_sync_finish(server)

    def server_sync_update_tree(self, server):
        """
        Method called when connection loading is finished
        """
        try:
            self.server_sync_progress(server, "")

            # Remove the server from tree; it will be created again below
            # FIXME: csun: this won't be necessary when we have controllers
            def remove_helper(model, path, iter):
                if self.treestore.get(iter, 1, 3) == (server.hostname, "server"):
                    self.treestore.remove(iter)
                    return True
                return False
            self.treestore.foreach(remove_helper)

            # TODO: csun: clean this up

            poolroot = None
            hostroot = {}
            root = ""
            server.treestore = self.treestore
            server.default_sr = ""

            for pool in server.all['pool'].keys():
                server.default_sr = server.all['pool'][pool]['default_SR']
                if server.all['pool'][pool]['name_label']:
                    poolroot = self.treestore.append(
                        self.main.treeroot,
                        [GdkPixbuf.Pixbuf.new_from_file(path.join(
                            utils.module_path(),
                            "images/poolconnected_16.png")),
                         server.all['pool'][pool]['name_label'], pool, "pool",
                         "Running", server.host, pool,
                         ['newvm', 'newstorage', 'importvm', 'disconnect'],
                         server.host])
            if poolroot:
                relacion = {}
                for ref in server.all['host'].keys():
                    relacion[str(server.all['host'][ref]['name_label'] + "_" +
                                 ref)] = ref
                server.all_hosts_keys = []
                rkeys = list(relacion.keys())
                rkeys.sort(key=str.lower)
                for ref in rkeys:
                    server.all_hosts_keys.append(relacion[ref])
                for h in server.all_hosts_keys:
                    host_uuid = server.all['host'][h]['uuid']
                    host = server.all['host'][h]['name_label']
                    host_enabled = server.all['host'][h]['enabled']
                    host_address = server.all['host'][h]['address']
                    if host_enabled:
                        hostroot[h] = self.treestore.append(
                            poolroot,
                            [GdkPixbuf.Pixbuf.new_from_file(
                                path.join(utils.module_path(),
                                    "images/tree_connected_16.png")),
                             host, host_uuid, "host", "Running", server.host,
                             h, ['newvm', 'importvm', 'newstorage',
                                 'clean_reboot', 'clean_shutdown', 'shutdown'],
                             host_address])
                    else:
                        hostroot[h] = self.treestore.append(
                            poolroot,
                            [GdkPixbuf.Pixbuf.new_from_file(path.join(
                                utils.module_path(),
                                "images/tree_disabled_16.png")),
                             host, host_uuid, "host", "Disconnected",
                             server.host, h, [], host_address])
                root = poolroot
            else:
                host_key = list(server.all['host'].keys())[0]
                host_uuid = server.all['host'][host_key]['uuid']
                host = server.all['host'][host_key]['name_label']
                host_address = server.all['host'][host_key]['address']
                host_enabled = server.all['host'][host_key]['enabled']
                if host_enabled:
                    hostroot[host_key] = self.treestore.append(
                        self.main.treeroot,
                        [GdkPixbuf.Pixbuf.new_from_file(path.join(
                            utils.module_path(),
                            "images/tree_connected_16.png")),
                         host, host_uuid, "host", "Running", server.host,
                         host_key,
                         ['newvm', 'importvm', 'newstorage', 'clean_reboot',
                          'clean_shutdown', 'shutdown', 'disconnect'],
                         host_address])
                else:
                    hostroot[host_key] = self.treestore.append(
                        self.main.treeroot,
                        [GdkPixbuf.Pixbuf.new_from_file(path.join(
                            utils.module_path(),
                            "images/tree_disabled_16.png")),
                         host, host_uuid, "host", "Running", server.host,
                         host_key,
                         ['newvm', 'importvm', 'newstorage', 'clean_reboot',
                          'clean_shutdown', 'shutdown', 'disconnect'],
                         host_address])

                root = hostroot[host_key]

            server.hostname = host
            server.hostroot = hostroot
            server.poolroot = poolroot
            relacion = {}
            for ref in server.all['vms'].keys():
                relacion[str(server.all['vms'][ref]['name_label'] + "_" + ref)] = ref
            server.all_vms_keys = []
            rkeys = list(relacion.keys())
            rkeys.sort(key=str.lower)
            for ref in rkeys:
                server.all_vms_keys.insert(0, relacion[ref])

            for vm in server.all_vms_keys:
                if not server.all['vms'][vm]['is_a_template']:
                    if not server.all['vms'][vm]['is_control_domain']:
                        server.add_vm_to_tree(vm)
                        for operation in server.all['vms'][vm]["current_operations"]:
                            server.track_tasks[operation] = vm
                    else:
                        server.host_vm[server.all['vms'][vm]['resident_on']] = [vm,  server.all['vms'][vm]['uuid']]

            # Get all storage record
            for sr in server.all['SR'].keys():
                if server.all['SR'][sr]['name_label'] != "XenServer Tools":
                    if len(server.all['SR'][sr]['PBDs']) == 0:
                        server.last_storage_iter = self.treestore.append(
                            root,
                            [GdkPixbuf.Pixbuf.new_from_file(path.join(
                                utils.module_path(),
                                "images/storage_detached_16.png")),
                             server.all['SR'][sr]['name_label'],
                             server.all['SR'][sr]['uuid'], "storage", None,
                             server.host, sr,
                             server.all['SR'][sr]['allowed_operations'], None])
                        continue
                    broken = False
                    for pbd_ref in server.all['SR'][sr]['PBDs']:
                        if not server.all['PBD'][pbd_ref]['currently_attached']:
                            broken = True
                            server.last_storage_iter = self.treestore.append(
                                root,
                                [GdkPixbuf.Pixbuf.new_from_file(path.join(
                                    utils.module_path(),
                                    "images/storage_broken_16.png")),
                                 server.all['SR'][sr]['name_label'],
                                 server.all['SR'][sr]['uuid'], "storage", None,
                                 server.host, sr,
                                 server.all['SR'][sr]['allowed_operations'],
                                 None])
                    if not broken:
                        if server.all['SR'][sr]['shared']:
                            if sr == server.default_sr:
                                server.last_storage_iter = self.treestore.append(
                                    root, [GdkPixbuf.Pixbuf.new_from_file(path.join(utils.module_path(),
                                                                                  "images/storage_default_16.png")),
                                           server.all['SR'][sr]['name_label'], server.all['SR'][sr]['uuid'],
                                           "storage", None, server.host, sr,
                                           server.all['SR'][sr]['allowed_operations'], None])
                            else:
                                server.last_storage_iter = self.treestore.append(
                                    root, [GdkPixbuf.Pixbuf.new_from_file(path.join(utils.module_path(),
                                                                                  "images/storage_shaped_16.png")),
                                           server.all['SR'][sr]['name_label'], server.all['SR'][sr]['uuid'],
                                           "storage", None, server.host, sr,
                                           server.all['SR'][sr]['allowed_operations'], None])

                        else:
                            for pbd in server.all['SR'][sr]['PBDs']:
                                if sr == server.default_sr:
                                    if server.all['PBD'][pbd]['host'] in hostroot:
                                        server.last_storage_iter = self.treestore.append(
                                            hostroot[server.all['PBD'][pbd]['host']],
                                            [GdkPixbuf.Pixbuf.new_from_file(path.join(utils.module_path(),
                                                                                    "images/storage_default_16.png")),
                                             server.all['SR'][sr]['name_label'], server.all['SR'][sr]['uuid'],
                                             "storage", None, server.host, sr,
                                             server.all['SR'][sr]['allowed_operations'], None])
                                    else:
                                        server.last_storage_iter = self.treestore.append(
                                            root, [GdkPixbuf.Pixbuf.new_from_file(path.join(
                                                utils.module_path(), "images/storage_shaped_16.png")),
                                                server.all['SR'][sr]['name_label'], server.all['SR'][sr]['uuid'],
                                                "storage", None, server.host, sr,
                                                server.all['SR'][sr]['allowed_operations'], None])

                                else:
                                    if server.all['PBD'][pbd]['host'] in hostroot:
                                        server.last_storage_iter = self.treestore.append(
                                            hostroot[server.all['PBD'][pbd]['host']],
                                            [GdkPixbuf.Pixbuf.new_from_file(path.join(utils.module_path(),
                                                                                    "images/storage_shaped_16.png")),
                                             server.all['SR'][sr]['name_label'], server.all['SR'][sr]['uuid'],
                                             "storage", None, server.host, sr,
                                             server.all['SR'][sr]['allowed_operations'], None])
                                    else:
                                        server.last_storage_iter = self.treestore.append(
                                            root, [GdkPixbuf.Pixbuf.new_from_file(path.join(
                                                utils.module_path(), "images/storage_shaped_16.png")),
                                                server.all['SR'][sr]['name_label'], server.all['SR'][sr]['uuid'],
                                                "storage", None, server.host, sr,
                                                server.all['SR'][sr]['allowed_operations'], None])

            for tpl in server.all_vms_keys:
                if server.all['vms'][tpl]['is_a_template'] and not server.all['vms'][tpl]['is_a_snapshot']:
                    if server.all['vms'][tpl]['last_booted_record'] == "":
                        self.treestore.append(root, [GdkPixbuf.Pixbuf.new_from_file(path.join(utils.module_path(),
                                                                                            "images/template_16.png")),
                                                     server.all['vms'][tpl]['name_label'], server.all['vms'][tpl]['uuid'],
                                                     "template", None, server.host, tpl,
                                                     server.all['vms'][tpl]['allowed_operations'], None])
                    else:
                        tpl_affinity = server.all['vms'][tpl]['affinity']

                        if tpl_affinity in hostroot:
                            self.treestore.append(hostroot[tpl_affinity],
                                                  [GdkPixbuf.Pixbuf.new_from_file(
                                                      path.join(utils.module_path(), "images/user_template_16.png")),
                                                   server.all['vms'][tpl]['name_label'], server.all['vms'][tpl]['uuid'],
                                                   "custom_template", None, server.host, tpl,
                                                   server.all['vms'][tpl]['allowed_operations'], None])
                        else:
                            self.treestore.append(root, [GdkPixbuf.Pixbuf.new_from_file(path.join(
                                utils.module_path(), "images/user_template_16.png")),
                                server.all['vms'][tpl]['name_label'], server.all['vms'][tpl]['uuid'], "custom_template", None,
                                server.host, tpl, server.all['vms'][tpl]['allowed_operations'], None])

            self.main.treeview.expand_all()

            # Create a new thread it receives updates
            self.main.xc_servers[self.main.selected_host].thread_event_next()
            # Fill alerts list on "alerts" window
            self.main.xc_servers[self.main.selected_host].fill_alerts(self.main.listalerts)
            self.main.update_n_alerts()
        finally:
            self.server_sync_finish(server)