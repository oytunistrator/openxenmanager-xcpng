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
import socket
import select
import sys
from threading import Thread
import traceback


class Tunnel:
    def __init__(self, session, location):
        self.client_fd = None
        self.server_fd = None
        self.ref = location[location.find("/", 8):] 
        self.session = session
        self.ip = location[8:location.find("/", 8)] 
        self.halt = False
        self.translate = False
        self.key = None

    def listen(self, port=None):
        sock = socket.socket()
        sock.bind(("127.0.0.1", port))
        sock.listen(1)
        self.client_fd, addr = sock.accept()
        self.server_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_fd.connect((self.ip, 80))
        # self.server_fd.send("CONNECT /console?ref=%s&session_id=%s HTTP/1.1\r\n\r\n" % (self.ref, self.session))
        self.server_fd.send("CONNECT %s&session_id=%s HTTP/1.1\r\n\r\n" % (self.ref, self.session))
        data = self.server_fd.recv(17)
        data = self.server_fd.recv(24)
        data = self.server_fd.recv(35)
        data = self.server_fd.recv(2)
        self.server_fd.setblocking(0)
        Thread(target=self.read_from_server, args=()).start()
        try:
            codes = [b"\x39", b"\x02", b"\x28", b"\x04", b"\x05", b"\x06", b"\x08", b"\x28", #/*  !"#$%&' */
                      b"\x0a", b"\x0b", b"\x09", b"\x0d", b"\x33", b"\x0c", b"\x34", b"\x35", #* ()*+,-./ */
                      b"\x0b", b"\x02", b"\x03", b"\x04", b"\x05", b"\x06", b"\x07", b"\x08", #* 01234567 */
                      b"\x09", b"\x0a", b"\x27", b"\x27", b"\x33", b"\x0d", b"\x34", b"\x35", #* 89:;<=>? */
                      b"\x03", b"\x1e", b"\x30", b"\x2e", b"\x20", b"\x12", b"\x21", b"\x22", #* @ABCDEFG */
                      b"\x23", b"\x17", b"\x24", b"\x25", b"\x26", b"\x32", b"\x31", b"\x18", #* HIJKLMNO */
                      b"\x19", b"\x10", b"\x13", b"\x1f", b"\x14", b"\x16", b"\x2f", b"\x11", #* PQRSTUVW */
                      b"\x2d", b"\x15", b"\x2c", b"\x1a", b"\x2b", b"\x1b", b"\x07", b"\x0c", #* XYZ[\]^_ */
                      b"\x29", b"\x1e", b"\x30", b"\x2e", b"\x20", b"\x12", b"\x21", b"\x22", #* `abcdefg */
                      b"\x23", b"\x17", b"\x24", b"\x25", b"\x26", b"\x32", b"\x31", b"\x18", #* hijklmno */
                      b"\x19", b"\x10", b"\x13", b"\x1f", b"\x14", b"\x16", b"\x2f", b"\x11", #* pqrstuvw */
                      b"\x2d", b"\x15", b"\x2c", b"\x1a", b"\x2b", b"\x1b", b"\x29"        #* xyz{|}~  */
                    ] 

            codes2 = ["\x0239", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x0c", "\x09", "\x0a", "\x1b", "\x1b", # 12
                   "\x33", "\x35", "\x34", "\x08", #//space", !"#$%&'()*+`-./ -> 3
                   "\x0b", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0a", #//0123456789 -> 10
                   #"\x0127", "\x27", "\x0133", "\x000d", "\x0134", "\x0135", "\x0103", #//:;<=>?@ 
                   "\x34", "\x33", "\x56", "\x0b", "\x56", "\x0c", "\x1f", #//:;<=>?@ -> 7
                   "\x11e", "\x130", "\x12e", "\x120", "\x112", "\x121", "\x122", "\x123", "\x117", "\x124", "\x125", "\x126", "\x132", "\x131",  # 14
                   "\x118", "\x119", "\x110", "\x113", "\x11f", "\x114", "\x116", "\x12f", "\x111", "\x12d", "\x115", "\x12c", #//A-Z -> 12
                   "\x1a", "\x2b", "\x1b", "\x07", "\x35", "\x29", #//[\]^_`
                   "\x1e", "\x30", "\x2e", "\x20", "\x12", "\x21", "\x22", "\x23", "\x17", "\x24", "\x25", "\x26", "\x32", "\x31", "\x18", "\x19", "\x10", \
                   "\x13", "\x1f", "\x14", "\x16", "\x2f", "\x11", "\x2d", "\x15", "\x2c", #a-z
                   "\x1a", "\x2b", "\x1b", "\x29" #//{|}~
            ]
            from struct import pack
            data = self.client_fd.recv(1024)
            while data and self.halt is False:
                if data[0] == 4 and self.translate:
                    if 32 < data[7] < 127 and data[7] not in range(80, 91):
                        if self.key:
                            data = b"\xfe" + data[1:7] + bytes([int(self.key, 16)])
                        else:
                            data = b"\xfe" + data[1:7] + codes[data[7]-32]
                self.server_fd.send(data)
                data = self.client_fd.recv(1024)
        except:
            if self.halt is False:
                print("Unexpected error:", sys.exc_info())
                print(traceback.print_exc())
            else:
                pass

        self.client_fd.close()

    def get_free_port(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        (host, port) = sock.getsockname()
        sock.close()
        return port

    def send_data(self, data):
        self.server_fd.send(data)

    def read_from_server(self):
        try:
            while self.halt is False:
                ready_to_read, ready_to_write, in_error = select.select([self.server_fd], [], [])
                if self.server_fd in ready_to_read:
                    data = self.server_fd.recv(1024)
                    if b"XenServer Virtual Terminal" in data:
                        self.translate = False
                        data = data[:7] + b"\x00" + data[8:]
                    elif b"+HVMXEN-" in data:
                        self.translate = True
                        data = data[:7] + b"\x00" + data[8:]
                    self.client_fd.send(data)
        except:
            if self.halt is False:
                print("Unexpected error:", sys.exc_info())
                print(traceback.print_exc())
            else:
                pass
        self.server_fd.close()

    def close(self):
        try:
            self.halt = True
            self.client_fd.send(b"close\n")
            self.client_fd.send(b"close\n")
            self.server_fd.send(b"close\n")
            del self
        except:
            pass
