#!/usr/bin/env python3
# -----------------------------------------------------------------------
# OpenXenManager
#
# Copyright (C) 2014 Daniel Lintott <daniel@serverb.co.uk>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the License, or (at your option) any later version.
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
import gi

gi.require_version("Gtk", "3.0")
import os
import sys

from gi.repository import Gtk

# FIXME: rather pathetic fix for ubuntu to show menus -  GTK3 migration should
# fix this
os.environ["UBUNTU_MENUPROXY"] = "0"

# Insert ./src at the beginning so repo code overrides any installed package
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from OXM.window import oxcWindow

if __name__ == "__main__":
    # Main function
    wine = oxcWindow()
    Gtk.main()
