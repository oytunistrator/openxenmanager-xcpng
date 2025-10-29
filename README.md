OpenXenManager introduction
==========================
OpenXenManager is a full-featured graphical interface to manage XCP-NG
hosts through the network.

OpenXenManager is an open-source multiplatform clone of Citrix XenCenter for XCP-NG.
It is written in Python, using GTK3 for its interface.

The homepage for OpenXenManager is at:
https://sourceforge.net/projects/openxenmanager/

Subscribe to the openxenmanager-announce mailing list for important information
and release announcements:
https://lists.sourceforge.net/lists/listinfo/openxenmanager-announce


Running OpenXenManager
======================
To launch OpenXenManager simply run the "openxenmanager" script.

Requirements:
* Python 3.6+
* PyGObject (GTK3 bindings)
* ConfigObj
* Raven
* GTK-VNC (Linux only)

Debian/Ubuntu Linux package dependencies:
python3 python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-gtk-vnc-1.0 python3-configobj python3-raven

Gentoo Linux package dependencies:
dev-python/pygobject dev-python/configobj net-libs/gtk-vnc dev-lang/python:3.6

macOS dependencies:
[brew](http://brew.sh/) install pygobject3 gtk+3
pip install configobj raven

OpenXenManager runs has been tested to run on Linux or Windows and should work
on MacOSX as well.


Help / bug reports
==================

If you have found a bug, please file a detailed report in our bug tracker:
  https://github.com/OpenXenManager/openxenmanager/issues

<img src="https://sentry-brand.storage.googleapis.com/sentry-logo-black.svg" alt="Sentry Logo" width="200px">

In addition to submitting bug reports, we will be collecting crash data via Sentry.io 
No personally identifying data is collected.

For help you can:

* Visit the forums:
  http://sourceforge.net/projects/openxenmanager/forums

* Send an email in the mailing list:
  https://lists.sourceforge.net/lists/listinfo/openxenmanager-users
  
Developers
==========

- Original Author: Alberto Gonzalez Rodriguez <alberto@pesadilla.org>
- Previous Developer: Cheng Sun <chengsun9@gmail.com>
- Current Developer: Daniel Lintott <daniel.j.lintott@gmail.com>
- Contributors:
  * Lars Hagström (DonOregano) <lars@foldspace.nu>
  * Sol Jerome (solj)
  * Ivan Zderadicka (izderadicka)
  * Jason Nelson (schplat)
