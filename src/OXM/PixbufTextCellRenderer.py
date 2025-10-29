from __future__ import print_function
# License: Public Domain
# Original Author: John Finlay <finlay at moeraki.com>
# http://www.daa.com.au/pipermail/pygtk/2004-September/008685.html

from gi.repository import Gtk, GObject, Gdk


PAD = 3


class PixbufTextCellRenderer(Gtk.CellRenderer):

    pixbuf = GObject.Property(type=GObject.TYPE_PYOBJECT)
    text = GObject.Property(type=str)
    background = GObject.Property(type=Gdk.Color)

    def __init__(self):
        super().__init__()
        self.prend = Gtk.CellRendererPixbuf()
        self.trend = Gtk.CellRendererText()
        self.percent = 0

    def do_render(self, cr, widget, background_area, cell_area, flags):
        self.update_properties()
        # ypad = self.get_property('ypad')
        px, py, pw, ph = self.prend.get_size(widget, cell_area)
        px += cell_area.x
        prect = Gdk.Rectangle()
        prect.x = px
        prect.y = cell_area.y
        prect.width = pw
        prect.height = ph
        tx, ty, tw, th = self.trend.get_size(widget, cell_area)
        tx = cell_area.x + (cell_area.width - tw) / 2
        ty = cell_area.y + ph + PAD
        trect = Gdk.Rectangle()
        trect.x = tx
        trect.y = ty
        trect.width = tw
        trect.height = th
        self.prend.render(cr, widget, background_area, prect, flags)
        self.trend.render(cr, widget, background_area, trect, flags)

    def do_get_size(self, widget, cell_area):
        self.update_properties()
        xpad = self.get_property("xpad")
        ypad = self.get_property("ypad")
        xoff, yoff, width, height = self.trend.get_size(widget, cell_area)
        pxoff, pyoff, pwidth, pheight = self.prend.get_size(widget, cell_area)
        height += pheight + PAD + ypad
        width = max(width, pwidth) + xpad * 2
        return xoff, yoff, width, height

    def update_properties(self):
        self.trend.set_property('text', self.get_property('text'))
        self.prend.set_property('pixbuf', self.get_property('pixbuf'))
        self.prend.set_property('cell-background-gdk', self.get_property('background'))

GObject.type_register(PixbufTextCellRenderer)
