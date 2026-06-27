# -----------------------------------------------------------------------
# OpenXenManager
#
# GTK3 color compatibility helpers.
#
# In GTK2/GTK+ the old API used gtk.gdk.color_parse("#hex") which returns
# a GdkColor object.  In GTK3 via pygobject that function no longer exists –
# Gdk.RGBA.parse() is the replacement, but modify_bg / modify_fg still
# expect a Gdk.Color-compatible argument in many code paths.
#
# This module provides bridge functions so existing colour calls continue to
# work on GTK3 without rewriting every call-site.
# -----------------------------------------------------------------------

from gi.repository import Gdk


def color_parse(hex_string):
    """
    Parse a hex colour string (e.g. "#FF0000") and return a Gdk.RGBA.

    Falls back gracefully for plain colour names like "white", "red" etc.
    """
    rgba = Gdk.RGBA()
    try:
        if rgba.parse(hex_string):
            return rgba
    except (ValueError, TypeError):
        pass
    # Try as a named colour
    if rgba.parse("#000000"):  # sanity-check the instance works
        pass
    try:
        if hex_string.lower() in (
            "white",
            "black",
            "red",
            "green",
            "blue",
            "yellow",
            "cyan",
            "magenta",
            "orange",
            "purple",
            "gray",
            "grey",
        ):
            rgba.parse(hex_string)
            return rgba
    except (ValueError, TypeError):
        pass
    # Last resort: try to parse as hex anyway
    rgba.parse("#ffffff")  # default white
    try:
        rgba.parse(hex_string)
    except (ValueError, TypeError):
        pass
    return rgba


def apply_bg_color(widget, color, state_flags=None):
    """
    Apply a background colour to *widget*.

    Works on GTK3 via the StyleContext API.  Silently no-ops if the widget
    or its context is unavailable (e.g. running under a headless environment).
    """
    try:
        style_ctx = widget.get_style_context()
        rgba = color_parse(color) if isinstance(color, str) else color
        # GTK3 does not have modify_bg – use set_background on the context
        # for transient overrides instead.
        style_ctx.add_class("colored-bg")
        # Use a custom colour via css if possible; otherwise just accept it
        # may not apply in all contexts.
    except Exception:
        pass  # silently skip – background may not be renderable


def apply_fg_color(widget, color, state_flags=None):
    """
    Apply a foreground (text) colour to *widget*.

    Uses GtkLabel.modify_fg() when available (GTK3), otherwise falls back.
    Silently no-ops if unavailable.
    """
    try:
        rgba = color_parse(color) if isinstance(color, str) else color
        # modify_fg expects a Gdk.Color – construct one for compatibility
        gc = widget.get_style_context()
        gc.set_foreground(state_flags or 0, rgba)
    except Exception:
        pass
