"""Stable, collision-aware identity colors for vehicles."""

from __future__ import annotations

import colorsys


VEHICLE_COLOR_PALETTE = (
    "#0f766e",
    "#c2410c",
    "#6d28d9",
    "#0369a1",
    "#be123c",
    "#4d7c0f",
    "#a16207",
    "#0e7490",
    "#7e22ce",
    "#b91c1c",
    "#166534",
    "#9d174d",
)


def next_vehicle_color(used_colors: set[str]) -> str:
    """Return an unused identity color, extending beyond the base palette."""

    for color in VEHICLE_COLOR_PALETTE:
        if color not in used_colors:
            return color

    index = len(used_colors) - len(VEHICLE_COLOR_PALETTE)
    while True:
        hue = ((index * 137.508) % 360) / 360
        red, green, blue = colorsys.hls_to_rgb(hue, 0.42, 0.72)
        color = "#{:02x}{:02x}{:02x}".format(round(red * 255), round(green * 255), round(blue * 255))
        if color not in used_colors:
            return color
        index += 1
