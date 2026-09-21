"""Log discovery, reading, parsing and analysis — no GTK in here.

Keeping the core free of widgets means the parsers and the scanner can be
tested without a display, which is how they got as robust as they are.
"""
