# -*- coding: utf-8 -*-
"""
Tkinter Theme Lister.

This script initializes a temporary Tkinter root window to access ttk styling
capabilities. It then prints a list of all available ttk themes on the current
system. This is useful for developers to identify themes that can be used
with `ttk.Style().theme_use()` for customizing the application's appearance.

The script destroys the root window after printing the themes, so it does not
display any GUI itself.
"""
from tkinter import ttk
import tkinter as tk

# Create a temporary root window (it won't be shown)
root = tk.Tk()
root.withdraw() # Hide the window

# Initialize a ttk Style object
style = ttk.Style(root)

# Get and print the list of available theme names
available_themes = style.theme_names()
print("Available ttk themes:")
for theme in available_themes:
    print(f"- {theme}")

# Destroy the temporary root window
root.destroy()
