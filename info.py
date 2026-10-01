import os

NAME = "LimiterNet"
VERSION = "1.0.0"
DESCRIPTION = "Per-application network monitor and limiter"
ICON = "favicon.ico"
ROOT = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(ROOT, "assets")
CONFIG = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), NAME, "config.json")