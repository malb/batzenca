import os

PALECADIR   = os.environ.get("PALECADIR", os.path.expanduser("~") + os.path.sep + ".paleca")
GPGHOMEDIR = PALECADIR + os.path.sep + "gnupg"
