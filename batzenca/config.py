import os

BATZENCADIR   = os.environ.get("BATZENCADIR", os.path.expanduser("~") + os.path.sep + ".batzenca")
GPGHOMEDIR = BATZENCADIR + os.path.sep + "gnupg"
