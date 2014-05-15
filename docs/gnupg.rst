GnuPG Interface
===============

Where is my Data?
-----------------

BatzenCA does not interfere with your normal OpenPGP public-key or secret-key
ring. Instead, it uses an independent GnuPG key database/keyring. By default it
is located in ``$HOME/.batzenca/gnupg``. This default can be changed by setting
the environment variable ``BATZENCADIR``. If ``BATZENCADIR`` is set, then the
GnuPG keyring will be located in ``$BATZENCADIR/gnupg``. The currently used home
dir can be queried as follows::

    >>> session.gnupg.home_dir

To work with the GnuPG directly you can run::

    $ gpg --homedir=$HOME/.batzenca/gnupg

GnuPG
-----

.. autoclass::  batzenca.gnupg.GnuPG
   :members:

.. autoclass::  batzenca.gnupg.KeyError
   :members:

PGP/MIME
--------

.. automodule::  batzenca.pgpmime
   :members:
