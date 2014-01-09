.. batzenca documentation master file, created by
   sphinx-quickstart on Thu Dec 12 16:49:36 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. automodule:: batzenca

.. toctree::
   :maxdepth: 4

Introduction
============

.. include:: ../readme.rst

Example
=======

.. include:: example.rst

GnuPG Interface
===============

Where is my Data?
-----------------

Batzenca does not interfere with your normal OpenPGP public-key or secret-key ring. Instead, it uses
an independent GnuPG key database or keyring. By default it is located in
``$HOME/.batzenca/gnupg``. This default can be changed by setting the environment variable
``BATZENCADIR``. If ``BATZENCA`` is set, then the GnuPG keyring will be located in
``$BATZENCADIR/gnupg``. The currently used home dir can be queried as follows::

    >>> session.gnupg.home_dir

.. note::

    Changing ``session.gnupg.home_dir`` has no effect.

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

Database
========

Where is my Data?
-----------------

Peers, keys, policies, mailinglists and releases are stored in an `SQLite
<https://en.wikipedia.org/wiki/SQLite>`_ database. By default it is located in
``$HOME/.batzenca/batzenca.db``. This default can be changed by setting the environment variable
``BATZENCADIR``. If ``BATZENCA`` is set, then the database will be located at
``$BATZENCADIR/batzenca.db``.

Design
------

 * New objects of type :class:`Foo` are created from scratch using :func:`Foo.__init__`. For
   querying the database class methods like :func:`Foo.from_bar` are provided which query the
   database for ``bar`` and return -- if found -- the object of type :class:`Foo` matching
   ``bar``. Some classes have additional class methods for creating fresh objects from scratch. For
   example, :class:`batzenca.database.keys.Key` has methods to create new objects from PGP keys
   stored in a file on disk.

 * Newly created objects are were not added to the current session automatically. The caller is
   responsible for calling::

      >>> session.add(obj)

 * To save changes to the database the caller must call::

     >>> session.commit()

EntryNotFound
-------------

.. autoclass:: batzenca.database.base.EntryNotFound

Key
---

.. automodule:: batzenca.database.keys
   :members:
   :special-members:

Peer
----

.. automodule::  batzenca.database.peers
   :members:
   :special-members:

Policy
------

.. automodule::  batzenca.database.policies
   :members:
   :special-members:

MailingList
-----------

.. automodule::  batzenca.database.mailinglists
   :members:
   :special-members:

Release
-------

.. automodule::  batzenca.database.releases
   :members:
   :special-members:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

