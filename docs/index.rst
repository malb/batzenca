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

GnuPG Interface
===============

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

      session.add(obj)

 * To save changes to the database the caller must call::

     session.commit()

.. autoclass:: batzenca.database.base.EntryNotFound

Keys
----

.. automodule:: batzenca.database.keys
   :members:
   :special-members:

Peers
-----

.. automodule::  batzenca.database.peers
   :members:
   :special-members:

Policies
--------

.. automodule::  batzenca.database.policies
   :members:
   :special-members:

MailingLists
------------

.. automodule::  batzenca.database.mailinglists
   :members:
   :special-members:

Releases
--------

.. automodule::  batzenca.database.releases
   :members:
   :special-members:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

