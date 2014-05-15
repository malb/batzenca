BatzenCA is a set of Python of classes and functions that ought to make managing
OpenPGP keys easier for certification authorities.

User-Case
---------

A group of users want to use a mailing list but with OpenPGP encrypted messages.
They don't want the server to be able to decrypt their messages either.  An easy
ad-hoc way of accomplishing this is by every user encrypting to every other
user.  This can easily accomplished using e.g. Thunderbird/Enigmail's
"Per-Recipient Rules".

As the group grows, verifying each other's OpenPGP keys becomes tedious.  Our
group of users choose not to use the `Web of Trust
<https://en.wikipedia.org/wiki/Web_of_trust>`_, say because they have a clear
definition who belongs on their list and who doesn't. Instead, they nominate a
user or a group of users as a `Certification Authority
<https://en.wikipedia.org/wiki/Certification_Authority>`_ (CA), so they are
actually doing the `X.509 <https://en.wikipedia.org/wiki/X.509>`_ thing with
OpenPGP: all users verify the CA's key and grant it full `owner trust
<http://gnutls.org/openpgp.html>`_.  The CA then checks new users' identities,
verifies their keys, signs and distributes them.  When users leave the group the
CA revokes its signature.  To update the users of our mailing list the CA sends
(ir)regular "releases" which contain all keys for those users active on our
mailing list. The remaining users import these keys and to update their
per-recipient rules to reflect these changes. In a nutshell: a poor person's CA
using OpenPGP.

This library makes the job of the CA easier by providing means to prepare such
releases.

Library Overview
----------------

The purpose of this library is to distribute OpenPGP keys in releases
(:class:`batzenca.database.releases.Release`). These releases contain active and
inactive keys (:class:`batzenca.database.keys.Key`) one for each user
(:class:`batzenca.database.peers.Peer`). Active are those keys which users ought
to use, while inactive keys are those where the signature was revoked
etc. Releases are meant for specific mailinglists
(:class:`batzenca.database.mailinglists.MailingList`). Each mailinglist
furthermore has a policy (:class:`batzenca.database.policies.Policy`) which
specifies what kind of PGP keys are acceptable - for example, it might specify
that keys must expire every 2 years.

Prerequisites
-------------

* BatzenCA relies on `PyMe <http://bitbucket.org/malb/pyme/>`_ >= 0.9.0 for
  talking to GnuPG.

  Note that an abandoned branch is available which attempts to switch to the
  newer `PyGPGME <https://launchpad.net/pygpgme>`_ is available `on Bitbucket
  <https://bitbucket.org/malb/batzenca/branch/pygpgme>`_. It was abandoned
  because PyGPGME does not provide an interface to all GPGME functions needed by
  BatzenCA.

* BatzenCA uses `SQLAlchemy <http://www.sqlalchemy.org/>`_ to talk to a SQLite
  database which stores all metadata about keys such as users, releases, mailing
  lists, policies etc.

* BatzenCA uses `GitPython
  <https://pythonhosted.org/GitPython/0.3.2/index.html>`_ to take snapshots of
  its database and the internal GnuPG directory.

Installation
------------

The easiest way to install all required Python packages is::

    pip install -r requirements.txt

Alternatives
------------

Alternatives to realising OpenPGP encrypted mailinglists include

* **Schleuder** "Schleuder is a gpg-enabled mailinglist with
  remailer-capabilities. It is designed to serve as a tool for group
  communication: subscribers can communicate encrypted (and pseudonymously)
  among themselves, receive emails from non-subscribers and send emails to
  non-subscribers via the list. Schleuder takes care of all de- and encryption,
  stripping of headers, formatting conversions, etc. Further schleuder can send
  out its own public key upon request and receive administrative commands by
  email." -- http://schleuder2.nadir.org/ Hence, users must trust that the
  server has not been compromised.

* **SELS** "Secure Email List Services (SELS) is an open source software for
  creating and developing secure email list services among user
  communities. SELS provides signature and encryption capabilities while
  ensuring that the List Server does not have access to email plain text. SELS
  has been developed with available open-source components and is compatible
  with many commonly used email clients." -- http://sels.ncsa.illinois.edu/
  However, the project is discontinued.

Full Documentation
------------------

The full documentation of BatzenCA is available at
http://batzenca.readthedocs.org.
