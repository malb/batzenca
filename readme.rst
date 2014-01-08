Batzenca is a set of Python of classes and function that ought to make managing OpenPGP keys
easier for certification authorities.

User-Case
---------

A group of users want to discuss on a mailing list but with OpenPGP encrypted messages. They don't
want the server to be able to decrypt their messages either. An easy ad-hoc way of accomplishing
this is by every user encrypting to every other user. This can easily accomplished using
e.g. Thunderbird/Enigmail's "Per-Recipient Rules".

As the group grows, verifying each other's OpenPGP keys becomes tedious. Our group of users choose
not to use the `Web of Trust <https://en.wikipedia.org/wiki/Web_of_trust>`_, say because they have a
clear definition who belongs on their list and who doesn't. Instead, they nominate a user or a group
of users as a `Certification Authority <https://en.wikipedia.org/wiki/Certification_Authority>`_
(CA), so they are actually doing the `X.509 <https://en.wikipedia.org/wiki/X.509>`_ thing with
OpenPGP: all users verify the CA's key and grant it full `owner trust
<http://gnutls.org/openpgp.html>`_. The CA then checks new user's identities, verifies their keys,
signs and distributes them. When users leave the group the CA revokes its signature. To update the
users of our mailing list the CA sends (ir)regular "releases" which contain all keys for those users
active on our mailing list. The remaining users import these keys and to update their per-recipient
rules to reflect these changes. In a nutshell: a poor person's CA using OpenPGP.

This library makes the job of the CA easier by providing means to prepare such releases.

Library Overview
----------------

The purpose of this library is to distribute OpenPGP keys in releases
(:class:`batzenca.database.releases.Release`). These releases contain active and inactive keys
(:class:`batzenca.database.keys.Key`) one for each user
(:class:`batzenca.database.peers.Peer`). Active are those keys which users ought to use, while
inactive keys are those where the signature was revoked etc. Releases are meant for specific
mailinglists (:class:`batzenca.database.mailinglists.MailingList`). Each mailinglist furthermore has
a policy (:class:`batzenca.database.policies.Policy`) which specifies what kind of PGP keys are
acceptable - for example, it might specify that keys must expire every 2 years.

Prerequisites
-------------

Batzenca relies on `PyMe <http://pyme.sourceforge.net/>`_ for talking to GnuPG. However, this
project appears to be dead and public-key export is broken in PyMe. Hence, the following patch needs
to be applied in order to use batzenca with PyMe

.. code-block:: diff

    diff -r 33a2029ded81 gpgme.i
    --- a/gpgme.i	Thu Sep 12 21:16:30 2013 +0200
    +++ b/gpgme.i	Thu Sep 12 22:11:43 2013 +0200
    @@ -75,11 +75,11 @@
     }
     %}
     
    -%typemap(arginit) gpgme_key_t recp[] {
    +%typemap(arginit) gpgme_key_t [] {
       $1 = NULL;
     }
     
    -%typemap(in) gpgme_key_t recp[] {
    +%typemap(in) gpgme_key_t [] {
       int i, numb = 0;
       if (!PySequence_Check($input)) {
         PyErr_Format(PyExc_ValueError, "arg %d: Expected a list of gpgme_key_t",
    @@ -104,7 +104,7 @@
         $1[numb] = NULL;
       }
     }
    -%typemap(freearg) gpgme_key_t recp[] {
    +%typemap(freearg) gpgme_key_t [] {
       if ($1) free($1);
     }
     
Alternatively, you can check out the "fixes" branch of https://bitbucket.org/malb/pyme/

An abandoned branch is available which attempts to switch to the newer `PyGPGME
<https://launchpad.net/pygpgme>`_ is available `on Bitbucket
<https://bitbucket.org/malb/batzenca/branch/pygpgme>`_. It was abandoned because PyGPGME does not
provide an interface to all GPGME functions needed by batzenca.

Alternatives
------------

Alternatives to realising OpenPGP encrypted mailinglists include

* **Schleuder** "Schleuder is a gpg-enabled mailinglist with remailer-capabilities. It is designed
  to serve as a tool for group communication: subscribers can communicate encrypted (and
  pseudonymously) among themselves, receive emails from non-subscribers and send emails to
  non-subscribers via the list. Schleuder takes care of all de- and encryption, stripping of
  headers, formatting conversions, etc. Further schleuder can send out its own public key upon
  request and receive administrative commands by email." -- http://schleuder2.nadir.org/ Hence,
  users must trust that the server has not been compromised.

* **SELS** "Secure Email List Services (SELS) is an open source software for creating and
  developing secure email list services among user communities. SELS provides signature and
  encryption capabilities while ensuring that the List Server does not have access to email plain
  text. SELS has been developed with available open-source components and is compatible with many
  commonly used email clients." -- http://sels.ncsa.illinois.edu/ However, the project is
  discontinued.
