Example
=======

We give a minimal example to get started.

The CA Key
----------

We create a key (:class:`batzenca.database.keys.Key`) for the Certification Authority (CA). First,
we generate the GnuPG key::

    >>> from batzenca import *   
    >>> session.gnupg.import_secret_key("filename.sec") # not implemented yet, use gpg directly

Alternatively, we can generate a fresh secret key for the CA::

    >>> from batzenca.util import import_secret_key
    >>> session.gnupg.generate_secret_key() # not implemented yet, use gpg directly

The Policy
----------

Now, we create is a policy (:class:`batzenca.database.policies.Policy`) which specifies constraints
on keys on our mailing list. In our case keys must have at least 2048 bits, we only accept RSA and
keys must expire within 720 days of creation::

    >>> import datetime
    >>> algorithms = (session.gnupg.GPGME_PK_RSA,)
    >>> policy = Policy("main policy", datetime.date(2014,1,1), ca=ca, 2048, 720, algorithms)

The Mailing List
----------------

We can now create a mailing list object
(:class:`batzenca.database.mailinglists.MailingList`). Mailing lists have few message templates
attached to it. In particular, a message (template) may be provided which is sent when a new user
(:class:`batzenca.database.peers.Peer`) joins the list
(:attr:`batzenca.database.mailinglists.MailingList.new_member_msg`) which is rendered by
:func:`batzenca.database.releases.Release.welcome_messages`::

    Hello {peer},
    
    you are now subscribed to {mailinglist} <{mailinglist_email}>.

    Best regards,
    {ca} <{ca_email}>


Secondly, we need a message (:attr:`batzenca.database.mailinglists.MailingList.key_update_msg`)
template for actual releases (:class:`batzenca.database.releases.Release`) of bundles of keys
(:class:`batzenca.database.keys.Key`) which is rendered by
:func:`batzenca.database.releases.Release.__call__`::

   Hello {mailinglist},

   Users
   -----

   The following people joined:

   {peers_in}

   The following people have a new key:

   {peers_changed}

   The following people have left this list:

   {peers_out}

   Keys
   ----

   The following keys are new:

   {keys_in}

   The following keys are no longer to be used:

   {keys_out}

   The complete list of all keys to be used is:

   {keys}

   {dead_man_switch}

   Best regards,
   {ca} <{ca_email}>

For the meaning of these fields see (:class:`batzenca.database.mailinglists.MailingList`). Note,
that the he expansion of ``{peers_in}`` and ``{peers_out}`` is a comma separated list of peers,
while ``{keys*}`` is structured by line breaks.

Thirdly, a message template can be provided which is turned into a message sent to users when their
keys are about to expire by :func:`batzenca.database.releases.Release.key_expiry_warning_messages`::

    Hello {peer},

    your key with key id {keyid} is going to expire on {expiry_date}.

    This key is used to encrypt messages for you on {mailinglist} <{mailinglist_email}>.

    Please provide a new key to continue receiving messages on this list.

    Best regards,
    {ca} <{ca_email}>

Finally, a dead man switch message may be provided. This message is used to replace the field
``{dead_man_switch}`` in :attr:`batzenca.database.mailinglists.MailingList.key_update_msg` if
``still_alive = True`` when calling :func:`batzenca.database.releases.Release.__call__`::

    This CA has not received any requests to disclose and/or modify any data for this
    mailinglist. Watch this space for this message to disappear.

With these in place, we can construct our :class:`batzenca.database.mailinglists.MailingList` object
(split over multiple lines for readability)::

    >>> ml = MailingList(name="batzenca", email="batzenca@thereisnohost.thereisnodomain", policy=policy)
    >>> ml.new_member_msg = new_member_msg
    >>> ml.key_update_msg = key_update_msg
    >>> ml.key_expiry_warning_msg = dead_man_switch_msg
    >>> ml.dead_man_switch_msg = dead_man_switch_msg

The Peers
---------

Users can have multiple keys over time. This is addressed by creating
:class:`batzenca.database.peers.Peer` objects which point to all the keys of a particular user::

    >>> keys = Key.from_filename("hansolo.asc")
    >>> keys[0].sign(ca)
    >>> han = Peer("Han Solo", keys)

The Releases
------------

Finally, we can create an actual release (:class:`batzenca.database.releases.Release`) which is what
we send out to our users::

    >>> rel = ml.new_release()
    >>> rel.add_key(han.key)

The Database
------------

Nothing what we've done so far was added to the database, except for the operations with GnuPG. To
add our objects (keys, peers, mailing lists, releases) to the database we have to add it::

    >>> session.add(ml)

We only need to add our mailing list as it points to all other objects created so far and ``add``
automatically cascades. However, this still isn't persisent. We need to commit our changes to the database::

   >>> session.commit()
