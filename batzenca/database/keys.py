"""
.. module:: keys
 
.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>

Keys represent PGP keys and are typically stored in the database.
"""
from base import Base, EntryNotFound
from sqlalchemy import Column, Integer, String, Date, ForeignKey
from sqlalchemy.ext.associationproxy import association_proxy

import datetime
import warnings

class Key(Base):
    """This class represents a PGP key. Distributing these keys for mailing lists is the purpose of
    this software package. It is also a design goal of this software package that the
    particularities of dealing with the GnuPG backend are hidden behind the functions of this
    class.

    :param keyid: a key id as an integer or a hex string
    :param str name: a username, if ``None`` is given, then it is read from GnuPG
    :param str email: an e-mail address, if ``None`` is given, then it is read from GnuPG
    :param timestamp: the timestamp when this key was created, if ``None`` is given, then it is
      read from GnuPG.

    .. note::

        The returned object was not added to any session.
    """
    __tablename__ = 'keys'

    id        = Column(Integer, primary_key=True)           #: database id
    kid       = Column(String, nullable=False, unique=True) #: 8 byte pgp key id of the form 0x0123456789abcdef
    name      = Column(String)                              #: user id
    email     = Column(String)                              #: email as stored in key
    timestamp = Column(Date)                                #: date it was added to the database
    peer_id   = Column(Integer, ForeignKey("peers.id"))

    releases    = association_proxy('release_associations', 'release') #: a list of releases this key is in

    @staticmethod
    def canonical_keyid(keyid):
        """Convert keyid to canonical representation as a hex string of the last
        64 bits.

        :param keyid: a key id as an integer or a hex string.

        """
        try:
            keyid = "0x%016x"%keyid
        except TypeError:
            pass
        return "0x%016x"%(int(keyid,16) % (1<<64))
    
    def __init__(self, keyid, name=None, email=None, timestamp=None):
        self.kid = Key.canonical_keyid(keyid)

        from batzenca.session import session

        try:
            _ = session.gnupg.key_get(self.kid)
        except KeyError:
            if name is None or email is None or timestamp is None:
                raise ValueError("The key %s does not exist in GnuPG and not enough information was provided for generating Key instance without it."%self.kid)
            self.name      = unicode(name.strip())
            self.email     = str(email.strip())
            self.timestamp = timestamp
            return

        uid = session.gnupg.key_uid(self.kid)

        self.name = uid.name
        self.email = str(uid.email)
        self.timestamp = session.gnupg.key_timestamp(self.kid)

        try:
            Key.from_keyid(self.kid)
            raise ValueError("Key with keyid '%s' already found in database."%self.kid)
        except EntryNotFound:
            pass
            

    @classmethod
    def from_keyid(cls, keyid):
        """Return the key with ``keyid`` from the database. If no such element is found an
        :class:`batzenca.database.base.EntryNotFound` exception is raised. If more than one element is found this is
        considered an inconsistent state of the database and a :class:`RuntimeError` exception is
        raised.

        :param keyid: key id as integer or a hex string

        .. note::

           The returned object was aquired from the master session and lives there.

        """
        keyid = Key.canonical_keyid(keyid)
            
        from batzenca.session import session
        res = session.db_session.query(cls).filter(cls.kid == keyid)

        if res.count() == 0:
            raise EntryNotFound("No key with key id '%s' in database."%keyid)
        else:
            if res.count() > 1:
                raise RuntimeError("More than one key with key id '%s' in database."%keyid)
            return res.first()

    @classmethod
    def from_name(cls, name):
        """Return a key with the given ``name`` from the database. If no such element is found an
        :class:`batzenca.database.base.EntryNotFound` exception is raised. If more than one element
        is found the "first" element is returned, where "first" has no particular meaning. In this
        case a warning is issued. In particular, no guarantee is given that two consecutive runs
        will yield the same result if more than one key has the provided ``name``.

        :param str name: the name the database is queried for
        
        .. note::

           The returned object was aquired from the master session and lives there.

        """
        from batzenca.session import session
        res = session.db_session.query(cls).filter(cls.name == name)

        if res.count() == 0:
            raise ValueError("No key with name '%s' in database."%name)
        else:
            if res.count() > 1:
                warnings.warn("More than one key with name '%s' found, picking first one."%name)
            return res.first()

    @classmethod
    def from_email(cls, email):
        """Return a key with the given ``email`` address from the database.

        If no such key is found an :class:`batzenca.database.base.EntryNotFound` exception is
        raised. If more than one element is found the "first" element is returned, where "first" has
        no particular meaning. In this case a warning is issued. In particular, no guarantee is
        given that two consecutive runs will yield the same result if more than one key has the
        provided ``email`` address.

        You can query the database for the most recent key matching an e-mail address you can call::

            Peer.from_email(email).key

        :param str email: the email the database is queried for
        
        .. note::

           The returned object was aquired from the master session and lives there.

        """
        from batzenca.session import session
        res = session.db_session.query(cls).filter(cls.email == email)

        if res.count() == 0:
            raise EntryNotFound("No key with email '%s' in database."%email)
        else:
            if res.count() > 1:
                warnings.warn("More than one key with email '%s' found, picking first one."%email)
            return res.first()

    @classmethod
    def from_filename(cls, filename):
        """Read the file ``filename`` into GnuPG and construct instances of
        :class:`batzenca.database.keys.Key` for each key contained in the file ``filename``. A tuple
        of :class:`batzenca.database.keys.Key` objects is returned.

        :param str filename: a file name
        
        .. note::

           The returned objects were not added to any session, any keys found in ``filename`` were
           added to the GnuPG database.

        """
        from batzenca.session import session

        with open(filename) as fh:
            data = fh.read()
            res = session.gnupg.keys_import(data)
            if len(res) == 0:
                raise EntryNotFound("No key found in in file '%s'"%filename)
            else:
                ret = []
                for fpr in res.keys():
                    keyid = Key.canonical_keyid(int("0x"+fpr[-16:],16))
                    try:
                        key = Key.from_keyid(keyid)
                    except EntryNotFound:
                        key = Key(keyid)
                    ret.append(key)
                return tuple(ret)

    @classmethod
    def from_str(cls, ascii_data):
        """Read the PGP keys in ``ascii_data`` into GnuPG and construct instances of
        :class:`batzenca.database.keys.Key` for each key contained in ``ascii_data``. A tuple of
        :class:`batzenca.database.keys.Key` objects is returned.

        :param str ascii_data: PGP keys in ASCII format
        
        .. note::
        
           The returned object was not added to any session, any keys found in ``ascii_data`` were
           added to the GnuPG database.

        """
        from batzenca.session import session
        res = session.gnupg.keys_import(ascii_data)
        if len(res) == 0:
            cut = "\n".join(ascii_data.splitlines()[:20])
            raise EntryNotFound("""No key found in in provided string\n\n%s"""%cut)
        else:
            ret = []
            for fpr in res.keys():
                keyid = Key.canonical_keyid( int("0x"+fpr[-16:],16) )
                try:
                    key = Key.from_keyid(keyid)
                except EntryNotFound:
                    key = Key(keyid)
                ret.append(key)
            return tuple(ret)

        
    def __nonzero__(self):
        """Return ``True`` if this key has at least one valid (not revoked, expired or disabled)
        subkey for signing and one valid subkey for encrypting.

        """
        from batzenca.session import session
        return session.gnupg.key_okay(self.kid)

    def is_expired(self):
        """Return ``True`` if all subkeys of this key which can be used for encryption are
        expired.

        """
        from batzenca.session import session
        return session.gnupg.key_expired(self.kid)

    def __str__(self):
        return u"%s: %s <%s>"%(self.kid,self.name,self.email)

    def __repr__(self):
        return "<Key: %s %s>"%(self.kid, self.email)

    def __len__(self):
        from batzenca.session import session
        return session.gnupg.key_min_len(self.kid)

    @property
    def expires(self):
        """Expirey date."""
        from batzenca.session import session
        return session.gnupg.key_expires(self.kid)

    @property
    def fingerprint(self):
        """This key's fingerprint as a string in groups of four."""
        from batzenca.session import session
        s = session.gnupg.key_fingerprint(self.kid)
        return " ".join(s[i:i+4] for i in range(0,len(s),4))

    def __lt__(self, other):
        """A key is smaller than another key if it is older."""
        return self.timestamp < other.timestamp

    def __hash__(self):
        return int(self.kid, 16)

    @property
    def algorithms(self):
        from batzenca.session import session
        return session.gnupg.key_pubkey_algos(self.kid)

    def is_signed_by(self, signer):
        from batzenca.session import session
        return session.gnupg.key_any_uid_is_signed_by(self.kid, signer.kid)

    def sign(self, signer):
        from batzenca.session import session
        session.gnupg.key_sign(self.kid, signer.kid)

    def revoke_signature(self, signer, reason=""):
        from batzenca.session import session
        session.gnupg.key_revsig(self.kid, signer.kid, 4, msg=reason)

    def is_valid(self):
        from batzenca.session import session
        return bool(self) and session.gnupg.key_validity(self.kid) > 0

    def hard_delete(self):
        raise NotImplementedError

    def _edit(self):
        """
        .. warning:

           This will open an interactive session using rawinput
        """
        from batzenca.session import session
        return session.gnupg.key_edit(self.kid)

    def delete_signature(self, signer):
        """Delete all signatures made by ``signer``.

        :param batzenca.database.keys.Key signer: - the signer for which to delete signatures.
        
        .. warning:

           This may open an interactive session using rawinput

        """
        from batzenca.session import session
        try:
            return session.gnupg.key_delete_signature(self.kid, signer.kid)
        except AttributeError:
            return session.gnupg.key_delete_signature(self.kid, signer)

    @property
    def signatures(self):
        """A tuple where each entry represents a key that signed this key. The
        entries are either :class:`batzenca.database.keys.Key` objects - if the
        key is present in the local GnuPG key store - or strings of the key
        id.

        """
        from batzenca.session import session
        keyids = tuple(Key.canonical_keyid( keyid ) for keyid in session.gnupg.key_signatures(self.kid))
        sigs = []
        for keyid in keyids:
            if int(self.kid, 16) == int(keyid,16):
                sigs.append(self)
                continue
            try:
                sigs.append(Key.from_keyid(int(keyid,16)))
            except EntryNotFound:
                sigs.append(keyid)
        return tuple(sigs)

    def clean(self, whitelist=None):
        """Remove all signatures except self-signature and those given in
        whitelist.

        :param iterable whitelist: a list of
            :class:`batzenca.database.keys.Key`,
            :class:`batzenca.database.peers.Peer`,
            :class:`batzenca.database.policies.Policy`,
            :class:`batzenca.database.mailinglists.MailingList`.
            :class:`batzenca.database.releases.Release`.
        """
        from keys import Key
        from peers import Peer
        from mailinglists import MailingList
        from policies import Policy
        from releases import Release

        def extract_key(obj):
            if isinstance(obj, str) or isinstance(obj, unicode):
                return obj
            elif isinstance(obj, Key):
                return obj
            elif isinstance(obj, Peer):
                return obj.Key
            elif isinstance(obj, Policy):
                return obj.ca
            elif isinstance(obj, MailingList):
                return obj.policy.ca
            elif isinstance(obj, Release):
                return obj.policy.ca
            else:
                raise TypeError("Type '%s' of '%s' not understood."%(type(obj),obj))

        if whitelist:
            whitelist = [extract_key(obj) for obj in whitelist]
        else:
            whitelist = []
        whitelist.append(self)

        for signature in set(self.signatures).difference(whitelist):
            self.delete_signature(signature)
        
    @property
    def _pyme_key(self):
        from batzenca.session import session
        return session.gnupg.key_get(self.kid)