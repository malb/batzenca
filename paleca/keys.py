from base import Base, EntryNotFound
from sqlalchemy import Column, Integer, String, Date, ForeignKey
from sqlalchemy.orm import Session

import datetime
import warnings

class Key(Base):
    """
    """

    __tablename__ = 'keys'

    id          = Column(Integer, primary_key=True)           # database id
    kid         = Column(String, nullable=False, unique=True) # 8 byte pgp key id of the form 0x0123456789abcdef
    name        = Column(String)                              # user id
    email       = Column(String)                              # email as stored in key
    date_added  = Column(Date)                                # date it was added to the database
    peer_id     = Column(Integer, ForeignKey("peers.id"))     # points to the peer this key belongs to

    def __init__(self, kid, name=None, email=None, date_added=None):
        self.kid = "0x%016x"%kid

        from gnupg import gpgobj
        if not gpgobj.key_exists(self.kid):
            if name is None or email is None:
                raise ValueError("The key %s does not exist in GnuPG and not enough information was provided for generating Key instance without it."%self.kid)
            self.name      = name.strip()
            self.email      = email.strip() # TODO: perform e-mail validation
            if date_added is None:
                date_added = datetime.date.today()
            self.date_added = date_added
            return

        uid = gpgobj.key_uid(self.kid)

        self.name = uid.name
        self.email = uid.email
        
        if date_added is None:
            self.date_added = datetime.date.today()

    @classmethod
    def from_keyid(cls, kid):
        """
        Query the database for key id kid.

        INPUT:

        - ``kid`` - key id as integer or string in hexadecimal format
        """
        try:
            kid = "0x%016x"%kid
        except TypeError:
            pass
        from setup import session as session_
        res = session_.query(cls).filter(cls.kid == kid)

        if res.count() == 0:
            raise EntryNotFound("No key with key id '%s' in database."%kid)
        else:
            if res.count() > 1:
                raise RuntimeError("More than one key with key id '%s' in database."%kid)
            return res.first()

    @classmethod
    def from_name(cls, name):
        "Query the database for name"
        from setup import session as session_
        res = session_.query(cls).filter(cls.name == name)

        if res.count() == 0:
            raise ValueError("No key with name '%s' in database."%name)
        else:
            if res.count() > 1:
                warnings.warn("More than one key with name '%s' found, picking first one."%name)
            return res.first()

    @classmethod
    def from_email(cls, email):
        from setup import session as session_
        res = session_.query(cls).filter(cls.email == email)

        if res.count() == 0:
            raise EntryNotFound("No key with email '%s' in database."%email)
        else:
            if res.count() > 1:
                warnings.warn("More than one key with email '%s' found, picking first one."%email)
            return res.first()

    @classmethod
    def from_file(cls, filename):
        raise NotImplementedError
        
    def is_valid(self):
        from gnupg import gpgobj
        return gpgobj.key_valid(self.kid)

    def is_expired(self):
        from gnupg import gpgobj
        return gpgobj.key_expired(self.kid)

    def __str__(self):
        return u"%s: %s <%s>"%(self.kid,self.name,self.email)

    def __repr__(self):
        return "<Key: %s>"%(self.kid)

    def __len__(self):
        from gnupg import gpgobj
        return gpgobj.key_min_len(self.kid)

    def expires(self):
        from gnupg import gpgobj
        return gpgobj.key_expires(self.kid)

    def creation_date(self):
        from gnupg import gpgobj
        return gpgobj.key_timestamp(self.kid)

    def is_signed_by(self, signer):
        from gnupg import gpgobj
        return gpgobj.key_any_uid_is_signed_by(self.kid, signer.kid)

    def __lt__(self, other):
        return self.creation_date() < other.creation_date()

    def __hash__(self):
        return int(self.kid, 16)

    @property
    def algorithms(self):
        from gnupg import gpgobj
        return gpgobj.key_pubkey_algos(self.kid)

    def sign(self, signer):
        raise NotImplementedError

    def hard_delete(self):
        raise NotImplementedError
