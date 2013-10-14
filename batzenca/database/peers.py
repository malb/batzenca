from base import Base, EntryNotFound
from keys import Key

from sqlalchemy import Column, Integer, String, Date, Boolean, ForeignKey, UnicodeText, BigInteger
from sqlalchemy.orm import relationship, backref

import warnings

class Peer(Base):
    """
    """
    __tablename__ = 'peers'

    id    = Column(Integer, primary_key=True)
    name  = Column(String, nullable=False)
    keys  = relationship('Key', backref=backref('peer'), order_by=Key.timestamp)

    data0 = Column(String)
    data1 = Column(String)
    data2 = Column(String)
    data3 = Column(String)

    def __init__(self, name, keys, data0='', data1='', data2='', data3=''):
        """
        .. note::

           The returned object was not added to any session.
        """
        self.name = name
        if isinstance(keys, Key):
            self.keys = [keys]
        else:
            self.keys = keys

        self.data0 = unicode(data0)
        self.data1 = unicode(data1)
        self.data2 = unicode(data2)
        self.data3 = unicode(data3)

    @classmethod
    def merge(cls, left, right):
        """
        We favour left over right.

        .. note::

           The returned object was not added to any session.
        """
        name = left.name
        keys = set(left.keys).union(right.keys)
        data0 = left.data0 if left.data0 else right.data0
        data1 = left.data1 if left.data1 else right.data1
        data2 = left.data2 if left.data2 else right.data2
        data3 = left.data3 if left.data3 else right.data3

        # calling session.delete and session.add doesn't seem right, call merge_peers function for
        # this.

        return Peer(name, list(keys), data0, data1, data2, data3)

    @classmethod
    def from_key(cls, key):
        """
        .. note::

           The returned object was queried from the main session and lives there.
        """
        from batzenca.session import session
        res = session.db_session.query(cls).join(Key).filter(Key.kid == key.kid)

        if res.count() == 0:
            raise EntryNotFound("No peer matching key '%s' in database."%key)
        else:
            if res.count() > 1:
                raise RuntimeError("More than one peer associated with key '%s'."%key)
            return res.first()

    @classmethod
    def from_name(cls, name):
        """
        .. note::

           The returned object was queried from the main session and lives there.
        """
        from batzenca.session import session
        res = session.db_session.query(cls).filter(cls.name == name)

        if res.count() == 0:
            raise EntryNotFound("No peer with name '%s' in database."%name)
        else:
            if res.count() > 1:
                warnings.warn("More than one peer with name '%s' found, picking first one."%name)
            return res.first()

    @classmethod
    def from_email(cls, email):
        """
        .. note::

           The returned object was queried from the main session and lives there.
        """
        from batzenca.session import session
        res = session.db_session.query(Peer).join(Key).filter(Key.peer_id == Peer.id, Key.email == email)

        if res.count() == 0:
            raise EntryNotFound("No peer with email '%s' in database."%email)
        else:
            if res.count() > 1 and len(res.all()) > 1: # we might find two keys but only one peer
                warnings.warn("More than one peer with email '%s' found, picking first one."%email)
            return res.first()

    def __repr__(self):
        return unicode(u"<Peer: %s, %s>"%(self.id, self.name)).encode('utf-8')

    def __str__(self):
        return unicode(self).encode('utf-8')
        
    def __unicode__(self):
        data = u", ".join( (self.data0, self.data1, self.data2, self.data3) )
        if data:
            return u"%s (%s)"%(self.name, data)
        else:
            return u"%s"%self.name

    def __hash__(self):
        return hash((self.name, self.data0, self.data1, self.data2, self.data3))

    @property
    def key(self):
        keys = sorted(self.keys, reverse=True)
        for key in keys:
            if key:
                return key
        return keys[0]

    @property
    def email(self):
        return str(self.key.email)
        
def merge_peers(left, right):
    from batzenca.session import session
    if isinstance(left, int):
        left = session.db_session.query(Peer).filter(Peer.id == left)

    if isinstance(right, int):
        right = session.db_session.query(Peer).filter(Peer.id == right)

    merged = Peer.merge(left, right)
    session.db_session.add(merged)
    session.db_session.delete(left)
    session.db_session.delete(right)
    return merged


def find_duplicates():
    from batzenca.session import session
    peers = session.db_session.query(Peer).all()
    email_addresses = set()
    for peer in sorted(peers, key=lambda x: x.name):
        print u"%20s %s"%(peer.name, peer.email)


