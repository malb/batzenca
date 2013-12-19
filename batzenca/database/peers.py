"""
.. module:: peers
 
.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>

Peers are people, typically.
"""
from base import Base, EntryNotFound
from keys import Key

from sqlalchemy import Column, Integer, String, Date, Boolean, ForeignKey, UnicodeText, BigInteger
from sqlalchemy.orm import relationship, backref

import warnings

class Peer(Base):
    """This class represents a peer which participates in mailing lists. Typically, a peer
    represents a person which has one or many PGP keys associated with her.

    :param str name: the name of the peer
    :param keys: an instance of :class:`batzenca.database.keys.Key` or a list of such instances
    :param str data0: arbitrary data
    :param str data1: arbitrary data
    :param str data2: arbitrary data
    :param str data3: arbitrary data

    .. note::

       The returned object was not added to any session.
    """
    __tablename__ = 'peers'

    id    = Column(Integer, primary_key=True) #: database id
    name  = Column(String, nullable=False) #: the peer's name
    keys  = relationship('Key', backref=backref('peer'), order_by=Key.timestamp) #: a list of all keys associated with this peer

    data0 = Column(String) #: free form data associated with this peer
    data1 = Column(String) #: free form data associated with this peer
    data2 = Column(String) #: free form data associated with this peer
    data3 = Column(String) #: free form data associated with this peer

    def __init__(self, name, keys, data0='', data1='', data2='', data3=''):
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
        """Merge the two peers ``left`` and ``right`` into a new peer.

        :param batzenca.database.peers.Peer left: first peer
        :param batzenca.database.peers.Peer right: second peer
        
        We favour ``left`` over ``right``. That is, if ``name``, ``email`` or ``dataX`` is set for
        ``left``, we pick this data even if these fields are set in ``right`` as well.
        
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
        """Return the peer associatied with ``key`` in the database.

        :param batzenca.database.keys.Key key: the key to query for
        
        :raises batzenca.database.base.EntryNotFound: when no entry is found
        :raises RuntimeError: if more than one element is found as this is considered an
            inconsistent state of the database

        .. note::

           The returned object was aquired from the master session and lives there.

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
        """Return a peer with the given ``name`` from the database.  If more than one element is
        found the "first" element is returned, where "first" has no particular meaning and is
        implementation specific.  In this case a warning is issued.

        :param str name: the name we are looking for

        :raises batzenca.database.base.EntryNotFound: when no entry is found

        .. note::

           The returned object was aquired from the master session and lives there.

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
        """Return a peer with the given ``email`` address from the database. A peer is defined to
        have an e-mail address associated with it, if any of the keys associated with it are for
        said e-mail address.

        If more than one element is found the "first" element is returned, where "first" has no
        particular meaning and is implementation specific.  In this case a warning is issued.

        :param str email: the email address we are looking for

        :raises batzenca.database.base.EntryNotFound: when no entry is found
        
        .. note::

           The returned object was aquired from the master session and lives there.

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
        data = (self.data0, self.data1, self.data2, self.data3)
        data = u", ".join(d for d in data if d)
        if data:
            return u"%s - %s"%(self.name, data)
        else:
            return u"%s"%self.name

    def __hash__(self):
        return hash((self.name, self.data0, self.data1, self.data2, self.data3))

    @property
    def key(self):
        """Return the most recent active key associated with this peer."""
        keys = sorted(self.keys, reverse=True)
        for key in keys:
            if key:
                return key
        return keys[0]

    @property
    def email(self):
        """ Return the e-mail address associated to the most rcent active key associated with this peer."""
        return str(self.key.email)
        
def merge_peers(left, right):
    """Wrapper around :func:`batzenca.database.peers.Peer.merge` which modifies the master session.

    :func:`batzenca.database.peers.Peer.merge` does not modify the master session in any way, but
    this function deletes both ``left`` and ``right`` and adds the result of
    :func:`batzenca.database.peers.Peer.merge`. This result is also returned.

    :param batzenca.database.peers.Peer left: the first peer
    :param batzenca.database.peers.Peer right: the second peer
    
    .. note ::

         Changes to the master session are not committed.

    """
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
