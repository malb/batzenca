import datetime

import warnings

import sqlalchemy
from sqlalchemy import Column, Integer, String, Date, Boolean, ForeignKey
from sqlalchemy.orm import relationship, backref, Session
from sqlalchemy.ext.associationproxy import association_proxy

from base import Base, EntryNotFound
from peers import Peer
from keys import Key

class ReleaseKeyAssociation(Base):
    """
    """

    __tablename__ = 'releasekeyassociations'

    left_id          = Column(Integer, ForeignKey('keys.id'),     primary_key=True)
    right_id         = Column(Integer, ForeignKey('releases.id'), primary_key=True)
    policy_exception = Column(Boolean)
    is_active        = Column(Boolean)

    key              = relationship("Key", backref=backref("release_associations", cascade="all, delete-orphan", order_by="Release.date") )
    release          = relationship("Release", backref=backref("key_associations", cascade="all, delete-orphan") )

    def __init__(self, key, active=True, policy_exception=False):
        self.key = key
        self.is_active = active
        self.policy_exception = policy_exception

class Release(Base):
    """
    """

    __tablename__ = 'releases'

    id             = Column(Integer, primary_key=True)
    mailinglist_id = Column(Integer, ForeignKey('mailinglists.id'))
    mailinglist    = relationship("MailingList", backref=backref("releases", order_by="Release.date", cascade="all, delete-orphan"))
    date           = Column(Date)

    policy_id      = Column(Integer, ForeignKey('policies.id'))
    policy         = relationship("Policy")

    keys           = association_proxy('key_associations', 'key')

    def __init__(self, mailinglist, date, active_keys, inactive_keys=None, policy=None):
        self.mailinglist = mailinglist

        if date is None:
            date = datetime.date.today()
        self.date = date

        if policy is not None:
            self.policy = policy
        else:
            self.policy = mailinglist.policy

        for key in active_keys:
            self.key_associations.append(ReleaseKeyAssociation(key=key))

        for key in inactive_keys:
            self.key_associations.append(ReleaseKeyAssociation(key=key, active=False))

    @classmethod
    def from_mailinglist_and_date(cls, mailinglist, date):
        from setup import session as session_
        res = session_.query(cls).filter(cls.mailinglist_id == mailinglist.id, cls.date == date)

        if res.count() == 0:
            raise EntryNotFound("No release for mailinglist '%s' with date '%s' in database."%(mailinglist, date))
        else:
            if res.count() > 1:
                warnings.warn("More than one release for mailinglist '%s' with date '%s' in database, picking first one"%(mailinglist, date))
            return res.first()

    def inherit(self, date=None, policy=None, deactivate_invalid=True):
        active_keys   = list(self.active_keys)
        inactive_keys = list(self.inactive_keys)

        if policy is None:
            policy = self.policy
            
        release = Release(mailinglist=self.mailinglist, 
                          date=date, 
                          active_keys = active_keys, 
                          inactive_keys = inactive_keys, 
                          policy=policy)

        if deactivate_invalid:
            release.deactivate_invalid() 

        for key in self.active_keys:
            if self.has_exception(key):
                release.add_exception(key)

        return release

    def verify(self, ignore_exceptions=False):
        for assoc in self.key_associations:
            if assoc.is_active and (ignore_exceptions or not assoc.policy_exception):
                self.policy.check(assoc.key)
    def __repr__(self):
        s = "<Release: %d, %s, %s (%s + %s) keys>"%(self.id, self.date, len(self.key_associations), len(self.active_keys), len(self.inactive_keys))
        return unicode(s).encode('utf-8')
                
    def __str__(self):
        return "release %s for mailinglist '%s' with %d keys (active: %d, inactive: %d)"%(self.date.isoformat(), self.mailinglist, len(self.key_associations), len(self.active_keys), len(self.inactive_keys))

    def print_active_keys(self):
        for key in sorted(self.active_keys):
            print key

    def dump_keys(self):
        from gnupg import gpgobj
        data = gpgobj.keys_export(self.keys)
        return data.read()

    def diff(self, other):
        prev_keys = set(other.active_keys + self.inactive_keys)
        self_keys = set(self.active_keys)
        
        keys_out = prev_keys.difference(self_keys)
        keys_in  = self_keys.difference(prev_keys)

        peers_in  = set([Peer.from_key(key) for key in keys_in ])
        peers_out = set([Peer.from_key(key) for key in keys_out])

        peers_joined  = peers_in.difference(peers_out)
        peers_changed = peers_in.intersection(peers_out)
        peers_left    = peers_out.difference(peers_in)

        return peers_joined, peers_changed, peers_left
    
    def publish(self, previous=None, check=True):

        keys = []

        if check:
            self.verify()

        for i,key in enumerate(sorted(self.active_keys, key=lambda x: x.name.lower())):
            peer = Peer.from_key(key)
            keys.append(u"  %3d. %s %s <%s>"%(i,key.kid, key.name, key.email))
            keys.append(u"       %s - %s %s %s %s"%(peer.name, peer.data0, peer.data1, peer.data2, peer.data3))
        keys = "\n".join(keys)

        if previous is None:
            previous = self.prev

        if previous:
            peers_joined, peers_changed, peers_left = self.diff(previous)
            diff_joined  = ", ".join(peer.name for peer in peers_joined)
            diff_changed = ", ".join(peer.name for peer in peers_changed)
            diff_left    = ", ".join(peer.name for peer in peers_left)
        else:
            diff_joined  = ""
            diff_changed = ""
            diff_left    = ""
        return self.mailinglist.key_update_msg.format(mailinglist=self.mailinglist.name, keys=keys,
                                                      diff_joined=diff_joined, diff_changed=diff_changed, diff_left=diff_left)

    @property
    def active_keys(self):
        if self.id is None:
            return [assoc for assoc in self.key_associations if assoc.is_active]
        from setup import session as session_
        return session_.query(Key).join(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.is_active == True).all()

    @property
    def inactive_keys(self):
        if self.id is None:
            return [assoc for assoc in self.key_associations if not assoc.is_active]
        from setup import session as session_
        return session_.query(Key).join(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.is_active == False).all()

    def deactivate_invalid(self):
        for assoc in self.key_associations:
            if assoc.is_active and not assoc.key.is_valid():
                assoc.is_active = False

    def _get_assoc(self, key):
        if key.id is None or self.id is None:
            for assoc in self.key_associations:
                if assoc.key is key and assoc.release is self:
                    return assoc
            raise ValueError("Key '%s' is not in release '%s'"%(key, self))

        from setup import session as session_
        res = session_.query(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.left_id == key.id, ReleaseKeyAssociation.right_id == self.id)
        if res.count() > 1:
            raise RuntimeError("The key '%s' is associated with the release '%' more than once; the database is in an inconsistent state."%(key, self))
        if res.count() == 0:
            raise ValueError("Key '%s' is not in release '%s'"%(key, self))
        return res.first()

    def add_exception(self, key):
        assoc = self._get_assoc(key)
        assoc.policy_exception = True

    def has_exception(self, key):
        assoc = self._get_assoc(key)
        return assoc.policy_exception

    def is_active(self, key):
        assoc = self._get_assoc(Key)
        return assoc.is_active

    def update_key_from_peer(self, peer):
        raise NotImplementedError

    def add_key(self, key, active=True, check=True):
        if check and active:
            self.policy.check(key)

        self.key_associations.append(ReleaseKeyAssociation(key=key, active=active))

    def __contains__(self, obj):
        from setup import session as session_


        if self.id is None:
            raise RuntimeError("The object '%s' was not committed to the database yet, we cannot issue queries involving its id yet."%self)

        try:
            if obj.id is None:
                raise RuntimeError("The object '%s' was not committed to the database yet, we cannot issue queries involving its id yet."%self)
        except AttributeError:
            raise TypeError("Cannot handle objects of type '%s'"%type(obj))

        if isinstance(obj, Key):
            res = session_.query(Key).join(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.left_id == obj.id, ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.left_id.is_active == True)
            if res.count() == 0:
                return False
            elif res.count() == 1:
                return True
            else:
                raise RuntimeError("The key '%s' is associated with the release '%' more than once; the database is in an inconsistent state."%(obj, self))
            
        elif isinstance(obj, Peer):
            res = session_.query(Peer).join(Key).join(ReleaseKeyAssociation).filter(Key.peer_id == obj.id, ReleaseKeyAssociation.left_id == Key.id, ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.left_id.is_active == True)
            if res.count() == 0:
                return False
            elif res.count() == 1:
                return True
            else:
                raise RuntimeError("The peer '%s' is associated with the release '%' more than once; the database is in an inconsistent state."%(obj, self))
        else:
            raise TypeError("Cannot handle objects of type '%s'"%type(obj))

    @property
    def prev(self):
        idx = self.mailinglist.releases.index(self)
        if idx > 0:
            return self.mailinglist.releases[idx-1]
        else:
            return None
