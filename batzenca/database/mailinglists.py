from sqlalchemy import Column, Integer, String, Date, ForeignKey, UnicodeText
from sqlalchemy.orm import relationship

from base import Base, EntryNotFound
from releases import Release, ReleaseKeyAssociation
from keys import Key

import warnings

class MailingList(Base):
    """
    """

    __tablename__ = 'mailinglists'

    id          = Column(Integer, primary_key=True) 
    name        = Column(String, unique=True, nullable=False)
    email       = Column(String)
    description = Column(UnicodeText)
    new_member_msg = Column(UnicodeText) # the message we send to a new member
    key_update_msg = Column(UnicodeText)

    policy_id   = Column(Integer, ForeignKey('policies.id'))
    policy      = relationship("Policy")

    def __init__(self, name, email, policy=None, description=None,  new_member_msg=None, key_update_msg=None):
        self.name = name
        self.email = email
        self.policy = policy
        self.description = unicode(description)
        self.key_update_msg = unicode(key_update_msg)
        self.new_member_msg = unicode(new_member_msg)

    @classmethod
    def from_name(cls, name):
        from batzenca.session import session
        res = session.db_session.query(cls).filter(cls.name == name)
        if res.count() == 0:
            raise EntryNotFound("No mailinglist with name '%s' found in database."%name)
        else:
            if res.count() > 1:
                warnings.warn("More than one mailinglist with name '%s' found, picking first one."%name)
            return res.first()
                
    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)

    @property
    def current_release(self):
        return self.releases[-1]
    
    def new_release(self, date=None, inherit=True, deactivate_invalid=True, delete_old_inactive_keys=True):
        if inherit is True:
            return self.current_release.inherit(date=date, deactivate_invalid=deactivate_invalid, delete_old_inactive_keys=delete_old_inactive_keys)
        elif inherit:
            if inherit.mailinglist is not self:
                raise ValueError("Cannot inherit from release '%s' because it is for '%s' instead of '%s'."%(inherit, inherit.mailinglist, self))
            return inherit.inherit(date=date, deactivate_invalid=deactivate_invalid, delete_old_inactive_keys=delete_old_inactive_keys)
        else:
            return Release(mailinglist=self, date=date, active_keys=[], inactive_keys=[], policy=self.policy)

    def __contains__(self, obj):
        """Return ``True`` if ``obj`` was ever in any release for this mailing list.

        INPUT:

        - ``obj`` - either an object of type :class:`batzenca.database.peers.Peer` or
          :class:`batzenca.database.keys.Key`

        """
        from batzenca.session import session
        from sqlalchemy.sql import or_
        
        query = session.db_session.query(Release).filter(Release.mailinglist == self)
        query = query.join(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.right_id == Release.id)
        query = query.join(Key)

        if isinstance(obj, Peer):
            q = [ReleaseKeyAssociation.left_id == key.id for key in obj.keys]
            query = query.filter(or_(*q))
        elif isinstance(obj, Key):
            query = query.filter(ReleaseKeyAssociation.left_id == obj.id)
        else:
            raise TypeError("Object of type '%s' passed, but only types `Peer` and `Key` are supported."%(type(obj)))
            
        if query.first() is not None:
            return True
        else:
            return False
            