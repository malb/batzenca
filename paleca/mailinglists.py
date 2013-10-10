from sqlalchemy import Column, Integer, String, Date, ForeignKey, UnicodeText
from sqlalchemy.orm import relationship

from base import Base, EntryNotFound
from releases import Release

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
        self.new_member_msg = unicode(key_update_msg)

    @classmethod
    def from_name(cls, name):
        from setup import session as session_
        res = session_.query(cls).filter(cls.name == name)
        if res.count() == 0:
            raise EntryNotFound("No mailinglist with name '%s' found in database."%name)
        else:
            if res.count() > 1:
                warnings.warn("More than one mailinglist with name '%s' found, picking first one."%name)
            return res.first()
                
    def add_release(self, release):
        assert(release.mailinglist is self)
        self.releases.append(release)

    def __str__(self):
        return self.name

    @property
    def current_release(self):
        return self.releases[-1]
    
    def new_release(self, date=None, inherit=True, deactivate_invalid=True):
        if inherit is True:
            return self.current_release.inherit(date=date, deactivate_invalid=deactivate_invalid)
        elif inherit:
            if inherit.mailinglist is not self:
                raise ValueError("Cannot inherit from release '%s' because it is for '%s' instead of '%s'."%(inherit, inherit.mailinglist, self))
            return inherit.inherit(date=date, deactivate_invalid=deactivate_invalid)
        else:
            return Release(mailinglist=self, date=date, keys=[], policy=self.policy)
