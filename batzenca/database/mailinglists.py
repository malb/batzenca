"""
.. module:: mailinglists
 
.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>

Mailing lists is what we do the work for.
"""

from sqlalchemy import Column, Integer, String, Date, ForeignKey, UnicodeText
from sqlalchemy.orm import relationship

from base import Base, EntryNotFound
from releases import Release, ReleaseKeyAssociation
from keys import Key
from peers import Peer

import warnings

class MailingList(Base):
    """This class represents a mailing list. A mailing list is an object which has one or more
    :class:`batzenca.database.releases.Release` objects associationed with it.

    :param str name: the name of this mailing list.
    :param str email: the e-mail address of this mailing list.

    :param policy: an object of type :class:`batzenca.database.policies.Policy` which is applied by
        default to releases

    :param str description: an informal description of this mailing list.

    :param str new_member_msg: this message ought to be sent to peers when they join the list for
      the first time. This message could contain etiquette etc.  This is string supports a limited
      number of template fields which are replaced by the actual values in
      :func:`batzenca.database.releases.Release.welcome_messages`. These fields are:

        ``{peer}`` - the name of the peer

        ``{mailinglist}`` - the name of this mailing list

        ``{mailinglist_email}`` - the email address of the mailing list on which the user is
        subscribed

        ``{ca}`` - the CA's name

        ``{ca_email}`` - the CA's e-mail address
    
    :param str key_update_msg: this message is sent when a new release is published. It typically
      contains a list of all keys associated with this release. For this reason this string supports
      a limited number of template fields which are replaced by the actual values in
      :func:`batzenca.database.releases.Release.publish`. These fields are:
        
        ``{mailinglist}`` - the name of this mailing list
        
        ``{peers_in}`` - a comma-separated list of names
        (:class:`batzenca.database.peers.Peer.name`) which are new in the current release.
        
        ``{peers_changed}`` - a comma-separated list of names
        (:class:`batzenca.database.peers.Peer.name`) which are changed their keys in the current
        release.
        
        ``{peers_out}`` - a comma-separated list of names
        (:class:`batzenca.database.peers.Peer.name`) which left the mailing list in the current
        release.
        
        ``{keys_in}`` - a line-break-separated list of keys (printed using
        :func:`batzenca.database.releases.Release._format_entry`) that joined the mailing list in
        the current release.
        
        ``{keys_out}`` - a line-break-separated list of keys (printed using
        :func:`batzenca.database.releases.Release._format_entry`) that left this mailing list in the
        current release.
        
        ``{keys}`` - a complete line-break-separated list of keys (printed using
        :func:`batzenca.database.releases.Release._format_entry`) in the current release.

        ``{ca}`` - the CA's name

        ``{ca_email}`` - the CA's e-mail address

        ``{dead_man_switch}`` - an optional message stating that no attempts were made to compel the
        CA to compromise the integrity of the list.
    
    :param str key_expiry_warning_msg: this message is sent when a key is about to expire, to warn
      the user about this fact. This is string supports a limited number of template fields which
      are replaced by the actual values in
      :func:`batzenca.database.releases.Release.key_expiry_message`. These fields are:

        ``{peer}`` - the name of the peer

        ``{keyid}`` - the key id of the expiring key

        ``{expiry_date}`` - the expiry date

        ``{mailinglist}`` - the name of the mailing list on which the user is subscribed

        ``{mailinglist_email}`` - the email address of the mailing list on which the user is
        subscribed

        ``{ca_email}`` - the CA's e-mail address

    :param str dead_man_switch_msg: this message is included in
        :attr:`batzenca.database.mailinglists.MailingList.key_update_msg` by
        :func:`batzenca.database.releases.Release.__call__` if the parameter ``still_alive`` is set
        to ``True`` when calling it.

    """

    __tablename__ = 'mailinglists'

    id          = Column(Integer, primary_key=True) 
    name        = Column(String, unique=True, nullable=False)
    email       = Column(String)
    description = Column(UnicodeText)
    new_member_msg         = Column(UnicodeText) # the message we send to a new member
    key_update_msg         = Column(UnicodeText)
    key_expiry_warning_msg = Column(UnicodeText)
    dead_man_switch_msg    = Column(UnicodeText)

    policy_id   = Column(Integer, ForeignKey('policies.id'))
    policy      = relationship("Policy")

    def __init__(self, name, email, policy=None, description='', new_member_msg='', key_update_msg='', key_expiry_warning_msg='', dead_man_switch_msg=''):
        self.name = name
        self.email = email
        self.policy = policy
        self.description = unicode(description)
        self.key_update_msg = unicode(key_update_msg)
        self.new_member_msg = unicode(new_member_msg)
        self.key_expiry_warning_msg = unicode(key_expiry_warning_msg)
        self.dead_man_switch_msg    = unicode(dead_man_switch_msg)

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

    @classmethod
    def all(cls):
        """Return all mailing lists from the database"""
        from batzenca import session
        res = session.db_session.query(MailingList)
        return tuple(res.all())
        
    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)

    @property
    def current_release(self):
        """
        Return the current release.
        """
        try:
            return self.releases[-1]
        except IndexError:
            raise IndexError("The mailing list '%s' has no release yet."%self)
    
    def new_release(self, date=None, inherit=True, deactivate_invalid=True, delete_old_inactive_keys=5):
        """Create a new release for this mailing list.

        If ``inherit == True`` then :func:`batzenca.database.releases.Release.inherit` is called and
        the remaining parameters are passed through. Otherwise a new empty release is created and no
        parameter except for ``date`` would make sense.
        
        :param date: the date of this release. If ``None`` today's date is used
        :param boolean inherit: inherit keys and policy from the currently active release
        :param boolean deactivate_invalid: deactivate keys which are no longer valid, e.g. because
          they are expired. Only applies if ``inherit=True``
        :param boolean delete_old_inactive_keys: delete inactive keys which have been around for a
          while, this parameter is passed to
          :func:`batzenca.database.releases.Release.delete_old_inactive_keys` as ``releasecount``

        .. note::

           If ``inherit == True`` the returned object was added to the main session and is
           associated with this mailing list.

        """
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

        :param obj: either an object of type :class:`batzenca.database.peers.Peer` or
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
            