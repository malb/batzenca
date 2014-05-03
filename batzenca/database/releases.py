"""Releases are bundles of objects of type :class:`batzenca.database.keys.Key` for a given
:class:`batzenca.database.mailinglists.MailingList`. "Making releases" is what this library is for.

.. module:: releases

.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>

"""
import os
import datetime

import warnings
import codecs

import sqlalchemy
from sqlalchemy import Column, Integer, String, Date, Boolean, ForeignKey
from sqlalchemy.orm import relationship, backref, Session
from sqlalchemy.ext.associationproxy import association_proxy

from base import Base, EntryNotFound
from peers import Peer
from keys import Key

class ReleaseKeyAssociation(Base):
    __tablename__ = 'releasekeyassociations'

    left_id          = Column(Integer, ForeignKey('keys.id'),     primary_key=True)
    right_id         = Column(Integer, ForeignKey('releases.id'), primary_key=True)
    policy_exception = Column(Boolean)
    is_active        = Column(Boolean)

    key              = relationship("Key", backref=backref("release_associations", cascade="all, delete-orphan") )
    release          = relationship("Release", backref=backref("key_associations", cascade="all, delete-orphan") )

    def __init__(self, key, active=True, policy_exception=False):
        self.key = key
        self.is_active = active
        self.policy_exception = policy_exception

class Release(Base):
    """Releases are bundles of objects of type :class:`batzenca.database.keys.Key`.

    Releases contain active and inactive keys. The former are keys users are expected to use. The
    latter inform the user about invalidated keys for example by revoked signatures.
    
    :param batzenca.database.mailinglists.MailingList mailinglist: the mailinglist for which this release
        is intended
    :param date: the date of this release
    :param iterable active_keys: keys distributed in this release that user ought to use
    :param iterable inactive_keys: keys which are not active in this release, yet should be
        distributed. For example, this could include keys with revocation signatures which are
        distributed to inform users about this revocation.
    :param batzenca.database.policies.Policy policy: the policy against which keys in this release
        should be checked

    """
    __tablename__ = 'releases'

    id             = Column(Integer, primary_key=True)
    mailinglist_id = Column(Integer, ForeignKey('mailinglists.id'))
    mailinglist    = relationship("MailingList", backref=backref("releases", order_by="Release.date", cascade="all, delete-orphan"))
    date           = Column(Date)
    published      = Column(Boolean)

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

        self.published = False

    @classmethod
    def from_mailinglist_and_date(cls, mailinglist, date):
        """Return the release on ``mailinglist`` for ``date`` from the database.  If more than one
        element is found the "first" element is returned, where "first" has no particular meaning
        and is implementation specific.  In this case a warning is issued.

        
        :param batzenca.database.mailinglists.MailingList mailinglist: the mailinglist on which the
            target release was released
        :param date: the date on which the target release was released
        
        :raises batzenca.database.base.EntryNotFound: when no entry is found

        .. note::

           The returned object was aquired from the master session and lives there.

        """
        from batzenca.session import session
        res = session.db_session.query(cls).filter(cls.mailinglist_id == mailinglist.id, cls.date == date)

        if res.count() == 0:
            raise EntryNotFound("No release for mailinglist '%s' with date '%s' in database."%(mailinglist, date))
        else:
            if res.count() > 1:
                warnings.warn("More than one release for mailinglist '%s' with date '%s' in database, picking first one"%(mailinglist, date))
            return res.first()

    def inherit(self, date=None, policy=None, deactivate_invalid=True, delete_old_inactive_keys=5):
        """Construct a new release by inheritance from this release. Inheritance means that active
        and inactive keys are carried forward.
        
        :param date: the date of this release. If ``None`` today's date is used
        :param boolean deactivate_invalid: deactivate keys which are no longer valid, e.g. because
          they are expired.
        :param boolean delete_old_inactive_keys: delete inactive keys which have been around for a
          while, this parameter is passed to
          :func:`batzenca.database.releases.Release.delete_old_inactive_keys` as
          ``releasecount``.

        """
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
        if delete_old_inactive_keys:
            release.delete_old_inactive_keys(delete_old_inactive_keys)
            
        for key in self.active_keys:
            if self.has_exception(key):
                release.add_exception(key)

        return release

    def verify(self, ignore_exceptions=False):
        """Check if all active keys in this release pass the policy check.

        :param boolean ignore_exceptions: keys may have a policy exception which means that they
           pass this test even though they do violate the policy. By default active keys with an
           existing policy exception are ignored. If ``True`` these keys are checked as well.

        """
        for assoc in self.key_associations:
            if assoc.is_active and (ignore_exceptions or not assoc.policy_exception):
                self.policy.check(assoc.key)

    def __repr__(self):
        s = "<Release: %s, %s (%s), %s (%s + %s) keys>"%(self.id, self.date, self.mailinglist, len(self.key_associations), len(self.active_keys), len(self.inactive_keys))
        return unicode(s).encode('utf-8')
                
    def __str__(self):
        from batzenca.database.policies import PolicyViolation
        inact_no_sig = 0
        inact_expired = 0
        policy = self.policy
        for key in self.keys:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", PolicyViolation)
                if policy.check_ca_signature(key) == False:
                    inact_no_sig += 1
                    continue

            if key.expires and key.expires < self.date:
                inact_expired += 1
                continue

        return "date: %10s, list: %10s, policy date: %10s, active keys: %3d, inactive keys: %2d (expired: %2d, not signed: %2d), total keys: %3d"%(self.date, self.mailinglist.name, self.policy.implementation_date,
                                                                                                                                                   len(self.active_keys), len(self.inactive_keys), inact_expired, inact_no_sig, len(self.keys))

    @property
    def ascii_keys(self):
        """All active and inactive keys in this release as OpenPGP ASCII text"""
        from batzenca.session import session
        return session.gnupg.keys_export([key.kid for key in self.keys])

    def diff(self, other=None):
        """Compare this release with ``other``.

        :param batzenca.database.releases.Release other: the release to compare
            against, if ``None`` then ``self.prev`` is chosen
        
        :return: this function returns five tuples:

        - ``keys_in`` - keys that are active in this release but are not active in ``other``
        - ``keys_out`` - all keys that are either active or inactive in ``other`` but are not active
          in this release.
        - ``peers_joined`` - peers active in this release but not in ``other``
        - ``peers_changed`` - peers that have different active keys in ``other`` and this release
        - ``peers_left`` - peers that are active in ``other`` but in this release

        """
        if other is None:
            other = self.prev
        
        keys_prev = set(other.active_keys + self.inactive_keys)        
        keys_curr = set(self.active_keys) # keys that are in this release

        # keys that used to be in but are not any more
        keys_out = keys_prev.difference(keys_curr)
        # keys that are new
        keys_in  = keys_curr.difference(other.active_keys)
        
        peers_prev = set([Peer.from_key(key) for key in keys_prev])
        peers_curr = set([Peer.from_key(key) for key in keys_curr])
        peers_in   = set([Peer.from_key(key) for key in keys_in  ])
        peers_out  = set([Peer.from_key(key) for key in keys_out ])

        peers_joined  = peers_curr.difference(peers_prev)
        peers_changed = peers_in.intersection(peers_out)
        peers_left    = peers_prev.difference(peers_curr)


        return keys_in, keys_out, peers_joined, peers_changed, peers_left

    @property
    def peers(self):
        """All active peers in this release"""
        return tuple(Peer.from_key(key) for key in sorted(self.active_keys, key=lambda x:
                                                          x.name.lower()))

    @staticmethod
    def _format_entry(i, key):
        return (u"  %3d. %s"%(i, key), u"       %s"%key.peer)

    @property
    def active_keys(self):
        """All active keys in this release."""
        if self.id is None:
            return [assoc for assoc in self.key_associations if assoc.is_active]
        from batzenca.session import session
        return session.db_session.query(Key).join(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.is_active == True).all()

    @property
    def inactive_keys(self):
        """All inactive keys in this release."""
        if self.id is None:
            return [assoc.key for assoc in self.key_associations if not assoc.is_active]
        from batzenca.session import session
        return session.db_session.query(Key).join(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.is_active == False).all()

    def deactivate_invalid(self):
        """Deactivate those keys which evaluate to false and those keys which are not signed by the
        CA.

        A key evaluates to false if it is expired. Keys are considered unsigned if the CA signature
        is revoked.

        """
        if self.published:
            raise ValueError("Release '%s' is already published and should not be modified."%self)

        for assoc in self.key_associations:
            if assoc.is_active:
                if not bool(assoc.key):
                    assoc.is_active = False
                elif not assoc.key.is_signed_by(self.policy.ca):
                    assoc.is_active = False

    def delete_old_inactive_keys(self, releasecount=5):
        """Remove those inactive keys which have been inactive for a while.

        :param boolean releasecount: the number of releases for which a key must have been inactive
            to be removed.

        """
        if self.published:
            raise ValueError("Release '%s' is already published and should not be modified."%self)

        old_release = self
        for i in range(releasecount):
            if old_release.prev:
                old_release = old_release.prev
            else:
                return

        delete_keys = []
        for key in self.inactive_keys:
            if key not in old_release.active_keys:
                delete_keys.append(key)
            elif key.expires and key.expires < self.date:
                delete_keys.append(key)
        for key in delete_keys:
            assoc = self._get_assoc(key)
            self.key_associations.remove(assoc)
            from batzenca.session import session
            session.db_session.delete(assoc)
            
                
    def _get_assoc(self, key):
        if key.id is None or self.id is None:
            for assoc in self.key_associations:
                if assoc.key is key and assoc.release is self:
                    return assoc
            raise ValueError("Key '%s' is not in release '%s'"%(key, self))

        from batzenca.session import session
        res = session.db_session.query(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.left_id == key.id, ReleaseKeyAssociation.right_id == self.id)
        if res.count() > 1:
            raise RuntimeError("The key '%s' is associated with the release '%' more than once; the database is in an inconsistent state."%(key, self))
        if res.count() == 0:
            raise ValueError("Key '%s' is not in release '%s'"%(key, self))
        return res.first()

    def add_exception(self, key):
        """Add a policy exception for the provided key.

        :param batzenca.database.keys.Key key: the key for which to add the exception

        """
        if self.published:
            raise ValueError("Release '%s' is already published and should not be modified."%self)

        assoc = self._get_assoc(key)
        assoc.policy_exception = True

    def has_exception(self, key):
        """Return ``True`` if the provided key has a policy exception.

        :param batzenca.database.keys.Key key: the key to check

        """
        assoc = self._get_assoc(key)
        return assoc.policy_exception

    def is_active(self, key):
        """Return ``True`` if the provided key is active in this release,

        :param batzenca.database.keys.Key key: the key to check

        """
        assoc = self._get_assoc(Key)
        return assoc.is_active

    def update_key_from_peer(self, peer):
        if not peer in self:
            raise ValueError("Peer '%s' is not in '%s'"%(peer, self))
        if peer.key in self:
            raise ValueError("Key '%s' of peer '%s' is already in release '%s'"%(peer.key, peer, self))

        from batzenca.session import session
        res = session.db_session.query(ReleaseKeyAssociation).join(Key).join(Peer).filter(Key.peer_id == peer.id, ReleaseKeyAssociation.left_id == Key.id, ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.is_active == True)

        for assoc in res.all():
            if not bool(assoc.key):
                assoc.is_active = False
            elif not assoc.key.is_signed_by(self.policy.ca):
                assoc.is_active = False
            else:
                raise ValueError("Key '%s' of peer '%s' has a valid signature by CA '%s' mandated in '%s'"%(assoc.key, peer, self.policy.ca, self.policy))

        self.add_key(peer.key, active=True, check=True)

    def add_key(self, key, active=True, check=True):
        if self.published:
            raise ValueError("Release '%s' is already published and should not be modified."%self)

        if key.peer is None:
            raise ValueError("Key '%s' has no peer associated"%key)
        else:
            if active and key.peer in self:
                raise ValueError("Peer '%s' associated with Key '%s' already has an active key in this release"%(key.peer, key))
            
        if check and active:
            self.policy.check(key)
                        
        self.key_associations.append(ReleaseKeyAssociation(key=key, active=active))

    def __contains__(self, obj):
        from batzenca.session import session

        if self.id is None:
            raise RuntimeError("The object '%s' was not committed to the database yet, we cannot issue queries involving its id yet."%self)

        try:
            if obj.id is None:
                raise RuntimeError("The object '%s' was not committed to the database yet, we cannot issue queries involving its id yet."%obj)
        except AttributeError:
            raise TypeError("Cannot handle objects of type '%s'"%type(obj))

        if isinstance(obj, Key):
            res = session.db_session.query(Key).join(ReleaseKeyAssociation).filter(ReleaseKeyAssociation.left_id == obj.id, ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.is_active == True)
            if res.count() == 0:
                return False
            elif res.count() == 1:
                return True
            else:
                raise RuntimeError("The key '%s' is associated with the release '%' more than once; the database is in an inconsistent state."%(obj, self))
            
        elif isinstance(obj, Peer):
            res = session.db_session.query(Peer).join(Key).join(ReleaseKeyAssociation).filter(Key.peer_id == obj.id, ReleaseKeyAssociation.left_id == Key.id, ReleaseKeyAssociation.right_id == self.id, ReleaseKeyAssociation.is_active == True)
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
        """
        The previous release.
        """
        idx = self.mailinglist.releases.index(self)
        if idx > 0:
            return self.mailinglist.releases[idx-1]
        else:
            return None

    @property
    def yaml(self):
        """YAML representation of this release.

        This contains the name of the database, the date of this release, the key id of the CA, all
        key ids of active and passive keys.

        """
        s = []
        s.append( "mailinglist: %s"%self.mailinglist.email )
        s.append( "date:        %04d-%02d-%02d"%(self.date.year, self.date.month, self.date.day) )
        s.append( "ca:          %s"%self.policy.ca.kid )
        
        s.append( "active keys:" )
        for key in self.active_keys:
            s.append( "  - %s"%key.kid )
        s.append( "" )
        s.append( "inactive keys:" )
        for key in self.inactive_keys:
            s.append( "  - %s"%key.kid )
        s.append( "" )
        return "\n".join(s)

    def expiring_keys(self, days=30):
        return tuple(key for key in self.active_keys if key.expires and key.expires < self.date + datetime.timedelta(days=days))
        
    def __call__(self, previous=None, check=True, still_alive=False):
        """Return tuple representing this release as a (message, keys) pair.

        :param batzenca.database.releases.Release previous: the previous release, we call
            :func:`batzenca.database.releases.Release.diff` on it.  if ``None`` then ``self.prev``
            is used.
        :param boolean check: if ``True`` then :func:`batzenca.database.releases.Release.verify` is
            run.

        :param boolean still_alive: if ``True`` then the field ``{dead_man_switch}`` in
            :attr:`batzenca.database.mailinglists.MailingList.key_update_msg` is replaced by
            :attr:`batzenca.database.mailinglists.MailingList.dead_man_switch_msg`.

        :return: a tuple containing two strings. The first one is
            :attr:`batzenca.database.mailingists.MailingList.key_update_msg` with the output of
            :class:`batzenca.database.releases.Release.diff` used to fill in its fields. The second
            component is ``self``'s :attr:`batzenca.database.releases.Release.ascii_keys`.

        """
        if check:
            self.verify()

        sorted_keys = lambda keys: sorted(keys, key=lambda x: x.name.lower())
            
        keys = []
        for i,key in enumerate(sorted_keys(self.active_keys)):
            keys.extend(Release._format_entry(i, key))
        keys = "\n".join(keys)

        if previous is None:
            previous = self.prev

        if previous:
            keys_in, keys_out, peers_joined, peers_changed, peers_left = self.diff(previous)

            keys_in  = "\n".join(sum([self._format_entry(i, key) for i,key in enumerate(sorted_keys(keys_in)) ], tuple()))
            keys_out = "\n".join(sum([self._format_entry(i, key) for i,key in enumerate(sorted_keys(keys_out))], tuple()))

            peers_joined  = ", ".join(peer.name for peer in peers_joined)
            peers_changed = ", ".join(peer.name for peer in peers_changed)
            peers_left    = ", ".join(peer.name for peer in peers_left)
        else:
            keys_in, keys_out, peers_joined, peers_changed, peers_left = "","","","",""
            
        msg = self.mailinglist.key_update_msg.format(mailinglist=self.mailinglist.name, keys=keys,
                                                     keys_in       = keys_in,
                                                     keys_out      = keys_out,
                                                     peers_in      = peers_joined,
                                                     peers_changed = peers_changed,
                                                     peers_out     = peers_left,
                                                     dead_man_switch = self.mailinglist.dead_man_switch_msg if still_alive else "",
                                                     ca=self.policy.ca.name,
                                                     ca_email=self.policy.ca.email)

        return msg, self.ascii_keys

    def release_message(self, previous=None, check=True, debug=False, attachments=None):
        """
        """
        ca = self.policy.ca
        mailinglist = self.mailinglist
        date_str = "%04d%02d%02d"%(self.date.year, self.date.month, self.date.day)

        body_, attachment_ = self(previous=previous, check=check)

        from email import encoders
        from email.mime.base import MIMEBase
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from batzenca.pgpmime import PGPMIME
        
        payload = MIMEMultipart()
        payload.attach(MIMEText(body_.encode('utf-8'),  _charset='utf-8'))

        attachment = MIMEBase('application', 'pgp-keys')
        attachment.set_payload(attachment_)
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', 'attachment', filename="%s_%s.asc"%(mailinglist.name, date_str))
        payload.attach(attachment)

        if attachments:
            for attachment in attachments:
                payload.attach(attachment)

        msg = PGPMIME(payload, self.active_keys, ca)
    
        # we are being a bit paranoid and check that we didn't fuck up encryption or something
        for key in self.active_keys:
            assert(key.kid not in msg.as_string())

        to = mailinglist.email if not debug else ca.email
            
        msg['To']      = to
        msg['From']    = ca.email
        msg['Subject'] = "KeyUpdate {date} [{mailinglist}]".format(date=date_str, mailinglist=mailinglist.name)

        return msg
        
    def welcome_messages(self, tolerance=180, debug=False):
        mailinglist = self.mailinglist
        ca = self.policy.ca
        today = datetime.date.today()
        tolerance = today - datetime.timedelta(days=tolerance)

        from email.mime.text import MIMEText
        from batzenca.pgpmime import PGPMIME


        M = []
        for peer in self.peers:
            was_recently_active = False
            for key in peer.keys:
                if any(rel.date > tolerance for rel in key.releases if rel.mailinglist == self.mailinglist and rel != self):
                    was_recently_active = True
                    break
            if not was_recently_active:
                body    = self.mailinglist.new_member_msg.format(peer=peer.name,
                                                                 mailinglist=mailinglist.name,
                                                                 mailinglist_email=mailinglist.email,
                                                                 ca=ca.name,
                                                                 ca_email=ca.email)
                payload = MIMEText(body.encode('utf-8'),  _charset='utf-8')
                msg = PGPMIME(payload, [peer.key, ca], ca)
                to = peer.email if not debug else ca.email
                msg['To']      = to
                msg['From']    = ca.email
                msg['Subject'] = "welcome to [{mailinglist}]".format(mailinglist=mailinglist.name)
                M.append( msg )
        return tuple(M)

    def key_expiry_messages(self, days=30, debug=False):
        mailinglist = self.mailinglist
        ca = self.policy.ca

        from email.mime.text import MIMEText
        from batzenca.pgpmime import PGPMIME

        M = []
        for key in self.expiring_keys(days=days):
            body    = self.mailinglist.key_expiry_warning_msg.format(peer=key.peer.name,
                                                                     keyid=key.kid,
                                                                     expiry_date=key.expires,
                                                                     mailinglist = mailinglist.name,
                                                                     mailinglist_email = mailinglist.email,
                                                                     ca_email = ca.email)
            payload = MIMEText(body.encode('utf-8'),  _charset='utf-8')
            msg = PGPMIME(payload, [key, ca], ca)
            to = key.email if not debug else ca.email
            msg['To']      = to
            msg['From']    = ca.email
            msg['Subject'] = "key expiry warning".format(mailinglist=mailinglist.name)
            M.append( msg )
        return tuple(M)


    def dump(self, filename=None):
        """Write this release to to filename.yaml and filename.asc where the
        former receives :attr:`batzenca.database.releases.Release.yaml` and the
        latter receives :attr:`batzenca.database.releases.Release.ascii_keys`.

        :param str filename: a string containing a full path and basename.

        """
        from batzenca import session
        
        if filename is None:
            filename = os.path.join(session.release_dump_path,
                                    "%s-%04d%02d%02d"%(self.mailinglist.name,
                                                       self.date.year, self.date.month, self.date.day))
        codecs.open(filename+".yaml", encoding="utf8", mode="w").write( self.yaml )
        open(filename+".asc", "w").write( self(previous=None, check=False)[1] )

        
    def send(self, smtpserver, previous=None, check=True, debug=False, attachments=None,
             new_peer_tolerance_days=180, key_expiry_warning_days=30):
        """Publish this release.

        This entails (if ``debug==False``):

        1. updating the release date of this release

        2. a call to :func:`batzenca.database.releases.Release.deactivate_invalid`

        3. sending an e-mail to new members who have not been on this list for ``new_peer_tolerance_days`` days.

        4. sending a key update message to the list

        5. sending a key expiry message to keys that expire within ``key_expiry_warning_days`` days
       
        6. a call to :func:`batzenca.database.releases.Release.dump`

        7. setting this release status to published.

        If ``debug == True`` then e-mails are sent to the CA's e-mail address instead of the list and/or
        peers. Furthermore, neither the date nor the published status of this release is affected in this case.

        :param smtpserver:
        :param batzenca.database.releases.Release previous: the previous release, we call
            :func:`batzenca.database.releases.Release.diff` on it.  if ``None`` then ``self.prev``
            is used.
        :param boolean check: if ``True`` then :func:`batzenca.database.releases.Release.verify` is
            run.
        :param boolean debug:
        :param iterable attachments:
        :param int new_peer_tolerance_days:
        :param int key_expiry_warning_days:

        .. warning:

            Calling this function may modify this release. Firstly, this function calls
            :func:`batzenca.database.releases.Release.deactivate_invalid`. Secondly, if ``debug`` is ``False``,
            :attr:`batzenca.database.releases.Release.date` is set to today's date and
            :attr:`batzenca.database.releases.Release.published` is set to ``True``.

        """
        if self.published:
            raise ValueError("Release '%s' is already published"%self)

        # 1. updating the release date of this release
            
        if not debug:
            self.date = datetime.date.today()

        # 2. a call to :func:`batzenca.database.releases.Release.deactivate_invalid`

        self.deactivate_invalid()

        # 3. sending an e-mail to new members who have not been on this list for ``new_peer_tolerance_days`` days.

        if new_peer_tolerance_days and self.mailinglist.new_member_msg:
            messages = self.welcome_messages(tolerance=new_peer_tolerance_days, debug=debug)
            for msg in messages:
                if debug:
                    smtpserver.sendmail(self.policy.ca.email, (msg['To'],self.policy.ca.email), msg.as_string())
                else: # we send a copy to self
                    smtpserver.sendmail(self.policy.ca.email, (self.policy.ca.email, ), msg.as_string())

        # 4. sending a key update message to the list

        msg = self.release_message(previous=previous, check=check, debug=debug, attachments=attachments)
        smtpserver.sendmail(self.policy.ca.email, (msg['To'],), msg.as_string())
       
        # 5. sending a key expiry message to keys that expire within ``key_expiry_warning_days`` days
                    
        if key_expiry_warning_days and self.mailinglist.key_expiry_warning_msg:
            messages = self.key_expiry_messages(days=key_expiry_warning_days, debug=debug)
            for msg in messages:
                if debug:
                    smtpserver.sendmail(self.policy.ca.email, (self.policy.ca.email,), msg.as_string())
                else:
                    # we send a copy to self
                    smtpserver.sendmail(self.policy.ca.email, (msg['To'],self.policy.ca.email), msg.as_string())

        # 6. a call to :func:`batzenca.database.releases.Release.dump`

        if not debug:
            self.dump()

        # 7. setting this release status to published.

        if not debug:
            self.published = True
