"""
.. module:: policies

.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>

Policies specify conditions for keys to be part of releases.
"""

import sqlalchemy
from sqlalchemy import Column, Integer, String, Date, Boolean, ForeignKey, UnicodeText
from sqlalchemy.orm import relationship, backref

import datetime
import warnings

from base import Base, EntryNotFound
from keys import Key
from peers import Peer
from mailinglists import MailingList

class PolicyViolation(Warning):
    """This warning is issued a :class:`batzenca.database.keys.Key` violates the conditions set by a
    :class:`batzenca.database.policies.Policy`.

    The default behaviour for warnings of this kind is that a message is displayed whenever it
    occurs. This behaviour can be modified by using Python's built-in warnings module::

        >>> with warnings.catch_warnings():
        ...   warnings.simplefilter("ignore", PolicyViolation)
        ...   # do something

    Alternatively, these warnings can be turned into exceptions::

        >>> with warnings.catch_warnings():
        ...   warnings.simplefilter("error", PolicyViolation)
        ...   # do something
    
    """
    def __init__(self, msg):
        Warning.__init__(self, msg.encode('utf8'))

class Policy(Base):
    """Releases are checked against policies.

    :param str name: the name of this policy
    :param implementation_date: the date this policy was implemented
    :param batzenca.database.keys.Key ca: the CA key
    :param int key_len: the minimum required key length
    :param int key_lifespan: the maximal key lifespan in days. For example, if ``key_lifespan`` is
        365, then a key passes if it expires within the next 365 from the point in time when it is
        checked.
    :param iterable algorithms: tuple of allowed algorithms

    """
    __tablename__ = 'policies'

    id                  = Column(Integer, primary_key=True) #: database id
    name                = Column(String) #: the name of this policy
    implementation_date = Column(Date) #: the date this policy was implemented

    ca                  = relationship('Key') #: the CA key
    ca_id               = Column(Integer, ForeignKey('keys.id'), nullable=False)

    key_len             = Column(Integer) #: the minimum required key length
    key_lifespan        = Column(Integer) #: the maximal key lifespan in days
    algorithms_str      = Column(String) 

    dead_man_switch     = Column(Boolean)
    description         = Column(UnicodeText)

    def __init__(self, name, implementation_date, ca, key_len, key_lifespan, algorithms, description=None):
        from batzenca.session import session

        self.name = name
        self.implementation_date = implementation_date
        self.ca = ca
        self.key_len = key_len
        self.key_lifespan = key_lifespan

        algs = []
        for alg in algorithms:
            try:
                algs.append(session.gnupg.alg_to_str[alg])
            except KeyError:
                raise ValueError("Algoritm '%s' is unknown. Supported algorithms are '%s'"%(alg, ", ".session.gnupg.str_to_alg.keys()))
        self.algorithms_str = ",".join(algs)
            
        self.description = unicode(description)

    @classmethod
    def from_key(cls, key):
        """Search the database for the policy matching the key.

        :param batzenca.database.keys.Key key: the key to query the database with
        
        .. note::

           The returned object was queried from the main session and lives there.

        """
        from batzenca.session import session
        res = session.db_session.query(cls).join(Key).filter(Key.kid == key.kid)

        if res.count() == 0:
            raise EntryNotFound("No peer matching key '%s' in database."%key)
        else:
            if res.count() > 1:
                warnings.warn("More than one release with key '%s' found, picking first one."%key)
            return res.first()

    @property
    def algorithms(self):
        """The set of allowed encryption or signature algorithms."""
        from batzenca.session import session
        return set([session.gnupg.str_to_alg[e] for e in self.algorithms_str.split(",")])

    def check_length(self, key):
        """Return ``True`` if the shortest subkey of ``key`` is shorter than the minimum key length
        mandated by this policy.

        :param batzenca.database.keys.Key key: the key to check

        .. note::

            This function issues a :class:`batzenca.database.policies.PolicyViolation` warning if
            ``key``'s length is too short.
        """
        if len(key) < self.key_len:
            msg = u"Key '%s' has key length %d but at least %d is required by '%s'."%(unicode(key), len(key), self.key_len, unicode(self))
            warnings.warn(msg, PolicyViolation)
            return False
        return True

    def check_algorithms(self, key):
        """Return ``True`` if all algorithms used by ``key`` are in the set of allowed algorithms for this policy.

        :param batzenca.database.keys.Key key: the key to check

        .. note::

            This function issues a :class:`batzenca.database.policies.PolicyViolation` warning if
            ``key``'s length is too short.
        """
        from batzenca.session import session

        key_algorithms = set(key.algorithms)
        algorithms = self.algorithms

        if not algorithms:
            return True

        if not key_algorithms.issubset(algorithms):
            diff = key_algorithms.difference(algorithms)
            diff_str = ",".join(session.gnupg.alg_to_str[e] for e in diff)
            msg = u"Key '%s' uses algorithm(s) '%s' which is/are not in '%s' as mandated by '%s'."%(unicode(key), diff_str, self.algorithms_str, unicode(self))
            warnings.warn(msg, PolicyViolation)
            return False
        return True

    def check_expiration(self, key):
        """Return ``True`` if the provided key expires within the time limit mandated by this  policy..

        :param batzenca.database.keys.Key key: the key to check

        .. note::

            This function issues a :class:`batzenca.database.policies.PolicyViolation` warning if
            ``key``'s length is too short.
        """
        if not key.expires and self.key_lifespan > 0:
            msg = u"Key '%s'does not expire but expiry of %d days is mandated by '%s'."%(unicode(key), self.key_lifespan, unicode(self))
            warnings.warn(msg, PolicyViolation)
            return False
        else:
            max_expiry = datetime.date.today() + datetime.timedelta(days=self.key_lifespan)
            if max_expiry < key.expires:
                msg = u"Key '%s' expires on %s but max allowed expiration date is %s."%(unicode(key), key.expires, max_expiry)
                warnings.warn(msg, PolicyViolation)
                return False
            return True

    def check_ca_signature(self, key):
        """Return ``True`` if the provided key is signed by the CA associated with this policy.

        :param batzenca.database.keys.Key key: the key to check

        .. note::

            This function issues a :class:`batzenca.database.policies.PolicyViolation` warning if
            ``key``'s length is too short.
        """
        if not key.is_signed_by(self.ca):
            msg = u"No UID of Key '%s' has a valid signature of the CA key '%s'"%(unicode(key), unicode(self.ca))
            warnings.warn(msg, PolicyViolation)
            return False
        return True

    def check(self, key, check_ca_signature=True):
        """Check if the provided key is valid according to this policy.

        This includes that it's minimum key length, used algorithms and expiration time satisfy the
        constraints set by this policy. Furthermore, the key also must a valid signature by this
        policy's CA unless ``check_signature`` is set to ``False``.

        :param boolean check_ca_signature: if ``False`` this function does not check if the key is
            signed by the CA's key. This might be useful when the CA decides whether to sign this
            key depending on whether it is valid otherwise.

        """
        ret = True
        ret &= self.check_length(key)
        ret &= self.check_algorithms(key)
        ret &= self.check_expiration(key)
        if check_ca_signature:
            ret &= self.check_ca_signature(key)
        return ret

    def __str__(self):
        return "%s: (%d, %d, (%s))"%(self.name, self.key_len, self.key_lifespan, self.algorithms_str)
