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
    """
    We warn when a policy is violated.
    """
    def __init__(self, msg):
        Warning.__init__(self, msg.encode('utf8'))

class Policy(Base):
    """
    """

    __tablename__ = 'policies'

    id                  = Column(Integer, primary_key=True)
    name                = Column(String)
    implementation_date = Column(Date)

    ca                  = relationship('Key')
    ca_id               = Column(Integer, ForeignKey('keys.id'), nullable=False)

    key_len             = Column(Integer)
    key_lifespan        = Column(Integer)
    algorithms_str      = Column(String) 

    dead_man_switch     = Column(Boolean)

    description         = Column(UnicodeText)

    def __init__(self, name, implementation_date, ca, key_len, key_lifespan, algorithms, description=None):
        """
        Generate a new Policy object.

        name -- the name of this policy

        implementation_date -- the date this policy was implemented

        ca -- the CA key

        key_len -- the minimum key length required

        key_lifespan -- the maximal key lifespan in days. If key_lifespan is 365, then a key passes
        if it expires within the next 365 from the point in time when it is checked.

        algorithms -- tuple of allowed algorithms

        """
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
        """
        Search the database for the policy matching the key ``key``.
        
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
        from batzenca.session import session
        return set([session.gnupg.str_to_alg[e] for e in self.algorithms_str.split(",")])

    def check_length(self, key):
        if len(key) < self.key_len:
            msg = u"Key '%s' has key length %d but at least %d is required by '%s'."%(unicode(key), len(key), self.key_len, unicode(self))
            warnings.warn(msg, PolicyViolation)
            return False
        return True

    def check_algorithms(self, key):
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

        if not key.expires() and self.key_lifespan > 0:
            msg = u"Key '%s'does not expire but expiry of %d days is mandated by '%s'."%(unicode(key), self.key_lifespan, unicode(self))
            warnings.warn(msg, PolicyViolation)
            return False
        else:
            max_expiry = datetime.date.today() + datetime.timedelta(days=self.key_lifespan)
            if max_expiry < key.expires():
                msg = u"Key '%s' expires on %s but max allowed expiration date is %s."%(unicode(key), key.expires(), max_expiry)
                warnings.warn(msg, PolicyViolation)
                return False
            return True

    def check_ca_signature(self, key):
        if not key.is_signed_by(self.ca):
            msg = u"No UID of Key '%s' has a valid signature of the CA key '%s'"%(unicode(key), unicode(self.ca))
            warnings.warn(msg, PolicyViolation)
            return False
        return True

    def check(self, key, check_ca_signature=True):
        ret = True
        ret &= self.check_length(key)
        ret &= self.check_algorithms(key)
        ret &= self.check_expiration(key)
        if check_ca_signature:
            ret &= self.check_ca_signature(key)
        return ret

    def __str__(self):
        return "%s: (%d, %d, (%s))"%(self.name, self.key_len, self.key_lifespan, self.algorithms_str)
