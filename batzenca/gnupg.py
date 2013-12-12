"""
.. module:: gnupg

.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>

Interface to low(er) level GnuPG interfaces.
"""

import pyme
import pyme.core
import pyme.pygpgme
import pyme.errors
import pyme.constants.keylist
import pyme.constants.sig
import pyme.constants.status

from collections import namedtuple
UID = namedtuple('UID', ['name', 'email',  'comment'])

import os
import datetime

class KeyError(Exception):
    """
    We raise this exception if there is a problem with a key
    """
    pass

class GnuPG(object):
    """
    A GnuPG context.
    """
    GPGME_PK_RSA   = pyme.pygpgme.GPGME_PK_RSA  
    GPGME_PK_RSA_E = pyme.pygpgme.GPGME_PK_RSA_E
    GPGME_PK_RSA_S = pyme.pygpgme.GPGME_PK_RSA_S
    GPGME_PK_ELG_E = pyme.pygpgme.GPGME_PK_ELG_E
    GPGME_PK_DSA   = pyme.pygpgme.GPGME_PK_DSA  
    GPGME_PK_ELG   = pyme.pygpgme.GPGME_PK_ELG

    alg_to_str = { GPGME_PK_RSA  : "GPGME_PK_RSA",
                   GPGME_PK_RSA_E: "GPGME_PK_RSA_E",
                   GPGME_PK_RSA_S: "GPGME_PK_RSA_S",
                   GPGME_PK_ELG_E: "GPGME_PK_ELG_E",
                   GPGME_PK_DSA  : "GPGME_PK_DSA",
                   GPGME_PK_ELG  : "GPGME_PK_ELG" }

    str_to_alg = { "GPGME_PK_RSA"  : GPGME_PK_RSA,
                   "GPGME_PK_RSA_E": GPGME_PK_RSA_E,
                   "GPGME_PK_RSA_S": GPGME_PK_RSA_S,
                   "GPGME_PK_ELG_E": GPGME_PK_ELG_E,
                   "GPGME_PK_DSA"  : GPGME_PK_DSA,
                   "GPGME_PK_ELG"  : GPGME_PK_ELG }

    _key_cache = {}

    @staticmethod
    def is_active(subkey):
        """
        Return ``True`` if ``subkey`` is neither revoked, expired or disabled.

        INPUT:

        - ``subkey`` - a PyGPGMe subkey object
        """
        return not (subkey.revoked or subkey.expired or subkey.disabled)
    
    def __init__(self, home_dir=None):
        """Construct a new instance of :class:`GnuPG`

        INPUT:

        - ``home_dir`` - specifiy the GNUPGHOME (default: ``None``)
        """
        pyme.core.check_version(None)

        self.home_dir = home_dir
        
        if home_dir is not None:
            if not os.path.exists(home_dir):
                os.mkdir(home_dir)
                os.chmod(home_dir, 0700)

            for engine in pyme.core.get_engine_info():
                pyme.core.set_engine_info(engine.protocol, engine.file_name, home_dir)

        self.ctx = pyme.core.Context()
        self.ctx.set_keylist_mode(pyme.constants.keylist.mode.SIGS)
        self.ctx.set_armor(1)

    def key_get(self, keyid):
        """Get the key object matching ``keyid``.
        
        INPUT:

        - ``keyid`` - a 16 character string encoding an integer in hexadecimal notation or an
          integer < 2^64
        """
        if isinstance(keyid, pyme.pygpgme._gpgme_key):
            return keyid

        # we are caching for performance reasons
        # TODO: does anything depend on us not caching?
        if keyid in self._key_cache:
            return self._key_cache[keyid]

        try:
            try:
                key = self.ctx.get_key("0x%x"%keyid, 0)
                self._key_cache[keyid] = key
                return key
            except TypeError:
                pass
            try:
                if keyid.startswith("0x"):
                    key = self.ctx.get_key(str(keyid), 0)
                else:
                    key = self.ctx.get_key("0x"+str(keyid), 0)
                self._key_cache[keyid] = key
                return key
            except AttributeError:
                raise KeyError("Key '%s' not found."%keyid)
        except pyme.errors.GPGMEError, e:
            raise KeyError("Key '%s' not found."%keyid)

    def have_secret_key(self, keyid):
        """Return ``True`` if we have the secret key for the key identified by``keyid``.

        INPUT:

        - ``keyid`` - a 16 character string encoding an integer in hexadecimal notation or an
          integer < 2^64
        """
        try:
            try:
                key = self.ctx.get_key("0x%x"%keyid, True)
                if key:
                    return True
            except TypeError:
                pass
            try:
                if keyid.startswith("0x"):
                    key = self.ctx.get_key(str(keyid), True)
                else:
                    key = self.ctx.get_key("0x"+str(keyid), True)
                if key:
                    return True
            except AttributeError:
                return False
        except pyme.errors.GPGMEError, e:
            return False
            
    def key_uid(self, keyid):
        """
        Return a named tuple ``(name,email,comment)`` with the default UID of the key ``keyid``

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        uids = self.key_get(keyid).uids
        return UID(unicode(uids[0].name, 'utf-8'), unicode(uids[0].email, 'utf-8'), unicode(uids[0].comment, 'utf-8'))

    def key_okay(self, keyid):
        """A key is "okay" if it has at least one not-expired, not-disabled, not-revoked subkey for
        both signing and encrypting.

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)

        # the .invalid attribute is not used by GnuPG
        assert(all(subkey.invalid == 0 for subkey in key.subkeys))
        
        subkeys = [subkey for subkey in key.subkeys if GnuPG.is_active(subkey)]
        if len(subkeys) == 0:
            return False

        if not any(subkey.can_sign for subkey in subkeys) or not any(subkey.can_encrypt for subkey in subkeys):
            return False
        return True

    def key_validity(self, keyid):
        """Return the validity of the key ``keyid``.

        A key's validity expresses the level of certainty that a given key belongs to the claimed
        UID. Where 0 is no certainty, and 5 is ultimate certainty (you own the secret key yourself).

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.

        """
        key = self.key_get(keyid)
        return max([uid.validity for uid in key.uids])
        
    def key_pubkey_algos(self, keyid):
        """Return a tuple of public-key enryption/signature algorithms for the key ``keyid``

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)
        return tuple([subkey.pubkey_algo for subkey in key.subkeys if GnuPG.is_active(subkey)])
        
    def key_expires(self, keyid):
        """Return the nearest date when any of the expiring encryption subkeys of ``keyid`` is going
        to expire.

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)
    
        timestamps = [subkey.expires for subkey in key.subkeys if (subkey.expires and subkey.can_encrypt)]
        if timestamps:
            return datetime.date.fromtimestamp(min(timestamps))
        else:
            return False

    def key_expired(self, keyid):
        """Return ``True`` if the key ``keyid`` is expired.

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)
        subkeys = [subkey for subkey in key.subkeys if (subkey.can_encrypt and not subkey.expired)]
        if len(subkeys) == 0:
            return True
        else:
            return False
    
    def key_timestamp(self, keyid):
        """Return the earliest timestamp on any of the subkeys of ``keyid``.

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)
        timestamp = min([subkey.timestamp for subkey in key.subkeys])
        return datetime.date.fromtimestamp(timestamp)

    def key_min_len(self, keyid):
        """Return the minimum key length of any of the subkeys of ``keyid``.

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)
        return min([subkey.length for subkey in key.subkeys])
            

    def key_any_uid_is_signed_by(self, keyid, signer_keyid):
        """Return ``True`` if any uid of the key ``keyid`` is signed by the key ``signer_keyid``.

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        - ``signer_keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.

        """
        key = self.key_get(keyid)

        signer_key = self.key_get(signer_keyid)

        sign_keys = set()
        for subkey in signer_key.subkeys:
            if subkey.can_sign and not subkey.disabled and not subkey.revoked:
                sign_keys.add(subkey.keyid)
            
        if sign_keys.intersection(self.key_signatures(keyid)):
            return True
        else:
            return False

    def key_signatures(self, keyid):
        """Return the list of keyids which match keys that signed the key ``keyid``.

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)
        sigs = set()
        for uid in key.uids:
            for sig in uid.signatures:
                if not sig.expired and not sig.revoked:
                    sigs.add(sig.keyid)

        for uid in key.uids:
            for sig in uid.signatures:
                if sig.revoked and sig.keyid in sigs:
                    sigs.remove(sig.keyid)
                
        return sigs

    def key_okay_encrypt(self, keyid):
        """Return ``True`` if the key ``keyid`` can be used for encryption.

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)
        if  not self.key_okay(key) or not self.key_validity(key) >= 4:
            return False
        return True
        
    def keys_export(self, keyids):
        """Return string containing keys in list ``keyids`` in ASCII armor format

        INPUT:

        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        from pyme.core import Data
        export_keys = Data()
        keys = [self.key_get(keyid) for keyid in keyids]
        self.ctx.op_export_keys(keys, 0, export_keys)
        export_keys.seek(0,0)
        return export_keys.read()

    def msg_sign(self, msg, keyid):
        """Sign the message ``msg`` with the key ``keyid``

        INPUT:

        - ``msg`` - a string
        - ``keyid`` - see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        """
        key = self.key_get(keyid)

        if not self.have_secret_key(keyid):
            raise ValueError("You do not have the secret key for %s in your GnuPG keyring."%keyid)
        
        msg = pyme.core.Data(msg)
        sig = pyme.core.Data()

        self.ctx.signers_clear()
        self.ctx.signers_add(key)

        self.ctx.op_sign(msg, sig, pyme.constants.sig.mode.DETACH)

        sig.seek(0,0)
        return sig.read()
    
    def msg_encrypt(self, msg, keyids, always_trust=False):
        """Encrypt the message ``msg`` under keys in the list ``keyids``.

        INPUT:

        - ``msg`` - a string
        - ``keyids`` - a list of key ids, see :func:`batzenca.gnupg.GnuPG.key_get` for details on accepted formats.
        - ``always_trust`` - If ``False`` on keys with validity >= 4 are accepted. Otherwise, any
          public key will do.
        """
        keys = [self.key_get(keyid) for keyid in keyids]

        if not always_trust:
            for key in keys:
                if  not self.key_okay(key) or not self.key_validity(key) >= 4:
                    raise ValueError("No UID of the key 0x%s has a sufficient level of validity, set always_trust=True if you want to force encryption."%key.subkeys[0].fpr[-16:])
        
        plain = pyme.core.Data(msg)
        cipher = pyme.core.Data()
        flags = pyme.constants.ENCRYPT_NO_ENCRYPT_TO
        if always_trust:
            flags |= pyme.constants.ENCRYPT_ALWAYS_TRUST
        retval = self.ctx.op_encrypt(keys, flags, plain, cipher)

        cipher.seek(0,0)
        return cipher.read()

    def msg_decrypt(self, cipher):
        """
        Decrypt the message ``cipher``.

        INPUT:
        
        - ``cipher`` - a string
        """
        cipher = pyme.core.Data(cipher)
        plain  = pyme.core.Data()
        try:
            self.ctx.op_decrypt(cipher, plain)
            plain.seek(0,0)
            return plain.read()
        except pyme.errors.GPGMEError, msg:
            raise ValueError(msg)

    def sig_verify(self, msg, sig):
        """Return the list of keys - represented by fingerprint strings - that signed the message
        ``msg`` in the detached signature ``sig``.
        
        INPUT:

        - ``msg`` - the message
        - ``sig`` - the signature
        """
        msg = pyme.core.Data(msg)
        sig = pyme.core.Data(sig)

        self.ctx.op_verify(sig, msg, None)
        result = self.ctx.op_verify_result()

        sigs = []
        for sign in result.signatures:
            if (sign.summary & pyme.constants.SIGSUM_VALID) == 1:
                sigs.append( sign.fpr )

        return tuple(sigs)
        
    def key_sign(self, keyid, signer_keyid, local=False):
        key = self.key_get(keyid)
        signer_key = self.key_get(signer_keyid)

        if not self.have_secret_key(signer_keyid):
            raise ValueError("You do not have the secret key for %s in your GnuPG keyring."%signer_keyid)
        
        out = pyme.core.Data()

        helper = {
            "GET_LINE"        : {"keyedit.prompt" : ("lsign" if local else "sign", "quit")}, 
            "GET_BOOL"        : {"sign_uid.okay" : "Y", "keyedit.save.okay" : "Y"},
            "ALREADY_SIGNED"  : None,
            "GOT_IT"          : None,
            "NEED_PASSPHRASE" : None,
            "GOOD_PASSPHRASE" : None,
            "USERID_HINT"     : None,
            "EOF"             : None,
            "skip"            : 0, 
            "data"            : out,
        }

        self.ctx.signers_clear()
        self.ctx.signers_add(signer_key)
        self.ctx.op_edit(key, edit_fnc, helper, out)
        self._key_cache = {} # invalidate the cache

    def key_delete_signature(self, keyid, signer_keyid):
        key = self.key_get(keyid)
        signer_key = self.key_get(signer_keyid)

        out = pyme.core.Data()

        for i, uid in enumerate(key.uids):
        
            cleaner = {
                "GET_LINE"        : {"keyedit.prompt" : ("uid %d"%(i+1), "delsig", "save")}, 
                "GET_BOOL"        : {"keyedit.save.okay" : "Y", "keyedit.delsig.unknown" : "Y"}, 
                "GOT_IT"          : None,
                "NEED_PASSPHRASE" : None,
                "GOOD_PASSPHRASE" : None,
                "USERID_HINT"     : None,
                "EOF"             : None,

                "signer"          : signer_key,
                "skip"            : 0, 
                "data"            : out,
            }
            self.ctx.op_edit(key, edit_fnc, cleaner, out)

        self._key_cache = {} # invalidate the cache
            
    def key_set_trust(self, id, trust):
        key = self.key_get(id)

        out = pyme.core.Data()

        helper = {
            "GET_LINE"        : { "keyedit.prompt" : ("trust", "quit"), 
                                  "edit_ownertrust.value" : str(trust),                                  
                              },
            "GET_BOOL"        : { "edit_ownertrust.set_ultimate.okay" : "Y" }, 
            "GOT_IT"          : None,
            "NEED_PASSPHRASE" : None,
            "GOOD_PASSPHRASE" : None,
            "USERID_HINT"     : None,
            "EOF"             : None,

            "skip"            : 0, 
            "data"            : out,
        }
        self.ctx.op_edit(key, edit_fnc, helper, out)
        self._key_cache = {} # invalidate the cache
        
    def keys_import(self, data):
        self._key_cache = {} # invalidate the cache
        data = pyme.core.Data(data)
        self.ctx.op_import(data)
        res =  self.ctx.op_import_result()
        return dict((r.fpr, r.status) for r in res.imports)

    def key_revsig(self, keyid, signer_keyid, code=4, msg=""):
        key = self.key_get(keyid)
        signer_key = self.key_get(signer_keyid)

        if not self.have_secret_key(signer_keyid):
            raise ValueError("You do not have the secret key for %s in your GnuPG keyring."%signer_keyid)
        
        out = pyme.core.Data()

        msg += "\n\n"
        msg = tuple(msg.splitlines())

        helper = {
            "GET_LINE"        : { "keyedit.prompt" : ("revsig", "quit"), 
                                  "ask_revocation_reason.code" : str(code) , 
                                  "ask_revocation_reason.text" :  msg
                              },
            "GET_BOOL"        : { "ask_revoke_sig.okay" : "Y", 
                                  "keyedit.save.okay" : "Y", 
                                  "ask_revocation_reason.okay" : "Y" }, 
            "GOT_IT"          : None,
            "NEED_PASSPHRASE" : None,
            "GOOD_PASSPHRASE" : None,
            "USERID_HINT"     : None,
            "EOF"             : None,

            "signer"          : signer_key,
            "skip"            : 0, 
            "data"            : out,
        }
        self.ctx.signers_clear()
        self.ctx.signers_add(signer_key)
        self.ctx.op_edit(key, edit_fnc, helper, out)
        self._key_cache = {} # invalidate the cache

    def key_edit(self, keyid):
        """
        .. warning:

           This will open an interactive session using rawinput
        """
        key = self.key_get(keyid)
        out = pyme.core.Data()

        helper = {
            "GOT_IT"          : None,
            "NEED_PASSPHRASE" : None,
            "GOOD_PASSPHRASE" : None,
            "EOF"             : None,

            "skip"            : 0, 
            "data"            : out,
        }
        self.ctx.signers_clear()
        self.ctx.op_edit(key, edit_fnc, helper, out)
        self._key_cache = {} # invalidate the cache
        
# from pygpa

stat2str = {}
for name in dir(pyme.constants.status):
    if not name.startswith('__') and name != "util":
        stat2str[getattr(pyme.constants.status, name)] = name

def edit_fnc(stat, args, helper):

    try:
        while True:
            helper["data"].seek(helper["skip"],0)
            data = helper["data"].read()
            helper["skip"] += len(data)

            if stat2str[stat] in helper:
                if helper[stat2str[stat]] is None:
                     return ""
    
                if args in helper[stat2str[stat]]:
                    ret = helper[stat2str[stat]][args]
                    if isinstance(ret, tuple):
                        helper[stat2str[stat]][args] = ret[1:]
                        return ret[0]
                    return ret

            if stat2str[stat] == "GET_BOOL" and args == "keyedit.delsig.valid":
                if any(sk.keyid[2:].upper() in data for sk in helper["signer"].subkeys):
                    return "Y"
                return "N"

            if stat2str[stat] == "GET_BOOL" and args == "ask_revoke_sig.one":
                for sk in helper["signer"].subkeys:
                    #0x....
                    if sk.keyid[2:].upper() in data:
                        return "Y"
                return "N"

            print data
            return raw_input("(%s) %s > " % (stat2str[stat], args))
    except EOFError:
        pass


