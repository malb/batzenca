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

    def __init__(self, home_dir=None):
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

    def key_exists(self, keyid):
        try:
            key = self.ctx.get_key(str(keyid), 0)
            return True
        except pyme.errors.GPGMEError, e:
            return False

    def key_get(self, keyid):
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
        uids = self.key_get(keyid).uids
        return UID(unicode(uids[0].name, 'utf-8'), unicode(uids[0].email, 'utf-8'), unicode(uids[0].comment, 'utf-8'))

    def key_okay(self, id):
        key = self.key_get(id)

        # it seems the .invalid attribute is not used by GnuPG
        assert(all(subkey.invalid == 0 for subkey in key.subkeys))
        
        subkeys = [subkey for subkey in key.subkeys if (not subkey.revoked and not subkey.expired and not subkey.disabled)]
        if len(subkeys) == 0:
            return False

        if not any(subkey.can_sign for subkey in subkeys) or not any(subkey.can_encrypt for subkey in subkeys):
            return False
        return True

    def key_validity(self, kid):
        key = self.key_get(kid)
        return max([uid.validity for uid in key.uids])
        
    def key_pubkey_algos(self, id):
        key = self.key_get(id)
        return tuple([subkey.pubkey_algo for subkey in key.subkeys])
        
    def key_expires(self, id):
        """
        We only consider keys that can be used for encryption
        """
        key = self.key_get(id)
    
        timestamps = [subkey.expires for subkey in key.subkeys if (subkey.expires and subkey.can_encrypt)]
        if timestamps:
            return datetime.date.fromtimestamp(min(timestamps))
        else:
            return False

    def key_expired(self, id):
        key = self.key_get(id)
        subkeys = [subkey for subkey in key.subkeys if (subkey.can_encrypt and not subkey.expired)]
        if len(subkeys) == 0:
            return True
        else:
            return False
    
    def key_timestamp(self, id):
        key = self.key_get(id)
        timestamp = min([subkey.timestamp for subkey in key.subkeys])
        return datetime.date.fromtimestamp(timestamp)

    def key_min_len(self, id):
        key = self.key_get(id)

        return min([subkey.length for subkey in key.subkeys])
            

    def key_any_uid_is_signed_by(self, id, signer_id):
        key = self.key_get(id)

        signer_key = self.key_get(signer_id)

        sign_keys = set()
        for subkey in signer_key.subkeys:
            if subkey.can_sign and not subkey.disabled and not subkey.revoked:
                sign_keys.add(subkey.keyid)
            
        if sign_keys.intersection(self.key_signatures(id)):
            return True
        else:
            return False

    def key_signatures(self, keyid):
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
            
    def key_export(self, id):
        from pyme.core import Data
        export_keys = Data()
        key = self.key_get(id)
        self.ctx.op_export(key.subkeys[0].fpr, 0, export_keys)
        export_keys.seek(0,0)
        return export_keys.read()

    def keys_export(self, ids):
        from pyme.core import Data
        export_keys = Data()
        keys = [self.key_get(id) for id in ids]
        self.ctx.op_export_keys(keys, 0, export_keys)
        export_keys.seek(0,0)
        return export_keys.read()

    def msg_sign(self, msg, keyid):
        key = self.key_get(keyid)

        if not self.have_secret_key(keyid):
            raise ValueError("You do not have the secret key for %s in your GnuPG keyring."%keyid)
        
        msg = pyme.core.Data(msg)
        sig = pyme.core.Data()

        self.ctx.signers_clear()
        self.ctx.signers_add(key)

        self.ctx.op_sign(msg, sig, pyme.constants.sig.mode.DETACH)

        sig.seek(0,0)
        signedtext = sig.read()
        return signedtext

    def key_okay_encrypt(self, keyid):
        key = self.key_get(keyid)
        if  not self.key_okay(key) or not self.key_validity(key) >= 4:
            return False
        return True

    
    def msg_encrypt(self, msg, keyids, always_trust=False):
        keys = [self.key_get(keyid) for keyid in keyids]

        for key in keys:
            if  not self.key_okay(key) or not self.key_validity(key) >= 4:
                raise ValueError("No UID of the key 0x%s has a sufficient level of validity, set always_trust=True if you want to force encryption."%key.subkeys[0].fpr[-16:])
        
        plain = pyme.core.Data(msg)
        cipher = pyme.core.Data()
        flags = pyme.constants.ENCRYPT_NO_ENCRYPT_TO
        if always_trust:
            flags |= constants.ENCRYPT_ALWAYS_TRUST
        self.ctx.op_encrypt(keys, flags, plain, cipher)
        # TODO: deal with op_encrypt_result
        cipher.seek(0,0)
        return cipher.read()
    

    def sig_verify(self, msg, sig, is_detached=True):
        msg = pyme.core.Data(msg)
        sig = pyme.core.Data(sig)

        if is_detached:
            self.ctx.op_verify(sig, msg, None)
        else:
            self.ctx.op_verify(sig, None, msg)
        result = self.ctx.op_verify_result()

        # List results for all signatures. Status equal 0 means "Ok".
        index = 0
        for sign in result.signatures:
            index += 1
            print "signature", index, ":"
            print "  summary:    ", (sign.summary & pyme.constants.SIGSUM_VALID) == 1
            print "  status:     ", sign.status
            print "  timestamp:  ", sign.timestamp
            print "  fingerprint:", sign.fpr
            print "  uid:        ", self.ctx.get_key(sign.fpr, 0).uids[0].uid

        # Print "unsigned" text. Rewind since verify put plain2 at EOF.
        msg.seek(0,0)
        
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


