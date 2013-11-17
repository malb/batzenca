import gpgme

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as ByteIO

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

    GPGME_PK_RSA   = gpgme.PK_RSA  
    GPGME_PK_RSA_E = gpgme.PK_RSA_E
    GPGME_PK_RSA_S = gpgme.PK_RSA_S
    GPGME_PK_ELG_E = gpgme.PK_ELG_E
    GPGME_PK_DSA   = gpgme.PK_DSA  
    GPGME_PK_ELG   = gpgme.PK_ELG

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
        self.home_dir = home_dir
        

        self.ctx = gpgme.Context()
        
        if home_dir is not None:
            if not os.path.exists(home_dir):
                os.mkdir(home_dir)
                os.chmod(home_dir, 0700)

            self.ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, self.home_dir)

        self.ctx.keylist_mode = gpgme.KEYLIST_MODE_SIGS
        self.ctx.armor = True

    def key_exists(self, keyid):
        try:
            key = self.ctx.get_key(str(keyid), 0)
            return True
        except gpgme.GpgmeError, e:
            return False

    def key_get(self, keyid):
        if isinstance(keyid, gpgme.Key):
k            return keyid

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
        except gpgme.GpgmeError, e:
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
        except gpgme.GpgmeError, e:
            return False
            
    def key_uid(self, keyid):
        uids = self.key_get(keyid).uids
        return UID(uids[0].name, uids[0].email, uids[0].comment)

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
        export_keys = BytesIO()
        key = self.key_get(id)
        self.ctx.export(key.subkeys[0].fpr, 0, export_keys)
        return export_keys.get_value()

    def keys_export(self, ids):
        raise NotImplementedError
        export_keys = BytesIO()
        keys = [self.key_get(id) for id in ids]
        self.ctx.export_keys(keys, 0, export_keys)
        return export_keys.get_value()

    def msg_sign(self, msg, keyid):
        key = self.key_get(keyid)

        if not self.have_secret_key(keyid):
            raise ValueError("You do not have the secret key for %s in your GnuPG keyring."%keyid)
        
        msg = BytesIO(msg)
        sig = BytesIO()

        self.ctx.signers = (key,)

        self.ctx.sign(msg, sig, gpgme.SIG_MODE_DETACH)
        return sig.get_value()

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
        
        plain = BytesIO(msg)
        cipher = BytesIO()
        flags = 0 # gpgme.ENCRYPT_NO_ENCRYPT_TO is missing
        if always_trust:
            flags |= gpgme.ENCRYPT_ALWAYS_TRUST
        retval = self.ctx.encrypt(keys, flags, plain, cipher)
        return cipher.getvalue()

    def msg_decrypt(self, cipher):
        cipher = BytesIO(cipher)
        plain  = BytesIO()
        self.ctx.op_decrypt(cipher, plain)
        return plain.getvalue()

    def sig_verify(self, msg, sig, is_detached=True):
        msg = BytesIO(msg)
        sig = BytesIO(sig)

        if is_detached:
            result = self.ctx.verify(sig, msg, None)
        else:
            result = self.ctx.verify(sig, None, msg)

        sigs = []
        for sign in result.signatures:
            if (sign.summary & gpgme.SIGSUM_VALID) == 1:
                sigs.append( sign.fpr )

        return tuple(sigs)
        
    def key_sign(self, keyid, signer_keyid, local=False):
        key = self.key_get(keyid)
        signer_key = self.key_get(signer_keyid)

        if not self.have_secret_key(signer_keyid):
            raise ValueError("You do not have the secret key for %s in your GnuPG keyring."%signer_keyid)
        
        out = BytesIO()

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

        self.ctx.signers =(signer_key,)
        self.ctx.edit(key, edit_fnc, helper, out)
        self._key_cache = {} # invalidate the cache

    def key_delete_signature(self, keyid, signer_keyid):
        key = self.key_get(keyid)
        signer_key = self.key_get(signer_keyid)

        out = BytesIO()

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
            self.ctx.edit(key, edit_fnc, cleaner, out)

        self._key_cache = {} # invalidate the cache
            
    def key_set_trust(self, id, trust):
        key = self.key_get(id)

        out = BytesIO()

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
        self.ctx.edit(key, edit_fnc, helper, out)
        self._key_cache = {} # invalidate the cache
        
    def keys_import(self, data):
        self._key_cache = {} # invalidate the cache
        data = BytesIO(data)
        result = self.ctx.import_(data)
        return dict((r.fpr, r.status) for r in result.imports)

    def key_revsig(self, keyid, signer_keyid, code=4, msg=""):
        key = self.key_get(keyid)
        signer_key = self.key_get(signer_keyid)

        if not self.have_secret_key(signer_keyid):
            raise ValueError("You do not have the secret key for %s in your GnuPG keyring."%signer_keyid)
        
        out = BytesIO()

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
        self.ctx.signers = (signer_key,)
        self.ctx.edit(key, edit_fnc, helper, out)
        self._key_cache = {} # invalidate the cache

    def key_edit(self, keyid):
        """
        .. warning:

           This will open an interactive session using rawinput
        """
        key = self.key_get(keyid)
        out = BytesIO()

        helper = {
            "GOT_IT"          : None,
            "NEED_PASSPHRASE" : None,
            "GOOD_PASSPHRASE" : None,
            "EOF"             : None,

            "skip"            : 0, 
            "data"            : out,
        }
        self.ctx.signers = tuple()
        self.ctx.op_edit(key, edit_fnc, helper, out)
        self._key_cache = {} # invalidate the cache
        
# from pygpa

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


