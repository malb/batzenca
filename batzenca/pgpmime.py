"""
.. module:: pgpmime

.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>

Realises PGP/MIME signatures and encryption.

.. note::

    This module is based on https://pypi.python.org/pypi/pgp-mime/
"""
from email import Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.encoders import encode_7or8bit
from email import encoders
from email.mime.base import MIMEBase
import email

import os
import mimetypes

from batzenca.session import session


class PGPMIMEsigned(MIMEMultipart):
    """
    A MIME-type for PGP/MIME signed messages.

    :param msg: a MIME object
    :param batzenca.database.keys.Key signer: the signing key
    """
    def __init__(self, msg=None, signer=None):
        if msg is None:
            return
        if msg.is_multipart():
            # we need these to get our message correctly parsed by KMail and Thunderbird
            msg.preamble = 'This is a multi-part message in MIME format.'
            msg.epilogue = '' 

        if signer is not None:
            msg_str = flatten(msg)
            sig     = session.gnupg.msg_sign(msg_str, signer.kid)
            sig = MIMEApplication(_data=sig,
                                  _subtype='pgp-signature; name="signature.asc"',
                                  _encoder=encode_7or8bit)
            sig['Content-Description'] = 'This is a digital signature.'
            sig.set_charset('us-ascii')

            MIMEMultipart.__init__(self, 'signed', micalg='pgp-sha1', protocol='application/pgp-signature')
            self.attach(msg)
            self.attach(sig)
            
    @classmethod
    def from_parts(cls, msg, sig):
        """Assemble a PGP/MIME signed message from its two parts: the message and the signature,
        both of which already properly encoded.

        :param msg: a MIME encoded message :param sig: a PGP/MIME signature

        """
        self = PGPMIMEsigned()
        MIMEMultipart.__init__(self, 'signed', micalg='pgp-sha1', protocol='application/pgp-signature')
        self.attach(msg)
        self.attach(sig)
        return self
            
    @property
    def signatures(self):
        """Return a list of keys for which this message has valid signatures.

        :return: a tuple of :class:`batzenca.database.keys.Key` objects
        """
        from batzenca.database.keys import Key
        
        subparts = self.get_payload()
        assert(len(subparts) == 2)
        msg, sig = subparts
        msg_str = flatten(msg)
        sigs = session.gnupg.sig_verify(msg_str, sig.get_payload())
        res = []
        for sig in sigs:
            try:
                key = Key.from_keyid(int(sig[-16:],16))
            except EntryNotFound:
                key = Key(int(sig[-16:],16))
            res.append(key)
        return tuple(res)

    def is_signed_by(self, signer):
        """Return ``True`` if the message is signed by ``signer``

        :param :class:`batzenca.database.keys.Key` signer: the potential signing key

        """
        from batzenca import EntryNotFound, Key

        signatures = self.signatures
            
        for sig in signatures:
            if isinstance(signer, Key):
                if key == signer:
                    return True
            else:
                if key.email == signer:
                    return True
        return False
        
class PGPMIMEencrypted(MIMEMultipart):
    """
    A MIME-type for PGP/MIME encrypted messages.

    :param msg: a MIME object
    :param iterable recipients: an iterable of recipients, where each entry is a
        :class:`batzenca.database.keys.Key` object.
    """
    def __init__(self, msg, recipients):
        MIMEMultipart.__init__(self, 'encrypted', micalg='pgp-sha1', protocol='application/pgp-encrypted')

        body = flatten(msg)
        encrypted = session.gnupg.msg_encrypt(body, [r.kid for r in recipients])

        payload = MIMEApplication(_data=encrypted,
                                  _subtype='octet-stream',
                                  _encoder=encode_7or8bit)
        payload['Content-Disposition'] = 'inline; name="encrypted.asc"'
        payload.set_charset('us-ascii')

        control = MIMEApplication(_data='Version: 1\n',
                                  _subtype='pgp-encrypted',
                                  _encoder=encode_7or8bit)
        control.set_charset('us-ascii')
        
        self.attach(control)
        self.attach(payload)
        self['Content-Disposition'] = 'attachment'

    def decrypt(self):
        """
        Decrypt this encrypted PGP/MIME message.

        :return: a MIMEType object
        """
        subparts = self.get_payload()
        assert(len(subparts) == 2)
        control, payload = subparts

        payload = payload.get_payload()
        raw = session.gnupg.msg_decrypt(payload)
        msg = email.message_from_string(raw)

        if msg.is_multipart():
            subparts = msg.get_payload()
            if len(subparts) == 2:
                msg, sig = subparts
                if "pgp-signature" in sig.get_content_subtype():
                    return PGPMIMEsigned.from_parts(msg, sig)
        return msg
        
def PGPMIME(msg, recipients, signer):
    """Construct a PGP/MIME signed and encrypted message from MIME message ``msg``, signed by
    ``signer`` and encrypted for all entries of ``recipients``.

    :param msg: the message to be signed and encrypted
    :param iterable recipients: an iterable of recipients, where each entry is a
        :class:`batzenca.database.keys.Key` object.
    :param signer: a signing key as an object of type :class:`batzenca.database.keys.Key`

    :return: a PGP/MIME encrypted message, containing a PGP/MIME signed message.
    """
    return PGPMIMEencrypted( PGPMIMEsigned(msg, signer), recipients)

def flatten(msg):
    from cStringIO import StringIO
    from email.generator import Generator
    fp = StringIO()
    g = Generator(fp, mangle_from_=False)
    g.flatten(msg)
    text = fp.getvalue()

    return '\r\n'.join(text.splitlines()) + '\r\n'
