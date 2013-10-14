"""
Based on https://pypi.python.org/pypi/pgp-mime/
"""
from email import Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.encoders import encode_7or8bit
from email import encoders
from email.mime.base import MIMEBase

import os
import mimetypes

from batzenca.session import session


class PGPMIMEsigned(MIMEMultipart):
    def __init__(self, msg, signer=None):
        if msg.is_multipart():
            # we need these to get our message correctly parsed by KMail and Thunderbird
            msg.preamble = 'This is a multi-part message in MIME format.'
            msg.epilogue = '' 

        if signer is not None:
            msg_str = flatten(msg)
            sig     = session.gnupg.msg_sign(msg_str, signer)
            sig = MIMEApplication(_data=sig,
                                  _subtype='pgp-signature; name="signature.asc"',
                                  _encoder=encode_7or8bit)
            sig['Content-Description'] = 'This is a digital signature.'
            sig.set_charset('us-ascii')

            MIMEMultipart.__init__(self, 'signed', micalg='pgp-sha1', protocol='application/pgp-signature')
            self.attach(msg)
            self.attach(sig)

    def verify(self):
        subparts = self.get_payload()
        assert(len(subparts) == 2)
        msg, sig = subparts
        msg_str = flatten(msg)
        res = session.gnupg.verify_signature(msg_str, sig.get_payload())
        return res

class PGPMIMEencrypted(MIMEMultipart):
    def __init__(self, msg, recipients):

        MIMEMultipart.__init__(self, 'encrypted', micalg='pgp-sha1', protocol='application/pgp-encrypted')

        body = flatten(msg)
        encrypted = session.gnupg.msg_encrypt(body, recipients)

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

def PGPMIME(msg, recipients, signer):
    return PGPMIMEencrypted( PGPMIMEsigned(msg, signer), recipients)

def flatten(msg):
    from cStringIO import StringIO
    from email.generator import Generator
    fp = StringIO()
    g = Generator(fp, mangle_from_=False)
    g.flatten(msg)
    text = fp.getvalue()

    return '\r\n'.join(text.splitlines()) + '\r\n'
