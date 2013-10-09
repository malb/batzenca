from email import Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.encoders import encode_7or8bit

from email import encoders
from email.message import Message
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import os
import mimetypes

class PGPMimeMessage(object):
    def __init__(self, to, cc=None, body=None, attachments=None):
        self.to = tuple(to)
        self.cc = tuple(cc) if cc else tuple()

        body = MIMEText(body.encode('utf-8'), 'plain', 'utf-8')
        body.add_header('Content-Disposition', 'inline')

        if attachments is None:
            self.msg = body
        else:
            self.msg = MIMEMultipart()
            self.msg.preamble = 'This is a multi-part message in MIME format.'

            self.msg.attach(body)

            for filename in attachments:
                path = os.path.abspath(filename)
                if not os.path.isfile(path):
                    continue
                # Guess the content type based on the file's extension.  Encoding
                # will be ignored, although we should check for simple things like
                # gzip'd or compressed files.
                ctype, encoding = mimetypes.guess_type(path)
                if ctype is None or encoding is not None:
                    # No guess could be made, or the file is encoded (compressed), so
                    # use a generic bag-of-bits type.
                    ctype = 'application/octet-stream'
                maintype, subtype = ctype.split('/', 1)

                if maintype == 'text':
                    fp = open(path)
                    # Note: we should handle calculating the charset
                    msg = MIMEText(fp.read(), _subtype=subtype)
                    fp.close()

                elif maintype == 'image':
                    fp = open(path, 'rb')
                    msg = MIMEImage(fp.read(), _subtype=subtype)
                    fp.close()

                elif maintype == 'audio':
                    fp = open(path, 'rb')
                    msg = MIMEAudio(fp.read(), _subtype=subtype)
                    fp.close()

                elif maintype == 'application':
                    fp = open(path, 'rb')
                    msg = MIMEApplication(fp.read(),_subtype=subtype, _encoder=encoders.encode_base64)
                    fp.close()

                else:
                    fp = open(path, 'rb')
                    msg = MIMEBase(maintype, subtype)
                    msg.set_payload(fp.read())
                    fp.close()
                    # Encode the payload using Base64
                    encoders.encode_base64(msg)

                # Set the filename parameter
                msg.add_header('Content-Disposition', 'attachment', filename=os.path.basename(path))
                self.msg.attach(msg)
        self.msg.epilogue = ''

    def __call__(self, signer):
        sig = self.sign(signer)

        msg = MIMEMultipart('signed', micalg='pgp-sha1',
                            protocol='application/pgp-signature')
        msg.attach(self.msg)
        msg.attach(sig)
        return msg

    def sign(self, signer):
        from gnupg import gpgobj

        body = flatten(self.msg, fix_cr=True)
        signature = gpgobj.msg_sign(body, signer)
        sig = MIMEApplication(_data=signature,
                              _subtype='pgp-signature; name="signature.asc"',
                              _encoder=encode_7or8bit)
        sig['Content-Description'] = 'This is a digital signature.'
        sig.set_charset('us-ascii')
        return sig


def flatten(msg, fix_cr=False):
    from cStringIO import StringIO
    from email.generator import Generator
    fp = StringIO()
    g = Generator(fp, mangle_from_=False)
    g.flatten(msg)
    text = fp.getvalue()

    if fix_cr:
        return '\r\n'.join(text.splitlines()) + '\r\n'
    else:
        return text
