"""
.. module:: utils

.. moduleauthor:: Martin R. Albrecht <martinralbrecht+batzenca@googlemail.com>

Various utility functions.
"""

import sys


def thunderbird_rules(release, mime_encode=False, mime_filename=None):
    """Return an XML string which matches that used by Thunderbird/Icedove to
    store "per-recipient rules"

    :param batzenca.database.releases.Release release: the target release

    :param boolean mime_encode: MIME encode before outputting

    :param str mime_filename: filename used for MIME encoding (default:
        '<mailinglist.name>_rules_<year>-<month>-<day>.xml')

    """
    from io import StringIO
    fh = StringIO()

    fh.write("""<?xml version="1.0" ?>\n""")
    fh.write("  <pgpRuleList>\n")
    key_ids = [str(key.kid.upper().replace("0X","0x")) for key in release.active_keys]
    fh.write("""    <pgpRule email="{%s}" encrypt="2" keyId="%s" negateRule="0" pgpMime="2" sign="2"/>\n"""%(release.mailinglist.email,", ".join(key_ids)))
    fh.write("  </pgpRuleList>\n")
    content = fh.getvalue()
    fh.close()

    if mime_encode:
        from email import encoders
        from email.mime.base import MIMEBase

        xml_rules = MIMEBase('application', 'xml')
        xml_rules.set_payload(content)
        encoders.encode_base64(xml_rules)

        if mime_filename is None:
            mime_filename = "%s_rules_%04d%02d%02d.xml"%(release.mailinglist.name,
                                                         release.date.year, release.date.month, release.date.day)

        xml_rules.add_header('Content-Disposition', 'attachment', filename=mime_filename)
        return xml_rules
    else:
        return content


def gpgconf_rules(release, mime_encode=False, mime_filename=None):
    """Return a string which matches that used GnuPG in gpg.conf to define groups."

    :param batzenca.database.releases.Release release: the target release

    :param boolean mime_encode: MIME encode before outputting

    :param str mime_filename: filename used for MIME encoding (default:
        '<mailinglist.name>_group_<year>-<month>-<day>.conf')

    """
    from io import StringIO
    fh = StringIO()

    key_ids = [str(key.kid) for key in release.active_keys]
    fh.write("group %s = %s\n"%(release.mailinglist.email, " ".join(key_ids)))
    content = fh.getvalue()
    fh.close()

    if mime_encode:
        from email import encoders
        from email.mime.base import MIMEBase

        gpg_rules = MIMEBase('text', 'plain')
        gpg_rules.set_payload(content)
        encoders.encode_base64(gpg_rules)

        if mime_filename is None:
            mime_filename = "%s_group_%04d%02d%02d.conf"%(release.mailinglist.name,
                                                          release.date.year, release.date.month, release.date.day)

        gpg_rules.add_header('Content-Disposition', 'attachment', filename=mime_filename)
        return gpg_rules
    else:
        return content


def plot_nkeys(mailinglists, active_only=True):
    """Write a PDF file which plots the number of (active) keys over time in all releases for all ``mailinglists``.

    :param iterable mailinglists: instances of :class:`batzenca.database.mailinglists.MailingList`

    :param boolean active_only: only consider active keys; if ``False`` all keys are considered


    .. note:: requires matplotlib
    """
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt

    plt.clf()
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m/%d/%Y'))
    for mailinglist in mailinglists:
        x = [release.date for release in mailinglist.releases]
        if active_only:
            y = [len(release.active_keys) for release in mailinglist.releases]
        else:
            y = [len(release.keys) for release in mailinglist.releases]

        plt.plot(x, y, linewidth=2.5, alpha=0.9, marker='o', label=mailinglist.name)

    plt.legend(loc='upper left')
    plt.gcf().set_size_inches(20, 5)
    plt.gcf().autofmt_xdate()
    plt.savefig("-".join([mailinglist.name for mailinglist in mailinglists]) + ".pdf")


def find_orphaned_keys():
    """Find keys in the GnuPG database which do not have an instance of :class:`Key` associated with it.

    This library uses two databases: the GnuPG database of keys and the database storing
    metainformation which the user mostly works with. This function returns those keys in the GnuPG
    database which do not have an entry in the user facing database.
    """
    from batzenca import EntryNotFound, Key, session
    orphans = []
    for key in session.gnupg.ctx.op_keylist_all(None, 0):
        dbkey = None
        for sk in key.subkeys:
            try:
                dbkey = Key.from_keyid(int(sk.keyid,16))
                break
            except EntryNotFound:
                pass
        if dbkey is None:
            orphans.append(Key(int(key.subkeys[0].keyid,16)))
    return tuple(orphans)


def import_new_key(key, peer=None, mailinglists=None, force=False, ignore_policy=False):
    """Import a new ``key`` for ``peer``.

    This function does the following for all mailing lists on which the provided
    ``peer`` is currently subscribed.

    1. check if the key passes policy checks

    2. revoke all signatures on the old key of the provided peer which is
       replaced by the provided ``key``

    3. sign the key with the CA key

    4. create a new release if necessary

    5. add the key the current release

    6. delete all superfluous signatures

    :param batzenca.database.keys.Key key: the new key

    :param batzenca.database.peers.Peer peer: the peer to use in case it cannot
        be determined automtically

    :param iterable mailinglists: a list of mailing lists to consider or
        ``None`` for all.

    :param boolean force: by default a key is only added to a list if the
        matching peer has a key in the current release. If ``force==True`` the
        key is added unconditionally.

    :param ignore_policy: ignore policy violations.

    """
    from batzenca.database import MailingList, Peer

    if peer is None:
        peer = Peer.from_email(key.email)
    if peer is None:
        raise ValueError("No peer provided")

    print(" key:: %s"%key)
    print("peer:: %s"%peer)
    print()

    if mailinglists is None:
        mailinglists = MailingList.all()

    mailinglists = [m for m in mailinglists if force or (peer in m.current_release)]

    # 1. check

    if not ignore_policy:
        for mailinglist in mailinglists:
            if not mailinglist.policy.check(key, check_ca_signature=False):
                raise ValueError("key %s does not pass policy check for %s"%(key, mailinglist))

    # 2. update peer

    if peer.key and peer.key != key:
        for mailinglist in mailinglists:
            if mailinglist.policy.ca in peer.key.signatures:
                peer.key.revoke_signature(mailinglist.policy.ca)
    key.peer = peer

    # 5. add the key the current release

    signatures = set([key])

    for mailinglist in mailinglists:
        print("# {} #".format(mailinglist))

        key.sign(mailinglist.policy.ca)
        signatures.add(mailinglist.policy.ca)

        if mailinglist.current_release.published:
            mailinglist.new_release()

        mailinglist.current_release.deactivate_invalid()
        if key not in mailinglist.current_release:
            mailinglist.current_release.add_key(key)

        print("done")
        print

    # 6. delete all superfluous signatures
    key.clean(signatures)

    print("signatures:")
    for signature in key.signatures:
        print("-", signature)


def smtpserverize(email):
    """Read BATZENCA_DIR/smtp.cfg and construct smtpserver object for entry matching ``email``

    :param string email: an e-mail address

    It is assumed that smtp.cfg has the following form::

        [email]
        host: example.com
        port: 25
        username: user
        password: secret!
        security: starttls

    Supported values for security are "starttls" and "tls".

    """
    import configparser
    import smtplib
    import os
    import ssl
    from batzenca import session

    context = ssl.create_default_context()

    config = configparser.ConfigParser()
    config.read(os.path.join(session.path, "smtp.cfg"))
    host = config.get(email, 'host')
    port = config.getint(email, 'port')
    security = config.get(email, 'security')

    if security.lower() == 'starttls':
        smtpserver = smtplib.SMTP(host, port=port)
        smtpserver.ehlo(name='localhost')
        smtpserver.starttls(context=context)
        smtpserver.login(config.get(email, "username"), config.get(email, "password"))
    elif security.lower() == 'tls':

        smtpserver = smtplib.SMTP_SSL(host, port=port, context=context)
        smtpserver.ehlo(name='localhost')
        smtpserver.login(config.get(email, "username"), config.get(email, "password"))
    else:
        raise ValueError("value '%s' for security not understood. Supported options are 'starttls' and 'tls'."%security)
    return smtpserver


def publish(mailinglists=None, debug=False, msg="", attach=[]):
    """Publish all outstanding releases.

    :param iterable mailinglists: a list of mailing lists to consider or ``None`` for all.
    :param boolean debug: do not send e-mail to lists but to CA e-mail address.
    :param string msg: message to be included in git commit
    :param list attach: each function in ``attach`` will be called on ``release`` with parameter
        ``mime_encode=True`` and the output attached to the release.
    """
    from batzenca import MailingList, session

    if mailinglists is None:
        mailinglists = MailingList.all()

    published_releases = []
    smtpservers = {}

    for i, mailinglist in enumerate(mailinglists):
        print("%3d. [%s] "%(i, mailinglist), end='')
        release = mailinglist.current_release

        if release.published:
            print()
            continue

        attachments = []
        for attach_fn in attach:
            attachments.append(attach_fn(release, mime_encode=True))

        attachments = tuple(attachments)

        email = release.policy.ca.email

        if email in smtpservers:
            smtpserver = smtpservers[email]
        else:
            smtpserver = smtpserverize(email)
            smtpservers[email] = smtpserver

        release.send(smtpserver, debug=debug, attachments=attachments)

        published_releases.append(mailinglist.name)

        print("published")
        sys.stdout.flush()

    for smtpserver in smtpservers.values():
        smtpserver.quit()

    if not debug:
        msg = msg + " " + ", ".join(published_releases)
        session.commit(verbose=True, snapshot=True, msg=msg)


def new_ca_key(new_key, old_key):
    """Switch CA key from ``old_key`` to ``new_key`` in all mailing lists with a policy matching
    ``old_key``.

    :param new_key: new CA key
    :param old_key: old CA key

    """
    import datetime
    from batzenca import MailingList, Policy, EntryNotFound

    mailinglists = [m for m in MailingList.all() if m.policy.ca == old_key]
    old_policies = set([m.policy for m in mailinglists])

    policy_map = {}
    for old_policy in old_policies:
        new_policy = Policy(old_policy.name,
                            datetime.date.today(),
                            new_key,
                            old_policy.key_len,
                            old_policy.key_lifespan,
                            old_policy.algorithms)
        policy_map[old_policy] = new_policy

    for mailinglist in mailinglists:
        if mailinglist.current_release.published:
            mailinglist.new_release()
        release = mailinglist.current_release
        policy = policy_map[release.policy]
        release.policy = policy
        mailinglist.policy = policy

        for key in release.active_keys:
            if key.is_signed_by(old_key):
                key.sign(new_key)

    try:
        import_new_key(new_key)  # update CA as member
    except EntryNotFound:  # sometimes the CA is no peer
        pass
