def thunderbird_rules(release):
    """Return an XML string which matches that used by Thunderbird/Icedove to store "per-recipient
    rules"

    :param batzenca.database.releases.Release release: the target release

    """
    import StringIO
    fh = StringIO.StringIO()

    fh.write("""<?xml version="1.0" ?>\n""")
    fh.write("  <pgpRuleList>\n")
    key_ids = [str(key.kid) for key in release.active_keys]
    fh.write("""    <pgpRule email="{%s}" encrypt="2" keyId="%s" negateRule="0" pgpMime="2" sign="2"/>\n"""%(release.mailinglist.email,", ".join(key_ids)))
    fh.write("  </pgpRuleList>\n")
    content = fh.getvalue()
    fh.close()
    return content

    
def plot_nkeys(mailinglists, active_only=True):
    """Write a PDF file which plots the number of (active) keys over time in all releases for all
    ``mailinglists``.

    :param iterable mailinglists: instances of :class:`batzenca.database.mailinglists.MailingList`
    :param boolean active_only: only consider active keys; if ``False`` all keys are considered

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

        plt.plot(x,y, linewidth=2.5, alpha=0.9, marker='o', label=mailinglist.name)

    plt.legend(loc='upper left')
    plt.gcf().set_size_inches(20,5) 
    plt.gcf().autofmt_xdate()
    plt.savefig("-".join([mailinglist.name  for mailinglist in mailinglists]) + ".pdf")


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

def import_new_key(key, peer=None):
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

    """
    from batzenca.database import MailingList, Peer
    
    if peer is None:
        peer = Peer.from_email(key.email)
    if peer is None:
        raise ValueError("No peer provided")

    print " key:: %s"%key
    print "peer:: %s"%peer
    print

    # 1. check
            
    for mailinglist in MailingList.all():
        if peer not in mailinglist.current_release:
            continue
        if not mailinglist.policy.check(key, check_ca_signature=False):
            raise ValueError("key %s does not pass policy check for %s"%(key, mailinglist))
    
    # 2. update peer

    if peer.key and peer.key != key:
        for mailinglist in MailingList.all():
            if peer not in mailinglist.current_release:
                continue
            if mailinglist.policy.ca in peer.key.signatures:
                peer.key.revoke_signature(mailinglist.policy.ca)
    key.peer = peer

    # 3. update mailing lists

    signatures = set([key])
    
    for mailinglist in MailingList.all():
        print "#",mailinglist,"#"
        if peer not in mailinglist.current_release:
            print "skipping"
            print
            continue

        key.sign(mailinglist.policy.ca)
        signatures.add(mailinglist.policy.ca)
        
        if mailinglist.current_release.published:
            _ = mailinglist.new_release()

        mailinglist.current_release.deactivate_invalid()
        if key not in mailinglist.current_release:
            mailinglist.current_release.add_key(key)

        print "done"
        print
        
    for signature in set(key.signatures).difference(signatures):
        key.delete_signature(signature)

    print "signatures:"
    for signature in key.signatures:
        print "-",signature
        