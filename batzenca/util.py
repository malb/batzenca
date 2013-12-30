def thunderbird_rules(release):
    """Return an XML string which matches that used by Thunderbird/Icedove to store 'per-recipient
    rules'

    INPUT:

    - ``release`` - an instance of :class:`Release`
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