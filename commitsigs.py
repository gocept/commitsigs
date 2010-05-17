# commitsigs.py - sign changesets upon commit
#
# Copyright 2009 Matt Mackall <mpm@selenic.com> and others
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2, incorporated herein by reference.

"""sign changesets upon commit

This extension will use GnuPG to sign the changeset hash upon each
commit and embed the signature directly in the changelog.

Use 'hg log --debug' to see the extra meta data for each changeset,
including the signature.
"""

import os, tempfile, subprocess, binascii, shlex

from mercurial import (util, cmdutil, extensions, revlog, error,
                       encoding, changelog)
from mercurial.node import short, hex, nullid
from mercurial.i18n import _


CONFIG = {'gpg.path': 'gpg', 'gpg.flags': []}


def sign(msg):
    cmd = [CONFIG["gpg.path"], "--detach-sign"] + CONFIG["gpg.flags"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    sig = p.communicate(msg)[0]
    return binascii.b2a_base64(sig).strip()


def verify(msg, sig, quiet=False):
    sig = binascii.a2b_base64(sig)
    try:
        fd, filename = tempfile.mkstemp(prefix="hg-", suffix=".sig")
        fp = os.fdopen(fd, 'wb')
        fp.write(sig)
        fp.close()
        stderr = quiet and subprocess.PIPE or None

        cmd = [CONFIG["gpg.path"]] + CONFIG["gpg.flags"] + \
            ["--status-fd", "1", "--verify", filename, '-']
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=stderr)
        out, err = p.communicate(msg)
        return 'GOODSIG' in out
    finally:
        try:
            os.unlink(filename)
        except OSError:
            pass


def chash(manifest, files, desc, p1, p2, user, date, extra):
    """Compute changeset hash from the changeset pieces."""
    user = user.strip()
    if "\n" in user:
        raise error.RevlogError(_("username %s contains a newline")
                                % repr(user))
    user, desc = encoding.fromlocal(user), encoding.fromlocal(desc)

    if date:
        parseddate = "%d %d" % util.parsedate(date)
    else:
        parseddate = "%d %d" % util.makedate()
    extra = extra.copy()
    if 'signature' in extra:
        del extra['signature']
    if extra.get("branch") in ("default", ""):
        del extra["branch"]
    if extra:
        extra = changelog.encodeextra(extra)
        parseddate = "%s %s" % (parseddate, extra)
    l = [hex(manifest), user, parseddate] + sorted(files) + ["", desc]
    text = "\n".join(l)
    return revlog.hash(text, p1, p2)


def ctxhash(ctx):
    """Compute changeset hash from a ``changectx``."""
    manifest, user, date, files, desc, extra = ctx.changeset()
    p1, p2 = ([p.node() for p in ctx.parents()] + [nullid, nullid])[:2]
    date = (int(date[0]), date[1])
    return chash(manifest, files, desc, p1, p2, user, date, extra)


def verifysigs(ui, repo, *revrange):
    """verify manifest signatures

    Verify the revision range specified or all changesets. The return
    code is one of:

    - 0 if all changesets had valid signatures
    - 1 if there were a changeset without a signature
    - 2 if an exception was raised while verifying a changeset
    - 3 if there were a changeset with a bad signature

    The final return code is the highest of the above.
    """
    if not revrange:
        revs = xrange(len(repo))
    else:
        revs = cmdutil.revrange(repo, revrange)

    retcode = 0
    for rev in revs:
        ctx = repo[rev]
        h = ctxhash(ctx)
        extra = ctx.extra()
        sig = extra.get('signature')
        if not sig:
            msg = _("** no signature")
            retcode = max(retcode, 1)
        else:
            ui.debug(_("signature: %s\n") % sig)
            try:
                if verify(hex(h), sig, quiet=True):
                    msg = _("good signature")
                else:
                    msg = _("** bad signature on %s") % short(h)
                    retcode = max(retcode, 3)
            except Exception, e:
                msg = _("** exception while verifying: %s") % e
                retcode = max(retcode, 2)
        ui.write("%d:%s: %s\n" % (ctx.rev(), ctx, msg))
    return retcode


def hook(ui, repo, node, **kwargs):
    """verify changeset signatures

    This hook is suitable for use as a ``pretxnchangegroup`` hook. It
    will verify that all pushed changesets carry a good signature. If
    one or more changesets lack a good signature, the push is aborted.
    """
    ctx = repo[node]
    if verifysigs(ui, repo, "%s:" % node) > 0:
        raise error.Abort(_("could not verify all changeset"))


def uisetup(ui):
    for key in CONFIG:
        val = CONFIG[key]
        uival = ui.config('commitsigs', key, val)
        if isinstance(val, list) and not isinstance(uival, list):
            CONFIG[key] = shlex.split(uival)
        else:
            CONFIG[key] = uival

def extsetup():

    def add(orig, self, manifest, files, desc, transaction,
            p1=None, p2=None, user=None, date=None, extra={}):
        h = chash(manifest, files, desc, p1, p2, user, date, extra)
        extra['signature'] = sign(hex(h))
        return orig(self, manifest, files, desc, transaction,
                    p1, p2, user, date, extra)

    extensions.wrapfunction(changelog.changelog, 'add', add)

cmdtable = {
    "verifysigs": (verifysigs, [], "[REV...]")
}