# autosign.py - automatically sign manifests upon commit
#
# Copyright 2009 Matt Mackall <mpm@selenic.com> and others
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2, incorporated herein by reference.

"""automatically sign manifests upon commit

This extension will use GnuPG to sign the manifest hash upon each
commit. The manifest hash is a cryptographic digest of the files in
the repository and their history.

The signature is embedded in the changelog. Use 'hg log --debug' to
see the extra meta data for each changeset, including the signature.
Since the signature is embedded in the changelog, the changelog
information itself is *not* signed. This means that it is possible to
switch commit messages without this being detected by this extension.
"""

import os, tempfile, subprocess, binascii

from mercurial import util, cmdutil, extensions
from mercurial.node import short, hex
from mercurial.i18n import _

def sign(msg):
    p = subprocess.Popen(["gpg", "--detach-sign"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
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

        p = subprocess.Popen(["gpg", "--status-fd", "1", "--verify",
                              filename, '-'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=stderr)
        out, err = p.communicate(msg)
        return 'GOODSIG' in out
    finally:
        try:
            os.unlink(filename)
        except OSError:
            pass

def checksigs(ui, repo, *revrange):
    """check manifest signatures

    Check the revision range specified or all changesets. The return
    code is one of:

    - 0 if all changesets had valid signatures
    - 1 if there were a changeset without a signature
    - 2 if an exception was raised while checking a changeset
    - 3 if there were a changeset with a bad signature

    The final return code is the highest of the above.
    """
    if not revrange:
        revs = xrange(1, len(repo))
    else:
        revs = cmdutil.revrange(repo, revrange)

    retcode = 0
    for rev in revs:
        ctx = repo[rev]
        mn = ctx.changeset()[0]
        extra = ctx.extra()
        sig = extra.get('signature')
        if not sig:
            msg =_("** no signature")
            retcode = max(retcode, 1)
        else:
            ui.debug(_("signature: %s\n") % sig)
            try:
                if verify(hex(mn), sig, quiet=True):
                    msg = _("good signature")
                else:
                    msg = _("** bad signature on %s") % short(mn)
                    retcode = max(retcode, 3)
            except Exception, e:
                msg = _("** exception while verifying: %s") % e
                retcode = max(retcode, 2)
        ui.write("%d:%s: %s\n" % (ctx.rev(), ctx, msg))
    return retcode

def hook(ui, repo, node, **kwargs):
    ctx = repo[node]
    for rev in range(ctx.rev(), len(repo)):
        checksig(ui, repo, rev)

def reposetup(ui, repo):

    class autosignrepo(repo.__class__):

        def _commitctx(self, *args, **kwargs):
            # Make changelog.add intercept the extra dictionary when
            # doing a commit in the repo.

            def add(orig, manifest, files, desc, transaction, p1=None, p2=None,
                  user=None, date=None, extra={}):
                # TODO: We could actually compute the changeset hash
                # from the arguments to this function and sign that
                # instead. It would only require stealing some more
                # code from changelog.add... Signing the manifest will
                # have to do for now.
                extra['signature'] = sign(hex(manifest))
                return orig(manifest, files, desc, transaction,
                            p1, p2, user, date, extra)

            old_add = extensions.wrapfunction(self.changelog, 'add', add)
            n = super(autosignrepo, self)._commitctx(*args, **kwargs)
            self.changelog.add = old_add
            return n

    repo.__class__ = autosignrepo

cmdtable = {
    "checksigs": (checksigs, [], "[REV...]")
}
