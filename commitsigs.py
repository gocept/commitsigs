# commitsigs.py - sign changesets upon commit
#
# Copyright 2009, 2010 Matt Mackall <mpm@selenic.com> and others
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2, incorporated herein by reference.

"""sign changesets upon commit

This extension will use GnuPG or OpenSSL to sign the changeset hash
upon each commit and embed the signature directly in the changelog.

Use 'hg log --debug' to see the extra meta data for each changeset,
including the signature.

You must first select the desired signature scheme::

  [commitsigs]
  scheme = gnupg

The two recognized schemes are ``gnupg`` (the default) and
``openssl``. If you use ``gnupg``, then you normally wont have to
configure other options. However, if ``gpg`` is not in your path or if
you have multiple private keys, then you may want to set the following
options::

  [commitsigs]
  gnupg.path = mygpg
  gnupg.flags = --local-user me

If you're using different GPG keys for different projects, you can configure
them using a multi-line mapping between key ids and full user-name strings
(where each key id may appear multiple times):

  [commitsigs]
  gnupg.keys =
      ABCDEF12 John Doe <johndoe@example.org>
      34567890 John Doe (work) <johndoe@example.com>

The extension allows only commits where the user name string matches the GPG
key's identity. If it is intentional that the two aren't exactly the same,
sets of aliases may be listed in a file named .hguseraliases sitting in the
repository root. That file contains identity strings, each on their own line,
with blocks of aliases for each identity separated by one or more blank lines:

  John Doe <johndoe@example.org>
  John Doe (feeling cool) <johndoe@example.org>

  Jane Doe <janedoe@example.org>
  Jane Doe (born Smith) <janesmith@example.org>

The ``openssl`` scheme requires a little more configuration. You need
to specify the path to your X509 certificate file and to a directory
filled with trusted certificates::

  [commitsigs]
  scheme = openssl
  openssl.certificate = my-cert.pem
  openssl.capath = trusted-certificates

You must use the ``c_rehash`` program from OpenSSL to prepare the
directoy with trusted certificates for use by OpenSSL. Otherwise
OpenSSL wont be able to lookup the certificates.

The verifysigs command lets you verify the signatures of some or all commits.
If a good signature is found, it tells you the belonging identity and warns
you if it differs from the committing user without being a known alias.

"""

import datetime
import os, tempfile, subprocess, binascii, shlex

from mercurial import (util, scmutil, extensions, revlog, error,
                       encoding, changelog)
from mercurial.node import short, hex, nullid
from mercurial.i18n import _


CONFIG = {
    'scheme': 'gnupg',
    'gnupg.path': 'gpg',
    'gnupg.flags': [],
    'gnupg.keys': '',
    'openssl.path': 'openssl',
    'openssl.capath': '',
    'openssl.certificate': ''
    }


def gnupgsign(msg, user):
    flags = CONFIG["gnupg.flags"]
    keyid = CONFIG.get('gnupg.keymap', {}).get(user)
    if keyid:
        flags.extend(['--local-user', keyid])
    cmd = [CONFIG["gnupg.path"], "--detach-sign"] + flags
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    sig = p.communicate(msg)[0]
    sig_encoded = binascii.b2a_base64(sig).strip()
    gpg_id = gnupgverify(msg, sig_encoded, quiet=True).get('identity')
    if gpg_id not in CONFIG['useraliases'].get(user, (user,)):
        raise error.Abort(
            _('Signature identity %r does not match committing user %r; '
              'check the .hguseraliases file.') % (gpg_id, user))
    return sig_encoded


def gnupgverify(msg, sig, quiet=False):
    sig = binascii.a2b_base64(sig)
    try:
        fd, filename = tempfile.mkstemp(prefix="hg-", suffix=".sig")
        fp = os.fdopen(fd, 'wb')
        fp.write(sig)
        fp.close()
        stderr = quiet and subprocess.PIPE or None

        cmd = [CONFIG["gnupg.path"]] + CONFIG["gnupg.flags"] + \
            ["--status-fd", "1", "--verify", filename, '-']
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=stderr)
        out, err = p.communicate(msg)
        success = 'GOODSIG' in out
        result = dict(
            success=success,
            )
        if success:
            lines = out.splitlines()
            details = []
            for line in lines:
                if 'SIG_ID' in line:
                    timestamp = datetime.datetime.fromtimestamp(
                        int(line.split()[-1]))
                    details.append(_('signature timestamp: %s') %
                                   timestamp.isoformat())
                if 'GOODSIG' in line:
                    keyinfo = line.split('GOODSIG', 1)[1].strip()
                    keyid, identity = keyinfo.split(None, 1)
                    details.append(_('pgp key id: %s') % keyid)
            result.update(
                identity=identity,
                details='; '.join(details),
                )
        return result
    finally:
        try:
            os.unlink(filename)
        except OSError:
            pass


def opensslsign(msg, user):
    try:
        fd, filename = tempfile.mkstemp(prefix="hg-", suffix=".msg")
        fp = os.fdopen(fd, 'wb')
        fp.write(msg)
        fp.close()


        cmd = [CONFIG["openssl.path"], "smime", "-sign", "-outform", "pem",
               "-signer", CONFIG["openssl.certificate"], "-in", filename]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        sig = p.communicate()[0]
        return sig
    finally:
        try:
            os.unlink(filename)
        except OSError:
            pass


def opensslverify(msg, sig, quiet=False):
    try:
        fd, filename = tempfile.mkstemp(prefix="hg-", suffix=".msg")
        fp = os.fdopen(fd, 'wb')
        fp.write(msg)
        fp.close()

        cmd = [CONFIG["openssl.path"], "smime",
               "-verify", "-CApath", CONFIG["openssl.capath"],
               "-inform", "pem", "-content", filename]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate(sig)
        return dict(
            success=err.strip() == "Verification successful",
            )
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

    # strip trailing whitespace and leading and trailing empty lines
    desc = '\n'.join([l.rstrip() for l in desc.splitlines()]).strip('\n')

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


VERIFICATION_RESULT_MESSAGES = {
    0: '%s good signatures',
    1: '%s unsigned commits',
    2: '%s errors while checking',
    3: '%s bad signatures',
}


def get_verification_stats(ui, repo, *revrange, **opts):
    """verify manifest signatures

    Verify repository heads, the revision range specified or all
    changesets. Each verification's result code is one of:

    - 0 if all changesets had valid signatures
    - 1 if there were a changeset without a signature
    - 2 if an exception was raised while verifying a changeset
    - 3 if there were a changeset with a bad signature

    The return value is the stats of all verification results.

    """
    if opts.get('only_heads'):
        revs = repo.heads()
    elif not revrange:
        revs = xrange(len(repo))
    else:
        revs = scmutil.revrange(repo, revrange)

    stats = dict.fromkeys(range(4), 0)
    user_aliases = CONFIG.get('useraliases', {})
    for rev in revs:
        retcode = 0
        ctx = repo[rev]
        h = ctxhash(ctx)
        extra = ctx.extra()
        sig = extra.get('signature')
        if not sig:
            msg = _("** no signature")
            retcode = 1
        else:
            ui.debug(_("signature: %s\n") % sig)
            try:
                scheme, sig = sig.split(":", 1)
                verifyfunc = sigschemes[scheme][1]
                result = verifyfunc(hex(h), sig, quiet=True)
                if result['success']:
                    msg = _("good %s signature") % scheme
                    identity = result.get('identity')
                    if identity:
                        msg += _(' by %s') % identity
                        user = ctx.user()
                        if identity not in user_aliases.get(user, (user,)):
                            msg += _(' but committed by %s') % user
                    details = result.get('details')
                    if details:
                        ui.note(details + '\n')
                else:
                    msg = _("** bad %s signature on %s") % (scheme, short(h))
                    retcode = 3
            except Exception, e:
                msg = _("** exception while verifying %s signature: %s") \
                    % (scheme, e)
                retcode = 2
        stats[retcode] += 1
        if not opts.get('quiet'):
            ui.write("%d:%s: %s\n" % (ctx.rev(), ctx, msg))
    return stats


def verifysigs(ui, repo, *revrange, **opts):
    """verify manifest signatures

    Verify repository heads, the revision range specified or all
    changesets. The return code is the highest of the codes occurring in the
    verification stats.

    """
    stats = get_verification_stats(ui, repo, *revrange, **opts)
    count_revs = sum(stats.values())
    if count_revs > 1:
        ui.write(_('\nchecked %s commits:\n') % count_revs)
        for retcode, count in sorted(stats.items()):
            if count:
                ui.write('  %s\n' %
                         (_(VERIFICATION_RESULT_MESSAGES[retcode]) % count))
    return max(retcode for retcode, count in stats.items() if count)


def verifyallhook(ui, repo, node, **kwargs):
    """verify changeset signatures

    This hook is suitable for use as a ``pretxnchangegroup`` hook. It
    will verify that all pushed changesets carry a good signature. If
    one or more changesets lack a good signature, the push is aborted.
    """
    ctx = repo[node]
    if verifysigs(ui, repo, "%s:" % node) > 0:
        raise error.Abort(_("could not verify all new changesets"))

def verifyheadshook(ui, repo, node, **kwargs):
    """verify signatures in repository heads

    This hook is suitable for use as a ``pretxnchangegroup`` hook. It
    will verify that all heads carry a good signature after push. If
    one or more changesets lack a good signature, the push is aborted.
    """
    ctx = repo[node]
    if verifysigs(ui, repo, True, "%s:" % node, only_heads=True) > 0:
        raise error.Abort(_("could not verify all new changesets"))


def verify_all_warn_hook(ui, repo, node, **kwargs):
    """verify signatures in repository heads

    This hook is suitable for use as a ``pretxnchangegroup`` hook. It
    will examine signatures on incoming commits and write out a warning if
    one or more changesets lack a good signature. Other than that, the
    operation will be unaffected.

    """
    stats = get_verification_stats(ui, repo, "%s:" % node, quiet=True)
    if stats[0] == sum(stats.values()):
        return
    out = _('Warning: signature verification issues with incoming commits. ')
    out += '; '.join(_(VERIFICATION_RESULT_MESSAGES[retcode]) % count
                     for retcode, count in sorted(stats.items())[1:]
                     if count)
    ui.write(out + '\n')


sigschemes = {'gnupg': (gnupgsign, gnupgverify),
              'openssl': (opensslsign, opensslverify)}


def uisetup(ui):
    for key in CONFIG:
        val = CONFIG[key]
        uival = ui.config('commitsigs', key, val)
        if isinstance(val, list) and not isinstance(uival, list):
            CONFIG[key] = shlex.split(uival)
        else:
            CONFIG[key] = uival
    if CONFIG['scheme'] not in sigschemes:
        raise util.Abort(_("unknown signature scheme: %s")
                         % CONFIG['scheme'])
    gnupg_key_lines = CONFIG.get('gnupg.keys')
    if gnupg_key_lines:
        gnupg_key_lines = [
            line.strip() for line in gnupg_key_lines.splitlines()]
        CONFIG['gnupg.keymap'] = {
            username: key for key, username in (
                line.split(None, 1) for line in gnupg_key_lines if line)}
    ui.setconfig('hooks', 'changegroup', verify_all_warn_hook)


def extsetup():

    def add(orig, self, manifest, files, desc, transaction,
            p1=None, p2=None, user=None, date=None, extra={}):
        h = chash(manifest, files, desc, p1, p2, user, date, extra)
        scheme = CONFIG['scheme']
        signfunc = sigschemes[scheme][0]
        extra['signature'] = "%s:%s" % (scheme, signfunc(hex(h), user))
        return orig(self, manifest, files, desc, transaction,
                    p1, p2, user, date, extra)

    extensions.wrapfunction(changelog.changelog, 'add', add)


def reposetup(ui, repo):
    if not hasattr(repo, 'root'):
        return
    CONFIG['useraliases'] = user_aliases = {}
    user_alias_path = repo.wjoin('.hguseraliases')
    if not os.path.isfile(user_alias_path):
        return
    user_ids = set()
    with open(user_alias_path) as user_alias_file:
        for line in user_alias_file:
            line = line.strip()
            if line:
                user_ids.add(line)
                user_aliases[line] = user_ids
            else:
                user_ids = set()


cmdtable = {
    "verifysigs": (verifysigs,
                   [('', 'only-heads', None, _('only verify heads'))], 
                   "[REV...]")
}
