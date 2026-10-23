"""The 'vouch:' keyring source and the legacy keyring warning.

The registry is built and served by the real git-vouch CLI, and keys and
signatures come from real ssh-keygen. Selectors are computed here from
'ssh-keygen -l', never by git-vouch. The upstream-signed samples are
independent oracles for the openssh and openpgp paths.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import patatt
from patatt import (
    RES_BADSIG,
    RES_NOKEY,
    RES_VALID,
    sign_message,
    validate_message,
)

TOPLEVEL = Path(__file__).parent.parent.parent
KEYS = str(TOPLEVEL / '.keys')
GIT_VOUCH = Path(
    os.environ.get('GIT_VOUCH', TOPLEVEL.parent / 'git-vouch' / 'git-vouch')
)
assert GIT_VOUCH.is_file(), f'git-vouch not found at {GIT_VOUCH}; set GIT_VOUCH'

LEGACY = 'verified via legacy keyring'


def run(*args: str, cwd: Path | None = None) -> str:
    cp = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)
    assert cp.returncode == 0, cp.stderr
    return cp.stdout


def selector(pub: Path) -> str:
    """Return 'k-' and the first 16 hex digits of ssh-keygen's SHA256 fingerprint."""
    fpr = run('ssh-keygen', '-l', '-E', 'sha256', '-f', str(pub)).split()[1]
    return 'k-' + base64.b64decode(fpr.removeprefix('SHA256:') + '=').hex()[:16]


class Registry:
    """A registry checkout written by git-vouch and synced with git vouch setup."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / 'registry'
        self.root.mkdir()
        run('git', 'init', '-q', '-b', 'main', cwd=self.root)
        (self.root / 'anchors.json').write_text('["anchor"]')
        self.register('anchor', 'anchor@example.org')

    def key(self, name: str) -> Path:
        """Return the private key file for name, generating it on first use."""
        path = self.tmp / name
        if not path.exists():
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path))
        return path

    def vouch(self, *args: str) -> None:
        run('git', 'vouch', *args, cwd=self.root)

    def register(self, handle: str, email: str) -> None:
        key = self.key(handle)
        self.vouch(
            'register',
            '--sign-with',
            str(key),
            '--handle',
            handle,
            '--name',
            handle.title(),
            '--email',
            email,
            f'{key}.pub',
        )

    def endorse(self, handle: str) -> None:
        self.vouch('endorse', '--sign-with', str(self.key('anchor')), handle)

    def sync(self) -> None:
        run('git', 'add', '-A', cwd=self.root)
        run('git', 'commit', '-q', '--allow-empty', '-m', 'r', cwd=self.root)
        run('git', 'vouch', 'setup', '--registry', str(self.root), cwd=self.tmp)
        patatt.VOUCHCACHE.clear()


@pytest.fixture(autouse=True)
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate git, gpg and the agent; put git-vouch on PATH; return its bin dir."""
    home = tmp_path / 'home'
    home.mkdir()
    gnupg = tmp_path / 'gnupg'
    gnupg.mkdir(mode=0o700)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    (bindir / 'git-vouch').symlink_to(GIT_VOUCH)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('GNUPGHOME', str(gnupg))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', str(home / '.gitconfig'))
    monkeypatch.setenv('PATH', f'{bindir}{os.pathsep}{os.environ["PATH"]}')
    monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
    monkeypatch.delenv('GIT_DIR', raising=False)
    monkeypatch.delenv('XDG_DATA_HOME', raising=False)
    monkeypatch.setattr(patatt, 'VOUCHCACHE', {})
    run('git', 'config', '--global', 'user.name', 'Test')
    run('git', 'config', '--global', 'user.email', 'test@example.org')
    return bindir


@pytest.fixture
def reg(tmp_path: Path) -> Registry:
    """Anchor and alice endorse each other; alice has a current, a retired and a
    revoked key; carol is registered but not endorsed."""
    reg = Registry(tmp_path)
    reg.register('alice', 'alice@example.org')
    reg.register('carol', 'carol@example.org')
    reg.endorse('alice')
    reg.vouch('endorse', '--sign-with', str(reg.key('alice')), 'anchor')
    alice = str(reg.key('alice'))
    for name in ('alice-old', 'alice-bad'):
        reg.vouch('add-key', '--sign-with', alice, f'{reg.key(name)}.pub')
    reg.vouch('retire-key', '--sign-with', alice, f'{reg.key("alice-old")}.pub')
    anchor = str(reg.key('anchor'))
    reg.vouch('revoke', '--sign-with', anchor, f'{reg.key("alice-bad")}.pub')
    reg.sync()
    return reg


def signed(key: Path, identity: str, sel: str) -> bytes:
    msg = (TOPLEVEL / 'samples' / 'unsigned.txt').read_bytes()
    msg = msg.replace(
        b'Konstantin Ryabitsev <konstantin@linuxfoundation.org>',
        f'Someone <{identity}>'.encode(),
        1,
    )
    return sign_message(msg, 'openssh', str(key), identity, sel)


def sample(name: str) -> bytes:
    return (TOPLEVEL / 'samples' / name).read_bytes()


def legacy_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if LEGACY in r.getMessage()]


@pytest.mark.parametrize('sources', [['vouch:'], ['vouch:', KEYS]])
def test_registry_key_verifies_via_vouch(
    reg: Registry, sources: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    sel = selector(reg.tmp / 'alice.pub')
    res = validate_message(signed(reg.key('alice'), 'alice@example.org', sel), sources)
    assert [(r[0], r[1], r[3]) for r in res] == [
        (RES_VALID, 'alice@example.org', f'vouch:alice@example.org/{sel}')
    ]
    assert legacy_warnings(caplog) == []


def test_selector_matches_ignoring_case(reg: Registry) -> None:
    sel = selector(reg.tmp / 'alice.pub').upper()
    res = validate_message(
        signed(reg.key('alice'), 'alice@example.org', sel), ['vouch:']
    )
    assert res[0][0] == RES_VALID


@pytest.mark.parametrize(
    ('signer', 'identity', 'selector_of'),
    [
        ('alice-old', 'alice@example.org', 'alice-old'),  # retired key
        ('alice-bad', 'alice@example.org', 'alice-bad'),  # revoked key
        ('carol', 'carol@example.org', 'carol'),  # registered, email not endorsed
        ('alice', 'nobody@example.org', 'alice'),  # not in the registry
        ('alice', 'alice@example.org', 'carol'),  # wrong selector
    ],
)
def test_no_registry_key(
    reg: Registry, signer: str, identity: str, selector_of: str
) -> None:
    sel = selector(reg.tmp / f'{selector_of}.pub')
    res = validate_message(signed(reg.key(signer), identity, sel), ['vouch:'])
    assert [r[0] for r in res] == [RES_NOKEY]


def test_registry_path_suffix_is_rejected(
    reg: Registry, caplog: pytest.LogCaptureFixture
) -> None:
    sel = selector(reg.tmp / 'alice.pub')
    msg = signed(reg.key('alice'), 'alice@example.org', sel)
    res = validate_message(msg, [f'vouch:{reg.root}'])
    assert [r[0] for r in res] == [RES_NOKEY]
    assert any('takes no registry path' in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize('identity', ['-h@example.org', '--help@example.org'])
def test_option_like_identity_is_not_an_option(reg: Registry, identity: str) -> None:
    """git vouch keys -h@example.org prints usage starting 'usage:' and exits 0."""
    res = validate_message(signed(reg.key('alice'), identity, 'usage:'), ['vouch:'])
    assert [r[0] for r in res] == [RES_NOKEY]


def test_other_key_under_registry_selector_is_badsig(reg: Registry) -> None:
    sel = selector(reg.tmp / 'alice.pub')
    res = validate_message(
        signed(reg.key('carol'), 'alice@example.org', sel), ['vouch:']
    )
    assert [(r[0], r[3]) for r in res] == [
        (RES_BADSIG, f'vouch:alice@example.org/{sel}')
    ]


def test_upstream_sample_via_vouch_output(env: Path, tmp_path: Path) -> None:
    """Feed the upstream key through a stand-in git-vouch; patatt runs it once."""
    key = (
        TOPLEVEL / '.keys/openssh/linuxfoundation.org/konstantin/20211115'
    ).read_text()
    log = tmp_path / 'args'
    stub = env / 'git-vouch'
    stub.unlink()
    stub.write_text(
        f'#!/bin/sh\necho "$@" >> {log}\necho "20211115 {" ".join(key.split()[:2])}"\n'
    )
    stub.chmod(0o755)
    for _ in range(2):
        res = validate_message(sample('openssh-signed.txt'), ['vouch:'])
        assert [(r[0], r[3]) for r in res] == [
            (RES_VALID, 'vouch:konstantin@linuxfoundation.org/20211115')
        ]
    assert log.read_text() == 'keys -- konstantin@linuxfoundation.org\n'


@pytest.mark.parametrize('registered', [False, True])
@pytest.mark.parametrize('name', ['pgp-signed.txt', 'openssh-signed.txt'])
def test_legacy_keyring_verifies_with_warning(
    reg: Registry, registered: bool, name: str, caplog: pytest.LogCaptureFixture
) -> None:
    if registered:
        reg.register('konstantin', 'konstantin@linuxfoundation.org')
        reg.endorse('konstantin')
        reg.sync()
    res = validate_message(sample(name), ['vouch:', KEYS])
    assert [r[0] for r in res] == [RES_VALID]
    keysrc = res[0][3]
    assert keysrc is not None and keysrc.startswith(KEYS)
    warnings = legacy_warnings(caplog)
    assert len(warnings) == 1 and keysrc in warnings[0]


def test_default_gpg_keyring_verifies_with_warning(
    reg: Registry, caplog: pytest.LogCaptureFixture
) -> None:
    run(
        'gpg',
        '--batch',
        '--import',
        f'{KEYS}/openpgp/linuxfoundation.org/konstantin/default',
    )
    res = validate_message(sample('pgp-signed.txt'), ['vouch:'])
    assert [r[0] for r in res] == [RES_VALID]
    keysrc = res[0][3]
    assert keysrc is not None and keysrc.startswith('(default keyring)/')
    assert len(legacy_warnings(caplog)) == 1


@pytest.mark.parametrize('name', ['pgp-signed.txt', 'openssh-signed.txt'])
def test_legacy_line_removed_fails(reg: Registry, name: str) -> None:
    res = validate_message(sample(name), ['vouch:'])
    assert [r[0] for r in res] == [RES_NOKEY]


def test_no_warning_without_vouch_source(caplog: pytest.LogCaptureFixture) -> None:
    res = validate_message(sample('pgp-signed.txt'), [KEYS])
    assert [r[0] for r in res] == [RES_VALID]
    assert legacy_warnings(caplog) == []


def test_git_vouch_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    git = shutil.which('git')
    assert git is not None
    bindir = tmp_path / 'gitonly'
    bindir.mkdir()
    (bindir / 'git').symlink_to(git)
    monkeypatch.setenv('PATH', str(bindir))
    res = validate_message(sample('openssh-signed.txt'), ['vouch:'])
    assert [r[0] for r in res] == [RES_NOKEY]
    assert any(
        "'vouch' is not a git command" in r.getMessage()
        for r in caplog.records
        if r.levelname == 'WARNING'
    )


def test_no_registry_configured(caplog: pytest.LogCaptureFixture) -> None:
    res = validate_message(sample('openssh-signed.txt'), ['vouch:'])
    assert [r[0] for r in res] == [RES_NOKEY]
    assert any('no registry configured' in r.getMessage() for r in caplog.records)
