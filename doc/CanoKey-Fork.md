# CanoKey fork maintenance

This fork tracks upstream https://github.com/Yubico/yubikey-manager and adds
a small set of CanoKey compatibility patches on top of each upstream release.

## Branches

- `canokey-X.Y.Z` (version branches): upstream tag `X.Y.Z` plus the CanoKey
  patch set. All development happens on the newest version branch. Version
  branches are never deleted: they are the permanent record of each release
  line, and hotfixes for older lines are committed there directly.
- `dev`: a movable pointer to the tip of the newest version branch. This is
  the GitHub default branch and the target of pull requests. It carries no
  history of its own and is only moved with `git branch -f`.
- `release`: a movable pointer to the commit currently published on PyPI.
  Tags live on this pointer; pushing a `v*` tag publishes to PyPI via CI
  (`.github/workflows/publish.yml`).

To see the current patch set:

    git fetch upstream --tags
    git log --oneline <upstream-tag>..canokey-X.Y.Z
    git diff <upstream-tag>..canokey-X.Y.Z

## Patch set layout

Each version branch is the upstream tag plus thematic patch commits, with a
single version-bump commit (`Set version to ...`) always last:

- Keep patches split by topic, and describe the firmware behavior that
  requires each patch in the commit message. Conflict resolution during
  upstream syncs is guided by these messages.
- The version-bump commit must stay last so that `cherry-pick
  <tag>..canokey-X.Y.Z~1` transports exactly the patch set.
- A version branch may be rebased/amended freely until a tag has been
  published from it; afterwards only new commits on top.

## Versioning

Versions follow the upstream base version with a post-release suffix, e.g.
`5.9.2.post1` for the first CanoKey release based on upstream 5.9.2.
(PyPI does not accept local version identifiers such as `5.9.2+ck1`.)

The `version` field in `pyproject.toml` and `__version__` in
`ykman/__init__.py` must match the release tag (`v<version>`); the publish
workflow fails otherwise.

## Releasing

1. Work on the newest version branch. Make sure it is green: unit tests
   (`uv run pytest`) and `pytest tests/device/` against real CanoKey
   hardware, including old firmware without the management application.
2. Amend the trailing version-bump commit to the release version.
3. Move the `release` pointer and tag:

       git branch -f release canokey-X.Y.Z
       git tag v<version> release
       git push origin release v<version>

4. Publish-fix cycles on the same upstream base increment the suffix
   (`5.9.2.post2`, ...). PyPI ordering guarantees these never shadow a
   newer upstream base.

## Syncing with upstream

When upstream publishes a new release tag (e.g. `5.10.0`):

1. Fetch and create the new version branch, carrying over the patch set
   (excluding the trailing version-bump commit):

       git fetch upstream --tags
       git switch -c canokey-5.10.0 5.10.0
       git cherry-pick 5.9.2..canokey-5.9.2~1

2. Resolve conflicts. They usually concentrate in `yubikit/management.py`,
   `yubikit/piv.py`, `yubikit/openpgp.py` and `yubikit/core/smartcard/`.
   Preserve the firmware behavior described in each patch commit message;
   do not blindly take the upstream side.

3. Run unit tests and the device test suite against real CanoKey hardware
   (see Releasing). Pay special attention to the areas the patch set
   covers: OATH (response chaining workaround), OpenPGP (RSA CRT import),
   PIV (key deletion) and device info reading (admin applet).

4. Add a new trailing version-bump commit (`5.10.0.post1`), then move the
   `dev` pointer:

       git branch -f dev canokey-5.10.0
       git push --force-with-lease origin dev

The old version branch is kept as-is; it can still receive hotfixes and
`X.Y.Z.postN` releases.
