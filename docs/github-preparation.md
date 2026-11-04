# Preparing and handing off the private Git repository

## What preparation does

- Organizes options under `deployments/`, with tenant-boundary diagrams.
- Keeps original implementation paths stable for local run recovery.
- Uses an exact publication manifest plus deny-by-default ignore rules.
- Provides offline content/path checks, local hooks and a CI validation job.
- Excludes real local settings, approvals, state, logs, inventories and tools.

It does **not** create a GitHub repository, configure a remote, create a commit,
push, accept Marketplace terms, change credentials or deploy/delete resources.

## Validate locally

From the repository root:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_publication.py --worktree
python3 scripts/check_publication.py --staged
```

The staged check inspects index content, not just current file contents. This
matters when a file was sanitized after an earlier sensitive version was staged.
The push hook additionally scans the complete history reachable from the exact
ref tips Git is about to push. Local editor/agent checkpoint refs are not part
of an ordinary branch push and are not scanned unless explicitly pushed.
The standalone `--history` check covers branches, tags, remote-tracking refs
and HEAD, not unrelated local tool refs.

The scanner reports **path, line and category**, not the matched value. Do not
disable a finding just because the destination repository is private.

## Install local hooks after cloning

```bash
git config --local core.hooksPath .githooks
```

Hooks are local configuration and do not automatically install on another
developer's clone. The CI job is the second line of defense; require it in
GitHub branch protection/rulesets after the remote exists.

## Before the first commit

1. Review `git status --short` and `git diff --cached` locally.
2. Confirm the index contains exactly the intended publication files.
3. Check `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT` locally.
   These commands can display personal information; do not paste their output
   into remote issues or shared logs.
4. If required by your privacy policy, configure a GitHub-provided no-reply
   address locally. Do not invent an address or change global Git identity.
5. Confirm repository visibility, owner organization, collaborator access,
   licensing and approved GitHub data classification with the owner.

No commit is created automatically by this preparation.

## Before the first push

Create the private destination through your approved organizational process.
Then, after verifying the destination, configure its remote manually.
No URL is preconfigured in this project.

Run:

```bash
python3 scripts/check_publication.py --staged --history
git remote -v
```

Review remote output locally. Do not bypass the push hook. Private URLs can
still point to the wrong organization or an unexpectedly public repository.

After upload, confirm private visibility and enable the required validation
check. Do not add Azure deployment credentials to GitHub just to run offline
tests.

## Limitations

Pattern scanning and allowlists are defense-in-depth, not a guarantee of
complete data-loss prevention. Arbitrary internal prose, images, renamed files,
encoded data and future credential formats require human review.

Retained ignored local files remain sensitive on the workstation. Ignoring them
does not encrypt, erase or rotate them. They remain available for live-lab
resume/cleanup and are not intended Git content.
