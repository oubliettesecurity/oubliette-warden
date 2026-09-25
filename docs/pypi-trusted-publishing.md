# PyPI Trusted Publishing (OIDC)

`oubliette-warden` publishes to PyPI from this repo (`oubliettesecurity/oubliette-warden`) via
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/). No API token
is stored in GitHub secrets. The workflow is `.github/workflows/publish.yml`.

## One-time setup (maintainer)

CI does not configure PyPI. Before the first tag is pushed, a maintainer must:

1. Sign in at [pypi.org](https://pypi.org) as a maintainer of **oubliette-warden** and open
   https://pypi.org/manage/project/oubliette-warden/settings/publishing/
2. Under **Add a new publisher** → **GitHub**, set:

   | Field | Value |
   |---|---|
   | Owner | `oubliettesecurity` |
   | Repository name | `oubliette-warden` |
   | Workflow name | `publish.yml` |
   | Environment name | `pypi` |

3. The publish job uses `environment: pypi`, so the OIDC claims match the
   publisher above. GitHub creates the `pypi` Environment the first time a job
   references it; create it ahead of time (Settings → Environments) if you want
   required reviewers or a wait timer before a publish.
4. Remove any other publisher on the project that points at a different
   workflow or repository.

## Tag-and-release flow

1. Bump `version` in `pyproject.toml` and `__version__` in `src/oubliette_warden/__init__.py`
   (`tests/test_version_sync.py` fails if they differ), update `CHANGELOG.md`
   if the repo has one, and merge. Do not publish from an untagged commit.
2. Tag the release commit and push the tag:

   ```bash
   git tag vX.Y.Z <commit>
   git push origin vX.Y.Z
   ```

   The workflow triggers only on `v[0-9]*.[0-9]*.[0-9]*` tags.
3. `Publish to PyPI` checks that the tag equals `v` + the pyproject version,
   builds sdist + wheel with uv (Python 3.13), runs `twine check`, runs
   `tests/test_packaging_boundary.py` against the built files (WARDEN_REQUIRE_DIST=1, fail closed), uploads with PEP 740
   attestations and `skip-existing: true`, and creates or updates the GitHub
   Release with the dist files attached.

Manual re-run: **Actions → Publish to PyPI → Run workflow** with an existing
tag. Set **dry_run** to build and gate only (no upload, no GitHub Release).

