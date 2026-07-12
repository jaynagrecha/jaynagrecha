# Live Fusion Center setup

Upload the entire contents of this package to the root of `jaynagrecha/jaynagrecha`,
including the hidden `.github` directory.

After committing:

1. Open the repository's **Actions** tab.
2. Select **Update live profile telemetry**.
3. Click **Run workflow** once.
4. In **Settings → Actions → General → Workflow permissions**, ensure
   **Read and write permissions** is enabled if the workflow receives a 403 while pushing.

The action runs every six hours and commits only when displayed telemetry changes.

Live fields:
- Public repository count
- Followers
- Stars across non-fork public repositories
- Contributions over the latest 365 days
- Latest pushed repository
- Three recent public GitHub activity events
- A daily rotating MITRE ATT&CK investigation

`data/profile.json` is a last-known-good fallback. Temporary GitHub API errors therefore
do not blank or corrupt the profile.

## Repository count: public vs all owned

Without an extra secret, GitHub Actions correctly displays **PUBLIC REPOS** because
the built-in `GITHUB_TOKEN` cannot enumerate your other private repositories.

To display the same total shown to you in GitHub's Repositories tab:

1. Create a fine-grained personal access token with read access to repository metadata
   for the repositories you want counted.
2. Add it in this profile repository under:
   **Settings → Secrets and variables → Actions → New repository secret**
3. Name the secret exactly: `PROFILE_TOKEN`
4. Run the workflow again.

The dashboard label automatically changes from `PUBLIC REPOS` to `OWNED REPOS`.
