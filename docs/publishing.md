# Publish on a personal GitHub account

The software author in `CITATION.cff` is Gabriele Donno. This package is intended for a new public repository on the author's personal account.

## Upload through the GitHub website

1. Extract the distribution ZIP and open `a2a-authorization-propagation-poc/`.
2. Go to https://github.com/new while signed in to the personal account.
3. Choose the personal account as **Owner**, set the repository name to `a2a-authorization-propagation-poc`, and select **Public**.
4. Leave **Add a README file** off, the `.gitignore` template unset and **Choose a license** unset. The supplied folder already contains the project README and `.gitignore`.
5. Click **Create repository**.
6. On the empty repository page, choose **uploading an existing file** (or **Add file → Upload files** if that menu is shown).
7. Drag the contents of `a2a-authorization-propagation-poc/` into the upload area: its files and its subfolders. Upload the extracted contents rather than the ZIP or its enclosing folder.
8. Confirm that `README.md`, `pyproject.toml`, `uv.lock`, `CITATION.cff`, `.gitignore`, `.env.example`, `SHA256SUMS`, and the project folders are included. The README must be at the repository root.
9. Enter the commit message `Initial thesis research artifact` and save the upload to the default branch.

The clean distribution contains fewer than GitHub's 100-file browser-upload limit, and each file is below the browser size limit. Do this upload before generating a local `.env`, keys, environments or execution outputs: browser uploads do not apply `.gitignore` rules.

The Italian guide next to the project folder is for the author and does not need to be uploaded. After upload, the link to share is the repository URL shown in the browser.

## Alternative: Git command line

With Git installed, open a terminal inside the project folder and run:

```bash
git init -b main
git add .
git status --short
git commit -m "Initial thesis research artifact"
```

Copy the HTTPS repository URL from GitHub, then use it as the remote:

```bash
git remote add origin https://github.com/YOUR_USERNAME/a2a-authorization-propagation-poc.git
git push -u origin main
```

Replace `YOUR_USERNAME` with the actual account name. Authenticate as prompted by Git. The `.gitignore` excludes generated `.env`, keys, Python environments and local execution results for Git-based commits.

Official instructions: https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository and https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github.
