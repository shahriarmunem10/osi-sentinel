# Uploading this project to GitHub

## Before you upload
* The default dashboard password is written in the README. That is fine for a course demo, but never deploy this tool to a shared server with it.
* `instance/` holds your database, secret key and API token. `.gitignore` already keeps it out of the repository. Do not remove that rule.
* Review the licence in `LICENSE` (MIT). Change it if your team prefers another one.

## Option A: GitHub website (no Git needed)
1. Sign in at github.com, press **New repository**, name it `osi-sentinel`, add a short description, keep it empty (no README, no .gitignore, no licence), press **Create repository**.
2. Unzip `osi-sentinel.zip` on your computer.
3. On the new repository page press **uploading an existing file**.
4. Open the unzipped folder, select everything inside it (including the `.gitignore` file, which may be hidden in Explorer: View, Show, Hidden items) and drag it into the browser. The browser upload accepts up to 100 files at a time, and this project has fewer.
5. Write a commit message such as "Initial commit" and press **Commit changes**.

## Option B: Git commands (recommended)
Install Git for Windows from git-scm.com, then in the unzipped folder:

```
git init
git add .
git commit -m "Initial commit: OSI Sentinel"
git branch -M main
git remote add origin https://github.com/<your-username>/osi-sentinel.git
git push -u origin main
```
The first push opens a browser window to sign in (Git Credential Manager). If it asks for a password, use a personal access token from GitHub, Settings, Developer settings, Personal access tokens, with the `repo` permission.

## Option C: GitHub Desktop
Install GitHub Desktop, choose File, Add local repository, select the folder, press Publish repository.

## After uploading
* Add the other two team members: repository Settings, Collaborators.
* Add topics: `network-security`, `scapy`, `flask`, `osi-model`, `intrusion-detection`.
* Add two or three screenshots to the README (drag the images into the README editor on GitHub).
* Check that `instance/` and `.venv/` did not appear in the file list.
