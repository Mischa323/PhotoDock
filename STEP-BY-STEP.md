# Step-by-step: get the per-screen colour change into your code

You have 3 changed files in this project's `repo-pr/` folder:
`server.js`, `index.html`, `screens.html` (plus `CHANGES.md`).

This guide takes you from "files in the project" → "PR open on GitHub".

---

## 0. Before you start — one important note
Your **GitHub `main` is older** than your local code: it does **not** have the screens/albums
feature yet. So this branch must be based on your **local** working copy, and at some point your
local screens/albums work also needs to be pushed. This guide assumes you're working in your
**local** `Terminal-Photo-Display` folder (the one that already has `screens.html`).

---

## 1. Download the changed files
- In the chat, click the **download card** ("Per-screen colour — changed files").
- Unzip it. You'll get `server.js`, `index.html`, `screens.html`, `CHANGES.md`.
- (Ignore/​delete `CHANGES.md` and this guide before committing — they're just notes.)

## 2. Open a terminal in your local repo
```bash
cd /path/to/Terminal-Photo-Display
```

## 3. Check your current git state
```bash
git status
git branch
```
- **If you have uncommitted screens/albums work:** commit it first so you have a clean baseline:
  ```bash
  git add -A
  git commit -m "WIP: screens + albums feature"
  ```
- Make sure `git status` shows **"nothing to commit, working tree clean"** before continuing.

## 4. Create a new branch for the colour change
```bash
git checkout -b screens-color
```

## 5. Copy the 3 changed files into the repo (overwrite the originals)
Replace the files at the repo root with the downloaded versions. For example:
```bash
cp ~/Downloads/repo-pr/server.js     ./server.js
cp ~/Downloads/repo-pr/index.html    ./index.html
cp ~/Downloads/repo-pr/screens.html  ./screens.html
```
(Adjust the source path to wherever you unzipped.)

## 6. Sanity-check the diff
```bash
git diff
```
You should see ONLY additions related to colour:
- `server.js`: a `SCREEN_COLORS` array + `color` handling in the 3 `/api/screens` routes.
- `index.html`: colour CSS for tabs + a colour swatch picker in the New Screen modal.
- `screens.html`: a colour picker in the wizard + a coloured accent on device cards.

If you see unrelated changes, stop — the files may have been based on a different version.

## 7. Run it locally and test
```bash
npm install      # if you haven't already
npm start
```
Then in the browser:
1. Go to the main page → **+ New Screen** → you should see a row of **colour swatches**. Pick one, create the screen.
2. The new screen's **tab** should show that colour (dot when inactive, full fill when active).
3. Open **Screens** (`/screens`) → the setup wizard step 1 should also have a colour picker, and device cards should show a coloured left edge matching their screen.

## 8. Commit
```bash
git add server.js index.html screens.html
git commit -m "Screens: per-screen colour (server-stored) + colour pickers"
```

## 9. Push
```bash
git push -u origin screens-color
```

## 10. Open the Pull Request
- The `git push` output prints a link like
  `https://github.com/Mischa323/Terminal-Photo-Display/pull/new/screens-color` — open it.
- Or go to the repo on GitHub and click **"Compare & pull request"**.
- ⚠️ Set the PR **base** to whatever branch holds your screens/albums feature
  (your local `main` if you've pushed it). Do **not** target the stale public `main` unless
  it already has screens/albums — otherwise the PR will show thousands of unrelated changes.

---

## If something goes wrong
- **`git diff` shows the whole file changed / huge diff:** likely a line-ending mismatch.
  Run `git diff --ignore-all-space` to see the real changes. The edits themselves are correct;
  it's just whitespace noise — safe to commit.
- **Want to undo and start over:**
  ```bash
  git checkout -- server.js index.html screens.html   # discard the copies
  git checkout main                                    # or your feature branch
  git branch -D screens-color
  ```
- **Prefer I hand this to Claude Code** to apply against your local repo automatically? Say the word.
