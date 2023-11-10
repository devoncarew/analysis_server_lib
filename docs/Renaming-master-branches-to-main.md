Many of our repos currently use `master` as the name of the default branch; over time we'd like to have them instead use `main` as the name of the default branch.

### Renaming master to main

The work per-repo is fairly modest. For people who want to take this on, here are the steps:

- pre-announce the move (as a GitHub issue or as a communication to the active user group)
- use the rename branch feature to rename `master` to `main`; this is available from the `<org>/<repo>/branches` page. If you do not have rights to rename the `master` branch, ping @devoncarew or @athomas
- update references to the old branch name (generally in the `.github/workflows` workflow files)
- for google3, in `third_party/dart/<packageName>/copy.bara.sky`, update the name of the branch that we sync to (`branch = "main"`)
- message to users that the change was made and how to update any local checkouts

GitHub's doc for this are here: [renaming a branch](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-branches-in-your-repository/renaming-a-branch). In-lined from there: "when you rename a branch on GitHub.com, any URLs that contain the old branch name are automatically redirected to the equivalent URL for the renamed branch. Branch protection policies are also updated, as well as the base branch for open pull requests (including those for forks) and draft releases."

### Updating a local checkout

After a rename, people with local checkouts will need to run:

```
git branch -m master main
git fetch origin
git branch -u origin/main main
git remote set-head origin -a
```

The GitHub UI will prompt users with the above steps the next time they visit the repo page.
