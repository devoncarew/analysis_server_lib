To help developers and reviewers with creating PRs, we provide a Github CI action to do some simple checks. At the moment, we are checking for

* License headers
* Changelog entry
.

The workflow can be used by inserting the following into a `.github/workflows/health.yaml` file in your repository:
```
name: Health
on:
  pull_request:
    branches: [ main ]
    types: [opened, synchronize, reopened, labeled, unlabeled]
jobs:
  health:
    uses: dart-lang/ecosystem/.github/workflows/health.yaml@main
#   with:
#     checks: "version,changelog,license" 
```