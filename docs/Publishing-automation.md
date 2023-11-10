## Contributions, PRs, and publishing

When contributing to packages that use our publishing validation and automation bot:

- if the package version is a stable semver version (`x.y.z`), the latest
  changes have been published to pub. Please add a new changelog section for
  your change, rev the service portion of the version, append `-dev`, and update
  the pubspec version to agree with the new version
- if the package version ends in `-dev`, the latest changes are unpublished;
  please add a new changelog entry for your change in the most recent section.
  When we decide to publish the latest changes we'll drop the `-dev` suffix
  from the package version
- for PRs, the `Publish` bot will perform basic validation of the info in the
  pubspec.yaml and CHANGELOG.md files
- when the PR is merged into the main branch, if the change includes reving to
  a new stable version, a repo maintainer will tag that commit with the pubspec
  version (e.g., `v1.2.3`); that tag event will trigger the `Publish` bot to
  publish a new version of the package to pub.dev

If the `dart pub publish --dry-run` step is failing during PR validation, and
it's for a reason that could legitimately be ignored (publishing using a
pre-release SDK?), repo committers can add the `publish-ignore-warnings` label
to the PR in order to ignore failures from a publishing dry-run. 

## More publishing conventions

For more information on dart-lang package publishing and maintenance conventions,
see https://github.com/dart-lang/sdk/wiki/External-Package-Maintenance.

## For committers: publishing a release

> TLDR: After merging a PR, create a new GitHub release to publish it. This is best done
using the link that firehose creates in the 'Package publishing' comment.

Once a new release is ready to go - the latest bits have landed in the default branch -
it can be published by tagging the commit with a well-formed tag. Generally this is in
the form of `package_name-v1.2.3`; the publishing automation will indicate the correct
tag to use in the PR.

There are two ways to do this. One is by tagging the commit via the command line and
pushing the new tag to the repo. That's correct, but there's a better way.

The 2nd way to publish is by creating a github release (see the `/releases` url of your
repo; e.g., https://github.com/dart-lang/tools/releases). Creating a new release there
will tag the commit as a by-product, which will trigger a release. To create a release:

- go to the `https://github.com/<org>/<repo>/releases` url
- click 'draft a new release'
- in 'choose tag', enter the tag of the correct publishing tag (you'll be creating a new tag)
- in 'release title', enter the same text as the tag (by convention; this area is free-form)
- in 'describe this release', enter the portion of the changelog entry for this release

Firehose will create a hyperlink in it's comment on the PR with all the release information
filled out. After the PR is merged - and we're ready to publish - it is highly recommended to
use this link to create the release (instead of manually filling in the information). This
helps make our releases more standardized and less error-prone.
