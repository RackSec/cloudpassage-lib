# Packaging Releases

We release this software on
[Clojars](https://clojars.org/cloudpassage-lib).

## Getting started with releases

1. First, you will need a Clojars account. You can sign up for one on their
   [website](https://clojars.org/register).

2. You will also need a PGP key for signing the packages. (If you don't already
   have one, you will have to create one.) Use this key to [encrypt a copy of
   your Clojars
   credentials](https://github.com/technomancy/leiningen/blob/792750b7a1bdf0499081c72b197df41cee5ef648/doc/DEPLOY.md#gpg),
   stored at `~/.lein/credentials.clj.gpg`.

   This will allow you to sign copies of the release.

3. Ask a current maintainer to add you to the
   [cloudpassage-lib](https://clojars.org/cloudpassage-lib) group on Clojars.
   Otherwise, you will not have the authorization to upload releases.

## Packaging and uploading a release

1. When you are ready to release a new version of the library, you should let
   everyone else know by opening a pull request to update the change log
   (`CHANGELOG.md`). We have a **release** label you can apply to your pull
   request.

   By convention, the person who reviews and merges this PR will create the new
   release.

   You should consider whether the release is a *patch*, *minor*, or *major*
   release. Patches are small internal changes that no consumer should care
   about. Minor releases contain improvements or new API calls, and do not break
   or change existing functionality. Major releases make "breaking" changes such
   that consumers of the library would have to make changes their code to
   upgrade to the new version. A patch release increments the version number by
   0.0.1; a minor release increments the version number by 0.0.1; finally, a
   major release increments the version number by 0.1.0.

2. Remove the word "-SNAPSHOT" from the version number in `project.clj`. And
   bump the version identifier appropriately (e.g. if this is a major release,
   bump 1.x.y to 2.0.0). Commit the change and create a new tag using the
   library name and the current version number. For example, `git tag
   cloudpassage-lib-1.0.0`

3. run `lein deploy clojars`. You will be asked for a gpg password, your clojars
   username, and password.

4. Bump current version numbers by a patch (x.y.z => x.y.z + 1) and add the
   suffix `-SNAPSHOT`.

5. Push the new tag and commits to master. For example,

```shell
$ git push origin cloudpassage-lib-1.0.0  # push the tag for the current release
$ git push origin master # push the release commits
```

Congratulations! You've completed a release.
