# 1.0.1

- Make logging less noisy by moving cache into to TRACE level

# 1.0.0

## Breaking changes

- Removed public `cloudpassage-lib.core/wcar` macro that was used to speak with
  redis.
- Signature for `cloudpassage-lib.core/fetch-token!` no longer requires a fernet
  key.
- Updated documentation to reflect dependency changes.
- redis and fernet are no longer required. This due to the api changes made in
  PR #73 (https://github.com/RackSec/cloudpassage-lib/pull/73).

# 0.2.7

- Update dependencies
- Hopefully the new `aleph` will address some of the intermittent livelocking
  we've seen in production

# 0.2.6

- Change warn statement to remove the word "error", which was setting off
  alerts (#66)

# 0.2.5

- Switch scans retry logic to exponential backoff, fix exception throwing on
  report error (#61)
- Use the new fernet library capabilities, removing our custom module (#60)

# 0.2.4

- Improve log level granularity (#56)

# 0.2.3

- Add exponential backoff retry logic to the library (#53) and use that
  logic when authenticating (#54)
- Bump the version of manifold to 1.4 (#52)
- Return a `manifold.deferred/deferred` from `get-auth-token!` instead of a
  fully realized value (#51)
- Extract `use-atom-log-appender!` from `scans-test` and place it inside of
  a new `test-utils` namespace (#47)
- Parse streamed json responses instead of realizing byte-streams as strings in
  `core.clj` (#46)

# 0.2.2

- Add retry logic on HTTP errors (#41)

# 0.2.1

- Add some error handling
- Fix a bug in which the last page of a paginated scan was not fetched (#31)
- Add `list-servers!` and `scan-each-server!` API, which allow the end user to
  fetch the most recent scan for each server as opposed to polling over a time
  range (#21)
- Update the various reporting APIs to use the server-level scan logic
- Add docs on preparing a release (#9)

# 0.2.0

- Use kebab-cased keywords in responses provided by `sca-report!`,
  `svm-report!`, and `fim-report!`. (#25)

# 0.1.7

- Add `sca-report!` reporting capability (#20)

# 0.1.6

- Add `svm-report!` reporting capability (#19)

# 0.1.5

- Add `scans-with-details!` functionality
- Improve `fim-report!` by using `scans-with-details!` to add details to scans
  (#10)

# 0.1.4

Redundant release while learning clojars

# 0.1.3

Redundant release while learning clojars

# 0.1.2

Redundant release while learning clojars

# 0.1.1

Redundant release while learning clojars

# 0.1.0

Initial version
