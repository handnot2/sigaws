## Changelog

### v0.6.0

Fixes:

- Enabled AWS Secure Token tests (`post-sts-token`). Use the AWS STS service to obtain
  temporary credentials and the corresponding session token. Use the temporary credentials
  to sign. The session token must be included as a request header or query string parameter
  `X-Amz-Secure-Token`.

  All AWS Signature V4 tests in the testsuite pass. (Exceptions: `post-vanilla-query-nonunreserved`
  and `post-vanilla-query-space`. These tests seem to be wrong.)

  AWS STS are supported only in request signing. They are not supported in the
  verifier (plug_sigaws).

  ([AWS STS Ref](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html))

### v0.5.0

Fixes:

- Handle normalization of path segments during signature computation (issue #6)

  The `normalize-path` tests in the AWS Signature V4 testsuite pass with
  with fix.

### v0.4.0

Fixes:

- Default to "/" when path component not present in URL

### v0.3.0

Fixes:

- aws-sig-v4-testsuite/get-header-value-multiline test fails (issue #3)

  Canonical value computation for request headers with multiline values
  was not correct. Becuase of that the corresponding AWS Signature V4 testsuite
  was failing. Fixed this issue.

- AWS testsuite URL changed - Update README.md (issue #4)

### v0.2.0

Enhancements:

- Support precomputed content hash (issue #2)

Fixes:

- Correct "cryto" to "crypto" (issue #1)
