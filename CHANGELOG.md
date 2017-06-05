## Changelog

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
