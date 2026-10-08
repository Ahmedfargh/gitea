// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secretscan

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskSecret(t *testing.T) {
	assert.Equal(t, "AKIA************MPLE", MaskSecret("AKIAIOSFODNN7EXAMPLE"))
	assert.Equal(t, "********", MaskSecret("short"))
	assert.Equal(t, "-----BEGIN RSA PRIVATE KEY----- [REDACTED]", MaskSecret("-----BEGIN RSA PRIVATE KEY-----"))
	assert.Equal(t, "ghp_********************************wxyz", MaskSecret("ghp_12345678901234567890123456789012wxyz"))
}

func TestScanPatch_DetectSecrets(t *testing.T) {
	patch := `commit a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
Author: Developer <dev@example.com>
Date:   Thu Oct 8 12:00:00 2026 +0000

    Add cloud config and keys

diff --git a/config/aws.env b/config/aws.env
new file mode 100644
--- /dev/null
+++ b/config/aws.env
@@ -0,0 +1,3 @@
+# AWS Config
+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
+AWS_REGION=us-west-2
diff --git a/certs/server.key b/certs/server.key
new file mode 100644
--- /dev/null
+++ b/certs/server.key
@@ -0,0 +1,3 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA0m...
+-----END RSA PRIVATE KEY-----
`
	findings, err := ScanPatch(strings.NewReader(patch))
	require.NoError(t, err)
	require.Len(t, findings, 2)

	assert.Equal(t, "AWS Access Key ID", findings[0].RuleName)
	assert.Equal(t, "config/aws.env", findings[0].Path)
	assert.Equal(t, 2, findings[0].LineNumber)
	assert.Equal(t, "AKIA************MPLE", findings[0].SecretMasked)

	assert.Equal(t, "Private Key", findings[1].RuleName)
	assert.Equal(t, "certs/server.key", findings[1].Path)
	assert.Equal(t, 1, findings[1].LineNumber)
	assert.Contains(t, findings[1].SecretMasked, "[REDACTED]")
}

func TestScanPatch_CleanDiff(t *testing.T) {
	patch := `commit a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
Author: Developer <dev@example.com>
Date:   Thu Oct 8 12:00:00 2026 +0000

    Update README

diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -5,2 +5,3 @@
 # My Project
-Old line
+New clean line
+Another safe line
`
	findings, err := ScanPatch(strings.NewReader(patch))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestScanPatch_SkipTrailer(t *testing.T) {
	patch := `commit a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
Author: Developer <dev@example.com>
Date:   Thu Oct 8 12:00:00 2026 +0000

    Add mock test credentials
    
    [skip-secret-scan]

diff --git a/tests/fixture.env b/tests/fixture.env
new file mode 100644
--- /dev/null
+++ b/tests/fixture.env
@@ -0,0 +1,1 @@
+AWS_KEY=AKIAIOSFODNN7EXAMPLE
`
	findings, err := ScanPatch(strings.NewReader(patch))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestFormatFindings(t *testing.T) {
	findings := []Finding{
		{
			CommitID:     "a1b2c3d4e5f6",
			Path:         "deploy/prod.env",
			LineNumber:   15,
			RuleName:     "AWS Access Key ID",
			SecretMasked: "AKIA************MPLE",
		},
	}
	out := FormatFindings(findings)
	assert.Contains(t, out, "Gitea Push Protection")
	assert.Contains(t, out, "AWS Access Key ID")
	assert.Contains(t, out, "deploy/prod.env:15")
	assert.Contains(t, out, "AKIA************MPLE")
	assert.Contains(t, out, "[skip-secret-scan]")
}
