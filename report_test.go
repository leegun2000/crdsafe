package main

import (
	"strings"
	"testing"
)

// crdsafe tells people to paste its report into public threads, and the apiserver embeds the
// offending value in a validation error. A stored repoURL can carry a token, a bucket name, an
// internal host. --redact has to remove those without removing the point of the report.
func TestRedactRemovesStoredValuesAndClusterIdentity(t *testing.T) {
	secret := "https://ci:ghp_exampleTokenValue1234567890@git.internal.example.com/repo.git"
	rep := &Report{
		Chart: "argo-cd", From: "1.0.0", To: "2.0.0",
		Cluster: "arn:aws:eks:eu-west-1:123456789012:cluster/prod",
		K8s:     "v1.33.4-eks-a1b2c3d",
		Findings: []Finding{{
			CRD: "applications.argoproj.io", Version: "v1alpha1", Path: "spec.source.repoURL",
			Kind: KindConstraint, Severity: SevCritical, Ratchet: RatchetTolerated,
			Detail:   "pattern constraint added when there was none previously",
			Affected: []Affected{{Namespace: "argocd", Name: "prod-app", Reason: `Invalid value: "` + secret + `": must be an https URL`}},
		}},
		Warnings: []string{`applications.argoproj.io: listing custom resources failed (Get "https://10.0.4.11:6443/apis/argoproj.io/v1alpha1/applications": dial tcp 10.0.4.11:6443: connect: refused); correlation skipped`},
	}

	var text, jsonOut strings.Builder
	red := rep.redacted()
	red.WriteText(&text)
	if err := red.WriteJSON(&jsonOut); err != nil {
		t.Fatal(err)
	}

	for _, leak := range []string{secret, "ghp_exampleTokenValue1234567890", "git.internal.example.com",
		"123456789012", "arn:aws:eks", "10.0.4.11"} {
		if strings.Contains(text.String(), leak) {
			t.Errorf("text output still contains %q", leak)
		}
		if strings.Contains(jsonOut.String(), leak) {
			t.Errorf("json output still contains %q", leak)
		}
	}

	// What must survive, or the report stops being worth sharing.
	for _, keep := range []string{"applications.argoproj.io", "spec.source.repoURL", "CRITICAL", "Invalid value"} {
		if !strings.Contains(text.String(), keep) {
			t.Errorf("redaction removed %q, which the reader needs", keep)
		}
	}
	if rep.Cluster == "" || !strings.Contains(rep.Findings[0].Affected[0].Reason, secret) {
		t.Error("redacted() must not mutate the original report")
	}
}
