package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"helm.sh/helm/v4/pkg/cli/values"
)

// A missing local chart used to come back as "repo testdata not found", because Helm reads an
// unresolvable a/b as repo/chart. The path the user typed has to be in the message.
func TestMissingLocalChartNamesThePath(t *testing.T) {
	for _, ref := range []string{
		"testdata/charts/does-not-exist.tgz",
		"./nope",
		"/tmp/definitely-not-here.tar.gz",
	} {
		_, _, err := LoadCRDs(ChartRef{Chart: ref}, values.Options{})
		if err == nil {
			t.Fatalf("%s: want an error", ref)
		}
		if !strings.Contains(err.Error(), ref) {
			t.Errorf("%s: error does not name the path: %v", ref, err)
		}
		if strings.Contains(err.Error(), "repo") {
			t.Errorf("%s: reported as a missing repository rather than a missing file: %v", ref, err)
		}
	}
}

// Helm accepts .json alongside .yaml in crds/ (chart.hasManifestExtension), so a chart can ship a
// CRD as JSON and Helm will install it. crdsafe has to read those, or it would report a clean
// upgrade for a chart it never opened.
func TestJSONChartsAreRead(t *testing.T) {
	crd := func(name, plural, kind string, maxLen int) string {
		return fmt.Sprintf(`{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition",
"metadata":{"name":%q},"spec":{"group":"json.example.com","scope":"Namespaced",
"names":{"plural":%q,"singular":"x","kind":%q},
"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object",
"properties":{"spec":{"type":"object","properties":{"label":{"type":"string","maxLength":%d}}}}}}}]}}`,
			name, plural, kind, maxLen)
	}
	write := func(dir string, maxLen int) string {
		for _, sub := range []string{"crds", "templates"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		files := map[string]string{
			"Chart.yaml":       "apiVersion: v2\nname: jsonchart\nversion: 1.0.0\n",
			"crds/a.json":      crd("fromcrds.json.example.com", "fromcrds", "FromCrds", maxLen),
			"templates/b.json": crd("fromtpl.json.example.com", "fromtpls", "FromTpl", maxLen),
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	root := t.TempDir()
	from := write(filepath.Join(root, "old"), 64)
	to := write(filepath.Join(root, "new"), 8)

	for _, dir := range []string{from, to} {
		crds, _, err := LoadCRDs(ChartRef{Chart: dir}, values.Options{})
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if len(crds) != 2 {
			t.Fatalf("%s: read %d CRDs, want 2 (one from crds/, one from templates/)", dir, len(crds))
		}
	}

	oldCRDs, _, _ := LoadCRDs(ChartRef{Chart: from}, values.Options{})
	newCRDs, _, _ := LoadCRDs(ChartRef{Chart: to}, values.Options{})
	findings, err := DiffCRDs(oldCRDs, newCRDs)
	if err != nil {
		t.Fatal(err)
	}
	if !has(findings, KindConstraint, "spec.label", SevMedium) {
		t.Fatalf("the tightened maxLength in the JSON CRDs was not reported: %+v", findings)
	}
}
