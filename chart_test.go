package main

import (
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
