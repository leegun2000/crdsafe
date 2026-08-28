package main

import (
	"testing"

	"helm.sh/helm/v4/pkg/cli/values"
)

// Real charts, pulled once and committed under testdata/charts. These check that extraction and
// classification survive reality; the severity model itself is pinned by the table test in
// diff_test.go. Never assert an exact severity here - the next chart bump would move it.
func TestRealChartPairs(t *testing.T) {
	tests := []struct {
		name      string
		from, to  string
		set       []string
		wantKinds []string
		wantCRDs  int
	}{
		{
			name: "argo-cd adds a required field to ApplicationSet status",
			from: "testdata/charts/argo-cd-7.3.11.tgz", to: "testdata/charts/argo-cd-7.4.0.tgz",
			wantKinds: []string{KindRequiredAdded}, wantCRDs: 3,
		},
		{
			name: "cert-manager narrows rotationPolicy to an enum",
			from: "testdata/charts/cert-manager-v1.7.3.tgz", to: "testdata/charts/cert-manager-v1.8.2.tgz",
			set:       []string{"installCRDs=true"},
			wantKinds: []string{KindEnumNarrowed}, wantCRDs: 6,
		},
		{
			name:      "aws-load-balancer-controller flips the storage version to v1beta1",
			from:      "testdata/charts/aws-load-balancer-controller-0.1.1.tgz",
			to:        "testdata/charts/aws-load-balancer-controller-1.0.8.tgz",
			wantKinds: []string{KindStorageVersion}, wantCRDs: 1,
		},
		{
			name: "istio base moves networking CRDs from v1beta1 to v1 storage",
			from: "testdata/charts/base-1.26.4.tgz", to: "testdata/charts/base-1.27.5.tgz",
			wantKinds: []string{KindStorageVersion}, wantCRDs: 14,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vals := values.Options{Values: tc.set}
			from, _, err := LoadCRDs(ChartRef{Chart: tc.from}, vals)
			if err != nil {
				t.Fatalf("load %s: %v", tc.from, err)
			}
			to, _, err := LoadCRDs(ChartRef{Chart: tc.to}, vals)
			if err != nil {
				t.Fatalf("load %s: %v", tc.to, err)
			}
			if len(to) != tc.wantCRDs {
				t.Errorf("extracted %d CRDs from %s, want %d", len(to), tc.to, tc.wantCRDs)
			}

			findings, err := DiffCRDs(from, to)
			if err != nil {
				t.Fatalf("DiffCRDs: %v", err)
			}
			seen := map[string]int{}
			for _, f := range findings {
				seen[f.Kind]++
			}
			for _, kind := range tc.wantKinds {
				if seen[kind] == 0 {
					t.Errorf("no %s finding; got %v", kind, seen)
				}
			}
			// Every finding must carry enough to correlate, or the live join silently does nothing.
			for _, f := range findings {
				if f.wholeCRD() {
					continue
				}
				if f.Path == "" {
					t.Errorf("%s finding on %s has no path: %+v", f.Kind, f.CRD, f)
				}
			}
		})
	}
}
