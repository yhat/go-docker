package checks

import "testing"

func TestVersionComp(t *testing.T) {
	versionTests := []struct {
		VStr string
		V    []int
		OK   bool
	}{
		{"1.5.4", []int{1, 5, 4}, true},
		{"1.5.3", []int{1, 5, 4}, false},
		{"1.5.3.5", []int{1, 5, 4}, false},
		{"1.5.4", []int{1, 5}, true},
		{"1.6", []int{1, 5}, true},
	}

	for _, vt := range versionTests {
		err := versionAtLeast(vt.VStr, vt.V)
		if vt.OK && (err != nil) {
			t.Errorf("%s %s %v", vt.VStr, vt.V, err)
		} else if !vt.OK && (err == nil) {
			t.Errorf("expected %s and %s to cause error", vt.VStr, vt.V)
		}
	}
}
