package eks

import "testing"

func TestTokenPrefix(t *testing.T) {
	if StsTokenPrefix != "k8s-aws-v1." {
		t.Fatalf("expected token prefix k8s-aws-v1., got: %s", StsTokenPrefix)
	}
}
