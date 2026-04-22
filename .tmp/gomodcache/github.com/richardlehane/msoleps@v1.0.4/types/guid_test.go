package types

import "testing"

func TestGuid(t *testing.T) {
	g, err := GuidFromString("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}")
	if err != nil {
		t.Fatal(err)
	}
	r := g.String()
	if r != "{F29F85E0-4FF9-1068-AB91-08002B27B3D9}" {
		t.Errorf("GUID round trip failed, expecting {F29F85E0-4FF9-1068-AB91-08002B27B3D9}, got %s", r)
	}
	g, err = GuidFromName("Bagaaqy23kudbhchAaq5u2chNd")
	if err != nil {
		t.Fatal(err)
	}
	r = g.String()
	if r != "{20001801-5DE6-11D1-8E38-00C04FB9386D}" {
		t.Errorf("Expecting {20001801-5DE6-11D1-8E38-00C04FB9386D} got %s", r)
	}
}
