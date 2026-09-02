package identity

import "testing"

func TestSelectGroupPrefersTheEarlierRule(t *testing.T) {
	rules := []GroupRule{{Match: "ops", Emit: "operators"}, {Match: "staff", Emit: "viewers"}}
	got, ok := SelectGroup([]string{"staff", "ops"}, rules)
	if !ok || got != "operators" {
		t.Fatalf("SelectGroup = %q, %v; want \"operators\", true", got, ok)
	}
}

func TestSelectGroupRenamesAcrossNamespaces(t *testing.T) {
	// The case this exists for: the upstream slugifies, the service provider
	// does not.
	got, ok := SelectGroup([]string{"omada_admins"}, []GroupRule{{Match: "omada_admins", Emit: "omada-admins"}})
	if !ok || got != "omada-admins" {
		t.Fatalf("SelectGroup = %q, %v; want \"omada-admins\", true", got, ok)
	}
}

func TestSelectGroupRefusesAnUnlistedPrincipal(t *testing.T) {
	if got, ok := SelectGroup([]string{"family"}, []GroupRule{{Match: "ops", Emit: "ops"}}); ok {
		t.Fatalf("SelectGroup = %q, true; want refusal", got)
	}
}
