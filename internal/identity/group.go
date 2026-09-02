package identity

// GroupRule accepts one group from the upstream and names the group the
// service provider should be told about. The two namespaces are independent:
// an upstream may slugify group names, and a service provider has its own
// naming, so requiring them to be identical would make one hostage to the
// other.
type GroupRule struct {
	// Match is the group name as the upstream reports it.
	Match string
	// Emit is the group name sent to the service provider.
	Emit string
}

// SelectGroup resolves the groups a principal holds to the single group a
// service provider should see. Rules are ordered precedence: the first rule
// whose group the principal holds wins. No rules means no opinion, and the
// caller should pass the principal's groups through unchanged.
func SelectGroup(groups []string, rules []GroupRule) (string, bool) {
	for _, rule := range rules {
		for _, group := range groups {
			if group == rule.Match {
				return rule.Emit, true
			}
		}
	}
	return "", false
}
