# METADATA
# description: |
#   Condition operators for data-authored rules (data.wantimpres26.rules). Pure: the caller resolves the field to
#   a value x, so the operators know nothing about where values come from (input, or the computed risk_score).
package wantimpres26.cond

import rego.v1

ops := {"eq", "neq", "in", "not_in", "gte", "lte", "class_any", "class_count_gte"}

# The op is the first argument so OPA's rule index picks one clause instead of trying all of them.
holds("eq", x, v) if x == v

# Missing fields (x = null) count as "not equal": e.g. an unknown region is offshore.
holds("neq", x, v) if x != v

holds("in", x, v) if x in v

holds("not_in", x, v) if not x in v

holds("gte", x, v) if {
	is_number(x)
	x >= v
}

holds("lte", x, v) if {
	is_number(x)
	x <= v
}

# x: content.classes; v: list of globs ("PII_ID.*").
holds("class_any", x, v) if {
	is_array(x)
	some cls in x
	some pattern in v
	glob.match(pattern, ["."], cls.type)
}

# x: content.classes; v: {"type": glob, "min": n}. Counts summed over every matching class.
holds("class_count_gte", x, v) if {
	is_array(x)
	sum([cls.count | some cls in x; glob.match(v.type, ["."], cls.type)]) >= v.min
}
