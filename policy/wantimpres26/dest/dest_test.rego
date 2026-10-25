package wantimpres26.dest_test

import rego.v1

import data.wantimpres26.dest

catalog := {"apps": {"chatgpt": {"sanction": "sanctioned", "region": "US", "ojk_approval_ref": "S-123/D.03/2026"}}}

test_catalog_overrides_pep if {
	d := dest.destination with input as {"destination": {"app_id": "chatgpt", "sanction": "unsanctioned", "region": "unknown"}}
		with data.wantimpres26.catalog as catalog
	d == {"app_id": "chatgpt", "sanction": "sanctioned", "region": "US", "ojk_approval_ref": "S-123/D.03/2026"}
}

test_unknown_app_keeps_pep_values if {
	d := dest.destination with input as {"destination": {"app_id": "llm-internal", "sanction": "sanctioned", "region": "ID"}}
		with data.wantimpres26.catalog as catalog
	d == {"app_id": "llm-internal", "sanction": "sanctioned", "region": "ID"}
}
