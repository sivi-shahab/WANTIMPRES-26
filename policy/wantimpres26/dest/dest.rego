# METADATA
# description: |
#   The destination the PDP decides on. For an app in the catalog (data.wantimpres26.catalog, ticket 16), the catalog is
#   the source of truth for sanction, hosting region, training use and the OJK approval reference; a status change reaches every decision with
#   the next release. Apps not in the catalog keep what the PEP sent (PEPs send unsanctioned for those).
package wantimpres26.dest

import rego.v1

app := data.wantimpres26.catalog.apps[input.destination.app_id]

destination := object.union(input.destination, object.filter(app, {"sanction", "region", "trains_on_data", "ojk_approval_ref"})) if app

else := input.destination
