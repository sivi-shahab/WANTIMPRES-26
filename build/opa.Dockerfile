# OPA sidecar (PDP). Rebuilt here only so it goes through the same SBOM + cosign signing as our images:
# Kyverno admits nothing in namespace wantimpres26 that the CI key did not sign.
FROM openpolicyagent/opa:1.21.1-static@sha256:4675ab04ad1627f74741d2d9c5142698c79e18b7b09f192587d31d6dba20838e
# The upstream image already runs as 1000:1000; stated again so the IaC scan sees it.
USER 1000:1000
