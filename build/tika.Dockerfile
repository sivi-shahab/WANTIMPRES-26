# Apache Tika server (file extraction for PDF / legacy Office, ticket 31). Rebuilt here only so it goes through
# the same SBOM + cosign signing as our images: Kyverno admits nothing in namespace wantimpres26 the CI key did not sign.
# Runs as the upstream non-root user (35002) under gVisor, without egress (deploy/base/connector-worker.yaml).
FROM apache/tika:3.2.3.0@sha256:3fafa194474c5f3a8cff25a0eefd07e7c0513b7f552074ad455e1af58a06bbea
USER 35002:35002
