// Package policy embeds the Rego modules and data documents the Policy Service bundles.
package policy

import "embed"

// Files holds every module, test and data.json under wantimpres26/ and system/, and the simulation corpus (corpus/*.jsonl,
// labelled canonical inputs; ticket 04 extends it). The bundle builder skips tests and the corpus.
//
//go:embed wantimpres26 system corpus
var Files embed.FS
