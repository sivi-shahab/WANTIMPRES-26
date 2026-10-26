---
title: License
outline: [2, 3]
---

# License

WANTIMPRES-26 is released under the **[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)**.

```text
Copyright 2026 The WANTIMPRES-26 Authors
```

The full license text is in the [`LICENSE`](https://github.com/sivi-shahab/WANTIMPRES-26/blob/main/LICENSE) file, and the copyright notice is in [`NOTICE`](https://github.com/sivi-shahab/WANTIMPRES-26/blob/main/NOTICE).

## Summary

::: info Not legal advice
This summary is for convenience only. The full license text is what applies legally.
:::

**You may:**
- use the code for any purpose, including commercially,
- modify the code and create derivative works,
- distribute the original or modified code,
- use the patents contributors hold on their contributions.

**Provided that you:**
- include a copy of the license and the `NOTICE` file when distributing,
- mark the files you changed,
- keep existing copyright, patent, and attribution notices.

**Limitations:**
- the license grants no right to use the project's name or trademarks,
- the code is provided as is, without warranty,
- the contributors' patent grant ends if you start patent litigation over this work.

## Contributions

Under Section 5 of the license, any contribution you submit to this project is licensed under the Apache License 2.0 unless you explicitly state otherwise. See [Contributing](./contributing) for how to contribute.

## Third-party components

Third-party components keep their own licenses. All of them are compatible with Apache-2.0. CI checks the licenses of Go and Python dependencies with Trivy, and the build fails if a forbidden license is found.

### Direct Go dependencies

| Module | License |
|---|---|
| `github.com/capitalone/fpe` | Apache-2.0 |
| `github.com/coreos/go-oidc/v3` | Apache-2.0 |
| `github.com/go-jose/go-jose/v4` | Apache-2.0 |
| `github.com/google/uuid` | BSD-3-Clause |
| `github.com/jackc/pgx/v5` | MIT |
| `github.com/minio/minio-go/v7` | Apache-2.0 |
| `github.com/open-policy-agent/opa` | Apache-2.0 |
| `github.com/redis/go-redis/v9` | BSD-2-Clause |
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 |
| `github.com/twmb/franz-go` (including `pkg/kadm`, `pkg/sr`) | BSD-3-Clause |
| `golang.org/x/oauth2`, `golang.org/x/text` | BSD-3-Clause |
| `sigs.k8s.io/yaml` | MIT and BSD-3-Clause |

Indirect dependencies are listed in `go.mod` and are checked by Trivy as well.

### Model service (Python)

| Package | License |
|---|---|
| `numpy` 1.26.4 | BSD-3-Clause |
| `onnxruntime` 1.19.2 | MIT |
| `tokenizers` 0.19.1 | Apache-2.0 |

### Models and training data

Model artifacts are not stored in the repository, but their provenance and licenses are recorded in `services/model-inference/MODELS.json`.

| Component | License |
|---|---|
| Base model `distilbert/distilbert-base-multilingual-cased` | Apache-2.0 |
| Internal synthetic data (`evalcorpus`) | Internal, produced by this project |
| Dataset `deepset/prompt-injections` | Apache-2.0 |
| Dataset `jackhhao/jailbreak-classification` | Apache-2.0 |
| Dataset `reshabhs/SPML_Chatbot_Prompt_Injection` | MIT |
| Dataset `cahya/alpaca-id-cleaned` | CC-BY-4.0 |

### Container images

| Image | License |
|---|---|
| `openpolicyagent/opa` | Apache-2.0 |
| `apache/tika` | Apache-2.0 |

### Documentation

| Component | License |
|---|---|
| VitePress, `vitepress-plugin-mermaid`, Mermaid (only to build this site) | MIT |
| The [Code of Conduct](./code-of-conduct), adapted from the Contributor Covenant 2.1 | CC-BY-4.0 |
