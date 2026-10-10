# Third-party notices

CTIParsor is released under the [Apache License 2.0](LICENSE). This
repository and the image built from it also carry the files below, copied
from other projects. Each keeps its own copyright and licence. The licence
texts are in [LICENSES/](LICENSES/), and [REUSE.toml](REUSE.toml) gives the
same information per file in the [REUSE](https://reuse.software) format,
which `reuse lint` checks in CI.

Every file listed as unmodified was compared byte for byte with its source
on 2026-10-10.

| Files | Source | Copyright | Licence | Modified |
|---|---|---|---|---|
| `pipeline/detection/opencti_snort/` | [OpenCTI](https://github.com/OpenCTI-Platform/opencti), `opencti-graphql/src/python/runtime/snort/` (ADR-0070) | 2021-2026 Filigran SAS | Apache-2.0 | no |
| `pipeline/data/stix2_json_schemas/` | [oasis-open/cti-stix2-json-schemas](https://github.com/oasis-open/cti-stix2-json-schemas), commit `9af1db4` | 2016 OASIS Open | BSD-3-Clause | no |
| `frontend/public/stix-icons/` (27 SVG) | [eclecticiq/stix-icons](https://github.com/eclecticiq/stix-icons), `White/normal/SVG/` | EclecticIQ | CC-BY-SA-4.0 | no |
| `frontend/public/stix-viz/stix2viz/stix2viz/stix2viz.js`, `frontend/public/stix-viz/application.css` | [oasis-open/cti-stix-visualization](https://github.com/oasis-open/cti-stix-visualization) | 2016 OASIS Open | BSD-3-Clause | no |
| `frontend/public/stix-viz/stix-viz.html`, `frontend/public/stix-viz/stix-viz-app.js` | adapted from cti-stix-visualization's `index.html` and `application.js` | 2016 OASIS Open; CTIParsor contributors | BSD-3-Clause AND Apache-2.0 | yes |
| `frontend/public/stix-viz/stix2viz/stix2viz/icons/` (52 PNG) | cti-stix-visualization, icons by Bret Jordan | Bret Jordan | CC-BY-SA-4.0 | no |
| `frontend/public/stix-viz/stix2viz/visjs/vis-network.min.js` | [vis-network](https://github.com/visjs/vis-network), as cti-stix-visualization ships it | 2011-2017 Almende B.V.; 2017-2019 visjs contributors | Apache-2.0 OR MIT | no |
| `frontend/public/stix-viz/require.js` | [RequireJS](https://github.com/requirejs/requirejs) 2.3.6, as cti-stix-visualization ships it | jQuery Foundation and other contributors | MIT | no |
| `frontend/public/stix-viz/domReady.js` | [RequireJS domReady](https://github.com/requirejs/domReady) 2.0.1, as cti-stix-visualization ships it | 2010-2012 The Dojo Foundation | MIT OR BSD-3-Clause | no |
| `pipeline/data/attack_relationships.json`, `attack_retrieval_corpus.json`, `attack_retrieval_embeddings.npy`, `gazetteer.json` | built from MITRE ATT&CK's STIX bundles in [mitre/cti](https://github.com/mitre/cti) (`scripts/build_indexes.py`) | The MITRE Corporation | LicenseRef-MITRE-ATTACK | derived |
| `pipeline/data/mitre_index.json`, `mitre_embeddings.npy`, `mitre_embeddings_meta.json`, `frontend/public/mitre_index.json` | built from ATT&CK and CAPEC's STIX bundles in mitre/cti | The MITRE Corporation | LicenseRef-MITRE-ATTACK AND LicenseRef-MITRE-CAPEC | derived |

## MITRE ATT&CK and CAPEC

The ATT&CK and CAPEC licences ask every copy to reproduce MITRE's copyright
designation:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with
> the permission of The MITRE Corporation.

> Copyright © 2007–2026, The MITRE Corporation.

ATT&CK® is a registered trademark and CAPEC™ a trademark of The MITRE
Corporation.

## CC BY-SA 4.0: the STIX icons

The two icon sets are shared under the terms of CC BY-SA 4.0, unmodified.
If you modify them, your version is shared under the same licence.

## What is not in this repository

- **Detection rule corpora** (Sigma, YARA, Suricata, Snort…) are cloned at
  bootstrap, not shipped here (`detection_corpora.yaml`). Each rule keeps its
  corpus's licence: the store records it per rule, and a rule export's
  manifest lists it.
- **Python and npm packages** are installed from their registries, at the
  versions the locks name. Their licences ship with each package, and the
  image's SBOM lists them (ADR-0075).
- **Models** (spaCy, CyNER, GLiNER, sentence-transformers) are downloaded at
  bootstrap under their own licences.
