# Third-party notices

CTIParsor is released under the [Apache License 2.0](LICENSE). This
repository and the image built from it also carry the files below, copied
from other projects. Each keeps its own copyright and licence. The licence
texts are in [LICENSES/](LICENSES/), and [REUSE.toml](REUSE.toml) gives the
same information per file in the [REUSE](https://reuse.software) format,
which `reuse lint` checks in CI.

Every file listed as unmodified was compared byte for byte with its source
on 2026-10-10, and the web fonts with their Fontsource packages on 2026-10-30.

| Files | Source | Copyright | Licence | Modified |
|---|---|---|---|---|
| `pipeline/detection/opencti_snort/` | [OpenCTI](https://github.com/OpenCTI-Platform/opencti), `opencti-graphql/src/python/runtime/snort/` (ADR-0070) | 2021-2026 Filigran SAS | Apache-2.0 | no |
| `pipeline/data/stix2_json_schemas/` | [oasis-open/cti-stix2-json-schemas](https://github.com/oasis-open/cti-stix2-json-schemas), commit `9af1db4` | 2016 OASIS Open | BSD-3-Clause | no |
| `docs/gazetteer-ordinary-words.md` (excerpts) | short excerpts of [AnnoCTR](https://github.com/boschresearch/anno-ctr-lrec-coling-2024) texts, whitespace-normalised and clipped, with links to their source lines | Bosch Research and AnnoCTR contributors | CC-BY-SA-4.0 (the document as a whole) | excerpted |
| `frontend/public/stix-icons/` (27 SVG) | [eclecticiq/stix-icons](https://github.com/eclecticiq/stix-icons), `White/normal/SVG/` | EclecticIQ | CC-BY-SA-4.0 | no |
| `frontend/public/stix-viz/stix2viz/stix2viz/stix2viz.js`, `frontend/public/stix-viz/application.css` | [oasis-open/cti-stix-visualization](https://github.com/oasis-open/cti-stix-visualization) | 2016 OASIS Open | BSD-3-Clause | no |
| `frontend/public/stix-viz/stix-viz.html`, `frontend/public/stix-viz/stix-viz-app.js` | adapted from cti-stix-visualization's `index.html` and `application.js` | 2016 OASIS Open; CTIParsor contributors | BSD-3-Clause AND Apache-2.0 | yes |
| `frontend/public/stix-viz/stix2viz/stix2viz/icons/` (52 PNG) | cti-stix-visualization, icons by Bret Jordan | Bret Jordan | CC-BY-SA-4.0 | no |
| `frontend/public/stix-viz/stix2viz/visjs/vis-network.min.js` | [vis-network](https://github.com/visjs/vis-network), as cti-stix-visualization ships it | 2011-2017 Almende B.V.; 2017-2019 visjs contributors | Apache-2.0 OR MIT | no |
| `frontend/public/stix-viz/require.js` | [RequireJS](https://github.com/requirejs/requirejs) 2.3.6, as cti-stix-visualization ships it | jQuery Foundation and other contributors | MIT | no |
| `frontend/public/stix-viz/domReady.js` | [RequireJS domReady](https://github.com/requirejs/domReady) 2.0.1, as cti-stix-visualization ships it | 2010-2012 The Dojo Foundation | MIT OR BSD-3-Clause | no |
| `frontend/public/fonts/` (15 `*.woff2`, `OFL.txt`) | [Fontsource](https://fontsource.org) variable packages `@fontsource-variable/inter` 5.3.0, `@fontsource-variable/source-serif-4` 5.3.1 and `@fontsource-variable/jetbrains-mono` 5.3.0, of [rsms/inter](https://github.com/rsms/inter), [adobe-fonts/source-serif](https://github.com/adobe-fonts/source-serif) and [JetBrains/JetBrainsMono](https://github.com/JetBrains/JetBrainsMono); the Latin, Latin Extended, Cyrillic, Cyrillic Extended and Greek subsets | 2016 The Inter Project Authors; 2020 The JetBrains Mono Project Authors; 2014-2021 Adobe Systems Incorporated | OFL-1.1 | no |
| `pipeline/data/warninglists.json` | three lists of [MISP/misp-warninglists](https://github.com/MISP/misp-warninglists), commit `af01b1d` (security-provider-blogpost, automated-malware-analysis, tranco10k; `scripts/build_warninglists.py`) | MISP project contributors | CC0-1.0 | values lower-cased and sorted |
| `pipeline/data/attack_relationships.json`, `attack_revoked.json`, `attack_retrieval_corpus.json`, `attack_retrieval_embeddings.npy`, `gazetteer.json` | the default ATT&CK track (release 19.2): built from MITRE ATT&CK's STIX bundles in [mitre/cti](https://github.com/mitre/cti) (`scripts/build_indexes.py`; ADR-0087) | The MITRE Corporation | LicenseRef-MITRE-ATTACK | derived |
| `pipeline/data/mitre_index.json`, `mitre_embeddings.npy`, `mitre_embeddings_meta.json` | the default ATT&CK track: built from ATT&CK and CAPEC's STIX bundles in mitre/cti | The MITRE Corporation | LicenseRef-MITRE-ATTACK AND LicenseRef-MITRE-CAPEC | derived |
| `pipeline/data/attack/20.0/attack_relationships.json`, `attack_revoked.json`, `attack_retrieval_corpus.json`, `attack_retrieval_embeddings.npy`, `gazetteer.json` | the v20.0 ATT&CK track: built from the STIX bundles of the v20.0 release of [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) (`scripts/build_attack_release.py`; ADR-0087) | The MITRE Corporation | LicenseRef-MITRE-ATTACK | derived |
| `pipeline/data/attack/20.0/mitre_index.json`, `mitre_embeddings.npy`, `mitre_embeddings_meta.json` | the v20.0 ATT&CK track: built from the same v20.0 bundles; its CAPEC entries are carried over from the default track's `mitre_index.json` | The MITRE Corporation | LicenseRef-MITRE-ATTACK AND LicenseRef-MITRE-CAPEC | derived |

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

Each of these is named below with the licence its own project states. A
licence marked "not verified" was not read from its source.

- **Detection rule corpora** (Sigma, YARA, Suricata…) are cloned at
  bootstrap: see [Detection rule corpora](#detection-rule-corpora).
- **Python and npm packages** are installed from their registries, at the
  versions the locks name. Their licences ship with each package, and the
  image's SBOM lists them (ADR-0075).
- **Models** are downloaded at bootstrap: see
  [Models downloaded at bootstrap](#models-downloaded-at-bootstrap).
- **Container images and system packages**: see
  [Container images and system packages](#container-images-and-system-packages).

## Detection rule corpora

The corpora are not in this repository or in the image. `bootstrap` (and
`scripts/sync_corpora.py`) clones the enabled ones from their upstream
repositories onto the operator's machine, under `corpora/`, and the rule store
then holds their rules. Each corpus keeps the licence `detection_corpora.yaml`
records for it, verified from its repository when the corpus was added.

- **No licence is opt-in.** A corpus whose licence is `none` (no LICENSE file
  upstream: all rights reserved) or unknown is disabled by default and enabled
  only by the operator's own choice ([docs/detection-coverage.md](docs/detection-coverage.md)).
  Today that is `russianpanda` and `mthcht`. `tests/test_corpus_licences.py`
  fails if such a corpus is enabled in the committed file.
- **Some enabled corpora carry obligations when their rules are
  redistributed:** the GPL ones (`tsale`, `p4t12ick` and `tbg-hunting` under
  GPL-3.0, `yara-rules` under GPL-2.0) and `elastic-artifacts` (Elastic-2.0,
  marked "restricted" in the registry). A rule export is such a
  redistribution: its `MANIFEST.json` names the licence and the corpus of each
  rule, so read them before passing an export on. This file does not say what
  those obligations are.

## Models downloaded at bootstrap

`docker/warm_models.py`, run by `bootstrap`, downloads three models from the
Hugging Face Hub into the `cti-cache` volume. They are not in this repository
or in the image. The licence is the one each model's card declares
(`cardData.license` of `https://huggingface.co/api/models/<id>`), read on
2026-11-01, and likewise for the base model and the training dataset a card
names.

| Model | Used for | Licence | Built on |
|---|---|---|---|
| [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) | text embeddings (Stage 2c); `pipeline/data/attack_retrieval_embeddings.npy` was computed with it | Apache-2.0 | [nreimers/MiniLM-L6-H384-uncased](https://huggingface.co/nreimers/MiniLM-L6-H384-uncased), MIT. The licences of the datasets it was trained on are not verified |
| [PranavaKailash/CyNER-2.0-DeBERTa-v3-base](https://huggingface.co/PranavaKailash/CyNER-2.0-DeBERTa-v3-base) | cybersecurity entities (Stage 2d) | MIT | DeBERTa v3 base, as the card says (it declares no base model): [microsoft/deberta-v3-base](https://huggingface.co/microsoft/deberta-v3-base), MIT. Trained on [CyNER2.0_augmented_dataset](https://huggingface.co/datasets/PranavaKailash/CyNER2.0_augmented_dataset), MIT, and on the original CyNER dataset, whose licence is not verified |
| [urchade/gliner_large-v2.1](https://huggingface.co/urchade/gliner_large-v2.1) | zero-shot entities (Stage 2e) | Apache-2.0 | the backbone its `gliner_config.json` names, [microsoft/deberta-v3-large](https://huggingface.co/microsoft/deberta-v3-large), MIT. Trained on [pile-mistral-v0.1](https://huggingface.co/datasets/urchade/pile-mistral-v0.1), Apache-2.0 |

`TTP_EMBEDDING_MODEL`, `CYNER_MODEL` and `GLINER_MODEL` replace them, and a
replacement carries its own licence. spaCy's `en_core_web_*` models are not
installed by the image or by `bootstrap` (Stage 2 falls back to them when
present); one an operator installs is under its own licence. A model served by
an LLM provider, or pulled into Ollama, is under that provider's terms.

## Container images and system packages

`Dockerfile` and `compose.yaml` pin every base image by digest. On 2026-11-01
the licences below were read from images on the build machine (the
application image built from this `Dockerfile`; the `postgres` and
`ubuntu/squid` images at the pinned digests) or, where marked, from the
project's own statement. Besides the project named in the first column, an
image holds operating-system packages, each under its own licence: in
`/usr/share/doc/<package>/copyright` on Debian and Ubuntu,
`/lib/apk/db/installed` on Alpine. The image's SBOM lists them (ADR-0075).

| Image | Where | Licence |
|---|---|---|
| `python:3.14-slim-bookworm` | the application image's base (Debian 12, Python 3.14.10) | Python Software Foundation License Version 2, and Zero-Clause BSD for documentation examples (`LICENSE.txt` in the image) |
| `node:26-bookworm-slim` | the frontend build stage, of which only `dist/` reaches the image, and the `frontend-dev` service (profile `dev`) | Node.js: MIT, with the licences of its bundled dependencies appended (`/usr/local/LICENSE` of `node:24-bookworm-slim`; the 26 image is not present, so not verified for it) |
| `postgres:18-alpine` | the `postgres` service | PostgreSQL License ([the project's statement](https://www.postgresql.org/about/licence/)). Alpine 3.24.2: `alpine-baselayout` and `busybox` GPL-2.0-only, `musl` MIT. The image's other contents are not verified |
| `nginxinc/nginx-unprivileged:1.31-alpine` | the `proxy` service (profile `proxy`) | nginx: BSD-2-Clause (apk metadata "2-clause BSD-like license" for nginx 1.31.6 and its modules, as in [the project's LICENSE](https://github.com/nginx/nginx/blob/master/LICENSE)). Read from local nginx-unprivileged images (nginx 1.31.6) whose digests are not the pinned one, so not verified for the pinned digest |
| `ubuntu/squid:6.6-24.04_edge` | the `capture-proxy` service | Squid 6.14 on Ubuntu 24.04.4: GPL-2.0 ([upstream COPYING](https://github.com/squid-cache/squid/blob/master/COPYING)); the package's copyright file adds the Debian packaging under the GPL and notices for third-party code |
| `ollama/ollama:0.40.12` | the `ollama` service (profile `ollama`) | Ollama: MIT ([the project's LICENSE](https://github.com/ollama/ollama/blob/main/LICENSE)). The image was not pulled: its contents (operating-system packages, GPU libraries) are not verified |

The application image installs these packages from Debian 12, unmodified
(`apt-get install` in `Dockerfile`; their source is in Debian's archive). The
licences are the `copyright` files of the application image built from this
`Dockerfile`:

| Package | Version | Licence |
|---|---|---|
| `ca-certificates` | 20250419~deb12u2 | MPL-2.0 (Mozilla's certificate list); GPL-2+ (Debian's scripts) |
| `git` | 1:2.39.5-0+deb12u3 | GPL-2.0, with files under LGPL-2.1+, MIT, BSD-3-Clause and others |
| `tini` | 0.19.0-1+b3 | MIT |
| `tesseract-ocr`, with `tesseract-ocr-eng`, `tesseract-ocr-osd` and `libtesseract5` | 5.3.0-2; 1:4.1.0-2 for the two language packages | Apache-2.0 |
| `poppler-utils` | 22.12.0-2+deb12u3 | GPL-2 or GPL-3 (one test file Apache-2.0) |
| `libxml2` | 2.9.14+dfsg-1.3~deb12u6 | MIT, with some files under ISC |
| `libxslt1.1` | 1.1.35-1+deb12u4 | MIT-style permission notice (Daniel Veillard); `libexslt` has its own, in the copyright file |
| `libmagic1` | 1:5.44-3 | BSD-2-Clause-like (the `file` project), with BSD-2-Clause variants, an MIT-style licence and public-domain files |

The packages these pull in (for example `libpoppler126` and `liblept5`) are not
listed one by one.

### Playwright and Chromium (the URL tab)

`python -m playwright install --with-deps --only-shell chromium` runs in the
`Dockerfile` unless it is built with `--build-arg INSTALL_CAPTURE=false`. The
`playwright` Python package (1.64.1) is Apache-2.0 by its metadata, and its
driver embeds the Node.js binary under the Node.js licence. In the image,
`/ms-playwright` holds two downloads (read on 2026-11-01):

- `chromium_headless_shell-1248` (273 MB), Chrome for Testing 156.0.8078.4 in
  its headless shell form. This is the browser `pipeline/web_capture.py`
  starts: a headless launch ran this executable in the image. Its `ABOUT` file
  names Google Chrome, "Copyright 2026 Google LLC. All rights reserved", and
  refers to the Terms of Service at `chrome://terms`, which were not verified.
  Its `LICENSE.headless_shell` is the Chromium project's BSD-style licence
  followed by the licences of its third-party code. It holds no Widevine
  module.
- `ffmpeg-1013` (5 MB), under LGPL-2.1 (`COPYING.LGPLv2.1`).

**Images built before 2026-11-01** also hold the full Chrome for Testing build:
the `Dockerfile` ran `playwright install --with-deps chromium`, which installs
it beside the shell. On main's image at 4df5cbd (Playwright 1.64.1) that is
`chromium-1248`, 403 MB, and it bundles `WidevineCdm/`, whose `LICENSE` says
the module is not open source and may not be distributed without a separate
licence agreement with Google. v0.2.0's image (Playwright 1.63.0) holds it as
`chromium-1243`, Widevine included; v0.1.0's, built by the same line, was not
checked. The pipeline never started that
build. `--only-shell` leaves it out, and `tests/test_web_capture.py` fails if
the `Dockerfile` installs it again. The images built before the change,
v0.1.0's and v0.2.0's among them, are to be deleted from the registry once
1.0 is released.

`--with-deps` also installs Debian packages (fonts and the libraries Chromium
links, such as `libnss3`), each under the licence in its `copyright` file; they
are not listed here.
