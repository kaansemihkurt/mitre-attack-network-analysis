# Bipartite Network Analysis in Threat Intelligence (MITRE ATT&CK)

**Türkçe:** [README.tr.md](README.tr.md)

> **Finding in one sentence:** In the MITRE ATT&CK v20.0 network of 174 threat groups and 515 techniques, just **6 techniques catch 90% of the groups** (17 catch all of them, versus 203 when techniques are picked by popularity), and the groups split into **4 behaviour families defined by tradecraft rather than by country** (modularity z ≈ 30 against 100 degree-preserving random networks).

**CV line:** *Bipartite network analysis in threat intelligence (MITRE ATT&CK): built a 689-node group–technique network from STIX data with Python/networkx, identified behaviour families with Newman-weighted projections and Louvain/Leiden, validated them against a null model, and derived a greedy detection-priority list that covers 90% of threat groups with 6 techniques.*

* **Interactive network (TR/EN):** <https://kaansemihkurt.vercel.app/projeler/mitre-attack>
* **Report (PDF):** [`report/rapor.pdf`](report/rapor.pdf) · **Slides:** [`report/sunum.pdf`](report/sunum.pdf) · **A3 poster:** [`report/poster_A3.pdf`](report/poster_A3.pdf)

Social Network Analysis term project, Manisa Celal Bayar University, Big Data Analytics programme (Fall 2026).

## Research questions
1. Which techniques should a defence team with a limited budget detect first?
2. Which threat groups behave similarly?

## Data and network
* **Source:** MITRE ATT&CK Enterprise STIX 2.1 from `github.com/mitre/cti`, tag `ATT&CK-v20.0`. It is downloaded by script and its SHA-256 hash is recorded in `metadata.json`.
* **Nodes:** 174 threat groups (`intrusion-set`) and 515 techniques/sub-techniques (`attack-pattern`).
* **Edges:** 4,815 "group uses technique" edges, undirected and unweighted.
* **Exclusions:** revoked or deprecated objects, and techniques that no group uses.
* **Projections:** group–group (174 nodes) and technique–technique (515 nodes), both with Newman (2001) weights: a technique shared by *d* groups contributes 1/(d−1).
* **Data dictionary:** [`data/DATA_DICTIONARY.md`](data/DATA_DICTIONARY.md).

## Methods
* **Basic measures:** density, components, average path length, diameter, Latapy bipartite clustering, projection clustering, assortativity.
* **Degree distribution:** tested with `powerlaw` (power law vs log-normal and exponential).
* **Centrality:** degree, betweenness, closeness, PageRank, eigenvector, plus Spearman correlations between them.
* **Communities:** Louvain vs Leiden, each with 10 seeds; stability measured with NMI and ARI.
* **Null model:** 100 degree-preserving bipartite rewirings, reported as z-scores.
* **Advanced methods:** Newman projection, Jaccard group clusters (k-NN Jaccard graph + Leiden), and greedy set-cover analysis (k = 1, 2, 3; plus a detectable-only variant).

## Key results
| | |
|---|---|
| Greedy coverage, k = 1 | 4 techniques → 86%, 6 → 90%, 17 → 100% of groups (popularity order: 203 for 100%) |
| Greedy coverage, k = 3 | 16 techniques → 80%, 29 → 90%, 49 → 100% |
| Communities | 4 families: phishing & malicious documents · network discovery & lateral movement · cloud/Linux/trusted relationship · social engineering & credential harvesting |
| Null model | modularity 0.092 vs 0.043 ± 0.002 (z ≈ 29.7); projection clustering z ≈ −0.5 (explained by the degree sequence alone) |
| Degree distribution | heavy-tailed, but log-normal fits better than a power law |

## Repository layout
```
src/fetch_build.py      download ATT&CK v20.0 and build the network (CSV + GraphML)
notebooks/analysis.ipynb  all analyses (executed, SEED = 42)
src/build_web.py        builds web/index.html (Cytoscape.js, self-contained)
src/make_poster.py      A3 poster
data/processed/         nodes.csv, edges.csv, *.graphml, metadata.json
results/                summary.json, centrality.csv, null_model_runs.csv, greedy_priority_lists.csv
figures/                figures used in the report and slides
web/                    interactive network (index.html) and its template
report/                 rapor.pdf, sunum.pdf, poster_A3.pdf
```

## Reproduce
```bash
python -m venv .venv && .venv\Scripts\activate      # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
python src/fetch_build.py                          # downloads raw data, writes data/processed/
jupyter notebook notebooks/analysis.ipynb          # Run All (the null-model cell takes ~5 min)
python src/build_web.py && python src/make_poster.py
```
All random steps use `SEED = 42`. Community algorithms run on integer-relabelled copies so results do not depend on Python's string hashing.

## AI use statement
An AI assistant (Claude, Anthropic) was used to prepare the data-collection script, the analysis notebook, the visualisations, the report and the slides. The student reviewed and ran every step and is responsible for explaining it in the presentation.

## License and attribution
Code: MIT. Data: MITRE ATT&CK® — © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation (ATT&CK Terms of Use). Cytoscape.js © The Cytoscape Consortium (MIT, `web/vendor/CYTOSCAPE_LICENSE.txt`).
