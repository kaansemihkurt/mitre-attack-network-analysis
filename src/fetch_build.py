"""
MITRE ATT&CK Enterprise (v20.0) verisinden iki parçalı tehdit grubu <-> teknik ağını kurar.

Çalıştırma (repo kökünden):
    python src/fetch_build.py

Ne yapar?
 1. Sabit sürümlü (ATT&CK-v20.0 etiketi) STIX JSON dosyasını GitHub'dan indirir
    (dosya data/raw altında zaten varsa tekrar indirmez) ve SHA-256 özetini kaydeder.
 2. İptal edilmiş (revoked) veya kullanımdan kalkmış (deprecated) kayıtları atar.
 3. Düğümler: tehdit grupları (intrusion-set) ve teknikler/alt-teknikler (attack-pattern).
    Kenar: "grup X, teknik Y'yi kullanır" (relationship_type = uses).
 4. Hiçbir grupla bağı olmayan teknikleri ağa almaz (araştırma sorusu açısından bilgi taşımaz).
 5. Çıktılar: data/processed/ altında düğüm ve kenar listeleri (CSV), iki parçalı ağ ve
    iki projeksiyon (GraphML), metadata.json.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx
import pandas as pd

ATTACK_VERSION = "20.0"
URL = ("https://raw.githubusercontent.com/mitre/cti/"
       f"ATT%26CK-v{ATTACK_VERSION}/enterprise-attack/enterprise-attack.json")

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / f"enterprise-attack-v{ATTACK_VERSION}.json"
OUT = ROOT / "data" / "processed"


def download() -> None:
    """Ham veriyi indir (zaten varsa atla)."""
    if RAW.exists():
        print(f"[indir] {RAW.name} zaten var, tekrar indirilmedi.")
        return
    import requests  # yalnızca indirme gerektiğinde

    RAW.parent.mkdir(parents=True, exist_ok=True)
    print(f"[indir] {URL}")
    r = requests.get(URL, timeout=120)
    r.raise_for_status()
    RAW.write_bytes(r.content)
    print(f"[indir] {len(r.content) / 1e6:.1f} MB kaydedildi.")


def attack_id(obj: dict) -> str | None:
    """STIX nesnesinin ATT&CK kimliğini (G0016, T1059.001 ...) döndür."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def attack_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def first_sentence(text: str, limit: int = 320) -> str:
    """Açıklamanın ilk cümlesi (citation etiketleri temizlenmiş)."""
    import re

    text = re.sub(r"\(Citation:[^)]*\)", "", text or "").strip()
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # markdown linkleri -> düz metin
    m = re.search(r"(.+?\.)(\s|$)", text)
    s = m.group(1) if m else text
    return (s[: limit - 1] + "…") if len(s) > limit else s


def build() -> dict:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    objs = data["objects"]

    groups, techs = {}, {}
    for o in objs:
        if not is_active(o):
            continue
        if o["type"] == "intrusion-set":
            groups[o["id"]] = o
        elif o["type"] == "attack-pattern":
            techs[o["id"]] = o

    edges = []
    for o in objs:
        if (o["type"] == "relationship" and o.get("relationship_type") == "uses"
                and is_active(o) and o["source_ref"] in groups and o["target_ref"] in techs):
            edges.append(o)

    # Aynı grup-teknik çifti birden fazla ilişkiyle gelebilir -> tekilleştir
    pairs = {}
    for e in edges:
        key = (attack_id(groups[e["source_ref"]]), attack_id(techs[e["target_ref"]]))
        pairs.setdefault(key, e)

    used_groups = {g for g, _ in pairs}
    used_techs = {t for _, t in pairs}

    # ---- Düğüm tablosu ----
    rows = []
    for o in groups.values():
        gid = attack_id(o)
        if gid not in used_groups:
            continue
        rows.append({
            "node_id": gid, "stix_id": o["id"], "node_type": "group", "name": o["name"],
            "is_subtechnique": False, "parent_technique": "",
            "tactics": "", "platforms": "",
            "aliases": ";".join(a for a in o.get("aliases", []) if a != o["name"]),
            "description": first_sentence(o.get("description", "")),
            "url": attack_url(o),
        })
    for o in techs.values():
        tid = attack_id(o)
        if tid not in used_techs:
            continue
        sub = bool(o.get("x_mitre_is_subtechnique", False))
        rows.append({
            "node_id": tid, "stix_id": o["id"], "node_type": "technique", "name": o["name"],
            "is_subtechnique": sub, "parent_technique": tid.split(".")[0] if sub else "",
            "tactics": ";".join(p["phase_name"] for p in o.get("kill_chain_phases", [])
                                if p.get("kill_chain_name") == "mitre-attack"),
            "platforms": ";".join(o.get("x_mitre_platforms", [])),
            "aliases": "",
            "description": first_sentence(o.get("description", "")),
            "url": attack_url(o),
        })
    nodes = pd.DataFrame(rows).sort_values(["node_type", "node_id"]).reset_index(drop=True)
    names = dict(zip(nodes.node_id, nodes.name))

    # ---- Kenar tablosu ----
    erows = [{
        "group_id": g, "technique_id": t,
        "group_name": names[g], "technique_name": names[t],
        "relationship_stix_id": e["id"],
        "relationship_created": e.get("created", ""), "relationship_modified": e.get("modified", ""),
    } for (g, t), e in sorted(pairs.items())]
    edges_df = pd.DataFrame(erows)

    deg = pd.concat([edges_df.group_id, edges_df.technique_id]).value_counts()
    nodes["degree"] = nodes.node_id.map(deg).astype(int)

    # ---- İki parçalı ağ ----
    B = nx.Graph(name="ATT&CK v20.0 grup-teknik iki parçalı ağ")
    for r in nodes.itertuples(index=False):
        B.add_node(r.node_id, bipartite=0 if r.node_type == "group" else 1,
                   node_type=r.node_type, name=r.name, is_subtechnique=bool(r.is_subtechnique),
                   tactics=r.tactics, platforms=r.platforms, url=r.url or "")
    B.add_edges_from(zip(edges_df.group_id, edges_df.technique_id))

    G_nodes = [n for n, d in B.nodes(data=True) if d["bipartite"] == 0]
    T_nodes = [n for n, d in B.nodes(data=True) if d["bipartite"] == 1]

    # ---- Projeksiyonlar: Newman (2001) ağırlıklandırması ----
    # w_ij = sum_k 1 / (d_k - 1); k: i ve j'nin ortak komşusu, d_k: k'nin derecesi
    # networkx bu formülü collaboration_weighted_projected_graph ile uygular.
    def project(side):
        P = nx.bipartite.collaboration_weighted_projected_graph(B, side)
        shared = nx.bipartite.weighted_projected_graph(B, side)  # ortak komşu sayısı
        for u, v, d in P.edges(data=True):
            d["weight"] = round(d["weight"], 6)
            d["shared"] = shared[u][v]["weight"]
        for n in P.nodes:
            P.nodes[n].update(B.nodes[n])
        return P

    PG = project(G_nodes)
    PT = project(T_nodes)

    OUT.mkdir(parents=True, exist_ok=True)
    nodes.to_csv(OUT / "nodes.csv", index=False, encoding="utf-8")
    edges_df.to_csv(OUT / "edges.csv", index=False, encoding="utf-8")
    nx.write_graphml(B, OUT / "attack_bipartite.graphml")
    nx.write_graphml(PG, OUT / "group_projection.graphml")
    nx.write_graphml(PT, OUT / "technique_projection.graphml")
    for P, fn in [(PG, "group_projection_edges.csv"), (PT, "technique_projection_edges.csv")]:
        pd.DataFrame([{"source": u, "target": v, "newman_weight": d["weight"], "shared": d["shared"]}
                      for u, v, d in P.edges(data=True)]).to_csv(OUT / fn, index=False)

    meta = {
        "source": "MITRE ATT&CK Enterprise STIX 2.1 (github.com/mitre/cti)",
        "attack_version": ATTACK_VERSION,
        "url": URL,
        "sha256": hashlib.sha256(RAW.read_bytes()).hexdigest(),
        "built_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "license": "MITRE ATT&CK Terms of Use — © The MITRE Corporation. Reproduced and "
                   "distributed with the permission of The MITRE Corporation.",
        "active_groups_total": len(groups),
        "active_techniques_total": len(techs),
        "groups_in_network": len(G_nodes),
        "techniques_in_network": len(T_nodes),
        "subtechniques_in_network": int(nodes.query("node_type=='technique'").is_subtechnique.sum()),
        "nodes": B.number_of_nodes(),
        "edges": B.number_of_edges(),
        "group_projection": {"nodes": PG.number_of_nodes(), "edges": PG.number_of_edges()},
        "technique_projection": {"nodes": PT.number_of_nodes(), "edges": PT.number_of_edges()},
    }
    (OUT / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return meta


if __name__ == "__main__":
    download()
    meta = build()
    print(json.dumps(meta, indent=2, ensure_ascii=False))
    sys.exit(0)
