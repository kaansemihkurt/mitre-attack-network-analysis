"""
A3 yatay statik poster (report/poster_A3.pdf + PNG önizleme).

Girdi : web/graph_data.json, results/summary.json, results/null_model_runs.csv (defter üretir)
Çalıştırma (repo kökünden):  python src/make_poster.py
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patheffects as pe
from matplotlib.collections import LineCollection
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
G = json.loads((ROOT / "web" / "graph_data.json").read_text(encoding="utf-8"))
R = json.loads((ROOT / "results" / "summary.json").read_text(encoding="utf-8"))
null = pd.read_csv(ROOT / "results" / "null_model_runs.csv")
OUT = ROOT / "report"; OUT.mkdir(exist_ok=True)

BG, PANEL, TEXT, MUTED = "#0b1220", "#111a2e", "#e6ecf7", "#93a3c0"
COLORS = ["#5aa9ff", "#f6ad55", "#68d391", "#f687b3", "#b794f4", "#4fd1c5"]
plt.rcParams.update({"pdf.fonttype": 42, "font.family": "DejaVu Sans", "text.color": TEXT, "axes.labelcolor": MUTED,
                     "xtick.color": MUTED, "ytick.color": MUTED, "axes.edgecolor": "#24324f"})

nodes = {n["id"]: n for n in G["nodes"]}
fig = plt.figure(figsize=(16.54, 11.69), facecolor=BG)  # A3 yatay

# ---------------- Ağ çizimi ----------------
ax = fig.add_axes([0.01, 0.06, 0.62, 0.86]); ax.set_facecolor(BG); ax.axis("off")
# Uç noktalardaki birkaç düğüm çekirdeği sıkıştırmasın diye yerleşimi %1–%99 aralığına kırpıyoruz
X = np.array([v["x"] for v in nodes.values()]); Y = np.array([v["y"] for v in nodes.values()])
x0, x1 = np.percentile(X, [1, 99]); y0, y1 = np.percentile(Y, [1, 99])
def tf(v):
    x = np.clip((v["x"] - x0) / (x1 - x0), -0.02, 1.02) * 1000
    y = np.clip((v["y"] - y0) / (y1 - y0), -0.02, 1.02) * 1000
    return (x, 1000 - y)
xy = {k: tf(v) for k, v in nodes.items()}
segs = [(xy[a], xy[b]) for a, b in G["edges"]]
ax.add_collection(LineCollection(segs, colors="#3a4a6b", linewidths=0.25, alpha=0.25, zorder=1))
T = [n for n in G["nodes"] if n["type"] == "technique"]
Gr = [n for n in G["nodes"] if n["type"] == "group"]
mxT, mxG = max(n["deg"] for n in T), max(n["deg"] for n in Gr)
ax.scatter([xy[n["id"]][0] for n in T], [xy[n["id"]][1] for n in T],
           s=[4 + 160 * (n["deg"] / mxT) for n in T], c="#8b9bb8", alpha=0.55, linewidths=0, zorder=2)
pr = [n for n in T if n.get("greedy3") and n["greedy3"] <= 8]
ax.scatter([xy[n["id"]][0] for n in pr], [xy[n["id"]][1] for n in pr],
           s=[4 + 160 * (n["deg"] / mxT) + 60 for n in pr], facecolors="none", edgecolors="#f6ad55", linewidths=1.8, zorder=3)
ax.scatter([xy[n["id"]][0] for n in Gr], [xy[n["id"]][1] for n in Gr],
           s=[20 + 420 * (n["deg"] / mxG) for n in Gr], c=[COLORS[n["comm"] % 6] for n in Gr],
           edgecolors=BG, linewidths=0.6, alpha=0.95, zorder=4)
stroke = [pe.withStroke(linewidth=2.6, foreground=BG)]
for n in sorted(Gr, key=lambda n: -n["deg"])[:28]:
    x, y = xy[n["id"]]
    ax.text(x, y + 9, n["name"], fontsize=8.2, ha="center", va="bottom", color=TEXT, weight="bold", path_effects=stroke, zorder=6)
for n in pr:
    x, y = xy[n["id"]]
    ax.text(x, y - 11, f"{n['id']} {n['name']}", fontsize=7.4, ha="center", va="top", color="#fbd38d", path_effects=stroke, zorder=6)
ax.set_xlim(-40, 1040); ax.set_ylim(-40, 1040)

# ---------------- Başlık ----------------
fig.text(0.015, 0.965, "Siber tehdit grupları teknik paylaşımına göre 4 davranış ailesine ayrışıyor; 6 teknik grupların %90'ını yakalıyor",
         fontsize=17, weight="bold", va="top")
fig.text(0.015, 0.932, "MITRE ATT&CK v20.0 · 174 tehdit grubu × 515 teknik · 4.815 \"kullanır\" bağı · İki parçalı ağ analizi",
         fontsize=10.5, color=MUTED, va="top")

# ---------------- Sağ sütun ----------------
X0, W = 0.645, 0.34
def panel(y, h):
    a = fig.add_axes([X0, y, W, h]); a.set_facecolor(PANEL); a.set_xticks([]); a.set_yticks([])
    for s in a.spines.values(): s.set_color("#24324f")
    return a

# Lejant
lg = panel(0.735, 0.19)
lg.text(0.03, 0.9, "Grup toplulukları (Leiden, Newman ağırlıklı projeksiyon)", fontsize=10, weight="bold", va="top", transform=lg.transAxes)
for i, c in enumerate(G["communities"]):
    yy = 0.72 - i * 0.15
    lg.scatter([0.05], [yy], s=90, color=COLORS[c["id"] % 6], transform=lg.transAxes)
    lg.text(0.09, yy, f"{c['tr']}  ({c['size']} grup)", fontsize=9, va="center", transform=lg.transAxes)
lg.text(0.03, 0.06, "● gri: teknik (boyut = kullanan grup sayısı)    ◯ turuncu: öncelikli ilk 8 tespit edilebilir teknik",
        fontsize=7.6, color=MUTED, transform=lg.transAxes)

# Bulgular
cs = R["coverage"]["summary"]; cd = R["coverage_detectable"]["summary"]
nm = {r["ölçü"]: r for r in R["null_model"]}
cg = R["communities_group"]
fd = panel(0.415, 0.305)
fd.text(0.03, 0.95, "Ana bulgular", fontsize=11, weight="bold", va="top", transform=fd.transAxes)
items = [
    f"1. Kapsama: açgözlü seçimle 4 teknik grupların %{100 * 0.862:.0f}'sını, 6 teknik %90'ını, {cs['k=1']['%100 için (greedy)']:.0f} teknik tamamını\n    en az bir teknikten yakalıyor (popülerlik sırasıyla tamamı için {cs['k=1']['%100 için (popülerlik)']:.0f} teknik).",
    f"2. Daha gerçekçi hedef (her grubu ≥3 tekniğinden yakalamak): %80 için {cs['k=3']['%80 için (greedy)']:.0f}, %90 için {cs['k=3']['%90 için (greedy)']:.0f} teknik.",
    f"3. Topluluklar ülkeye değil saldırı tarzına göre ayrışıyor; Louvain = Leiden (NMI = {cg['Louvain_vs_Leiden']['NMI']:.2f}),\n    modülerlik {cg['Leiden']['modularity_best']:.3f}, 10 tohumda NMI ≈ {cg['Leiden']['NMI_mean']:.2f}.",
    f"4. Null model (100 derece korumalı rastgele ağ): modülerlik z = {nm['modülerlik (Louvain)']['z-skoru']:.1f} → yapı rastlantı değil;\n    projeksiyon kümelenmesi z = {nm['kümelenme (transitivity)']['z-skoru']:.1f} → yüksek kümelenme derece dizisinden geliyor.",
    f"5. Teknik dereceleri ağır kuyruklu (medyan 4, en yaygın teknik 90 grup) ama log-normal\n    kuvvet yasasından daha iyi uyuyor; merkeziyet ölçüleri birbiriyle güçlü ilişkili (Spearman 0,86–0,99).",
    "6. En güçlü Newman bağı LAPSUS$ – Scattered Spider; Jaccard'a göre en benzer büyük çift\n    Patchwork – Sidewinder (J = 0,39).",
]
import textwrap
for i, t in enumerate(items):
    t = textwrap.fill(" ".join(t.split()), 98, subsequent_indent="    ")
    fd.text(0.03, 0.85 - i * 0.137, t, fontsize=7.9, va="top", transform=fd.transAxes, linespacing=1.3)

# Kapsama eğrisi
ca = fig.add_axes([X0 + 0.032, 0.085, W * 0.42, 0.27]); ca.set_facecolor(PANEL)
nG = len(Gr)
for k, col in [("1", "#5aa9ff"), ("3", "#f6ad55")]:
    cu = np.array(R["coverage"]["curves"][k]) / nG * 100
    pc = np.array(R["coverage"]["pop_curves"][k][:len(cu)]) / nG * 100
    ca.plot(np.arange(1, len(cu) + 1), cu, color=col, lw=2, label=f"Açgözlü k={k}")
    ca.plot(np.arange(1, len(pc) + 1), pc, color=col, lw=1, ls="--", alpha=.7, label=f"Popülerlik k={k}")
ca.set_xlim(0, 60); ca.set_ylim(0, 102); ca.axhline(90, color="#4a5878", lw=.7, ls=":")
ca.set_xlabel("Tespit edilen teknik sayısı", fontsize=8); ca.set_ylabel("Kapsanan grup %", fontsize=8)
ca.set_title("En az teknikle en çok grup\n(açgözlü vs popülerlik sırası)", fontsize=9, color=TEXT); ca.tick_params(labelsize=7)
ca.legend(fontsize=6.5, frameon=False, labelcolor=TEXT, loc="lower right")

# Null model histogramı
na = fig.add_axes([X0 + 0.032 + W * 0.54, 0.085, W * 0.39, 0.27]); na.set_facecolor(PANEL)
na.hist(null["modülerlik (Louvain)"], bins=np.arange(0.034, 0.1, 0.002), color="#9fb3d9", edgecolor=PANEL)
obs = nm["modülerlik (Louvain)"]["gerçek"]
na.axvline(obs, color="#fc8181", lw=2.2)
na.text(obs - 0.002, na.get_ylim()[1] * 0.9, "gerçek\nağ", color="#fc8181", fontsize=7.5, ha="right", va="top")
na.set_xlim(min(null["modülerlik (Louvain)"].min(), obs) - 0.005, obs + 0.008)
na.set_title("Modülerlik: gerçek ağ vs\n100 rastgele ağ (z ≈ 30)", fontsize=9, color=TEXT)
na.set_xlabel("Modülerlik", fontsize=8); na.set_ylabel("Rastgele ağ sayısı", fontsize=8); na.tick_params(labelsize=7)

fig.text(0.015, 0.018, "Kaan Semih Kurt · Manisa Celal Bayar Üniversitesi, Büyük Veri Analistliği · Sosyal Ağ Analizi dönem ödevi (2026)   |   "
         "Veri: MITRE ATT&CK® v20.0 — © The MITRE Corporation, izinle yeniden dağıtılmıştır   |   Yerleşim: ForceAtlas2 (seed 42)",
         fontsize=7.5, color=MUTED)
fig.savefig(OUT / "poster_A3.pdf", facecolor=BG)
fig.savefig(OUT / "poster_A3_preview.png", facecolor=BG, dpi=60)
print("report/poster_A3.pdf yazıldı")
