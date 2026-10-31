"""
Etkileşimli ağ sayfasını (web/index.html) üretir.

Girdi : web/graph_data.json (defterin son bölümü üretir), web/template.html, web/vendor/cytoscape.min.js
Çıktı : web/index.html — tek dosya, internet bağlantısı gerektirmez (Cytoscape.js ve veri gömülü).

Çalıştırma (repo kökünden):  python src/build_web.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"

html = (WEB / "template.html").read_text(encoding="utf-8")
import json
import numpy as np

g = json.loads((WEB / "graph_data.json").read_text(encoding="utf-8"))
# Uç noktalardaki birkaç düğüm görünümü sıkıştırmasın diye konumları %1–%99 aralığına kırp (posterle aynı)
X = np.array([n["x"] for n in g["nodes"]]); Y = np.array([n["y"] for n in g["nodes"]])
x0, x1 = np.percentile(X, [1, 99]); y0, y1 = np.percentile(Y, [1, 99])
for n in g["nodes"]:
    n["x"] = round(float(np.clip((n["x"] - x0) / (x1 - x0), -0.02, 1.02) * 1000), 1)
    n["y"] = round(float(np.clip((n["y"] - y0) / (y1 - y0), -0.02, 1.02) * 1000), 1)
data = json.dumps(g, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
lib = (WEB / "vendor" / "cytoscape.min.js").read_text(encoding="utf-8")
html = html.replace("/*__CYTOSCAPE__*/", lib).replace("/*__DATA__*/", data)
(WEB / "index.html").write_text(html, encoding="utf-8")
print(f"web/index.html yazıldı ({len(html.encode('utf-8')) / 1e6:.2f} MB)")
