# Tehdit İstihbaratında İki Parçalı Ağ Analizi (MITRE ATT&CK)

**English:** [README.md](README.md)

> **Bulgunun tek cümlelik özeti:** MITRE ATT&CK v20.0'daki 174 tehdit grubu ve 515 teknikten oluşan ağda yalnızca **6 teknik grupların %90'ını yakalıyor** (17 teknik tamamını; tekniği popülerliğe göre seçmek tamamı için 203 teknik gerektiriyor) ve gruplar **ülkeye göre değil saldırı tarzına göre 4 davranış ailesine** ayrışıyor (100 derece korumalı rastgele ağa göre modülerlik z ≈ 30).

**CV cümlesi:** *Tehdit istihbaratında iki parçalı ağ analizi (MITRE ATT&CK): STIX verisinden Python/networkx ile 689 düğümlü grup–teknik ağı kurdum; Newman ağırlıklı projeksiyon ve Louvain/Leiden ile davranış ailelerini belirleyip null modelle doğruladım, açgözlü kapsama analiziyle tehdit gruplarının %90'ını 6 teknikle yakalayan bir tespit öncelik listesi çıkardım.*

* **Etkileşimli ağ (TR/EN):** <https://kaansemihkurt.vercel.app/projeler/mitre-attack>
* **Rapor:** [`report/rapor.pdf`](report/rapor.pdf) · **Sunum:** [`report/sunum.pdf`](report/sunum.pdf) · **A3 poster:** [`report/poster_A3.pdf`](report/poster_A3.pdf)

Sosyal Ağ Analizi dönem ödevi, Manisa Celal Bayar Üniversitesi, Büyük Veri Analistliği (2026 Güz).

## Araştırma soruları
1. Savunma ekibi sınırlı bütçeyle hangi teknikleri öncelikle tespit etmeli?
2. Hangi tehdit grupları benzer davranıyor?

## Veri ve ağ
* **Kaynak:** `github.com/mitre/cti`, etiket `ATT&CK-v20.0` (STIX 2.1). Veri script ile indirilir; SHA-256 özeti `metadata.json`'a yazılır.
* **Düğümler:** 174 tehdit grubu ve 515 teknik/alt-teknik.
* **Kenarlar:** 4.815 "grup tekniği kullanır" bağı; yönsüz ve ağırlıksız.
* **Dışarıda kalanlar:** iptal edilmiş/eskimiş kayıtlar ve hiçbir grubun kullanmadığı teknikler.
* **Neden alt-teknikler ayrı düğüm:** tespit kuralları bu düzeyde yazılır; ana tekniğe toplandığında ağ 378 düğüme düşer.
* **Veri sözlüğü:** [`data/DATA_DICTIONARY.md`](data/DATA_DICTIONARY.md).

## Yöntem
* **Temel ölçüler:** yoğunluk, bileşenler, ortalama yol ve çap, Latapy iki parçalı kümelenme, projeksiyon kümelenmesi, derece benzeşimi.
* **Derece dağılımı:** `powerlaw` ile test (kuvvet yasası, log-normal ve üstel dağılımla karşılaştırıldı).
* **Merkeziyet:** derece, betweenness, closeness, PageRank, eigenvector; aralarındaki Spearman korelasyonu.
* **Topluluk tespiti:** Louvain ve Leiden, her biri 10 tohumla; kararlılık NMI ve ARI ile ölçüldü.
* **Null model:** 100 derece korumalı rastgele iki parçalı ağ; sonuçlar z-skoruyla verildi.
* **İleri yöntem:** Newman ağırlıklı projeksiyon, Jaccard ile grup kümeleri (k-NN Jaccard ağı + Leiden), açgözlü kapsama (k = 1, 2, 3 ve yalnız tespit edilebilir teknikler).

## Çalıştırma
```bash
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python src/fetch_build.py
jupyter notebook notebooks/analysis.ipynb      # Run All (null model hücresi ~5 dk)
python src/build_web.py && python src/make_poster.py
```
Tüm rastgele adımlarda `SEED = 42` kullanılır.

## Yapay zekâ beyanı
Bu projede veri toplama scripti, analiz defteri, görselleştirmeler, rapor ve sunum yapay zekâ asistanı **Claude (Anthropic)** ile birlikte hazırlanmıştır. Öğrenci tüm adımları inceleyip çalıştırmış ve sunumda açıklamaktan sorumludur.

## Lisans ve atıf
Kod: MIT. Veri: MITRE ATT&CK® — © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. Cytoscape.js © The Cytoscape Consortium (MIT).
