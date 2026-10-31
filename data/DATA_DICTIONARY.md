# Veri sözlüğü / Data dictionary

**Kaynak:** MITRE ATT&CK Enterprise, STIX 2.1 paketi — `github.com/mitre/cti`, sürüm etiketi `ATT&CK-v20.0` (MITRE yayın tarihi: 13 Ekim 2026).
**Toplama:** `src/fetch_build.py` ile 29–30 Ekim 2026'da indirildi; dosyanın SHA-256 özeti ve oluşturulma zamanı `data/processed/metadata.json` içinde.
**Lisans:** ATT&CK Terms of Use — araştırma, geliştirme ve ticari amaçlı kullanım ve kopyalama, MITRE'nin telif notu ve lisans metni korunduğu sürece serbesttir.
© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
**Kişisel veri:** Yoktur. Düğümler kamuya açık tehdit grubu adları ve ATT&CK teknikleridir; bireysel kullanıcı bilgisi içermez.

## `data/processed/nodes.csv` — 689 satır (her satır bir düğüm)
| Sütun | Anlamı |
|---|---|
| `node_id` | ATT&CK kimliği: grup `G####`, teknik `T####`, alt-teknik `T####.###` |
| `stix_id` | STIX nesne kimliği (`intrusion-set--…` / `attack-pattern--…`) |
| `node_type` | `group` (tehdit grubu) veya `technique` (teknik/alt-teknik) |
| `name` | ATT&CK'teki ad |
| `is_subtechnique` | Alt-teknik mi? (`True`/`False`) |
| `parent_technique` | Alt-teknikse ana tekniğin kimliği (ör. `T1059`) |
| `tactics` | Tekniğin taktikleri, `;` ile ayrılmış (ör. `execution`) |
| `platforms` | Tekniğin platformları, `;` ile ayrılmış (ör. `Windows;Linux`) |
| `aliases` | Grubun diğer adları, `;` ile ayrılmış |
| `description` | MITRE açıklamasının ilk cümlesi (İngilizce, atıf etiketleri temizlenmiş) |
| `url` | attack.mitre.org sayfası |
| `degree` | İki parçalı ağdaki derece (grup: kullandığı teknik sayısı; teknik: kullanan grup sayısı) |

## `data/processed/edges.csv` — 4.815 satır (her satır bir "kullanır" kenarı)
| Sütun | Anlamı |
|---|---|
| `group_id`, `group_name` | Tehdit grubu |
| `technique_id`, `technique_name` | Kullanılan teknik/alt-teknik |
| `relationship_stix_id` | Kaynak STIX ilişki nesnesinin kimliği (`relationship_type = uses`) |
| `relationship_created`, `relationship_modified` | İlişkinin ATT&CK'e eklenme / güncellenme zamanı (ISO 8601) |

## Projeksiyon kenar listeleri — `group_projection_edges.csv`, `technique_projection_edges.csv`
| Sütun | Anlamı |
|---|---|
| `source`, `target` | Aynı türden iki düğüm (iki grup ya da iki teknik) |
| `newman_weight` | Newman (2001) ağırlığı: ortak her komşu *k* için 1/(d_k − 1) toplamı |
| `shared` | Ortak komşu sayısı (ham ortak teknik / ortak grup sayısı) |

## GraphML dosyaları
* `attack_bipartite.graphml` — iki parçalı ağ; düğüm öznitelikleri: `bipartite` (0 = grup, 1 = teknik), `node_type`, `name`, `is_subtechnique`, `tactics`, `platforms`, `url`.
* `group_projection.graphml`, `technique_projection.graphml` — kenar öznitelikleri `weight` (Newman) ve `shared`.

## Ağ kurma kararları
* İptal edilmiş (`revoked`) veya kullanımdan kalkmış (`x_mitre_deprecated`) nesneler ve ilişkiler çıkarıldı.
* Hiçbir grupla bağı olmayan teknikler ağa alınmadı (706 aktif teknikten 515'i kullanılıyor).
* Aynı grup–teknik çifti için birden fazla ilişki varsa tek kenar tutuldu. Kenarlar yönsüz ve ağırlıksız.
* Kampanya (`campaign`) ve yazılım (`malware`/`tool`) üzerinden dolaylı grup–teknik bağları dahil edilmedi.
