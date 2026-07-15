# Raport i Detajuar — Platforma e Hetimit me AI

Ky raport shpjegon në shqip çdo hap që u krye deri tani në këtë projekt, në mënyrë
që të kuptohet plotësisht se çfarë është bërë, pse është bërë, dhe si funksionon.

## 1. Çfarë është kjo të dhëna (konteksti)

Brenda dosjes `TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM/` gjendet një
**koleksion real i forenzikës digjitale (DFIR)**, i mbledhur nga një mjet i quajtur
**Velociraptor** duke përdorur një shabllon **KAPE** (Kroll Artifact Parser and
Extractor). Kjo do të thotë:

- Të dhënat vijnë nga një kompjuter real me Windows 10, me emrin `TriDsk-WKS02`.
- Janë mbledhur skedarë dhe metadata nga profile reale përdoruesish:
  `Abdallah.Kh`, `dallen`, `wayne`, `yscott`, `it01`, `administrator`.
- Kjo **NUK është një bazë të dhënash artificiale (sintetike)** — janë prova
  dixhitale reale, prandaj trajtohen si të ndjeshme (privatësi) gjatë gjithë
  procesit.

Struktura kryesore:

| Skedar/Dosje | Çfarë përmban |
|---|---|
| `client_info.json` | Identiteti i makinës (hostname, IP, OS) |
| `collection_context.json` | Metadata mbi vetë procesin e mbledhjes (kush e nisi, sa u pritej, sa u mblodh) |
| `log.json` | Regjistri (log) i ekzekutimit të mbledhjes |
| `requests.json` | Kërkesat konkrete që iu dërguan makinës |
| `uploads.json` | Indeksi i çdo skedari të mbledhur |
| `results/...All File Metadata.json` | Metadata e skedarëve (madhësi, kohët e krijimit/ndryshimit) |
| `results/...Uploads.json` | Regjistrimi i skedarëve që u kopjuan realisht |
| `uploads/` | Vetë **provat** — kopjet reale të skedarëve dhe artefakteve NTFS (`$MFT`, `$LogFile`, etj.) |

## 2. Detyra e vërtetë (5 hapat e kërkuar)

Profesori/detyra kërkon një platformë që:

1. **Kupton struktura të ndryshme JSON** — çdo skedar më sipër ka format të
   ndryshëm (disa janë "një objekt i vetëm", disa janë "një rresht = një JSON").
2. **Normalizon dhe korrelon të dhënat** — i bashkon të gjitha burimet në një
   skemë të përbashkët, duke hequr duplikatet.
3. **Ndërton një graf njohurish (knowledge graph)** — lidh skedarë, përdorues,
   dhe artefaktet që i mblodhën, si një hartë marrëdhëniesh.
4. **Zbulon probleme/anomali në mbledhje** — p.sh. nëse mbledhja ishte e
   pjesshme, nëse skedarë u prenë (truncated), etj.
5. **Përgjigjet pyetjeve hetimore me AI** — një agjent që përgjigjet duke u
   bazuar VETËM në të dhënat reale, duke cituar burimin e saktë (skedar +
   rreshtin), pa shpikur asnjë fakt.

## 3. Hapi 1 & 2 — Parsimi (kuptimi i strukturave)

Skedari [`src/investigation_platform/parsers.py`](src/investigation_platform/parsers.py)
lexon çdo lloj skedari JSON të përmendur më sipër dhe e kthen në një listë
`RawRecord` — çdo rekord mban:

- `source_file` — nga cili skedar erdhi
- `line_no` — nga cili rresht (numër) erdhi
- `data` — vetë të dhënat JSON

Kjo është **themeli i "provenance"** (gjurmës së burimit) — çdo fakt që del në
fund do të mund të çohet mbrapsht te rreshti ekzakt nga ku erdhi.

## 4. Hapi 3 — Normalizimi dhe heqja e duplikateve

Skedari [`src/investigation_platform/normalize.py`](src/investigation_platform/normalize.py)
merr tre burime kryesore (të gjitha lidhen me skedarë individualë):

- **All File Metadata** (26,369 rreshta) — metadata e skedarëve
- **Uploads** (26,369 rreshta) — regjistrimi i ngarkimit + hash SHA256
- **uploads.json** (24,956 rreshta) — indeksi i brendshëm i Velociraptor-it

I bashkon të tria sipas **shtegut (path) kanonik** të skedarit (p.sh.
`C:\Users\wayne\...`), dhe çdo herë që i njëjti shteg shfaqet më shumë se një
herë, e trajton si **duplikatë** dhe e "kollapson" në një rekord të vetëm, duke
mbajtur shënim se sa herë u përsërit.

**Rezultati real i matur:**
- 77,694 rreshta të papërpunuar → **25,030 skedarë unikë**
- **2,778 rreshta duplikatë** u hoqën (skedarë të listuar më shumë se një herë
  për shkak të mbivendosjes së rregullave të mbledhjes KAPE)

Rezultati ruhet te `data/normalized/files.jsonl` (skedar i injoruar nga git, sepse
përmban prova reale).

## 5. Hapi 4 — Zbulimi i anomalive/problemeve

Skedari [`src/investigation_platform/anomalies.py`](src/investigation_platform/anomalies.py)
kontrollon të dhënat e pastruara dhe kontekstin e mbledhjes për probleme
konkrete. Gjetjet reale në këtë rast:

- **Mbledhja ishte e paplotë**: vetëm **82.76%** e të dhënave të pritura u
  mblodhën realisht — 4.55 GB nga 5.50 GB të pritura, pra **~947 MB mungojnë**.
  Kjo llogaritet direkt nga `collection_context.json` (`total_expected_uploaded_bytes`
  vs `total_uploaded_bytes`).
- **119 skedarë** kanë mospërputhje mes madhësisë së pritur dhe asaj që u
  ngarkua realisht (shenjë e kopjimit të pjesshëm/të ndërprerë).
- **50 skedarë** shfaqen në regjistrimet e ngarkimit por nuk kanë rekord
  përkatës në "All File Metadata" — vlen të kontrollohen më nga afër.
- **7 rreshta** në `log.json` u shënuan si jo-standard (nivel jo DEFAULT/INFO),
  por të gjitha janë **njoftime të padëmshme** të motorit të pyetjeve (VQL) —
  p.sh. "duke krijuar 30 workers" — **jo gabime të vërteta**. Asnjë dështim
  fatal nuk u gjet në log.

Të gjitha gjetjet ruhen te `data/reports/anomalies.json`, secila me referencë
të saktë (`provenance`) te të dhënat burimore.

## 6. Hapi 5 — Grafi i njohurive (Knowledge Graph)

Skedari [`src/investigation_platform/graph.py`](src/investigation_platform/graph.py)
ndërton një graf me:

- **Nyje (nodes)**: 1 host, 6 përdorues real, 25,030 skedarë, 3 artefakte
  mbledhëse (gjithsej **25,040 nyje**)
- **Lidhje (edges)**: host → ka_profil → përdorues → zotëron → skedar →
  u_mblodh_nga → artefakt (gjithsej **99,072 lidhje**)

Kjo lejon pyetje si "cilët skedarë i përkasin përdoruesit X?" të përgjigjen
duke ndjekur lidhje reale, jo duke hamendësuar.

Ekzistojnë dy mënyra për ta parë këtë graf:

- `data/graph/knowledge_graph.graphml` — format standard, hapet me softuer
  si **Gephi** ose **yEd** (falas), përfshin gjithçka.
- `data/graph/graph_viewer.html` — një skedar HTML i vetëmjaftueshëm (funksionon
  offline, hapet direkt në browser me dopio-klikim), që shfaq skeletin
  host→përdorues→artefakt në mënyrë interaktive; duke klikuar mbi një përdorues
  shfaqet lista e skedarëve të tij (me madhësi, datë ndryshimi, dhe burimin).

## 7. Hapi 6 — Agjenti AI (përgjigje pyetjesh)

Skedari [`src/investigation_platform/agent.py`](src/investigation_platform/agent.py)
ofron një grup "veglash" (tools) — funksione që kthejnë VETËM fakte të marra
direkt nga të dhënat e normalizuara/grafi/raporti i anomalive:

- `list_users` — listën e përdoruesve realë
- `files_by_user` — skedarët e një përdoruesi specifik
- `collection_completeness` — sa e plotë ishte mbledhja
- `size_mismatches` — skedarët me madhësi të mospërputhur
- `log_problems` — problemet nga log-u
- `anomaly_summary` — përmbledhje e përgjithshme

**Parimi kryesor**: një model AI (p.sh. Claude) mund të vendoset mbi këto vegla
për të formuluar përgjigje në gjuhë natyrale, POR çdo fakt që thotë duhet të
vijë nga rezultati i një vegle — asgjë nuk shpiket. Nëse pyetja nuk mund të
përgjigjet nga të dhënat, përgjigja e saktë është "të dhënat nuk e tregojnë
këtë", jo një hamendësim.

U testua me pyetje reale, si:
- "How complete was the collection?" → 82.76%, me burim `collection_context.json`
- "which users are on this machine?" → 6 përdoruesit realë
- "what files belong to wayne" → lista e skedarëve të wayne, me `provenance`
  (skedar + rresht) për secilin
