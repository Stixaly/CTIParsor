# Workflow de développement assisté — Claude + Qwen3.8 local

## Contexte matériel

Un modèle local **Qwen3.8** (27,3B, quantization Q4_K_M) tourne sur une station
NVIDIA DGX Spark GB10, accessible sur le réseau local à `192.168.0.29:11434`.

Capacités : `completion`, `tools`, `thinking`, `vision`.
Fenêtre de contexte native : 262144 tokens.

> **La CLI `ollama` n'est PAS installée** — ni dans le PATH Windows, ni dans WSL,
> et `$OLLAMA_HOST` est vide. Le **serveur** répond : on l'appelle directement en
> HTTP (voir « Comment appeler Qwen »). Ne perds pas de temps à chercher la CLI.

## Environnement d'exécution

Le `python` Windows est le stub Microsoft Store. **Tout** passe par WSL :

```
wsl -e bash -lc "cd /mnt/c/Users/parra/Documents/tools-NLP/CTIParsor && .venv/bin/python ..."
```

| Besoin | Commande |
|---|---|
| Tests | `SKIP_HEAVY_MODELS=1 .venv/bin/python -m pytest -q` (~1200 tests, ~2 min) |
| Tests sur PostgreSQL | la même commande avec `CTIPARSOR_TEST_DATABASE_URL=postgresql://ctiparsor:ctitest@127.0.0.1:5433/ctiparsor` (conteneur `cti-pg-test`, `docker start cti-pg-test` via `wsl -u root`) — **obligatoire** pour tout changement qui touche `api/db.py`, `api/queue_loop.py` ou une requête SQL |
| Tests ciblés | `... -m pytest tests/test_<module>.py -q` (quelques secondes) |
| Conteneurs | `wsl -u root -e bash -c "cd /mnt/c/... && make docker-smoke"` — le socket Docker n'est accessible qu'à root dans WSL ; `bash scripts/docker_smoke.sh --no-build --job` pour un rapport de bout en bout |
| Lint | `.venv/bin/python -m ruff check <chemins>` |
| **Typecheck Python** | `.venv/bin/python -m mypy pipeline/ api/ models/ --ignore-missing-imports --no-error-summary` |
| Typecheck front | `cd frontend && npm run build` **depuis WSL** (ou `node node_modules/typescript/bin/tsc --noEmit -p tsconfig.json`) |

`SKIP_HEAVY_MODELS=1` désactive spaCy/CyNER/GLiNER/sentence-transformers.
`pytest` n'existe que dans `.venv`.

**mypy tourne en CI** (`.github/workflows/ci.yml`) et il est facile de l'oublier :
`ruff` seul ne le remplace pas. Il est en `continue-on-error: true`, donc
*consultatif* — une erreur n'échoue pas le build, mais elle reste une erreur.
Lance-le avant de clore une étape qui touche `pipeline/`, `api/` ou `models/`.

**Le front se construit depuis Linux, jamais depuis Windows.** `setup.sh` vise
Ubuntu/Debian/RHEL/Fedora et node 24 ; `frontend/node_modules` doit donc être un
arbre Linux. Un `npm install` lancé depuis Windows y laisse
`@rollup/rollup-win32-*` et des shims qui font `exec node.exe`, et la
construction WSL meurt sur `exec: node.exe: not found` — un message qui ressemble
à un problème de PATH sans en être un. Correctif : `npm ci` depuis WSL.

## Deux stores, trois rôles (ADR-0044/0045/0046)

`api.db.get_conn()` est le **job store** (PostgreSQL si `DATABASE_URL`, sinon
SQLite) ; `api.db.get_rule_conn()` est le **rule store** (toujours SQLite,
FTS5). Sans `DATABASE_URL` c'est la même connexion — ce qui masque les
erreurs : un test qui écrit des règles via `get_conn()` passe sur SQLite et
échoue sur PostgreSQL. Toute fonction qui lit `entities` ET les tables de
règles prend `jobs_conn=`. Le pipeline est réclamé dans la table `jobs` par
`api/queue_loop.py` selon `CTIPARSOR_ROLE` (`all` = installation hôte, `api`
+ `worker` = conteneurs). Carte complète : `docs/architecture.md`.

## Répartition des rôles

**Qwen3.8 écrit le code. Claude ne l'écrit pas.**

**Toi (Claude)** — architecte et relecteur. Tu ne produis pas de code applicatif :
- comprendre le besoin, le découper en étapes vérifiables
- **prendre toutes les décisions d'architecture** : schéma de données, contrats
  d'API, découpage en modules, formules et pondérations, seuils
- rédiger les spécifications précises que Qwen exécute
- relire, corriger et valider tout ce que Qwen produit
- écrire les fichiers sur le disque
- lancer les tests, interpréter les résultats, **valider sur données réelles**
- décider quand une étape est terminée

**Qwen3.8** — exécutant. Il écrit :
- les modules, fonctions et classes correspondant à tes spécifications
- les tests unitaires quand tu lui donnes les cas à couvrir
- les variantes quand tu veux comparer des approches
- la documentation et les docstrings à partir de code existant

Tu délègues la production. Tu ne délègues jamais une décision.

Une spécification pour Qwen est déjà un travail d'architecte : si tu dois écrire
la signature exacte, les types, les cas limites et la table de constantes, tu as
fait le travail de conception — Qwen fait la frappe. C'est le partage voulu.

## Comment appeler Qwen

### Le script

Crée-le une fois par session dans le scratchpad, puis réutilise-le :

```python
#!/usr/bin/env python3
"""Envoie un fichier de spec à Qwen3.8 via l'API HTTP d'Ollama.
Usage: qwen.py spec.txt [num_predict]"""
import json, sys, urllib.request

spec = open(sys.argv[1], encoding="utf-8").read()
payload = {
    "model": "qwen3.8",
    "prompt": spec,
    "stream": False,
    "think": False,
    "options": {"num_ctx": 32768, "temperature": 0.2,
                "num_predict": int(sys.argv[2]) if len(sys.argv) > 2 else 6000},
}
req = urllib.request.Request(
    "http://192.168.0.29:11434/api/generate",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=1800) as r:
    out = json.load(r)
sys.stdout.write(out.get("response", ""))
sys.stderr.write(f"\n[qwen] eval_count={out.get('eval_count')} "
                 f"done_reason={out.get('done_reason')}\n")
```

Appel (depuis WSL — `python3` sous Git Bash est le stub Store) :

```
wsl -e bash -lc "cd <scratchpad> && python3 qwen.py spec_atoms.txt 7000 > out.md 2> err.txt"
```

### Les trois options qui comptent

| Option | Pourquoi |
|---|---|
| `"think": false` | supprime le bloc `Thinking…` : la réponse est du code, rien à nettoyer |
| `"num_ctx": 32768` | **indispensable** — Ollama tronque par défaut très en dessous des 262144 tokens du modèle et dégrade silencieusement les specs longues |
| `"temperature": 0.2` | production de code déterministe, pas de créativité |

Monte `num_ctx` si tu envoies du code existant en contexte. Signale-le-moi si tu
dépasses ~100 k tokens : il faudra un Modelfile dédié.

### Débit

~3000 tokens en quelques minutes. Une génération de 400 lignes prend 3 à 6 min :
**lance-la en arrière-plan** et avance sur autre chose (schéma, docs, tests
d'intégration) pendant ce temps. N'attends jamais passivement.

### Plusieurs fichiers par appel

Une réponse peut contenir **N blocs markdown**, pas un seul. Demande-les
explicitement et extrais-les par index :

> Réponds uniquement avec le code, dans DEUX blocs markdown python séparés.
> Bloc 1 = `pipeline/x.py`. Bloc 2 = `tests/test_x.py`.

Mesuré : 3 blocs (types TS + client + composant React, 384 lignes) livrés en un
seul appel de 4405 tokens, `tsc --noEmit` propre du premier coup. Un aller-retour
au lieu de trois.

**Groupe systématiquement le module avec son harnais de validation** (le script
qui le lance sur `cti_stix.db` / `corpora/` et imprime les stats). Ils sont
indépendants, le harnais coûte ~40 lignes de spec, et sans lui tu l'écriras
toi-même — c'est ce qui est arrivé 15 fois sur une session, soit **932 lignes**
que j'ai tapées au lieu de les déléguer.

### Ne sérialise pas

Le piège de débit n'est pas la génération, c'est l'attente. Le cycle naturel —
spécifier → attendre → relire → corriger → valider → spécifier — laisse la
station **inactive pendant la majorité du temps écoulé**.

- **Lance la spec suivante dès que la précédente est revenue**, avant de relire.
  La relecture se fait pendant que la station travaille.
- **Deux appels en vol** quand les specs sont indépendantes (un module et les
  tests d'un autre, un adaptateur et un script d'analyse).
- Le seul ordre à respecter : ne délègue pas B si sa spec dépend du code de A.

### Vérification

```
curl -s -m 6 http://192.168.0.29:11434/api/tags
```
Doit lister `qwen3.8:latest`. Si ça ne répond pas, la station est éteinte —
préviens-moi, ne bascule pas silencieusement sur une écriture directe.

## Qualité des spécifications

Qwen3.8 est compétent mais **littéral**. La qualité du résultat dépend presque
entièrement de la précision de la demande. Une spécification complète contient :

1. **Le langage et la version** (ex. Python 3.12, TypeScript strict)
2. **Le chemin du fichier** à produire
3. **La signature exacte attendue** : noms, paramètres typés, type de retour
4. **Le comportement**, cas limites explicités un par un
5. **Les erreurs à lever** et dans quelles conditions
6. **Les dépendances autorisées** — et interdire le reste explicitement
7. **Le contexte** : le code existant avec lequel ça doit s'intégrer
8. **Le style** : conventions du projet, docstrings, gestion des erreurs

Et systématiquement, en tête :

> Réponds uniquement avec le code, dans un seul bloc markdown, sans explication
> avant ni après.

### Ce qui fait vraiment la différence

Observé en production sur ce projet — ces trois choses transforment le résultat :

- **Imposer les tables de constantes en entier.** Ne dis pas « une table qui
  mappe les champs Sigma vers des classes » : écris les 80 lignes de la table
  dans la spec. Qwen les recopie fidèlement ; livré à lui-même il en invente une
  plausible et fausse.
- **Une règle de normalisation par cas, énumérée.** « Normalise la valeur » →
  résultat imprévisible. « Pour la classe `hash` : découper sur `,`, prendre la
  partie après le dernier `=`, ne garder que `^[0-9a-f]{32,128}$` » → exact.
- **Nommer les fonctions privées attendues.** Si tu veux `_normalize`,
  `_resolve_class`, `_collect`, dis-le : tu obtiens une structure relisible et
  testable au lieu d'une seule fonction de 200 lignes.

Ne dis jamais « écris une fonction qui gère les utilisateurs ». Dis quelle
signature, quels types, quels cas d'erreur, quel format de retour.

Si le résultat est mauvais deux fois de suite, le problème est dans la
spécification, pas dans le modèle. Reformule plus précisément.

### Écris les commentaires de spec en anglais

Qwen recopie tes tables de constantes **verbatim, commentaires compris**. Une
table commentée en français arrive telle quelle dans un fichier dont tout le
reste est en anglais. Vécu sur `dedup.py` : le commentaire de `FOLDING_RELATIONS`
a dû être retraduit après coup. Rédige les blocs destinés à être copiés dans le
code directement en anglais ; le reste de la spec peut rester en français.

## Relecture — relis ta spec avant de relire le code

**Mesuré sur une session de 11 délégations (3763 lignes livrées) : il y a eu plus
de défauts venant de MA spécification que de l'implémentation de Qwen** — environ
15-18 contre 10-12.

Les trois défauts les plus graves de la session étaient tous des fautes de spec,
fidèlement implémentées :

| Défaut | Origine |
|---|---|
| 854 règles de blocklist Tor fondues en une seule (dédup) | ma spec ne hachait que le corps, pas l'en-tête |
| Les IP de C2 en liste `[1.2.3.4,...]` jetées | ma spec disait « ignorer si contient `[` » |
| 57 groupes de règles YARA écrasées en base | ma spec faisait de `meta.id` la clé — il n'est pas unique |

**Donc : avant de relire le code, relis la spec en te demandant « est-ce que la
règle que j'ai écrite est vraie sur les vraies données ? »** Une table de
constantes inventée au jugé produit du code parfait qui fait la mauvaise chose.

### Passe `ruff --fix` AVANT de lire

~33 des corrections d'une session étaient du bruit mécanique (`W293` ×14,
`E501` ×13, `F401` ×6). Elles volent l'attention aux deux bugs qui détruisaient
des données. Lance `ruff check <fichier> --select E,F,W,I --fix` dès l'extraction,
**puis** lis.

## Ce que Qwen rate systématiquement

Environ **5 défauts par 400 lignes**, toujours les mêmes familles. Cherche-les
explicitement, ils ne sautent pas aux yeux :

| Famille | Exemple réel |
|---|---|
| **Garde de type manquante sur entrée non fiable** | `key.split("\|")` sur une clé YAML qui peut être un `int` → `AttributeError` |
| **Argument d'entrée non gardé** | `doc.get(...)` sans vérifier que `doc` est bien un dict |
| **Structures imbriquées incomplètes** | descend dans les dicts d'une liste, pas dans les listes d'une liste |
| **Sémantique de parcours de chaîne** | cherche des séparateurs dans l'ordre de la boucle au lieu du plus à gauche — `http://h?a=/b` renvoie l'hôte `h?a=` |
| **Imports inutilisés** | `Counter` importé jamais utilisé → ruff F401 |
| **Aucune sortie anticipée** | collecte tout puis tronque, au lieu de s'arrêter à la limite — fatal sur les gros corpus |
| **Recalcul en boucle** | `tuple(FROZENSET)` reconstruit à chaque itération |
| **Itérable consommé deux fois** | `tuple(techniques)` puis `for t in techniques` — un générateur est vidé par le premier, tout le reste est silencieusement vide |
| **Instruction « ignore X » non appliquée** | spec : « les modificateurs sont IGNORÉS » → `"AssemblyTitle" ascii wide` gardé entier dans la valeur |
| **Contrat documenté violé** | `_strip_comments` promettait de préserver les offsets et mangeait 2 caractères par `/*` — tous les corps de règles décalés |
| **Requête par élément au lieu d'un balayage** | 2 requêtes × 6349 clusters = ~12 000 allers-retours SQLite, dominant le rebuild |

Corrige-les toi-même, directement. Ne renvoie pas à Qwen pour un import oublié :
le coût est dans le ré-amorçage, pas dans la relecture.

Vérifie aussi, comme pour n'importe quel code : imports hallucinés, cas limites
traités, injections, chemins non validés, secrets en dur.

## Boucle d'exécution

Pour chaque étape :

1. **Spécifier** — selon les 8 points ci-dessus
2. **Déléguer** — appeler Qwen, en arrière-plan si c'est long
3. **Relire** — grille ci-dessus + correspondance à la spec
4. **Corriger** les défauts mineurs directement
5. **Écrire** le fichier
6. **Tester** — tests ciblés d'abord, suite complète avant de clore
7. **Lint** — `ruff check`, et `tsc --noEmit` si tu as touché au front
8. **Valider sur données réelles** — voir ci-dessous, c'est non négociable
9. **Itérer** en cas d'échec : renvoyer à Qwen l'erreur complète, le code
   incriminé et ce qui était attendu
10. **Ne passer à l'étape suivante que si tout passe**

### Étape 8 : la validation sur données réelles

**Les tests unitaires qui passent ne prouvent rien sur la qualité d'un résultat.**

Cas vécu sur ce projet : 26 tests unitaires au vert, ruff propre, typecheck
propre — et la fonctionnalité livrée sortait des scores de pertinence de 1.000
sur `/dev/null`. Quatre défauts de fond, tous invisibles aux tests, tous trouvés
en lançant le code sur les vrais rapports de `cti_stix.db`.

Donc, pour toute fonctionnalité qui **classe, score, filtre ou extrait** :

- exécute-la sur les vraies données du projet (`cti_stix.db`, `corpora/`)
- regarde le **top 10** du résultat et demande-toi si un analyste le validerait
- mesure l'**avant/après** chiffré et rapporte-le
- mesure la **latence** si c'est derrière un endpoint

Puis écris un test qui verrouille chaque défaut trouvé.

### Étape 8bis : vérifie que le test verrouille vraiment

Un test écrit après coup peut passer **pour la mauvaise raison**. Remets le défaut
et relance : s'il passe encore, il ne verrouille rien.

Mesuré : sur 3 tests de non-régression vérifiés ainsi, **2 passaient à tort**.

- `test_negated_content_is_never_indexed` passait même en supprimant le garde,
  parce que la valeur testée était rejetée par un *autre* filtre en aval.
- `test_posix_path_keeps_forward_slashes` passait car il utilisait la plateforme
  par défaut ; le garde ne mord que si la plateforme vaut `windows`.

Le cas le plus coûteux est un test qui existait **avant** : `test_dedupe_elects_
canonical_by_priority` était au vert depuis toujours alors que la dédup ne
repliait que 11 règles sur 11 396 — sa fixture rendait la règle « convertie »
identique à sa source, une conversion qui n'existe jamais en amont. **Une fixture
inventée à la main peut valider un comportement que la réalité n'a jamais.**

Corollaire : quand un test échoue, demande-toi d'abord si c'est le *code* ou la
*fixture* qui a tort. Un test qui échoue sur des données inventées à la main
révèle souvent un vrai biais du code — dans le cas ci-dessus, un comptage qui
faisait voter deux fois les artefacts Windows.

## Reprise en main

Tu écris le code toi-même **uniquement** dans ces cas :

- **correction d'un défaut de relecture** (import, garde de type, F401) sur du
  code que Qwen vient de produire — un aller-retour pour trois caractères coûte
  plus qu'il ne rapporte
- **trois allers-retours** avec Qwen n'ont pas produit un résultat correct :
  dis-le-moi explicitement avant de reprendre la main
- **la station Qwen ne répond pas** : préviens-moi, ne bascule pas en silence

Tout le reste — modules, fonctions, tests, migrations, routes API, composants
React — part en spécification chez Qwen, y compris ce qui te paraît court.

**Y compris les scripts jetables.** Les harnais de validation, les scripts de
mesure, les scripts d'ingestion : c'est le volume qu'on s'autorise à écrire
soi-même « parce que c'est plus rapide », et c'est faux. Mesuré sur une session :
**932 lignes réparties en 15 scripts**, tous de la même forme (ouvrir un corpus,
itérer, compter, imprimer un tableau) — exactement ce que Qwen fait bien, et sans
table de constantes ni cas limite à énumérer, donc une spec très courte suffit.
Groupe-les avec le module qu'ils valident (voir « Plusieurs fichiers par appel »)
et ils ne coûtent aucun aller-retour supplémentaire.

Seuil pratique pour les corrections : **en dessous de ~30 lignes, corrige
toi-même** (le coût est dans le ré-amorçage) ; **au-dessus, renvoie une spec de
correction**.

Les décisions d'architecture ne sont pas du code : le schéma SQL que tu conçois,
la formule de score que tu choisis, le contrat d'API que tu arrêtes, l'ADR que tu
rédiges restent à toi. Tu les écris dans la spec ; Qwen produit l'implémentation.

## Documentation d'architecture

Ce projet tient des ADR dans `docs/adr/`. Toute décision structurante en produit
un, écrit **par toi**, avant la délégation :

- contexte chiffré (mesure le problème, ne le décris pas)
- options considérées avec le verdict de chacune
- décision et conséquences, y compris ce qui devient plus difficile
- l'index `docs/adr/README.md` et le schéma de dépendances sont à mettre à jour

L'ADR doit refléter ce qui a été **construit**, pas ce qui était prévu : si la
validation sur données réelles t'a fait ajouter quatre garde-fous, ils y figurent
avec la raison qui les a rendus nécessaires.

Mets aussi à jour `README.md`, `CHANGELOG.md` et la doc concernée dans `docs/`.

## Signaler ce que tu fais

Annonce brièvement chaque délégation et son issue :

```
→ Délégation à Qwen : extraction des atomes Sigma (spec 120 lignes)
← Reçu 399 lignes, 5 corrections (clé non-str, doc non gardé, listes
  imbriquées, pas de sortie anticipée, F401)
✓ Tests 26/26 · ruff propre · corpus réel : 241 951 atomes / 11 393 règles
```

Rapporte les échecs tels quels, avec la sortie. Si une étape est sautée, dis-le.

## Dépannage

| Symptôme | Cause / correctif |
|---|---|
| `ollama: command not found` | normal, la CLI n'existe pas — utilise l'API HTTP |
| `/api/tags` ne répond pas | station éteinte ou hors réseau — préviens-moi |
| réponse tronquée | `done_reason` ≠ `stop` → augmente `num_predict` |
| code incohérent sur une spec longue | `num_ctx` trop bas ou absent |
| bloc `Thinking…` dans la sortie | `"think": false` manquant |
| `Python est introuvable` | `python3` de Git Bash = stub Store → passe par WSL |
| `pytest: not found` | utilise `.venv/bin/python -m pytest`, pas le python système |
| `content` vide via `/v1/chat/completions` | l'endpoint compatible OpenAI d'Ollama **ignore `think:false`** : Qwen émet des tokens de raisonnement qui consomment `max_tokens`. Le `think:false` ne marche que sur `/api/generate`. Sur `/v1`, prévois un `max_tokens` large. |
| un log en arrière-plan reste vide | double piège de bufferisation : préfixe la commande de `stdbuf -oL`, et n'insère jamais un `grep` sans `--line-buffered` dans le tuyau |
| `tail -f` d'un fichier WSL ne montre rien | `/tmp` de WSL ≠ `/tmp` de Git Bash — écris les logs dans le scratchpad, pas dans `/tmp` |
| accents/emoji cassés dans la sortie | la console WSL sous cet hôte annonce une taille d'écran invalide ; sans effet sur les fichiers écrits, ignore |
