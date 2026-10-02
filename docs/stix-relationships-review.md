# Revue de la génération des liens STIX 2.1

Revue du 2 octobre 2026, sur le commit `5314e4e`. Le code applicatif n'a pas été modifié.

**Conclusion.** Le catalogue des relations recommandées est presque complet. Les principaux changements à faire concernent la fidélité des liens : le système réécrit certains verbes et certaines extrémités pour satisfaire sa politique interne, et cette politique est parfois présentée comme une obligation STIX. Je recommande de conserver les faits extraits, de distinguer les recommandations de la norme de ses exigences, puis de partager un seul catalogue entre extraction, interface, API et export.

**Références et périmètre.** J'ai lu l'extraction et la validation Stage 3, le mapping Stage 4, la complétion Stage 4b, la validation Stage 5, les API de relations et de politique, les contraintes frontend et les ADR concernés. Références externes : [STIX 2.1 OASIS Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), [texte actuellement publié par OASIS](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html), [détail des corrections Errata 01, CSD01 du 2 avril 2025](https://docs.oasis-open.org/cti/stix/v2.1/errata01/csd01/stix-v2.1-errata01-csd01.html), [contrôles du validateur OASIS](https://stix2-validator.readthedocs.io/en/latest/best-practices.html).

**Distinction normative essentielle.** Une `relationship` relie des SDO/SCO ; ses extrémités ne peuvent pas être des SRO ou des objets méta. Son verbe respecte les caractères ASCII minuscules, chiffres et tirets. La spécification recommande ses couples prédéfinis, mais permet aussi des verbes définis par les utilisateurs. Un couple absent du catalogue recommandé n'est donc pas, à lui seul, une violation de la norme. [STIX 2.1, §5.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).

**1. Priorité haute — Corriger les relations communes dans l'interface.**

`frontend/src/stix/relConstraints.ts:127` définit les trois verbes comme universels, puis `pairVerbs():133` les ajoute à tous les couples. Le backend, dans `pipeline/stix_rel_spec.py:197`, réserve déjà `duplicate-of` et `derived-from` aux objets de même type, conformément au catalogue commun (§3.7). L'interface peut donc proposer `malware duplicate-of tool`, mais Stage 4 exportera `related-to`.

Changement recommandé : calculer les verbes communs en fonction des deux types, puis afficher séparément les verbes recommandés et les relations personnalisées. Un analyste doit pouvoir comprendre avant validation ce qui sera exporté. Ajouter un test qui compare les options frontend au résultat du backend.

**2. Priorité haute — Conserver l'identité des extrémités.**

`pipeline/stage4_stix_mapping.py:327` remplace un SCO par son Indicator lorsqu'un côté est un observable et que le verbe n'est pas listé pour le couple direct. Reproduction en mémoire : `ipv4-addr related-to malware` devient `indicator related-to malware`. Cela change le sujet de l'assertion. Une relation avec une adresse n'est pas automatiquement une relation avec une règle de détection.

Changement recommandé : conserver les SCO pour les faits qui portent sur eux ; réserver la conversion vers un Indicator aux assertions de détection explicitement identifiées. Pour `indicates`, rendre cette conversion visible et traçable. Pour une relation personnalisée correctement documentée, ne pas changer les extrémités sous prétexte qu'elle est absente des tables.

Le même principe s'applique au filtre SCO–attack-pattern (`:318`, `:1048`) : c'est un choix de précision du projet, pas une interdiction générale STIX. Le garder pour les sorties automatiques douteuses, tout en permettant une relation personnalisée étayée par un analyste.

**3. Priorité haute — Remplacer les réécritures automatiques par une décision explicite.**

Le vocabulaire fermé de `models/schemas.py:55` est utilisé par l'API (`api/routes/relationships.py:168`) et l'export (`pipeline/stage4_stix_mapping.py:1060`, `:1100`, `:2329`). Le helper accepte un verbe inconnu mais l'exporte comme `related-to`. Reproduction : la bibliothèque `stix2` accepte `malware executes file`, tandis que `_add_relationship()` produit `related-to`. Il s'agit ici d'un exemple de verbe personnalisé, pas d'un couple recommandé.

Je recommande trois profils d'application :

- **Recommandé** : catalogue STIX et relations communes ; les propositions hors catalogue restent à revoir.
- **Étendu** : relations personnalisées documentées, avec validation syntaxique et des extrémités.
- **Compatibilité consommateur** : restrictions supplémentaires pour la cible d'import, identifiées comme telles.

Une proposition mal formée doit être rejetée ou mise en attente. Une relation indéterminée peut devenir `related-to` si la source établit réellement une association. Un simple verbe non reconnu ne suffit pas à prouver cette association.

**4. Priorité moyenne — Versionner le catalogue et intégrer l'errata.**

La comparaison automatisée des tables par objet, hors tables inverses et avant expansion du joker SCO, donne 120 entrées dans le code et 120 dans le texte OASIS actuel. Seule différence : `malware-analysis analysis-of malware` dans le dépôt, `malware-analysis av-analysis-of malware` dans le texte actuel. L'[errata §1.2](https://docs.oasis-open.org/cti/stix/v2.1/errata01/csd01/stix-v2.1-errata01-csd01.html) documente précisément cette correction. L'ancien texte OS utilisait bien `analysis-of` : il faut annoncer la référence choisie, pas qualifier tous les anciens bundles d'invalides.

Fichiers concernés : `pipeline/stix_rel_spec.py:111`, `models/schemas.py:66`, les prompts `pipeline/stage3_llm.py:503` et `:653`, `frontend/src/stix/relConstraints.ts:98`, les listes de verbes dans `tokens.ts` et `Policy.tsx`.

Changement recommandé : un catalogue versionné, dont le frontend et les prompts sont générés ou alimentés par API. Ajouter `av-analysis-of` pour la référence actualisée ; conserver l'historique du verbe demandé et gérer explicitement les anciennes données. Les sections par objet doivent rester la référence de comparaison, plutôt que l'annexe B seule (§5.1.1).

**5. Priorité moyenne — Exposer les liens intégrés aux objets.**

Le mapping crée surtout des SCO isolés (`pipeline/stage4_stix_mapping.py:1504`) et des SRO. Il n'alimente pas les liens techniques intégrés à partir des assertions extraites. Possibilités à ajouter :

| Fait extrait | Représentation à prendre en charge |
|---|---|
| Résolution DNS | `domain-name.resolves_to_refs` |
| Appartenance d'une IP à un AS | `ipv4-addr/ipv6-addr.belongs_to_refs` |
| Échantillon d'un malware | `malware.sample_refs` vers file/artifact |
| Fichier dans un répertoire | `file.parent_directory_ref` |
| Extrémités d'un trafic | `network-traffic.src_ref`, `dst_ref` |
| Exécutable d'un processus | `process.image_ref` |

Ces propriétés sont définies dans les [sections des objets STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html). Pour DNS et IP–AS, les SRO correspondants sont également définis : leur usage actuel n'est pas une erreur. Choisir la forme selon les besoins de provenance, confiance et temporalité. Ne pas inférer une résolution DNS simplement parce qu'un domaine et une IP figurent dans le même rapport.

Point associé : `NETWORK_TRAFFIC` devient actuellement `Software(name=...)` (`:1530`). Construire un vrai NetworkTraffic lorsque les propriétés nécessaires sont disponibles ; sinon garder une assertion non résolue. Un Software ne préserve pas le type ni les références d'un trafic réseau.

**6. Priorité moyenne — Séparer observation, détection et dérivation interne.**

Le projet génère `indicator based-on SCO` (`pipeline/stage4_stix_mapping.py:829`), exception explicitement enregistrée dans `_PROJECT_EXTENSIONS` (`pipeline/stix_rel_spec.py:142`). C'est un couple personnalisé permis ; le couple recommandé est `indicator based-on observed-data` (§4.7.2). Ne pas fabriquer un ObservedData avec les dates de construction pour satisfaire ce catalogue.

Je recommande de garder l'exception dans le profil étendu, de la signaler dans le profil recommandé, et de créer ObservedData seulement quand le document fournit une observation exploitable. Ajouter ensuite le SRO `Sighting` pour les assertions d'observation d'un SDO : il utilise notamment `sighting_of_ref`, `observed_data_refs` et `where_sighted_refs`. [STIX 2.1 §5.2](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).

Cela implique une représentation d'extraction distincte pour les observations ; ajouter seulement un verbe à la liste ne suffirait pas. La génération systématique d'Indicators pour les valeurs acceptées (`:911`) devrait aussi dépendre de leur rôle dans le rapport : une valeur technique peut être une victime ou un contexte bénin.

**7. Priorité moyenne — Valider et limiter les politiques de réécriture.**

L'API de politique vérifie que chaque règle est un dictionnaire (`api/routes/policy.py:162`), mais pas son couple typé. `_apply_policy()` (`pipeline/stage4_stix_mapping.py:2259`) peut remplacer toute relation d'un couple par un verbe unique. Une règle malware→file en `drops` peut ainsi transformer une assertion `downloads`, même si les deux sont recommandées. La validité du couple ne garantit pas la fidélité à la source.

Changement recommandé : schéma de règle strict, validation par catalogue/profil, et distinction entre « préférer un verbe pour une proposition indéterminée » et « corriger cette assertion ». Prévisualiser le résultat effectif avant enregistrement. Une correction humaine doit garder la trace du fait initial.

**8. Priorité moyenne — Traiter la complétion comme une hypothèse analytique.**

Stage 4b applique des compositions comme `uses + uses → uses` et `indicates + uses → indicates` (`pipeline/stage4b_graph_completion.py:125`). Une famille de malware peut utiliser plusieurs techniques sans qu'un acteur ou un hash particulier soit associé à chacune. Le contrôle final du couple typé ne tranche pas cette question.

Le marquage `x_evidence_label=inferred` et les prémisses (`:560`) sont une bonne base. Je recommande une revue distincte des liens inférés, des conditions sur les entités intermédiaires et leurs occurrences, et des mesures de précision par règle avant activation. Ces compositions sont des heuristiques du projet.

**9. Priorité moyenne — Rendre le résultat de validation explicite.**

`pipeline/stage5_validation.py:199` et `:203` retournent `True` même quand les schémas manquent. Lors de cette revue, `_schemas_installed()` retourne **True** : je ne conclus donc pas que cet environnement saute actuellement la validation. Le contrat de retour reste ambigu pour les autres installations.

Retour recommandé : statut `validated`, `invalid` ou `unverified`, plus erreurs, avertissements, version des schémas et profil appliqué. Le validateur distingue les erreurs obligatoires des avertissements de bonnes pratiques ; le contrôle `202` concerne les couples recommandés, et `strict=True` transforme les avertissements en erreurs. [Documentation OASIS du validateur](https://stix2-validator.readthedocs.io/en/latest/best-practices.html).

Conserver les avertissements dans le résultat consultable, avec une explication pour chaque extension intentionnelle. Figer les versions de schémas plutôt que restaurer silencieusement depuis une branche distante mouvante.

**10. Compléments utiles.**

- Unifier les listes de SCO : le routage Stage 4 ne contient que 14 des 18 types de `SCO_TYPES`. Les quatre absents sont directory, email-message, process et x509-certificate ; surtout un problème pour une extension future de l'extraction.
- Donner à la validation de relation un résultat structuré : type connu ou inconnu, syntaxe, extrémités autorisées, couple recommandé, extension du projet, décision du profil. `rel_is_suggested()` accepte actuellement des types/champs vides (`pipeline/stix_rel_spec.py:191`).
- Alimenter les prompts avec les couples directionnels réellement disponibles. Aujourd'hui ils donnent essentiellement une liste globale de verbes, puis Stage 4 corrige les propositions tardivement.
- Conserver le ledger et la gestion prudente des dates. Ajouter la référence normative, le profil et les décisions sur les liens intégrés. Tester séparément les contraintes de dates et les hypothèses temporelles sur les liens inférés.

**Ordre de mise en œuvre proposé.** D'abord partager/versionner le catalogue, corriger les verbes communs et intégrer l'errata. Ensuite sécuriser le contrat API→prévisualisation→export : extrémités conservées, profils explicites, avertissements visibles, policies validées. Puis ajouter les références intégrées, ObservedData et Sighting avec leur modèle d'extraction. Enfin mesurer les règles de complétion sur des exemples annotés.

**Vérification effectuée.** 88 tests existants passent : `test_stix_rel_spec.py`, `test_stix_self_edges.py`, `test_stage4_paths.py`, `test_stage4b_completion.py`, `test_stage5.py`. Comparaison automatisée du catalogue et reproductions en mémoire décrites ci-dessus. Aucun appel d'extraction LLM ni import OpenCTI n'a été effectué. La réussite de ces tests confirme les comportements actuels, pas une couverture exhaustive de la norme.

**Tests à ajouter lors de l'implémentation.** Parité complète frontend/backend/prompts ; verbes communs selon les types ; couples et sens recommandés ; verbes personnalisés selon le profil ; rejet des extrémités méta/SRO ; conservation d'un SCO lié par related-to ; visibilité d'une conversion en Indicator ; distinction drops/downloads malgré une politique ; av-analysis-of et reprise des données anciennes ; liens intégrés et références résolues ; observations sans dates inventées ; absence de schémas signalée ; hypothèses de complétion soumises à revue.
