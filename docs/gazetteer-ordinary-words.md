# Gazetteer: ordinary-word forms — contextual review draft

**Audit B 8.3.2 · Revision: 2026-10-11 · Status: proposed decisions, not implemented.**

This revision replaces blanket alias removal with a decision for each of 151 forms:
the original 142 plus nine additions already present in the shipped index. All original
forms remain in the inventory. Groups A–D preserve the original organisation, not its
original policy. Canonical status does not establish that an occurrence denotes a threat.

## Decision rules

| Decision | Proposed behaviour | Limitation |
|---|---|---|
| **RETAIN** | Keep current case-insensitive candidate matching for this form. | Provisional preservation of recall, not proof of precision. |
| **CASE** | Accept a surface whose first character is uppercase, including `PatchWork`, `RainDrop` and ALL CAPS. Withhold an all-lowercase occurrence from automatic gazetteer emission. | A sentence start, title or other proper name can still pass; casing is only a filter. Lowercase technical mentions can be missed. |
| **CONTEXT** | Accept any casing only when the local sentence, explicit alias construction or structured command evidence identifies the intended object. Apply the form-specific exclusions in the table. | A nearby word such as “malware”, a whole report about attacks, or a capital letter is insufficient. Unresolved identity must remain unresolved. |

“Withhold” means withhold this Stage 2b automatic match. Keep the original text and
allow another extractor or an analyst to identify it from evidence. Do not ban the
canonical entity across the pipeline and do not delete aliases from the knowledge index.
For CONTEXT rows, prefer an explicit naming relation, typed apposition, alias equation,
or command invocation over a proximity-keyword rule. Platform/family evidence is required
where two malicious tools share a name. A failed check must not claim the occurrence's span.

Every row is a review proposal. **No corpus occurrence** means there is no local empirical
basis for measuring that rule's benefit or recall cost. The synthetic examples are proposed
acceptance checks, not observed usage or additional counts. CASE suggestions without positive
evidence are provisional; no production deployment is justified solely by these tables.

## Evidence and counting method

Counts cover the 400 unique files in `data/annoctr-repo/AnnoCTR/all/text/*.txt`, read as
UTF-8 without removing Markdown, URLs, tables or filenames. Do not add `train_ext`: it
duplicates the 70 train documents. The columns **L/T/U/M** mean lowercase, title case,
all uppercase and other mixed case; the categories are mutually exclusive. **Docs** is
the number of files with at least one occurrence, before identity disambiguation.

For each lowercase form, search `text.lower()` with this Python regex:

```python
pattern = r"(?<![^\W_])(?<!-)" + re.escape(form) + r"(?![^\W_])(?!-)"
```

This uses the current matcher boundary: letters, digits and hyphens block a match;
underscores do not. Count case on the corresponding original-text surface, checking
`islower()`, then `isupper()`, then `istitle()`, otherwise mixed. Lowercasing was checked
not to change string lengths in these 400 files, so these excerpt offsets are valid here.
These are raw candidate occurrences, not output entities: longest-match overlap handling
and canonical deduplication have not been applied. The current matcher emits at most
one result per canonical name per document, which is not the same as per MITRE identity.

The former table used a different underscore boundary. At production boundaries,
`page` is 699 lowercase / 59 non-lowercase, `spark` 9 / 12, and `ping` 27 / 7.
The split into T/U/M also exposes why an uppercase-only rule would discard title-case names.

Excerpts below preserve source words and casing, with whitespace collapsed and `…`
marking a clipped window; they are illustrative, not exhaustive or gold annotations.
Each link identifies the local corpus file, split and one-based occurrence line.
Corpus files are git-ignored and must be present locally to follow these links.
`general_only` means the report has no cybersecurity annotation layer; it does not mean
that its threat mentions are negatives. Test excerpts are explicitly labelled diagnostic.

Only 120 reports have the cyber layer (70 train / 16 dev / 34 test). The earlier review
already inspected some test contexts, so this inventory must not be presented as an
untouched held-out evaluation. Tune on train/dev; freeze decisions before evaluation,
report that exposure, and seek an additional untouched holdout for confirmatory claims.
See [ADR-0060](adr/0060-evaluation-protocol.md).

## Source checks that change the proposal

- **Joker remains a valid alias.** MITRE lists it under Bread, an Android malware family.
  This supports keeping malware mentions eligible, while excluding Joker’s Stash.
  [MITRE S0432](https://attack.mitre.org/software/S0432/).
- **Elfin remains a valid actor name.** MITRE lists it under APT33; the six local
  capitalised occurrences concern that actor. [MITRE G0064](https://attack.mitre.org/groups/G0064/).
- **`meek` is normally lowercase.** It names a Tor transport plugin, so context must
  admit that spelling. [MITRE S0175](https://attack.mitre.org/software/S0175/).
- **MEDUSA needs identity disambiguation.** S1220 is a Linux rootkit. The corpus's
  Android Medusa mentions must not map to it merely because they say “malware”.
  [MITRE S1220](https://attack.mitre.org/software/S1220/).
- **Element names are historical, and uppercase is not mandatory.** Microsoft moved
  to a weather-based taxonomy in 2023; its own 2019 article also uses title-case Thallium,
  Barium and Strontium. Preserve historical aliases for old reports, including title case.
  [Microsoft taxonomy change](https://www.microsoft.com/en-us/security/blog/2023/04/18/microsoft-shifts-to-a-new-threat-actor-naming-taxonomy/),
  [Microsoft title-case usage](https://blogs.microsoft.com/on-the-issues/2019/12/30/microsoft-court-action-against-nation-state-cybercrime/).

Official pages were consulted on 2026-10-11 for these specific questions; the inventory's
names, types and IDs remain those of the project's pinned gazetteer. This is not a fresh
audit of every vendor alias mapping or an ATT&CK index update. Vendor clusters can overlap;
a live naming-table similarity must not silently rewrite the local identity mapping.

## Inventory

**151 forms: 1 RETAIN, 105 CASE, 45 CONTEXT.** 54 forms occur in this corpus; 97 do not.

### A. Alias forms from the original draft (26)

| Form | Indexed identity/type | L/T/U/M; Docs | Decision | Rationale / required context | Representative context |
|---|---|---|---|---|---|
| `agenda` | Qilin (malware, S1242) | 0/1/0/0; 1 | **CONTEXT** | Require an explicit Qilin/Agenda ransomware identity; meeting agendas do not qualify. | “…t “Dagordning för det kommande mötet på fredagen” translates to “Agenda for the upcoming meeting on Friday” (bottom left) !&#91;emotet_2&#93;(/sites/default/files/inline-images/Emotet_2.png…” [general_only; L142](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-08-28_comprehensive-look-emotets-summer-2020.txt#L142) |
| `armageddon` | Gamaredon Group (threat_actor, G0047) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Armageddon passes; armageddon is withheld. Identity still needs review. |
| `aurora` | Hydraq (malware, S0203) | 0/3/0/0; 1 | **CONTEXT** | Require Hydraq software identity; an Aurora exploit or operation is not itself the malware. | “…Aurora Exploit Still Floating ... December 17, 2013 It's been around two years since Microsoft released a patch for…” [general_only; L1](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2013-12-17_aurora-exploit-still-floating.txt#L1) |
| `briar` | Mandrake (malware, S0485) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Briar passes; briar is withheld. Identity still needs review. |
| `canopy` | STARWHALE (malware, S1037) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Canopy passes; canopy is withheld. Identity still needs review. |
| `chromium` | Earth Lusca (threat_actor, G1006) | 4/16/0/0; 11 | **CONTEXT** | Require actor attribution compatible with G1006; exclude browsers and chemical uses. | “…ble of stealing passwords, cookies, cards, and autofill forms of Chromium and Mozilla browsers. This stealer also collects files from the specified path, takes screenshots, and instal…” [train; L9](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2020-08-14_purplewave-new-infostealer-russia.txt#L9)<br>“…&#42; Download and execute the file &#42; Supports all browsers based on Chromium &#42; Supports all Gecko-based browsers Execution starts with dropping a copy of itself into the AppData/Roaming…” [train; L87](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2021-02-09_discord-cdn-popular-choice-hosting.txt#L87) |
| `cicada` | menuPass (threat_actor, G0045) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Cicada passes; cicada is withheld. Identity still needs review. |
| `electrum` | Sandworm Team (threat_actor, G0034) | 1/13/0/0; 9 | **CONTEXT** | Require Sandworm actor identity; exclude the cryptocurrency wallet, including wallet theft. | “…&#42; Credential stealing of some cryptocurrency wallets, including Electrum, MultiBit, Ethereum, Jaxx Liberty, Bytecoin, Atomic, and Exodus &#42; Stealing credential of FTP clients, includi…” [train; L51](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2020-06-26_taurus-new-stealer-town.txt#L51)<br>“…egram session files &#42; Stealing Steam application data &#42; Stealing Electrum wallet data &#42; Loading and executing additional module/malware !&#91;PurpleWave Login Panel&#93;(/cdn-cgi/image/format…” [train; L18](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2020-08-14_purplewave-new-infostealer-russia.txt#L18) |
| `elfin` | APT33 (threat_actor, G0064) | 0/6/0/0; 3 | **RETAIN** | Retain provisionally: six observed capitalised uses name APT33; no ordinary-word hit under these boundaries. This is not proof that lowercase use is safe. | “…sidents. &#124; &#42;&#42;APT 33 and the energy sector&#42;&#42; APT33, also known as Elfin Group has kept a notable activity during the last three years. Its target is generalist although a large part…” [general_only; L229](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-09-18_geopolitical-strategy-of-iran-and.txt#L229)<br>“…the &#91;Gorgon Group&#93;(https://attack.mitre.org/groups/G0078/) and &#91;Elfin Group&#93;(https://attack.mitre.org/groups/G0064/). Remcos is primarily delivered to victims via malicious attach…” [train; L21](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2021-05-05_catching-rats-over-custom-protocols.txt#L21) |
| `james` | Milan (malware, S1015) | 0/0/0/0; 0 | **CONTEXT** | Require Milan malware identity; a person named James is insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “James (S1015)” is explicit identity evidence; the bare name is insufficient. |
| `joker` | Bread (malware, S0432) | 1/49/0/0; 5 | **CONTEXT** | Require Android malware identity compatible with Bread; exclude Joker’s Stash and other named worms. | “…age &#42; Read Scanner &#42; Print Scanner #### &#42;&#42;Targeted Categories:&#42;&#42; Joker malware authors have targeted some categories of apps more than others. Based on the 50+ payloads we have see…” [general_only; L25](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2021-07-20_joker-joking-google-play.txt#L25)<br>“…More annoying than crippling: Joker’s Stash takedown is temporary Dec 17, 2020 Law enforcement has allegedly seized proxy servers used in connect…” [train; L1](../data/annoctr-repo/AnnoCTR/all/text/intel471_2020-12-17_jokers-stash-fbi-interpol-dns.txt#L1) |
| `karma` | VOID MANTICORE (threat_actor, G1055) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Karma passes; karma is withheld. Identity still needs review. |
| `mantis` | APT-C-23 (threat_actor, G1028) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Mantis passes; mantis is withheld. Identity still needs review. |
| `mirage` | Ke3chang (threat_actor, G0004) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Mirage passes; mirage is withheld. Identity still needs review. |
| `monsoon` | Patchwork (threat_actor, G0040) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Monsoon passes; monsoon is withheld. Identity still needs review. |
| `oxide` | Mandrake (malware, S0485) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Oxide passes; oxide is withheld. Identity still needs review. |
| `page` | Elise (malware, S0081) | 699/58/1/0; 139 | **CONTEXT** | Require explicit naming as the Elise malware alias; a web page or file component is insufficient. | “…iliate program is closed. Stay safe and good luck.&#42; &#42;The landing page, servers, and other resources will be taken down within 48 hours.&#42; --- DarkSide was not the only group to mak…” [dev; L31](../data/annoctr-repo/AnnoCTR/all/text/intel471_2021-05-14_darkside-ransomware-shut-down-revil.txt#L31)<br>“…ites/default/files/images/blogs/Terror_EK_Activity/Flash_landing_page.png) Figure 11: Calls to three flash payloads from Flash exploit webpage. We have seen changes in the Flash e…” [general_only; L40](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2017-10-24_terror-exploit-kit-malvertising-campaign.txt#L40) |
| `photo` | Derusbi (malware, S0021) | 8/6/0/0; 10 | **CONTEXT** | Require an identified Derusbi backdoor; ordinary images, attachments and URL paths do not qualify. | “…ies, access databases and in general any action allowed by .NET. Photo (also called: “dersubi”): A DLL that is the backdoor, this one has the following capabilities: ▪ Listing dire…” [train; L71](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-05-30_leviathan-geostrategy-and-ttp-technical.txt#L71)<br>“…post.com/report-microsofts-github-account-gets-hacked/155587/), &#91;photo editing app Pixlr&#93;(https://siliconangle.com/2021/01/20/shinyhunters-publishes-1-9m-stolen-user-credentials-ph…” [test diagnostic; L5](../data/annoctr-repo/AnnoCTR/all/text/intel471_2021-08-23_shinyhunters-data-breach-mitre-attack.txt#L5) |
| `rattlesnake` | Sidewinder (threat_actor, G0121) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Rattlesnake passes; rattlesnake is withheld. Identity still needs review. |
| `reaper` | APT37 (threat_actor, G0067) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Reaper passes; reaper is withheld. Identity still needs review. |
| `scorpion` | ChChes (malware, S0144) | 0/1/0/0; 1 | **CONTEXT** | Require ChChes malware identity; exclude company names such as Magic Scorpion. | “…based big data service company 杭州魔蝎数据科技有限公司 (Eng. Hangzhou Magic Scorpion Data Technology Co. Ltd.and placed restrictions on the company. ccording to the Chinese state broadcaster Ch…” [dev; L49](../data/annoctr-repo/AnnoCTR/all/text/intel471_2021-04-19_china-cybercrime-big-data-privacy.txt#L49) |
| `snake` | Uroburos (malware, S0022); Turla (threat_actor, G0010) | 0/3/0/0; 1 | **CONTEXT** | Resolve Turla actor versus Uroburos malware explicitly; Snake Keylogger supports neither mapping. | “…r 19&#93;(/sites/default/files/inline-images/19.png) The payload was Snake Keylogger in this case. Later samples used Liverpool Football Club-themed download locations. In this sample…” [general_only; L93](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2022-01-24_dtpacker-net-packer-curious-password.txt#L93) |
| `soldier` | SysUpdate (malware, S0663) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Soldier passes; soldier is withheld. Identity still needs review. |
| `tick` | BRONZE BUTLER (threat_actor, G0060) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Tick passes; tick is withheld. Identity still needs review. |
| `trinity` | FrameworkPOS (malware, S0503) | 1/0/0/0; 1 | **CONTEXT** | Require FrameworkPOS malware identity; a hostname component is insufficient. | “…this campaign: &#42; armandosofsalem&#91;.&#93;com/l9k7hg4/b4387kfd&#91;.&#93;exe &#42; trinity.ad-ventures&#91;.&#93;es/l9k7hg4/b4387kfd&#91;.&#93;exe &#42; 188.226.152&#91;.&#93;172/l9k7hg4/b4387kfd&#91;.&#93;exe In this blog, we will prov…” [general_only; L14](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2016-01-29_malicious-office-files-dropping-kasidet.txt#L14) |
| `viper` | Sakula (malware, S0074) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Viper passes; viper is withheld. Identity still needs review. |

### B. Canonical or shared forms from the original draft (78)

| Form | Indexed identity/type | L/T/U/M; Docs | Decision | Rationale / required context | Representative context |
|---|---|---|---|---|---|
| `anchor` | Anchor (malware, S0504) | 2/18/0/0; 3 | **CASE** | Preserve Anchor malware mentions; withhold lowercase URL/path fragments as automatic name evidence. | “…s://nationalcollege.edu&#91;.&#93;np/admin/assets/js/jquery/tiny/plugins/anchor/.anchor/sysWow64.exe&#42;&#42;&#42;” !&#91;Decrypted Macro code&#93;(/cdn-cgi/image/format=auto/sites/default/files/images/blogs/…” [dev; L58](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2021-07-14_targeted-attack-government-organizations-delivers.txt#L58)<br>“…dropping PowerBrace. &#42;&#42;Linking DPRK threat actors to TrickBot – Anchor and PowerRatankba&#42;&#42; On Dec. 10, 2019, SentinelOne researchers published a &#91;blog post and report&#93;(https://labs…” [general_only; L54](../data/annoctr-repo/AnnoCTR/all/text/intel471_2020-09-16_partners-in-crime-north-koreans.txt#L54) |
| `apostle` | Apostle (malware, S1133) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Apostle passes; apostle is withheld. Identity still needs review. |
| `avenger` | Avenger (malware, S0473) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Avenger passes; avenger is withheld. Identity still needs review. |
| `axiom` | Axiom (threat_actor, G0001) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Axiom passes; axiom is withheld. Identity still needs review. |
| `backspace` | BACKSPACE (malware, S0031) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: BACKSPACE passes; backspace is withheld. Identity still needs review. |
| `bitter` | BITTER (threat_actor, G1002) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: BITTER passes; bitter is withheld. Identity still needs review. |
| `bookworm` | BOOKWORM (malware, S1226) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: BOOKWORM passes; bookworm is withheld. Identity still needs review. |
| `boombox` | BoomBox (malware, S0635) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: BoomBox passes; boombox is withheld. Identity still needs review. |
| `bread` | Bread (malware, S0432) | 0/0/0/0; 0 | **CONTEXT** | Require the Android malware family, not food or a generic noun. Provisional: unobserved. | No corpus occurrence. Synthetic: “Bread (S0432)” is explicit identity evidence; the bare name is insufficient. |
| `calendar` | CALENDAR (malware, S0025) | 2/0/0/0; 2 | **CONTEXT** | Require the named malware; calendar access or events are ordinary application features. | “…nts in file shares, key meetings with clients or partners in the calendar, corporate directory, notes from projects or meetings. They use this access to execute the next step— conduct…” [general_only; L14](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-10-22_combatting-bec-and-eac-how.txt#L14)<br>“…ation with full email access (read, write and send mails, tasks, calendar events, contacts and notes) &#42; Add a forwarding rule - a straightforward way of getting notifications on impor…” [general_only; L134](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-03-23_oauth-abuse-think-solarwindssolorigate-campaign.txt#L134) |
| `cannon` | Cannon (malware, S0351) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Cannon passes; cannon is withheld. Identity still needs review. |
| `carbon` | Carbon (malware, S0335) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Carbon passes; carbon is withheld. Identity still needs review. |
| `chameleon` | Chameleon (malware, S1083) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Chameleon passes; chameleon is withheld. Identity still needs review. |
| `chaos` | Chaos (malware, S0220) | 1/1/0/0; 2 | **CONTEXT** | Require the specific S0220 identity; capitalised headline prose about chaos is insufficient. | “…pments. Hacking the database of voters in key states could cause chaos on Election Day. One could, for example, manipulate the voting intention polls, disable voters on the voting…” [train; L60](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-10-18_cyber-iii-cold-war-hack.txt#L60)<br>“…Security Brief: Mobile Phishing Increases More Than 300% as 2020 Chaos Continues November 02, 2020 COVID-19 rapidly shifted our society to rely on remote communication—and it’s cle…” [general_only; L1](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-11-02_mobile-phishing-increases-more-300.txt#L1) |
| `charger` | Charger (malware, S0323) | 1/0/0/0; 1 | **CASE** | Withhold the lowercase device accessory; capitalised ordinary uses remain a known limitation. | “…ing Device Powered On/Off, Device Attached / Removed to/from the charger, Apps installed/removed/updated. &#42; Silently monitor all inbound and outbound SMS messages. &#42;&#42;How the app can…” [general_only; L32](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2014-01-09_want-spy-google-play-will.txt#L32) |
| `chimera` | Chimera (threat_actor, G0114) | 0/1/0/0; 1 | **CASE** | Preserve named APT-group usage; no blanket alias deletion. | “…which has been detected on targets hit by the APT group known as Chimera. The use of “VMProtect” by the actors makes the analysis of their code more time-consuming (although it simpl…” [test diagnostic; L4](../data/annoctr-repo/AnnoCTR/all/text/lab52_2021-04-29_chimera-apt-updates-on-its.txt#L4) |
| `circles` | Circles (malware, S0602) | 2/0/0/0; 2 | **CASE** | Withhold generic criminal/social circles; capitalised prose remains ambiguous. | “…are known private gangs operating in tight, close-knit criminal circles using direct and private communication channels that we have little visibility into. What we are aiming to do…” [train; L16](../data/annoctr-repo/AnnoCTR/all/text/intel471_2020-11-16_ransomware-as-a-service-2020.txt#L16)<br>“…they were published. However, it is more of a concern in certain circles that the GRU failed in its operations than to have leaked the identities or modus operandi of some of its mem…” [train; L8](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-10-18_cyber-gru-xiv-conclusions.txt#L8) |
| `cleaver` | Cleaver (threat_actor, G0003) | 0/1/0/0; 1 | **CASE** | Preserve named operation/group candidates; the excerpt alone does not prove actor identity. | “…ocial networks to generate misinformation in the US society. &#124; &#124; Cleaver &#124; 2012 – 2014 &#124; Operation for industrial and government espionage purposes. &#124; &#124; Ababil &#124; Dec.2011 – May 2013…” [general_only; L110](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-09-18_geopolitical-strategy-of-iran-and.txt#L110) |
| `crimson` | Crimson (malware, S0115) | 0/16/0/0; 2 | **CASE** | Preserve Crimson RAT and uppercase variants; withhold lowercase colour use. | “…n be considered for flagging RC4 encrypted Remcos traffic. ### &#42;&#42;Crimson RAT&#42;&#42; Crimson RAT has been favored by threat actors for targeted attacks on governments and organizations in…” [train; L44](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2021-05-05_catching-rats-over-custom-protocols.txt#L44)<br>“…Targeted Attack on Indian Financial Institution Delivers Crimson RAT April 01, 2020 In 2016, the Crimson remote-access trojan (RAT) made headlines when it was found to be use…” [general_only; L1](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2020-04-01_targeted-attack-indian-financial-institution.txt#L1) |
| `crutch` | Crutch (malware, S0538) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Crutch passes; crutch is withheld. Identity still needs review. |
| `cuba` | Cuba (malware, S0625) | 2/7/0/0; 2 | **CONTEXT** | Require the ransomware family; a country, target location or sanctions list is insufficient. | “…Cuba Ransomware Analysis December 14, 2021 Due to the recent warning published by the FBI &#91;about Cuba ransomware&#93;(…” [general_only; L1](../data/annoctr-repo/AnnoCTR/all/text/lab52_2021-12-14_cuba-ransomware-analysis.txt#L1)<br>“…e-icts-supply-chain) including China, Russia, Iran, North Korea, Cuba, and Venezuela. Further, the &#91;UK government&#93;(https://www.gov.uk/government/speeches/foreign-secretary-on-the-…” [dev; L63](../data/annoctr-repo/AnnoCTR/all/text/quoteintelligence_2021-01-27_supply-chain-attacks-cybersecurity-regulations.txt#L63) |
| `disco` | Disco (malware, S1088) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Disco passes; disco is withheld. Identity still needs review. |
| `donut` | Donut (tool, S0695) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Donut passes; donut is withheld. Identity still needs review. |
| `dustpan` | DUSTPAN (malware, S1158) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: DUSTPAN passes; dustpan is withheld. Identity still needs review. |
| `embargo` | Embargo (malware, S1247) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Embargo passes; embargo is withheld. Identity still needs review. |
| `empire` | Empire (tool, S0363) | 4/6/0/0; 6 | **CONTEXT** | Require the post-exploitation tool; distinguish unrelated names such as China Central Empire. | “…gation is that the attackers after running the VBS used it as an Empire post-exploitation framework (&lt;https://github.com/EmpireProject/Empire&gt;). A total of five scripts plus the one…” [train; L18](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-04-02_wirte-group-attacking-the-middle.txt#L18)<br>“…b forums, like HLODAY or HZDG (华中帝国, also known as China Central Empire), have gone down during this time. More often, skilled Chinese actors make their way to international forums,…” [train; L38](../data/annoctr-repo/AnnoCTR/all/text/intel471_2020-12-10_china-cybercrime-undergrond-deepmix-tea.txt#L38) |
| `epic` | Epic (malware, S0091) | 0/6/0/0; 4 | **CONTEXT** | Require S0091 malware identity; exclude Epic/Epic Privacy browser mentions. | “…Go. &#42; ChromePlus &#42; Uran &#42; BlackHawk &#42; CoolNovo &#42; AcWebBrowser &#42; Epic Browser &#42; Baidu Spark &#42; Rockmelt &#42; Sleipnir &#42; SRWare Iron &#42; Titan Browser &#42; Flock &#42; Vivaldi &#42; Sputnik &#42; Maxth…” [general_only; L38](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2019-03-15_immortal-information-stealer.txt#L38)<br>“…RockMelt, Vivaldi, Go Browser, Sputnik, Kometa, Uran, QIP Surf, Epic Privacy Browser, Brave, Cent Browser, CocCoc, 7 Star, Elements Browser, Safer Technologies, Mustang, Superbir…” [general_only; L117](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2020-04-14_fake-vpn-sites-deliver-infostealers.txt#L117) |
| `equation` | Equation (threat_actor, G0020) | 1/5/0/0; 5 | **CONTEXT** | Require actor identity; exclude Microsoft Equation Editor and ordinary mathematical prose. | “…ocument is in RTF format, and has an OLE object related with the Equation Editor. During the last years, this OLE objects have been a good indicator that a document may aim to exploit…” [train; L5](../data/annoctr-repo/AnnoCTR/all/text/lab52_2020-01-09_icefog-apt-group-abusing-recent.txt#L5)<br>“…er Attackers: How Very Attacked People Figure into Your Security Equation")™ (VAPs) in healthcare. We use the term to describe users within an organization who are the most heavily ta…” [general_only; L43](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-11-06_new-healthcare-report-reveals-cyber.txt#L43) |
| `exodus` | Exodus (malware, S0405) | 1/6/0/0; 5 | **CONTEXT** | Require the malware identity; exclude cryptocurrency wallets even in malware reports. | “…tions &#42; Coinomi &#42; Guarda &#42; Atomic Wallet &#42; Electrum &#42; Ethereum &#42; Exodus &#42; Bytecoin &#42; Armory &#42; Zcash &#42; Bitcoin &#42; Litecoin Instant messenger clients &#42; Pidgin Email clients &#42; Outlook O…” [train; L219](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2021-03-30_ares-malware-grandson-kronos-banking.txt#L219)<br>“…omi, waves-exchange, Ledger Live, Electrum, Electron Cash, Jaxx, Exodus, MultiBitHD, and Atomic. 1.b. Downloads stage 2: the following network request is a download of the next stag…” [general_only; L211](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-01-26_new-year-new-version-danabot.txt#L211) |
| `explosive` | Explosive (malware, S0569) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Explosive passes; explosive is withheld. Identity still needs review. |
| `flame` | Flame (malware, S0143) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Flame passes; flame is withheld. Identity still needs review. |
| `gazer` | Gazer (malware, S0168) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Gazer passes; gazer is withheld. Identity still needs review. |
| `griffon` | GRIFFON (malware, S0417) | 0/1/0/0; 1 | **CASE** | Preserve named payload usage, including Griffon and GRIFFON. | “…ader. During our analysis of JSSLoader, it additionally loaded a Griffon payload which is historically associated with another actor, TA3546, also known as FIN7 or Carbanak. In the f…” [train; L72](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-06-24_jssloader-recoded-and-reloaded.txt#L72) |
| `havoc` | Havoc (malware, S1229) | 6/0/0/0; 5 | **CASE** | Withhold ordinary havoc; a named tool still needs correct identity downstream. | “…like Russia against the US electronic voting system could wreak havoc. It should also be noted that the electoral system is still not considered a critical infrastructure of the n…” [train; L9](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-10-18_cyber-iii-cold-war-hack.txt#L9)<br>“…SpyNote RAT. &#42;&#42;Command execution&#42;&#42; Command execution can create havoc for victim if the malware developer decides to execute commands in the victim’s device. Leveraging this featu…” [general_only; L44](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2017-01-23_spynote-rat-posing-netflix-app.txt#L44) |
| `inception` | Inception (threat_actor, G0100) | 2/0/0/0; 2 | **CASE** | Withhold ordinary inception; sentence-initial usage can still be a false positive. | “…ment author "vps". NetWire has been a widely employed tool since inception in 2002, offering malware for multiple operating systems, including Windows, MacOS, and Linux. The RAT is sol…” [general_only; L6](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-12-02_geofenced-netwire-campaigns.txt#L6)<br>“…own to be involved in pharmaceutical and replica spam since it's inception as was detailed by Arbor Networks &#91;here&#93;(https://www.arbornetworks.com/blog/asert/lethic-spambot-analysis-pil…” [general_only; L5](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2015-06-11_gamarue-dropping-lethic-bot.txt#L5) |
| `insomnia` | INSOMNIA (malware, S0463) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: INSOMNIA passes; insomnia is withheld. Identity still needs review. |
| `judy` | Judy (malware, S0325) | 0/0/0/0; 0 | **CONTEXT** | Require the malware identity; a first name alone is insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “Judy (S0325)” is explicit identity evidence; the bare name is insufficient. |
| `kevin` | Kevin (malware, S1020) | 0/1/0/0; 1 | **CONTEXT** | Require S1020 malware identity; Kevin Beaumont is a researcher, not this malware. | “…asons, and it was soon identified as such by British researcher &#91;Kevin Beaumont&#93;(https://twitter.com/GossiTheDog/status/1409121823376117772). !&#91;&#93;(https://lab52.io/blog/wp-content/u…” [test diagnostic; L5](../data/annoctr-repo/AnnoCTR/all/text/lab52_2021-07-05_quick-review-of-babuk-ransomware.txt#L5) |
| `lucifer` | Lucifer (malware, S0532) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Lucifer passes; lucifer is withheld. Identity still needs review. |
| `machete` | Machete (malware, S0409); Machete (threat_actor, G0095) | 0/0/0/0; 0 | **CONTEXT** | Resolve actor G0095 versus malware S0409; do not select the first index entry. Provisional: unobserved. | No corpus occurrence. Synthetic: “Machete (S0409) malware” identifies software; “Machete (G0095) actor” identifies the group. |
| `mango` | Mango (malware, S1169) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Mango passes; mango is withheld. Identity still needs review. |
| `matryoshka` | Matryoshka (malware, S0167) | 1/0/0/0; 1 | **CASE** | Withhold the observed lowercase descriptive use; no validated positive in this sample. | “…own-2016-07-07/index-noparams.PNG) &#42;Fig 13 - The meta tag of the matryoshka splash page&#42; It turned out that the HTML didn't actually load properly (it appears the meta refresh directi…” [general_only; L64](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2016-07-07_sundown-chronicles-observations-exploit-kits.txt#L64) |
| `medusa` | MEDUSA (malware, S1220) | 0/4/0/0; 1 | **CONTEXT** | Require the S1220 Linux rootkit identity; Android Medusa and Medusa ransomware are different software. | “…ian users. &#42; TangleBot, while sharing some similarities with the Medusa malware, has some key distinguishing features that make it particularly threatening, such as its advanced beh…” [general_only; L6](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-10-04_mobile-malware-tanglebot-untangled.txt#L6) |
| `meek` | meek (tool, S0175) | 0/0/0/0; 0 | **CONTEXT** | Allow lowercase with explicit Tor/HTTPS transport or tool naming; reject the ordinary adjective. Provisional: unobserved. | No corpus occurrence. Synthetic: “The tool meek tunnels Tor traffic over HTTPS” qualifies; “a meek response” does not. |
| `meteor` | Meteor (malware, S0688) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Meteor passes; meteor is withheld. Identity still needs review. |
| `milan` | Milan (malware, S1015) | 0/0/0/0; 0 | **CONTEXT** | Require the malware identity; a city or personal name is insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “Milan (S1015)” is explicit identity evidence; the bare name is insufficient. |
| `mosquito` | Mosquito (malware, S0256) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Mosquito passes; mosquito is withheld. Identity still needs review. |
| `mythic` | Mythic (tool, S0699) | 0/1/0/0; 1 | **CASE** | Preserve named tool usage and mixed/all-uppercase spellings. | “…eam tool appearing more often in Proofpoint data. Others include Mythic, Meterpreter, and the Veil Framework. The use of publicly available tooling aligns with a broader trend obser…” [train; L102](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-06-29_cobalt-strike-favorite-tool-apt.txt#L102) |
| `ninja` | Ninja (malware, S1100) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Ninja passes; ninja is withheld. Identity still needs review. |
| `octopus` | Octopus (malware, S0340) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Octopus passes; octopus is withheld. Identity still needs review. |
| `pandora` | Pandora (malware, S0664) | 1/0/0/0; 1 | **CASE** | Withhold lowercase extension components; capitalised homonyms remain possible. | “…ekeychain;&#42;.vme;&#42;.$48E2C16BE0736950; &#42;.gte;&#42;.egs;&#42;.mkeyb;&#42;.fve;&#42;.pandora;&#42;.rdz;&#42;.wza;&#42;.jpi;&#42;.smbp;&#42;.pjpg;&#42;.efu;&#42;.xmm;&#42;.paw;&#42;.rte;&#42;.rbb;&#42;.atc;&#42;.azf;&#42;.suf;&#42;.isk;&#42;.xrm-ms;&#42;.x26;&#42;.cef;&#42;.…” [general_only; L140](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2016-11-21_look-recent-stampado-ransomware-variant.txt#L140) |
| `patchwork` | Patchwork (threat_actor, G0040) | 3/2/0/1; 5 | **CASE** | Preserve Patchwork/PatchWork; withhold the ordinary noun. | “…New PatchWork Spearphishing Attack October 22, 2019 Recently, a somewhat more elaborated phishing has caught our attention…” [general_only; L1](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-10-22_new-patchwork-campaign-against-pakistan.txt#L1)<br>“…eed tools for each security need and kludge them together into a patchwork defense. Or should you look for an all-encompassing solution, one that may not address every need well but un…” [general_only; L3](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-09-23_beyond-api-why-technical-partnerships.txt#L3) |
| `play` | Playcrypt (malware, S1162); Play (threat_actor, G1040) | 32/84/0/0; 33 | **CONTEXT** | Resolve Play actor versus Playcrypt software; exclude Google Play, Play Protect and Play store. | “…fications, opening pages on a victim’s browser, disabling Google Play Protect to prevent its detection, opening a SOCKS connection and creating a SOCKS proxy for communication dep…” [general_only; L42](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-04-27_flubot-android-malware-spreading-rapidly.txt#L42)<br>“…omething that (unfortunately) works. While money and geopolitics play big roles, there are some other means that have allowed ransomware infections to proliferate with little resi…” [test diagnostic; L8](../data/annoctr-repo/AnnoCTR/all/text/intel471_2021-07-28_ransomware-as-a-service-fivehands.txt#L8) |
| `pony` | Pony (malware, S0453) | 0/4/0/0; 4 | **CASE** | Preserve named malware usage; initial capital is a precision heuristic only. | “…group as well as more widely distributed malware like Dridex and Pony.&#42; &#42;…&#42; &#42;The last TA505 campaigns featuring The Trick appeared in mid-September 2017 with payloads alternating…” [general_only; L126](../data/annoctr-repo/AnnoCTR/all/text/intel471_2020-09-16_partners-in-crime-north-koreans.txt#L126)<br>“…reat actor group preferred to drop the Gozi ISFB trojan and Evil Pony credential harvester until mid-2019, when the group replaced Gozi ISFB with Cobalt Strike. This switch serves…” [general_only; L47](../data/annoctr-repo/AnnoCTR/all/text/intel471_2021-05-19_cobalt-strike-cybercriminals-trickbot-qbot.txt#L47) |
| `prestige` | Prestige (malware, S1058) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Prestige passes; prestige is withheld. Identity still needs review. |
| `proton` | Proton (malware, S0279) | 0/1/0/0; 1 | **CONTEXT** | Require S0279 malware identity; Proton email is a different product. | “…ctim to contact the attacker through the anonymous and encrypted Proton email address to decrypt files, with no mention of payment type or amount. (HTML table) !&#91;&#93;(data:image/gif;ba…” [general_only; L206](../data/annoctr-repo/AnnoCTR/all/text/quoteintelligence_2020-01-27_the-chicken-keeps-laying-new.txt#L206) |
| `raindrop` | Raindrop (malware, S0565) | 0/0/0/1; 1 | **CASE** | Preserve RainDrop as well as Raindrop and RAINDROP. | “…ervsystem&#91;.&#93;com bigtopweb&#91;.&#93;com - &#42;Added 1/20/21 in relation to RainDrop&#42; &#96;&#96;&#96; &#42;&#42;IPs&#42;&#42; &#96;&#96;&#96; 13.59.205.66 54.193.127.66 54.215.192.52 34.203.203.23 139.99.115.204 5.252.177.25 5.252.177…” [train; L52](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2020-12-22_hitchhikers-guide-solarwinds-incident-response.txt#L52) |
| `reptile` | REPTILE (malware, S1219) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: REPTILE passes; reptile is withheld. Identity still needs review. |
| `responder` | Responder (tool, S0174) | 0/0/0/0; 0 | **CONTEXT** | Require the named offensive tool; an incident responder is a role. Provisional: unobserved. | No corpus occurrence. Synthetic: “Responder (S0174)” is explicit identity evidence; the bare name is insufficient. |
| `rover` | Rover (malware, S0090) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Rover passes; rover is withheld. Identity still needs review. |
| `royal` | Royal (malware, S1073) | 0/10/0/0; 4 | **CONTEXT** | Require Royal ransomware identity; Royal Road is a different tool and Royal Thai Police an organisation. | “…al&#92;Temp&#92;wd4sx.wmf. This method is used by a known variant of the Royal Road RTF weaponizer which is shared among numerous Chinese APT actors. The execution of the WMF file ultimate…” [general_only; L27](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-09-01_chinese-apt-ta413-resumes-targeting.txt#L27)<br>“…g, “ข้อความด่วนจากสำนักงานตำรวจแห่งชาติ (Urgent message from the Royal Thai Police),” or “Последната полициска покана пред апсењето (The last police invitation before the arrest)”…” [general_only; L25](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-08-26_threat-actor-profile-ta2719-uses.txt#L25) |
| `ruler` | Ruler (tool, S0358) | 0/0/0/0; 0 | **CONTEXT** | Require the named tool; ordinary people or measuring instruments do not qualify. Provisional: unobserved. | No corpus occurrence. Synthetic: “Ruler (S0358)” is explicit identity evidence; the bare name is insufficient. |
| `samurai` | Samurai (malware, S1099) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Samurai passes; samurai is withheld. Identity still needs review. |
| `shark` | Shark (malware, S1019) | 0/1/0/0; 1 | **CONTEXT** | Require S1019 malware identity; Shark Tank is a different proper name. | “…ent, well-known individuals can fall for them. In February 2020, Shark Tank’s Barbara Corcoran nearly &#91;lost&#93;(https://www.proofpoint.com/us/corporate-blog/post/shark-tanks-barbara-c…” [general_only; L23](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2020-12-07_understanding-bec-scams-supplier-invoicing.txt#L23) |
| `silence` | Silence (threat_actor, G0091) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Silence passes; silence is withheld. Identity still needs review. |
| `solar` | Solar (malware, S1166) | 0/0/0/0; 0 | **CONTEXT** | Require the named malware; ordinary solar/energy language is insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “Solar (S1166)” is explicit identity evidence; the bare name is insufficient. |
| `spaceship` | SPACESHIP (malware, S0035) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: SPACESHIP passes; spaceship is withheld. Identity still needs review. |
| `spark` | Spark (malware, S0543) | 9/11/1/0; 2 | **CONTEXT** | Require S0543 malware identity; exclude Apache Spark and Baidu Spark. | “…ed to spread through SSH, PostgreSQL, Redis, Hadoop YARN, Apache Spark, HashiCorp Consul, and SaltStack. Many DreamBus plugins share code, for example, to create a lock file named…” [general_only; L57](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2021-01-22_dreambus-botnet-technical-analysis.txt#L57)<br>“…ran &#42; BlackHawk &#42; CoolNovo &#42; AcWebBrowser &#42; Epic Browser &#42; Baidu Spark &#42; Rockmelt &#42; Sleipnir &#42; SRWare Iron &#42; Titan Browser &#42; Flock &#42; Vivaldi &#42; Sputnik &#42; Maxthon &#42;&#42;Credential steali…” [general_only; L39](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2019-03-15_immortal-information-stealer.txt#L39) |
| `strider` | Strider (threat_actor, G0041) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Strider passes; strider is withheld. Identity still needs review. |
| `sunspot` | SUNSPOT (malware, S0562) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: SUNSPOT passes; sunspot is withheld. Identity still needs review. |
| `supernova` | SUPERNOVA (malware, S0578) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: SUPERNOVA passes; supernova is withheld. Identity still needs review. |
| `teardrop` | TEARDROP (malware, S0560) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: TEARDROP passes; teardrop is withheld. Identity still needs review. |
| `terracotta` | TERRACOTTA (malware, S0545) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: TERRACOTTA passes; terracotta is withheld. Identity still needs review. |
| `triton` | Triton (malware, S1009) | 0/0/1/0; 1 | **CASE** | Preserve TRITON and Triton; casing does not establish identity by itself. | “…n the Middle East, Europe, and North America. The group has used TRITON malware to manipulate industrial safety systems. ### Gamaredon Active since at least 2013, this APT has mainl…” [test diagnostic; L62](../data/annoctr-repo/AnnoCTR/all/text/quoteintelligence_2021-04-28_us-sanctions-against-russias-cyber.txt#L62) |
| `uppercut` | UPPERCUT (malware, S0275) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: UPPERCUT passes; uppercut is withheld. Identity still needs review. |
| `windshield` | WINDSHIELD (malware, S0155) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: WINDSHIELD passes; windshield is withheld. Identity still needs review. |
| `wiper` | Wiper (malware, S0041) | 4/0/0/0; 2 | **CONTEXT** | Require the specific S0041 identity; a generic destructive-malware class is insufficient. | “…di energy company Aramco was the victim of a destructive malware wiper attack. &#124; &#124; Bowman &#124; August– Sep. 2013 &#124; The Bowman’s energetic company in NY was compromised. &#124; &#124; Saffron Ro…” [general_only; L130](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-09-18_geopolitical-strategy-of-iran-and.txt#L130)<br>“…nomKit building kit. &#42; &#42;&#42;TerraWiper.&#42;&#42; AMaster Boot Record (MBR) wiper. &#42; &#42;&#42;TerraCrypt.&#42;&#42; A ransomware, also known as &#42;PureLocker.&#42; &#42; &#42;&#42;TerraTV.&#42;&#42; A custom DLL designed to hijack l…” [general_only; L15](../data/annoctr-repo/AnnoCTR/all/text/quoteintelligence_2020-01-27_the-chicken-keeps-laying-new.txt#L15) |
| `zipline` | ZIPLINE (malware, S1114) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: ZIPLINE passes; zipline is withheld. Identity still needs review. |

### C. Historical element-based actor names from the original draft (35)

| Form | Indexed identity/type | L/T/U/M; Docs | Decision | Rationale / required context | Representative context |
|---|---|---|---|---|---|
| `actinium` | Gamaredon Group (threat_actor, G0047) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Actinium passes; actinium is withheld. Identity still needs review. |
| `americium` | Agrius (threat_actor, G1030) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Americium passes; americium is withheld. Identity still needs review. |
| `barium` | APT41 (threat_actor, G0096) | 0/1/2/0; 2 | **CASE** | Accept Barium and BARIUM; do not enforce a vendor-specific uppercase convention. | “…tied to PRC’s Ministry of State Security. TA415 is also known as Barium and APT41. Proofpoint identified TA415 delivering Cobalt Strike as a first-stage payload in limited campaigns…” [train; L68](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-06-29_cobalt-strike-favorite-tool-apt.txt#L68)<br>“…th Asia. ### Introduction The Winnti Group (also known as APT41, BARIUM, and Blackfly) is an alleged Chinese state-sponsored umbrella organization in China’s intelligence branch lin…” [train; L16](../data/annoctr-repo/AnnoCTR/all/text/quoteintelligence_2020-04-20_winnti-group-insights-from-the.txt#L16) |
| `bismuth` | APT32 (threat_actor, G0050) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Bismuth passes; bismuth is withheld. Identity still needs review. |
| `bromine` | Dragonfly (threat_actor, G0035) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Bromine passes; bromine is withheld. Identity still needs review. |
| `copernicium` | APT38 (threat_actor, G0082) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Copernicium passes; copernicium is withheld. Identity still needs review. |
| `curium` | CURIUM (threat_actor, G1012) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: CURIUM passes; curium is withheld. Identity still needs review. |
| `dubnium` | Darkhotel (threat_actor, G0012) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Dubnium passes; dubnium is withheld. Identity still needs review. |
| `europium` | OilRig (threat_actor, G0049) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Europium passes; europium is withheld. Identity still needs review. |
| `gadolinium` | Leviathan (threat_actor, G0065) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Gadolinium passes; gadolinium is withheld. Identity still needs review. |
| `gallium` | GALLIUM (threat_actor, G0093) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: GALLIUM passes; gallium is withheld. Identity still needs review. |
| `hafnium` | HAFNIUM (threat_actor, G0125) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: HAFNIUM passes; hafnium is withheld. Identity still needs review. |
| `holmium` | APT33 (threat_actor, G0064) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Holmium passes; holmium is withheld. Identity still needs review. |
| `iridium` | Sandworm Team (threat_actor, G0034) | 0/4/0/0; 2 | **CONTEXT** | Require Sandworm actor identity; exclude Iridium browser and chemical/product names. | “…r Sleipnir &#42; Elements &#42; Kometa &#42; Chedot &#42; CentBrowser &#42; 7 Star &#42; Iridium &#42; MapleStudio ChromePlus &#42; Torch &#42; Yandex Browser &#42; Epic Privacy Browser &#42; Opera &#42; Brave Browser &#42; Vivaldi &#42;…” [train; L204](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2021-03-30_ares-malware-grandson-kronos-banking.txt#L204)<br>“…gon IncomingServer IndexOf InstancesOf Internet Download Manager Iridium Browser Iridium&#92;User Data IterationCount JDownloader K-Meleon KeyDataBlob Kometa Kometa&#92;User Data Length Lieb…” [general_only; L499](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2020-08-24_linkedin-job-seeker-phishing-campaign.txt#L499) |
| `krypton` | Turla (threat_actor, G0010) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Krypton passes; krypton is withheld. Identity still needs review. |
| `manganese` | APT5 (threat_actor, G1023) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Manganese passes; manganese is withheld. Identity still needs review. |
| `mercury` | MuddyWater (threat_actor, G0069) | 3/1/0/0; 1 | **CONTEXT** | Require MuddyWater actor identity; exclude the Mercury intelligence portal, URLs and other names. | “…ets’ supply chains. &#91;Request a Free Trial to Read Full Report in Mercury!&#93;(https://quointelligence.eu/talk-to-an-expert/) ### Update Hijacking and Code Signing Advanced Persistent Th…” [dev; L29](../data/annoctr-repo/AnnoCTR/all/text/quoteintelligence_2021-01-27_supply-chain-attacks-cybersecurity-regulations.txt#L29)<br>“…a&#91;supply chain attack on Taiwanese government entities&#93;(https://mercury.quointelligence.eu/INTTicket/show/6449). The attack leveraged trusted relationships and privileged network ac…” [dev; L26](../data/annoctr-repo/AnnoCTR/all/text/quoteintelligence_2021-01-27_supply-chain-attacks-cybersecurity-regulations.txt#L26) |
| `neodymium` | NEODYMIUM (threat_actor, G0055) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: NEODYMIUM passes; neodymium is withheld. Identity still needs review. |
| `nickel` | Ke3chang (threat_actor, G0004) | 0/0/0/0; 0 | **CONTEXT** | Require Ke3chang actor identity; chemical or commodity references are insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “Nickel (G0004)” is explicit identity evidence; the bare name is insufficient. |
| `phosphorus` | Magic Hound (threat_actor, G0059) | 0/0/1/0; 1 | **CASE** | Preserve PHOSPHORUS and title case; allow explicit identity evidence to be reviewed downstream. | “…in the United States and Israel. TA453 (aka CHARMING KITTEN and PHOSPHORUS) has historically aligned with Islamic Revolutionary Guard Corps (IRGC) collection priorities, targeting diss…” [general_only; L14](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-03-30_badblood-ta453-targets-us-and.txt#L14) |
| `platinum` | PLATINUM (threat_actor, G0068) | 0/0/0/0; 0 | **CONTEXT** | Require actor G0068 identity; metal, product or service-tier names are insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “PLATINUM (G0068)” is explicit identity evidence; the bare name is insufficient. |
| `plutonium` | Andariel (threat_actor, G0138) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Plutonium passes; plutonium is withheld. Identity still needs review. |
| `polonium` | POLONIUM (threat_actor, G1005) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: POLONIUM passes; polonium is withheld. Identity still needs review. |
| `potassium` | menuPass (threat_actor, G0045) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Potassium passes; potassium is withheld. Identity still needs review. |
| `promethium` | PROMETHIUM (threat_actor, G0056) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: PROMETHIUM passes; promethium is withheld. Identity still needs review. |
| `radium` | Lotus Blossom (threat_actor, G0030) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Radium passes; radium is withheld. Identity still needs review. |
| `rubidium` | Fox Kitten (threat_actor, G0117) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Rubidium passes; rubidium is withheld. Identity still needs review. |
| `seaborgium` | Star Blizzard (threat_actor, G1033) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Seaborgium passes; seaborgium is withheld. Identity still needs review. |
| `silicon` | Sea Turtle (threat_actor, G1041) | 0/0/0/0; 0 | **CONTEXT** | Require Sea Turtle actor identity; Silicon Valley and materials are insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “Silicon (G1041)” is explicit identity evidence; the bare name is insufficient. |
| `strontium` | APT28 (threat_actor, G0007) | 0/0/1/0; 1 | **CASE** | Preserve STRONTIUM and title case; uppercase-only matching is unjustified. | “…t customers about a new APT28 (&#42;aka&#42; Sofacy, Sednit, Fancy Bear, STRONTIUM, etc. campaign targeting government bodies of &#91;NATO&#93;(https://www.nato.int/) members (or countries cooperating…” [train; L15](../data/annoctr-repo/AnnoCTR/all/text/quoteintelligence_2020-09-22_apt28-zebrocy-malware-campaign-nato.txt#L15) |
| `tantalum` | Mustang Panda (threat_actor, G0129) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Tantalum passes; tantalum is withheld. Identity still needs review. |
| `thallium` | Kimsuky (threat_actor, G0094) | 0/1/0/0; 1 | **CASE** | Accept Thallium and THALLIUM; the test excerpt is diagnostic, not a tuning sample. | “…al actors that make up the activity publicly tracked as Kimsuky, Thallium and Konni Group. &#42; TA406 doesn’t usually employ &#91;malware&#93;(https://www.proofpoint.com/us/threat-reference/malw…” [test diagnostic; L6](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-11-18_triple-threat-north-korea-aligned.txt#L6) |
| `yttrium` | APT29 (threat_actor, G0016) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Yttrium passes; yttrium is withheld. Identity still needs review. |
| `zinc` | Lazarus Group (threat_actor, G0032) | 0/0/0/0; 0 | **CONTEXT** | Require Lazarus actor identity; chemical and product references are insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “Zinc (G0032)” is explicit identity evidence; the bare name is insufficient. |
| `zirconium` | ZIRCONIUM (threat_actor, G0128) | 0/0/0/0; 0 | **CASE** | Accept initial-capital and all-uppercase actor names; withhold ordinary lowercase chemical use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: ZIRCONIUM passes; zirconium is withheld. Identity still needs review. |

### D. Command names (3)

| Form | Indexed identity/type | L/T/U/M; Docs | Decision | Rationale / required context | Representative context |
|---|---|---|---|---|---|
| `expand` | Expand (tool, S0361) | 7/0/0/0; 7 | **CONTEXT** | Allow lowercase command use (expand.exe or an explicit CAB extraction command); reject the ordinary verb. | “…tmp &#42; The resulting decoded file has the CAB file format. &#42; Uses expand.exe to extract the contents of the CAB file to the %temp% directory. The components of the cab file are shown…” [general_only; L101](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2020-06-11_return-higaisa-apt.txt#L101)<br>“…commercial ties with Iran. During 2016, Iran and China agreed to expand bilateral ties and increase trade to $ 600 billion by 2025. This business planning was truncated at the time…” [train; L17](../data/annoctr-repo/AnnoCTR/all/text/lab52_2020-02-18_the-role-of-china-in.txt#L17) |
| `ping` | Ping (tool, S0097) | 27/3/4/0; 19 | **CONTEXT** | Allow executable/command use or explicit utility naming; an application Ping Reply message is insufficient. | “…C:&#92;Users&#92;Win7 64Bit&#92;AppData&#92;Roaming&#92;Windows&#92;winlogin.exe” &#42; Uses ping.exe to check the status of other devices and networks. + cmd /D /R ping -n 10 localhost &amp;&amp; del C:&#92;payment&#92;_in…” [general_only; L92](../data/annoctr-repo/AnnoCTR/all/text/zscaler_2014-12-21_compromised-wordpress-sites-serving-multiple.txt#L92)<br>“…orting Socks Proxy Off 2003554 - ET MALWARE Bandook v1.2 Client Ping Reply 2003555 - ET MALWARE Bandook v1.35 Initial Connection and Report 2003556 - ET MALWARE Bandook v1.35 K…” [general_only; L144](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-07-19_new-threat-actor-uses-spanish.txt#L144) |
| `route` | route (tool, S0103) | 23/3/0/0; 9 | **CONTEXT** | Allow an explicit route command (e.g. route print/add); reject ordinary paths, trade routes and the verb. | “…Approximately since 2009, China has aimed to build up a maritime route known as OBOR (One Belt, One Road). The main goal of this project is to develop a safe trading corridor to ex…” [train; L9](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-05-30_leviathan-geostrategy-and-ttp-technical.txt#L9)<br>“…en though it has not been observed that it copies itself to that route at any time. This implies that along with being run with administrator privileges, it also requires having be…” [general_only; L26](../data/annoctr-repo/AnnoCTR/all/text/lab52_2019-04-02_orangeworm-group-kwampirs-analysis-update.txt#L26) |

### E. Additional candidates (9)

| Form | Indexed identity/type | L/T/U/M; Docs | Decision | Rationale / required context | Representative context |
|---|---|---|---|---|---|
| `biscuit` | BISCUIT (malware, S0017) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: BISCUIT passes; biscuit is withheld. Identity still needs review. |
| `covenant` | Covenant (tool, S1155) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Covenant passes; covenant is withheld. Identity still needs review. |
| `dragonfly` | Dragonfly (threat_actor, G0035) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Dragonfly passes; dragonfly is withheld. Identity still needs review. |
| `elise` | Elise (malware, S0081) | 0/0/0/0; 0 | **CONTEXT** | Require the malware identity; a first name alone is insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “Elise (S0081)” is explicit identity evidence; the bare name is insufficient. |
| `hexane` | HEXANE (threat_actor, G1001) | 0/0/0/0; 0 | **CONTEXT** | Require actor G1001 identity; a chemical reference is insufficient. Provisional: unobserved. | No corpus occurrence. Synthetic: “HEXANE (G1001)” is explicit identity evidence; the bare name is insufficient. |
| `mandrake` | Mandrake (malware, S0485) | 0/0/0/0; 0 | **CASE** | Keep the name/alias with an initial capital, including internal capitals and ALL CAPS; withhold lowercase ordinary use. Provisional: unobserved. | No corpus occurrence. Synthetic casing check: Mandrake passes; mandrake is withheld. Identity still needs review. |
| `maze` | Maze (malware, S0449) | 0/10/0/0; 5 | **CASE** | Preserve named ransomware usage; lowercase URL components are not positive evidence. | “…as been used in over 125 ransomware incidents in 2020. &#42;&#42;Egregor/Maze&#42;&#42; As this report was being published, the crew behind the Maze ransomware service announced it was shutting d…” [train; L62](../data/annoctr-repo/AnnoCTR/all/text/intel471_2020-11-16_ransomware-as-a-service-2020.txt#L62)<br>“…ried out with popular ransomware variants, such as DoppelPaymer, Maze, Netwalker, Ryuk and REvil, as well as lesser-known variants like LockBit, Nefilim, Pysa and Thanos. The astr…” [train; L21](../data/annoctr-repo/AnnoCTR/all/text/intel471_2020-12-01_ransomware-attack-access-merchants-infostealer.txt#L21) |
| `nobelium` | APT29 (threat_actor, G0016) | 0/0/1/0; 1 | **CASE** | Historical actor alias present in this index; accept Nobelium and NOBELIUM. | “…-malware) May 2021 – &#91;New sophisticated email-based attack from NOBELIUM&#93; (https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/) ##…” [train; L127](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-06-29_cobalt-strike-favorite-tool-apt.txt#L127) |
| `sliver` | Sliver (tool, S0633) | 1/2/6/0; 1 | **CASE** | Preserve Sliver/SLIVER tooling; lowercase technical uses remain a recall risk to measure. | “…Security Brief: TA551 Uses ‘SLIVER’ Red Team Tool in New Activity October 20, 2021 Proofpoint researchers identified a new campaign from the hig…” [dev; L1](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-10-20_ta551-uses-sliver-red-team.txt#L1)<br>“…d documents. The attachments ultimately lead to the download of &#91;Sliver&#93;(https://github.com/BishopFox/sliver/tree/6c02971b54831884d30407b632a379947dd289ad), an open-source, cross-pl…” [dev; L14](../data/annoctr-repo/AnnoCTR/all/text/proofpoint_2021-10-20_ta551-uses-sliver-red-team.txt#L14) |

## Acceptance examples for contextual rules

These are **synthetic specifications**, not additional corpus evidence. A local positive
must establish the intended identity; a negative below should withhold only that mapping,
not erase other entities in the sentence. Unknown or different malware may still be
extracted by another stage without an incorrect MITRE ID.

| Form | Eligible positive | Withhold this mapping |
|---|---|---|
| `joker` | “Joker, the Android billing-fraud malware also called Bread” → S0432 | “Joker’s Stash closed”; “the KR.joker worm” |
| `photo` | “The Derusbi backdoor, also called Photo” → S0021 | “a photo attachment”; a `/photo/2` URL |
| `page` | “Elise malware, also known as Page” → S0081 | “visit the Page”; “landing_page.png” |
| `play` | “Playcrypt ransomware, also called Play” → S1162; “the Play threat actor (G1040)” → G1040 | “Google Play”; bare “Play ransomware” must not choose actor versus software by index order |
| `snake` | “Snake, the Uroburos malware” → S0022; “Turla, also called Snake” → G0010 | “Snake Keylogger”; bare “Snake malware” without disambiguating evidence |
| `medusa` | “The MEDUSA Linux rootkit (S1220)” → S1220 | “Medusa Android malware”; “Medusa ransomware” |
| `meek` | “The meek Tor transport tunnels over HTTPS” → S0175 | “a meek response” |
| `cuba` | “The Cuba ransomware family encrypted files” → S0625 | “organisations in Cuba were attacked” |
| `equation` | “The Equation threat group (G0020)” → G0020 | “malware exploits Equation Editor” |
| `electrum` / `exodus` | Explicit Sandworm alias / explicit S0405 malware identity | “malware steals Electrum and Exodus wallets” |
| `epic` / `spark` / `proton` | Explicit identification of S0091 / S0543 / S0279 | “Epic Privacy Browser”; “Apache Spark vulnerability”; “Proton email” |
| `royal` | “The Royal ransomware family (S1073)” → S1073 | “Royal Road weaponizer”; “Royal Thai Police” |
| `wiper` | “Wiper (S0041) is the malware family named in this report” → S0041 | “a destructive wiper”; “Shamoon is a wiper” |
| `expand` | “The command expand.exe extracts this CAB archive” → S0361 | “expand access”; the Salsa20 string “expand 32-byte k” |
| `ping` | `cmd /c ping -n 1 localhost`; “uses the ping utility” → S0097 | “Bandook Client Ping Reply” as a protocol/signature name |
| `route` | “The command route print lists routes” → S0103 | “maritime route”; “copy the file to that route” |

## Operational contract for context checks

This section specifies proposed behaviour; the record fields and policy gates below
are an implementation contract, not capabilities already present in the matcher.
The inventory's three decisions remain unchanged. Apply the following checks to each
occurrence, before claiming spans or deduplicating identities.

### Context scope and precedence

Use the sentence containing the occurrence. For Markdown, a list item, table row or
code command is its own unit: do not borrow identity evidence from a neighbouring row,
another list item, a heading or a different code block. A display-wrapped paragraph may
be rejoined, provided its original offsets are preserved. Multi-sentence coreference is
out of scope for this deterministic rule; send it to review instead of expanding the window.
The short excerpts in the inventory are for reading, not the runtime context boundary.

Apply this order:

1. **Locate the occurrence in the original text.** Preserve spelling, casing and offsets.
   A token found only inside a URL, filename or an opaque code/string literal is not
   naming evidence. A parsed executable or command invocation is the explicit exception
   for command-name rules. Markdown link labels can carry naming evidence; the link
   destination alone cannot establish the entity.
2. **Exclude a conflicting sense attached to this occurrence.** Examples include
   `Google Play`, `Play Protect`, `Play store`, `Joker's Stash` (including a curly
   apostrophe), `Equation Editor`, `Epic Privacy Browser`, `Apache Spark` and
   `Royal Road`. Match these exclusions case-insensitively with word boundaries.
   They override a nearby cyber keyword. They do not ban every occurrence of the form
   in the sentence or document: a second, explicitly named threat can still qualify.
3. **Find a naming construction and its identity evidence.** Accept an explicit alias
   relation such as `X, also known as Y`, a typed apposition such as `Cuba ransomware`,
   or a directly attached identifier such as `Machete (S0409)`. The canonical anchor
   must itself be identified in the appropriate sense: an unrelated word elsewhere in
   the unit is not an anchor. IDs inside unrelated links or technique lists do not qualify.
   If the relation explicitly denies equivalence (`X is not Y`), it supplies no alias link.
4. **Resolve the intended object.** Narrow candidates by the naming relation, explicit
   type, and required platform/family evidence. A typed noun phrase alone does not resolve
   known homonyms: `Medusa malware` is insufficient for S1220; `Play ransomware` is
   insufficient to choose actor versus software. Conflicting evidence is unresolved,
   even when only one of the possible real-world identities exists in the local index.
5. **Apply the row's decision.** RETAIN keeps baseline candidate eligibility; CASE requires
   an initial uppercase character; CONTEXT requires the identity evidence above. Casing
   alone is not a confidence upgrade or an override for an exclusion. Unsupported language,
   unclear sentence boundaries or an unrecognised construction give no contextual approval.

This is a finite, versioned rule policy, not an instruction to classify a sentence by
counting nearby words such as `malware`, `attack`, `group` or `tool`. Its first release
targets English naming constructions, matching the scope of this draft. Additional
languages need their own reviewed constructions and evaluation data.

For command forms, recognise the executable token in an actual command position, or
an explicit prose description of the named utility. For example, `ping -n 1 localhost`,
`route print`, and `expand.exe archive.cab` qualify as command mentions;
`echo "route print"`, a protocol label `Ping Reply`, and an opaque Salsa20 constant do
not establish an invocation. A documented example command can identify a tool, but does
not establish that an attacker executed it. The command must never be executed by this check.

### Output when identity cannot be resolved

Separate candidate recognition from creation of a canonical `RawEntity`. Use these
proposed outcomes; a candidate list is diagnostic data, not a list of asserted entities.

| Outcome | Meaning | Proposed output |
|---|---|---|
| `resolved` | The occurrence passes its policy and denotes one supported identity. | Eligible for a typed canonical entity with the resolved MITRE ID; apply the separate confidence/review gate below. |
| `unresolved` | A named actor/tool/malware may be present, but the intended identity or type cannot be chosen. | Preserve a diagnostic candidate with the verbatim surface and possible identities; emit no canonical Stage 2b entity from this occurrence. |
| `excluded` | The occurrence is a known different sense, or fails the row's required casing/context check. | Emit no entity for this mapping; retain a reason in the evaluation trace. Other occurrences and other extractors remain eligible. |

For CASE/RETAIN, `resolved` means a unique index candidate survived the configured
filters; it does not mean empirical correctness has been established. In particular,
passing a case check does not resolve a known same-name collision.

An unresolved record should carry `surface`, original offsets, the local evidence unit,
candidate `(mitre_id, entity_type)` pairs, `outcome`, `reason`, `rule_id` and
`policy_version`. Suggested reasons include `ambiguous_identity`, `conflicting_type`,
`different_software_family`, `missing_context`, `case_mismatch` and `benign_name`.
These names describe the proposed contract; they are not existing schema fields.

Do not turn an unresolved candidate into a guessed-type `RawEntity` with `mitre_id=None`:
later alias resolution could attach the very ID that this check withheld. Review or a
separate extractor may resolve it only with additional, attributable evidence. Such a
resolution must preserve the original candidate and the reason for the new identity.
For example, `Snake Keylogger` may be a valid malware mention while remaining excluded
from the Turla and Uroburos mappings. An excluded mapping is not a claim that the whole
mention is benign.

## Confidence, acceptance and export

The current matcher assigns **0.92** to canonical matches and **0.88** to alias matches
([Stage 2b](../pipeline/stage2b_gazetteer.py)). These are nominal source scores, not
measured probabilities for the ambiguous forms. The current server-side auto-accept
threshold is **0.90**, subject to its eligibility checks and control sample
([decision policy](../pipeline/decisions.py)). Thus canonical status can cross the
automatic threshold even when the match is an ordinary word.

The proposed policy must treat three questions separately: did the occurrence pass
matching, may its identity be accepted automatically, and may the entity be exported?

- Keep the original nominal score in provenance; do not invent a new calibrated probability
  because a name has a capital letter or is near a cyber keyword. Casing adds no score bonus.
- Before validation, run the new policy in **shadow mode**: record proposed outcomes beside
  the baseline, without changing production output. The 151 review proposals are not a
  production allow-list. Unobserved forms remain baseline behaviour plus diagnostics until
  there is enough labelled evidence to activate their individual rules.
- For any pilot that persists entities from unvalidated rules, require individual review.
  CASE-only evidence and unresolved/conflicting identities must never become auto-accepted
  merely by inheriting 0.92. An unresolved occurrence remains a diagnostic candidate, not
  an exportable entity. A resolved but unvalidated pilot entity must be explicitly held
  with a policy-specific reason, rather than only assigned a lower score.
- This distinction matters in this project: `accepted IS NULL` with no `held_reason`
  still satisfies `SHIPS`. A lower confidence or “pending” status alone does not stop
  export. Carry any hold through persistence and downstream processing; do not let an
  alias lookup, merge, or confidence update silently remove it. An individual analyst
  decision can release a held entity using the existing review mechanism.
- Automatic acceptance for an activated rule requires separately validated eligibility
  for its decision class and entity type. Synthetic examples, automatically accepted
  rows and retained gazetteer scores are not calibration labels. Use attributable human
  judgements and keep the existing control sample. If evidence is insufficient, keep
  manual review; extraction-rule acceptance alone does not approve auto-acceptance.

This proposes a review/eligibility gate rather than an arbitrary replacement score
such as 0.89. Its persistence, deduplication and export behaviour must be implemented
and checked before a pilot can rely on it; this document does not wire that gate into code.

## A named entity is not an observed attack action

Resolve entity identity separately from the assertion that an actor used it. An entity
can be mentioned in a negation, a comparison, a recommendation or a hypothetical example.
These mentions can support NER without supporting an affirmative `uses` relationship.
Negation of usage is different from negation of an alias relation.

| Source text (synthetic) | Entity interpretation | Relationship interpretation |
|---|---|---|
| “The actor did not use the Empire post-exploitation framework.” | Empire identifies S0363. | Do not create an affirmative `uses` edge from this sentence. |
| “The actor may have used Empire.” | Preserve the named-tool candidate; resolve under its context rule. | Preserve uncertainty for the relationship validator; do not mark usage observed. |
| “Administrators can run ping -n 1 localhost to test connectivity.” | A Ping utility mention can qualify. | This is advice, not evidence of attacker execution. |
| “The actor used Joker, the Android malware also called Bread.” | Joker resolves to S0432. | The source reports usage; that is not automatically an independently observed fact. |
| “This sample is not the MEDUSA Linux rootkit.” | The comparison identifies the referenced S1220 entity. | Do not label the sample S1220 or assert that it was deployed. |

Stage 2b provides mention/identity evidence. Relationship extraction and validation
remain responsible for the participants, polarity, modality and evidence grade of an
action. Neither a successful context check nor a high gazetteer score supplies these facts.

## Proposed acceptance gates before activation

The following numbers are **proposed engineering targets**, selected to make the tradeoff
reviewable. They are not measured results or thresholds justified by this corpus already.
Freeze them, the active form list and the policy version before evaluating the candidate
release. Any later adjustment creates a new exploratory configuration; do not reuse a
consulted holdout as fresh confirmation. These entity gates supplement ADR-0060 and do
not replace its separate TTP acceptance rule.

Compare old and proposed Stage 2b on the same documents with the same index, corpus and
overrides. For document-level scoring, use distinct `(document_id, entity_type, mitre_id)`
triples, with the same ATT&CK ID mapping on predictions and gold. Count a wrong identity
as a false positive and, when it displaced the correct identity, a false negative too.
Keep mention-level scoring alongside it so that a surviving alias elsewhere in the
document cannot hide a lost valid occurrence. Resolve gold ambiguities explicitly;
exclude unadjudicated items from the primary denominator and report their count separately.

Define the **affected document set** before running either policy: documents containing
at least one raw match of an inventoried form under the fixed boundary rule. Do not build
this subset from accepted predictions. Within those documents, score all actor/tool/malware
identities so that an overlap or span-claiming change cannot hide its collateral effects.
Also report results over the complete evaluable document set and separately by entity type.
No missing cyber layer is a negative label; supplementary documents need manual annotation.

| Gate | Proposed requirement |
|---|---|
| Deterministic regression cases | 100% of the frozen acceptance suite passes on both Aho–Corasick and regex paths; outputs agree on identity, type and policy outcome. No unresolved identity is chosen by entry order. |
| Protected valid mentions | No lost valid mention in the reviewed positive regression set. Include Joker without Bread, Elfin, title-case element aliases, lowercase meek with Tor context, command forms, internal capitals, and a valid mention after an excluded one. Synthetic cases test behaviour; real labelled cases are required for accuracy claims. |
| Precision on affected documents | Micro precision improves by at least **5 percentage points**, and the lower bound of the paired 95% confidence interval for the precision difference is above zero. |
| Recall over all evaluable documents | Micro recall drops by at most **1 percentage point**; the lower bound of the paired 95% interval for the recall difference is at least **−2 percentage points**. |
| Per-type safeguard | No actor/tool/malware type loses more than **2 percentage points** of recall or precision. Report per-form changes as well; an aggregate gain does not waive the protected-case gate. |
| Output and provenance | Zero canonical entities emitted from unresolved occurrences; zero auto-accepts from unvalidated policy evidence; zero exports of held pilot entities before individual acceptance. Check end-to-end behaviour, not just matcher output. |
| Evidence sufficient to decide | An undefined metric, an interval that fails a gate, or a type with no evaluable positives is **inconclusive**, not a pass. For each rule being activated, require real adjudicated positive and negative contexts from at least **five distinct documents per class**; this is a coverage floor, not proof of precision. Forms without that coverage remain in shadow mode. |

“Percentage points” means an absolute difference of 0.01 per point, not a relative
percentage. Use document-paired bootstrap intervals with 10,000 resamples, seed 13 and
2.5th/97.5th percentiles; resample complete documents so repeated mentions stay together.
If a required interval has undefined precision/recall in a resample, report the undefined
resamples and treat that gate as inconclusive rather than silently discarding them.
Do not bootstrap individual mentions as if they were independent reports. The coverage
floor does not make small-sample intervals reliable by itself.

Evaluate candidate extraction before review holds and the final exported output separately.
Otherwise withholding everything for review could look like a precision improvement while
destroying usable recall. Report held/unresolved volume and analyst workload beside P/R/F1.
An auto-acceptance policy needs its own human-labelled precision evaluation; the gates
above decide extraction activation, not whether a score is calibrated.

All gates are conjunctive for the proposed active subset. A failure or inconclusive result
keeps that version in shadow mode; a reduced subset must be versioned and reevaluated.
If the baseline precision leaves less than five points of possible improvement, revise
that target explicitly before a new evaluation rather than waiving it after seeing scores.
Use a new untouched holdout for a confirmatory claim because this review has already
consulted examples from the original test split.

## Implementation and evaluation boundaries

1. Keep all aliases in `pipeline/data/gazetteer.json`. It is shared with
   `pipeline/aliases.py` for canonicalisation and identity resolution. Put extraction
   policy in a separately versioned configuration keyed by surface form and, when needed,
   MITRE ID/type. Do not implement these decisions as canonical deny-list entries.
2. Apply the same policy in both Aho–Corasick and regex paths, using the original surface
   for case checks. Check each occurrence before span claiming and deduplication: an earlier
   ordinary use must not hide a later qualifying mention. Analyst-promoted overrides need an
   explicit precedence rule before implementation; this draft does not change their behaviour.
3. Resolve collisions such as `play`, `machete` and `snake` using evidence and type, not
   index order. `machete` also exposes canonical-name deduplication across distinct IDs.
   Keep identity-resolution work explicit; a case predicate alone cannot fix these defects.
4. Separate true named-entity mentions, ordinary language, benign products, other threat
   identities, URL/filename components and unresolved cases. Label document-level identity
   outcomes as well as mention-level outcomes; never use all raw counts as false positives.
5. For unobserved forms, retain the proposal as provisional and collect labelled positive
   and negative cases from additional reports. Synthetic checks test specified behaviour,
   not accuracy or representativeness. This inventory is not claimed to exhaust all ordinary
   words in the gazetteer. `comet` still has no standalone entry in this snapshot.
6. Before deployment, apply the operational contract and proposed acceptance gates above.
   Compare old and proposed matching on the same train/dev documents,
   reporting per-type/per-form precision, recall, unique emitted identities, and lost valid
   documents. Verify both matcher paths on positive/negative contexts, initial/mixed/all-uppercase
   forms, lowercase technical uses, repeated mentions, overlapping names and ambiguous IDs.
   Freeze a decision rule and policy revision before held-out evaluation. No accuracy gain,
   test score or completed runtime validation is claimed by this document revision.

## Reproducibility record

- Project commit read: `8f739b44ac96216987eaea539009289126db2d89`.
- AnnoCTR checkout commit: `d510b6949e1938d47c93a43eedd562dc538439dc`.
- Gazetteer SHA-256: `04e33f7897a0aa5ee181f9cc43f112992b1ef8794bb6e3f7d04256948d2c77de`.
- Corpus content SHA-256: `577ba17e253e861ecd9fd2561667b062741fb8a3d2e75507460a24fc178e7339`. Computed over files sorted by filename, concatenating UTF-8 filename, NUL, original file bytes, NUL for each file.
- Source: AnnoCTR by Bosch Research and contributors, [dataset repository](https://github.com/boschresearch/anno-ctr-lrec-coling-2024), CC-BY-SA 4.0. Excerpts above are whitespace-normalised and clipped from that corpus; attribution and source links are retained.
- Mechanical checks: every inventoried form and identity exists in the shipped index; counts cover exactly 400 unique texts; each observed excerpt contains its matched surface and links to the corresponding source line. These checks validate the document evidence, not the proposed extraction rules.
