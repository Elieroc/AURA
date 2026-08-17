{#-
  Rapport d'incident technique — Aura-SOC / DFIR-IRIS (type Investigation, Markdown).

  Contexte Jinja fourni par IRIS (app/datamgmt/reporter/report_db.py,
  export_case_json_for_report) : case, iocs, assets, timeline, tasks, notes,
  evidences, comments, doc_id, user, date, export_date.

  Pièges vérifiés sur IRIS v2.4.27 :
  - les dates de `case` et de `notes` sont des STR (marshmallow), celles de
    timeline/tasks/assets/evidences sont des datetime → macro `dt()`.
  - `evidences` n'exporte PAS la description : le corps riche posé par
    soc_agent.iris._evidences (full_log + JSON brut + deep-link) n'est pas
    récupérable ici, seul le nom/hash/taille l'est.
  - l'environnement Jinja est sandboxé (IrisJinjaEnv) : pas d'attribut dunder,
    pas d'appel de type. Appeler .strftime() sur un datetime reste permis.
  - `notes` est une liste plate ; le répertoire est dans note.directory.name.
-#}
{%- macro dt(v, fmt='%Y-%m-%d %H:%M') -%}
{%- if not v %}—{% elif v.strftime is defined %}{{ v.strftime(fmt) }}{% else %}{{ v }}{% endif -%}
{%- endmacro -%}
{#- Rétrograde les titres d'une note (elle commence en `#`) de deux niveaux,
    sinon ses sections remontent au-dessus du plan numéroté du rapport.
    Ordre décroissant obligatoire : sinon `#` réécrirait ce que `##` vient de
    produire. Le `\n` initial permet de traiter un titre en début de note. -#}
{%- macro corps(v) -%}
{{ ('\n' ~ (v | string)) | replace('\n#### ', '\n###### ') | replace('\n### ', '\n##### ') | replace('\n## ', '\n#### ') | replace('\n# ', '\n### ') }}
{%- endmacro -%}
{%- macro cell(v, n=110) -%}
{{ (v if v else '—') | string | replace('\n', ' ') | replace('\r', ' ') | replace('|', '\\|') | truncate(n, true, '…') }}
{%- endmacro -%}
{#- Extrait la justification LLM du corps de tâche posé par
    soc_agent.mitigate._task_desc (section "## Pourquoi" ... "## Comment
    annuler"). Pas un champ IRIS séparé : le motif voyage dans
    task_description depuis toujours, cette macro le ressort pour sa propre
    colonne au lieu de le laisser noyé dans le "Détail" tronqué à 200 car. -#}
{%- macro motif(v) -%}
{%- set txt = (v if v else '') | string -%}
{%- if '## Pourquoi' in txt -%}
{{ cell(txt.split('## Pourquoi')[1].split('## Comment annuler')[0].strip(), 200) }}
{%- else -%}
—
{%- endif -%}
{%- endmacro -%}
{%- set notes_ia = notes | selectattr('directory') | selectattr('directory.name', 'equalto', 'Analyse IA') | list -%}
{#- Notes du répertoire « Exposition » : posées par soc_agent.iris._note_exposition,
    calculées en Python depuis l'inventaire de vulnérabilités (aucun LLM). Elles
    ont leur SECTION propre et sortent donc de `notes_autres`, sinon elles
    atterriraient dans le fourre-tout de fin de rapport. -#}
{%- set notes_expo = notes | selectattr('directory') | selectattr('directory.name', 'equalto', 'Exposition') | list -%}
{%- set notes_traitees = (notes_ia + notes_expo) | map(attribute='note_id') | list -%}
{%- set notes_autres = notes | rejectattr('note_id', 'in', notes_traitees) | list -%}
{%- set evts_cles = timeline | selectattr('event_in_summary') | list -%}
{%- set assets_compromis = assets | selectattr('asset_compromise_status_id', 'equalto', 1) | list -%}

# Rapport d'incident — {{ case.name }}

| | |
|---|---|
| **Document** | `{{ doc_id }}` — généré le {{ date }} par {{ user }} |
| **Case IRIS** | #{{ case.case_id }} (`{{ case.case_uuid }}`){% if case.soc_id %} — SOC ID `{{ case.soc_id }}`{% endif %} |
| **Client** | {{ case.client.customer_name if case.client else '—' }} |
| **Ouverture** | {{ dt(case.open_date) }} |
| **Clôture** | {{ dt(case.close_date) }} |
| **État** | {{ case.state.state_name if case.state else '—' }} |
| **Sévérité** | {{ case.severity.severity_name if case.severity else '—' }} |
| **Classification** | {{ case.classification.name if case.classification else '—' }} |
| **Propriétaire** | {{ case.owner.user_name if case.owner else '—' }} |
| **Machines** | {{ case.tags | map(attribute='tag_title') | join(', ') if case.tags else '—' }} |

## 1. Synthèse

{{ case.description if case.description else "_Pas de description sur le case._" }}

**Périmètre** : {{ assets | length }} machine(s) impliquée(s) dont {{ assets_compromis | length }} compromise(s) · {{ iocs | length }} IOC · {{ timeline | length }} évènement(s) de timeline · {{ evidences | length }} pièce(s) de preuve · {{ tasks | length }} action(s).

## 2. Analyse

{% if notes_ia -%}
{% for note in notes_ia %}
> Source : note IRIS « {{ note.note_title }} » (répertoire {{ note.directory.name }}), dernière mise à jour {{ dt(note.note_lastupdate) }}.

{{ corps(note.note_content) }}

{% endfor -%}
{%- else -%}
_Aucune note dans le répertoire « Analyse IA » : le triage LLM n'a pas produit de rapport pour ce case._
{%- endif %}

## 3. Machines concernées

{% if assets -%}
| Machine | Type | IP | Compromission | Analyse | Description |
|---|---|---|---|---|---|
{% for a in assets -%}
| **{{ cell(a.asset_name, 40) }}** | {{ cell(a.type, 30) }} | {{ cell(a.asset_ip, 40) }} | {{ cell(a.asset_compromise_status, 20) }} | {{ cell(a.analysis_status, 20) }} | {{ cell(a.asset_description, 160) }} |
{% endfor %}
{%- else -%}
_Aucun asset rattaché au case._
{%- endif %}

## 4. Exposition aux vulnérabilités

{% if notes_expo -%}
{% for note in notes_expo %}
> Source : inventaire Wazuh (Vulnerability Detection), journalisé par `soc_agent.vulns` — dernière mise à jour {{ dt(note.note_lastupdate) }}. Contenu **calculé**, pas rédigé par le modèle : contrairement à la section 2, il ne comporte ni interprétation ni verdict.

{{ corps(note.note_content) }}

{% endfor -%}
{%- else -%}
_Aucune note d'exposition sur ce case._ Deux causes possibles, qu'il faut distinguer avant de conclure quoi que ce soit : le case est antérieur à la mise en service du suivi VOC, ou le module `soc_agent.vulns` n'a pas pu répondre au moment de sa création. Dans les deux cas, l'absence de cette section ne signifie **pas** que la machine est à jour — l'état courant se lit avec `python -m soc_agent.vulns --agent <id>` ou dans le dashboard VOC.
{%- endif %}

## 5. Indicateurs de compromission

{% if iocs -%}
| Valeur | Type | Description | Tags |
|---|---|---|---|
{% for i in iocs | sort(attribute='ioc_type.type_name') -%}
| `{{ cell(i.ioc_value, 120) }}` | {{ cell(i.ioc_type.type_name if i.ioc_type else '—', 25) }} | {{ cell(i.ioc_description, 140) }} | {{ cell(i.ioc_tags, 40) }} |
{% endfor %}
{%- else -%}
_Aucun IOC rattaché au case._
{%- endif %}

## 6. Chronologie

{% if timeline -%}
Fenêtre : {{ dt((timeline | first).event_date) }} → {{ dt((timeline | last).event_date) }} (UTC).

| Date (UTC) | Évènement | Machines | Source |
|---|---|---|---|
{% for e in timeline -%}
| {{ dt(e.event_date, '%Y-%m-%d %H:%M:%S') }} | {{ '**' if e.event_in_summary else '' }}{{ cell(e.event_title, 90) }}{{ '**' if e.event_in_summary else '' }} | {{ cell(e.assets | join(', '), 50) }} | {{ cell(e.event_source, 20) }} |
{% endfor %}

{% if evts_cles -%}
### 6.1 Détail des évènements marquants

{% for e in evts_cles %}
#### {{ dt(e.event_date, '%Y-%m-%d %H:%M:%S') }} — {{ e.event_title }}

{{ corps(e.event_content) if e.event_content else "_Sans contenu._" }}
{% if e.iocs %}
IOC liés : {% for i in e.iocs %}`{{ i.ioc_value }}`{{ ", " if not loop.last }}{% endfor %}
{% endif %}
{% endfor %}
{%- endif -%}
{%- else -%}
_Timeline vide._
{%- endif %}

## 7. Actions et remédiations

{% if tasks -%}
| Action | Statut | Ouverte le | Clôturée le | Tags | Motif | Détail |
|---|---|---|---|---|---|---|
{% for t in tasks | sort(attribute='task_open_date') -%}
| **{{ cell(t.task_title, 60) }}** | {{ cell(t.task_status, 20) }} | {{ dt(t.task_open_date) }} | {{ dt(t.task_close_date) }} | {{ cell(t.task_tags, 30) }} | {{ motif(t.task_description) }} | {{ cell(t.task_description, 200) }} |
{% endfor %}

Rappel : les tâches posées par le soc-agent tracent des remédiations **déjà exécutées** automatiquement (XDR autonome). Une tâche passée en `Canceled` déclenche l'annulation de la remédiation correspondante au cycle suivant.
{%- else -%}
_Aucune action enregistrée sur ce case._
{%- endif %}

## 8. Preuves conservées

{% if evidences -%}
{{ evidences | length }} alerte(s) Wazuh brute(s) archivée(s) dans l'onglet Evidence du case (full_log + JSON complet consultables dans IRIS).

| Pièce | Ajoutée le | Taille | SHA-256 |
|---|---|---|---|
{% for ev in evidences | sort(attribute='date_added') -%}
| {{ cell(ev.filename, 100) }} | {{ dt(ev.date_added) }} | {{ ev.file_size }} o | `{{ ev.file_hash }}` |
{% endfor %}
{%- else -%}
_Aucune pièce de preuve attachée._
{%- endif %}

{% if notes_autres %}
## 9. Notes complémentaires

{% for note in notes_autres %}
### {{ note.note_title }}

> Répertoire : {{ note.directory.name if note.directory else '—' }} — mise à jour {{ dt(note.note_lastupdate) }}

{{ corps(note.note_content) }}

{% endfor %}
{% endif %}
---

Rapport généré depuis DFIR-IRIS le {{ dt(export_date) }} UTC — case #{{ case.case_id }} — document `{{ doc_id }}`.
Chaîne Aura-SOC : détection Wazuh → corrélation soc-agent → triage LLM → remédiation autonome. Les verdicts d'analyse sont produits par un modèle de langage et ne constituent pas une frontière de sécurité : les garde-fous sont déterministes (code + scripts d'active response).
