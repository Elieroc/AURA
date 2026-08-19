{#-
  Rapport de veille data-leak — Aura-SOC / DFIR-IRIS (type Investigation, Markdown).

  Structure volontairement DIFFÉRENTE du rapport d'incident technique
  (incident-technique-fr.md) : un case de ce template documente l'exposition
  d'une PERSONNE (email dans une fuite de données), pas une machine compromise.
  Pas de section machines/timeline/exposition — elles seraient vides, IRIS
  n'attache ni asset ni évènement à ces cases. Posé par soc_agent.data_leak.py.

  Contexte Jinja fourni par IRIS (app/datamgmt/reporter/report_db.py,
  export_case_json_for_report) : case, iocs, notes, doc_id, user, date,
  export_date. `assets`/`timeline`/`tasks`/`evidences` existent mais restent
  vides pour ce type de case — non utilisés ici.

  Pièges vérifiés sur IRIS v2.4.27 (identiques à incident-technique-fr.md) :
  - dates de `case`/`notes` en STR (marshmallow) → macro dt() ci-dessous ;
  - `notes` est une liste plate, le répertoire est dans note.directory.name ;
  - environnement Jinja sandboxé (IrisJinjaEnv) : pas d'attribut dunder.
-#}
{%- macro dt(v, fmt='%Y-%m-%d %H:%M') -%}
{%- if not v %}—{% elif v.strftime is defined %}{{ v.strftime(fmt) }}{% else %}{{ v }}{% endif -%}
{%- endmacro -%}
{#- Rétrograde les titres de la note (elle commence en `#`), sinon ses
    sections remontent au-dessus du plan du rapport. -#}
{%- macro corps(v) -%}
{{ ('\n' ~ (v | string)) | replace('\n#### ', '\n###### ') | replace('\n### ', '\n##### ') | replace('\n## ', '\n#### ') | replace('\n# ', '\n### ') }}
{%- endmacro -%}
{%- macro cell(v, n=110) -%}
{{ (v if v else '—') | string | replace('\n', ' ') | replace('\r', ' ') | replace('|', '\\|') | truncate(n, true, '…') }}
{%- endmacro -%}
{%- set notes_fuite = notes | selectattr('directory') | selectattr('directory.name', 'equalto', 'Fuite de données') | list -%}
{%- set notes_traitees = notes_fuite | map(attribute='note_id') | list -%}
{%- set notes_autres = notes | rejectattr('note_id', 'in', notes_traitees) | list -%}
{%- set email = iocs | selectattr('ioc_type.type_name', 'equalto', 'Email') | map(attribute='ioc_value') | first -%}

# Veille data-leak — {{ email if email else case.name }}

| | |
|---|---|
| **Document** | `{{ doc_id }}` — généré le {{ date }} par {{ user }} |
| **Case IRIS** | #{{ case.case_id }} (`{{ case.case_uuid }}`){% if case.soc_id %} — SOC ID `{{ case.soc_id }}`{% endif %} |
| **Compte surveillé** | {{ email if email else '—' }} |
| **Détection** | {{ dt(case.open_date) }} |
| **Sévérité** | {{ case.severity.severity_name if case.severity else '—' }} |
| **Classification** | {{ case.classification.name if case.classification else '—' }} |
| **État** | {{ case.state.state_name if case.state else '—' }} |
| **Propriétaire** | {{ case.owner.user_name if case.owner else '—' }} |
| **Tags** | {{ case.tags | map(attribute='tag_title') | join(', ') if case.tags else '—' }} |

## 1. Résumé

{{ case.description if case.description else "_Pas de description sur le case._" }}

Ce case documente l'exposition d'un **compte** dans une fuite de données
publique, détectée par la veille data-leak (source : XposedOrNot). Il ne
s'agit pas d'un incident sur une machine du parc — aucune remédiation
technique n'est déclenchée automatiquement, l'action attendue est côté
utilisateur (rotation de mot de passe, MFA).

## 2. Détail de la fuite

{% if notes_fuite -%}
{% for note in notes_fuite %}
> Source : note IRIS « {{ note.note_title }} », dernière mise à jour {{ dt(note.note_lastupdate) }}.

{{ corps(note.note_content) }}

{% endfor -%}
{%- else -%}
_Aucune note dans le répertoire « Fuite de données » : le détail XposedOrNot
n'a pas pu être écrit sur ce case._
{%- endif %}

## 3. Indicateur

{% if iocs -%}
| Valeur | Type | Description |
|---|---|---|
{% for i in iocs -%}
| `{{ cell(i.ioc_value, 120) }}` | {{ cell(i.ioc_type.type_name if i.ioc_type else '—', 25) }} | {{ cell(i.ioc_description, 140) }} |
{% endfor %}
{%- else -%}
_Aucun IOC rattaché au case._
{%- endif %}

{% if notes_autres %}
## 4. Notes complémentaires

{% for note in notes_autres %}
### {{ note.note_title }}

> Répertoire : {{ note.directory.name if note.directory else '—' }} — mise à jour {{ dt(note.note_lastupdate) }}

{{ corps(note.note_content) }}

{% endfor %}
{% endif %}
---

Rapport généré depuis DFIR-IRIS le {{ dt(export_date) }} UTC — case #{{ case.case_id }} — document `{{ doc_id }}`.
Chaîne veille data-leak Aura-SOC : groupe IRIS « veille-data-leak » → XposedOrNot → soc-agent-data-leak. La détection porte sur des fuites PUBLIQUES déjà survenues ; elle ne mesure ni ne garantit l'absence d'autres expositions non indexées par la source.
