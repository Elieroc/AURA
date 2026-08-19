{#-
  Rapport mensuel SOC — Aura-SOC (Markdown, généré par
  soc_agent.monthly_report.render_markdown, PAS par le moteur de rapport
  IRIS : contrairement à incident-technique-fr.md, ce template n'a pas de
  case en contexte, donc pas de `case`/`iocs`/`timeline` IRIS — seulement le
  dict retourné par `report()`.

  Contexte attendu : period, start, end, generated_at, alerting, global_kpi,
  performance, hosts, remediation, vulnerability (cf. monthly_report.py pour
  le détail des clés).
-#}
# Rapport mensuel SOC — {{ period }}

Période : {{ start }} → {{ end }} · généré le {{ generated_at }}.

## 1. Synthèse

- **{{ global_kpi.total_events }}** événements reçus, **{{ global_kpi.actionable_events }}** actionnables (≥ Medium), **{{ global_kpi.highcrit_events }}** High/Critical
- **{{ alerting.incidents }}** incidents ouverts après corrélation, **{{ remediation.iris_cases }}** cases IRIS créés
- MTTD moyen **{{ performance.mttd_avg_minutes if performance.mttd_avg_minutes is not none else '—' }} min** · MTTR moyen **{{ performance.mttr_avg_minutes if performance.mttr_avg_minutes is not none else '—' }} min**
- **{{ global_kpi.active_machines }}** machines émettrices sur le parc
- **{{ vulnerability.outside_sla_total }}** vulnérabilités hors SLA sur le parc

## 2. Indicateurs clés (alignés sur le dashboard Wazuh « Global »)

Ces chiffres sont calculés sur la **même population** que le dashboard OSD Global : tous les événements reçus, **avant** le filtrage du bruit par soc-agent. Ils doivent correspondre à ce que vous voyez déjà dans Wazuh — c'est voulu, c'est la même source. La section 3 (Alerting) donne la vue **après** filtrage, qui leur est délibérément inférieure.

| Indicateur | Valeur |
|---|---|
| Événements reçus | {{ global_kpi.total_events }} |
| Actionnables (≥ Medium) | {{ global_kpi.actionable_events }} |
| High + Critical | {{ global_kpi.highcrit_events }} |
| Machines émettrices | {{ global_kpi.active_machines }} |

**Top règles déclenchées (toutes sources, brut)**

| Règle | Description | Occurrences |
|---|---|---|
{% for r in global_kpi.top_rules -%}
| {{ r.rule_id }} | {{ r.rule_desc or '—' }} | {{ r.n }} |
{% endfor %}

**Top tactiques MITRE ATT&CK (≥ Medium)**

{% for t in global_kpi.top_tactics -%}
- {{ t.tactic }} : {{ t.n }}
{% endfor %}

**Top IP sources (≥ Medium)**

{% for s in global_kpi.top_srcips -%}
- {{ s.srcip }} : {{ s.n }}
{% endfor %}

### Performance de détection et de réponse (MTTD / MTTR)

Sur les {{ performance.total_incidents }} incident(s) ouvert(s) ce mois-ci, {{ performance.remediated_count }} ont reçu une remédiation confirmée ({{ performance.remediated_pct if performance.remediated_pct is not none else '—' }}%).

| Délai | Moyenne | Médiane |
|---|---|---|
| MTTD (capteur → détection) | {{ performance.mttd_avg_minutes if performance.mttd_avg_minutes is not none else '—' }} min | {{ performance.mttd_median_minutes if performance.mttd_median_minutes is not none else '—' }} min |
| MTTR (détection → remédiation) | {{ performance.mttr_avg_minutes if performance.mttr_avg_minutes is not none else '—' }} min | {{ performance.mttr_median_minutes if performance.mttr_median_minutes is not none else '—' }} min |

## 3. Alerting (après filtrage du bruit)

| Sévérité | Alertes |
|---|---|
{% for s in alerting.by_severity -%}
| {{ s.level }} | {{ s.n }} |
{% endfor %}

**Top règles déclenchées**

| Règle | Description | Occurrences |
|---|---|---|
{% for r in alerting.top_rules -%}
| {{ r.rule_id }} | {{ r.rule_desc or '—' }} | {{ r.n }} |
{% endfor %}

**Top tactiques MITRE ATT&CK**

{% for t in alerting.top_tactics -%}
- {{ t.tactic }} : {{ t.n }}
{% endfor %}

**Qualité de la détection (verdicts analystes)**

| Verdict | Incidents |
|---|---|
{% for v in alerting.verdicts -%}
| {{ v.verdict }} | {{ v.n }} |
{% endfor %}

## 4. Machines touchées

{{ hosts.distinct_agents }} machine(s) distincte(s) ont ouvert au moins un incident ce mois-ci.

**Répartition par priorité CMDB (P1 = critique)**

| Priorité | Incidents |
|---|---|
{% for p in hosts.by_priority -%}
| P{{ p.priority }} | {{ p.incidents }} |
{% endfor %}

**Top machines**

| Machine | Priorité | Rôle | Incidents | Niveau max |
|---|---|---|---|---|
{% for h in hosts.top_hosts -%}
| {{ h.agent_name or h.agent_id }} | P{{ h.priority }} | {{ h.role or '—' }} | {{ h.incidents }} | {{ h.max_level }}/15 |
{% endfor %}

## 5. Remédiation

{{ remediation.iris_cases }} incident(s) ont donné lieu à un case IRIS ce mois-ci.

| Statut | Actions |
|---|---|
{% for s in remediation.by_status -%}
| {{ s.status }} | {{ s.n }} |
{% endfor %}

**Répartition par type d'action (exécutées)**

{% for a in remediation.by_action -%}
- {{ a.action }} : {{ a.n }}
{% endfor %}

## 6. Gestion des vulnérabilités (VOC)

{% if vulnerability._note %}
_{{ vulnerability._note }}_
{% else %}
Couverture du scan : **{{ vulnerability.coverage_pct }}%** ({{ vulnerability.scanned }}/{{ vulnerability.total_assets }} machines connues de la CMDB).
{% if vulnerability.coverage_pct is none %}
_Aucun asset connu de la CMDB — le taux de couverture ne peut pas être calculé._
{% endif %}

**Vulnérabilités ouvertes par sévérité**

| Sévérité | Ouvertes |
|---|---|
{% for s in vulnerability.open_by_severity -%}
| {{ s.severity or 'non classée' }} | {{ s.n }} |
{% endfor %}

- Hors SLA (tous statuts confondus) : **{{ vulnerability.outside_sla_total }}**
- Nouvelles vulnérabilités (30 derniers jours) : **{{ vulnerability.new_30d }}**
- Corrigées (30 derniers jours) : **{{ vulnerability.fixed_30d }}**
- Délai moyen de correction (MTTR, 30 j) : **{{ vulnerability.mttr_days if vulnerability.mttr_days is not none else '—' }} jours**

**Machines les plus exposées**

| Machine | Priorité | Score | Niveau | Critique | High | Hors SLA |
|---|---|---|---|---|---|---|
{% for e in vulnerability.top_exposed -%}
| {{ e.agent_name or e.agent_id }} | P{{ e.priority }} | {{ e.score }}/100 | {{ e.level }} | {{ e.critical }} | {{ e.high }} | {{ e.outside_sla }} |
{% endfor %}
{% endif %}

---

Rapport généré automatiquement par `soc_agent.monthly_report` — chaîne Aura-SOC : détection Wazuh → corrélation soc-agent → triage LLM → remédiation autonome. Toutes les valeurs (sections 2 à 5) sont calculées en base, aucun LLM impliqué ; la section 6 reprend l'état courant du suivi VOC (`soc_agent.vulns`).
