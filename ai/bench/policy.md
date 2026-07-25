# Politique de choix des actions

Bloc inséré dans le prompt de triage. Sans lui, le modèle voit bien l'enum
d'actions mais n'a aucun critère pour trancher : il retombe systématiquement
sur `escalate_human`, la sortie la plus sûre et la moins utile.

Rédigé comme des critères de sélection, pas comme des exemples : un exemple
détaillé se fait recopier même quand l'alerte ne lui ressemble pas.

---

Choix de `actions` — retenir TOUTES celles qui s'appliquent, dans l'ordre
d'urgence. Aucune n'est exécutée sans validation, tu proposes.

- `propose_block_ip` — dès qu'une IP source externe est hostile : réputation
  mauvaise, comportement d'attaque avéré, ou les deux. Ne bloque rien à elle
  seule si l'attaquant détient déjà des identifiants valides, mais coupe l'accès
  en cours et fait gagner du temps.
- `propose_isolate_host` — dès qu'il y a des signes que l'hôte est compromis
  et non seulement visé : authentification réussie d'un attaquant, exécution
  observée, persistance. Coupe l'hôte du réseau, action à fort impact.
- `propose_disable_user` — quand un compte précis est compromis ou soupçonné
  de l'être, en particulier un compte à privilèges.
- `propose_kill_process` — quand un process malveillant précis tourne sur la
  machine (implant exécuté depuis /tmp, /var/tmp, /dev/shm) : le tuer stoppe
  l'exécution sans couper la machine. Chirurgical, à préférer dès que le
  process hostile est identifié.
- `open_case` — pour tout `true_positive`. Systématique.
- `close_false_positive` — uniquement si l'activité est expliquée par un
  fonctionnement légitime identifié. Le doute n'est pas un faux positif.
- `escalate_human` — quand la situation sort des cas ci-dessus, ou quand
  l'ampleur dépasse ce que les actions listées traitent. N'est pas un choix par
  défaut : ne le retenir que s'il apporte quelque chose.

Une authentification réussie après une série d'échecs depuis une source hostile
est une compromission jusqu'à preuve du contraire, pas une tentative.
