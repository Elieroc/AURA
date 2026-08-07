<?php
/**
 * Active l'envoi syslog de pfSense vers un manager Wazuh, SANS toucher aux
 * cibles syslog déjà configurées (remoteserver reste intact ; on complète
 * remoteserver2/remoteserver3 s'il reste de la place).
 *
 * pfSense (FreeBSD, appliance) n'a pas de paquet wazuh-agent officiel : le
 * chemin supporté est syslog direct, décodé côté manager par
 * wazuh/config/wazuh_cluster/decoders/pfsense-nohostname.xml + les règles
 * 100810-100812 (cf. wazuh/agents/pfsense/README.md pour le pourquoi).
 *
 * Usage, EN ROOT sur pfSense (shell direct, pas le menu pfSsh.php) :
 *   scp configure-syslog.php root@<pfsense>:/tmp/
 *   ssh root@<pfsense> 'php -f /tmp/configure-syslog.php -- <IP_DU_MANAGER>'
 *
 * <IP_DU_MANAGER> : IP du manager Wazuh TELLE QUE PFSENSE LA JOINT. Sur un
 * pare-feu multi-interfaces, la source d'un paquet sortant est l'IP de
 * l'interface la plus proche de la destination, PAS forcément l'IP
 * WAN/mgmt — c'est aussi cette IP qu'il faut mettre dans <allowed-ips> côté
 * manager (wazuh_manager.conf). Se tromper ici ne casse rien (juste pas de
 * flux) ; se tromper côté manager fait tomber le filtre allowed-ips en
 * silence (paquets reçus par le noyau, jetés par wazuh-remoted sans log
 * d'erreur exploitable).
 *
 * Idempotent : si l'IP:port demandé est déjà dans un des 3 remoteserver,
 * ne fait rien. Écrit dans remoteserver2 puis remoteserver3 (jamais
 * remoteserver, réservé à ce qui existait avant nous).
 */

require_once("config.inc");
require_once("system.inc");

global $config;

$args = $argv;
array_shift($args); // nom du script
$manager = $args[0] ?? null;
if (!$manager) {
    fwrite(STDERR, "Usage: php -f configure-syslog.php -- <ip_manager>[:port]\n");
    exit(1);
}
if (strpos($manager, ':') === false) {
    $manager .= ':514';
}

$syslog = &$config['syslog'];
$existing = [$syslog['remoteserver'] ?? '', $syslog['remoteserver2'] ?? '', $syslog['remoteserver3'] ?? ''];

if (in_array($manager, $existing, true)) {
    echo "Déjà configuré : $manager\n";
    exit(0);
}

$slot = null;
foreach (['remoteserver2', 'remoteserver3'] as $candidate) {
    if (empty($syslog[$candidate])) {
        $slot = $candidate;
        break;
    }
}
if ($slot === null) {
    fwrite(STDERR, "remoteserver2 et remoteserver3 sont déjà pris — libérer un slot ou éditer main à la place.\n");
    exit(1);
}

$syslog['enable'] = 'enabled';
$syslog['filter'] = 'enabled'; // catégorie "Firewall Events" : sans ça, filterlog part seulement en local
$syslog[$slot] = $manager;

write_config("Aura-SOC: syslog remote vers Wazuh ($manager) sur $slot, sans toucher aux cibles existantes");
system_syslogd_start();

echo "OK — $slot = $manager\n";
print_r($config['syslog']);
