<?php
/*
 * Aura-SOC — configure Suricata on pfSense for Wazuh ingestion.
 *
 * Run as root ON the pfSense box (root shell, not the restricted pfSsh.php menu):
 *
 *     php -f /tmp/configure-suricata.php -- [<pfsense-interface-key> [<vlan-label>]]
 *
 * Default target is 'wan' (labelled LAN100 here). Beware the naming trap: the
 * pfSense interface KEY is what config.xml uses ('wan', 'opt1', ...), while the
 * VLAN name lives in the 'descr' field. LAN100 is the 'wan' interface.
 *
 * What it does, idempotently:
 *   1. Creates a Suricata instance on the target interface if missing, cloning
 *      an existing instance so the ~200 config keys keep sane values.
 *   2. Enables a base set of Emerging Threats categories on that instance.
 *   3. Forces EVE output to a regular JSON file on EVERY instance. The package
 *      default is syslog, which lands in the pfSense system log where the Wazuh
 *      agent never looks — an instance configured that way reports nothing at
 *      all, silently.
 *   4. Restricts EVE to alert/drop/anomaly on every instance. Protocol
 *      transaction logging measured ~450 MB/day per interface.
 *   5. Suppresses the stream-events category on every instance (virtio offload
 *      artefacts, measured ~200 alerts/s).
 *
 * Then restart: /usr/local/etc/rc.d/suricata.sh restart
 * The Wazuh agent side is a single localfile, see README.md.
 */

require_once("config.inc");
require_once("/usr/local/pkg/suricata/suricata.inc");

global $g, $rebuild_rules;

$target = $argv[1] ?? 'wan';
$label  = $argv[2] ?? 'LAN100';

/* Reputation/blocklist categories (drop, dshield, ciarmy, compromised) are left
 * out on purpose: on a WAN-facing interface they fire on internet background
 * noise and drown everything else. */
$ET_BASE = array(
	'emerging-attack_response.rules',
	'emerging-botcc.rules',
	'emerging-coinminer.rules',
	'emerging-current_events.rules',
	'emerging-exploit.rules',
	'emerging-exploit_kit.rules',
	'emerging-malware.rules',
	'emerging-mobile_malware.rules',
	'emerging-phishing.rules',
	'emerging-remote_access.rules',
	'emerging-scan.rules',
	'emerging-shellcode.rules',
	'emerging-user_agents.rules',
	'emerging-web_client.rules',
	'emerging-web_server.rules',
);

/* EVE event types to switch off: everything that logs a transaction rather than
 * a detection. */
$EVE_OFF = array(
	'eve_log_http', 'eve_log_dns', 'eve_log_tls', 'eve_log_dhcp', 'eve_log_nfs',
	'eve_log_smb', 'eve_log_krb5', 'eve_log_ikev2', 'eve_log_tftp', 'eve_log_quic',
	'eve_log_files', 'eve_log_ssh', 'eve_log_smtp', 'eve_log_snmp', 'eve_log_mqtt',
	'eve_log_ftp', 'eve_log_http2', 'eve_log_rfb', 'eve_log_stats', 'eve_log_flow',
	'eve_log_netflow', 'eve_log_bittorrent', 'eve_log_pgsql', 'eve_log_rdp',
	'eve_log_sip',
);

$a_rule = config_get_path('installedpackages/suricata/rule', []);
if (count($a_rule) < 1) {
	echo "No Suricata instance configured yet: create the first one from the web UI.\n";
	exit(1);
}

/* --- 1. Instance on the target interface ------------------------------- */

$have_target = false;
foreach ($a_rule as $r) {
	if ($r['interface'] == $target) {
		$have_target = true;
	}
}

if (!$have_target) {
	/* Clone whichever instance exists: guessing the ~200 keys by hand is how
	 * you end up with a yaml Suricata refuses to load. */
	$new = $a_rule[0];
	$new['interface'] = $target;
	$new['descr']     = $label;
	$new['uuid']      = suricata_generate_id();
	$new['enable']    = 'on';
	/* IDS only. Blocking from an IDS whose rules nobody has tuned yet is how you
	 * take the network down on a false positive. */
	$new['blockoffenders'] = 'off';
	$a_rule[] = $new;
	echo "Created instance on {$target} ({$label}), uuid {$new['uuid']}\n";
	/* New rule categories below need the rule files rebuilt. */
	$rebuild_rules = true;
} else {
	echo "Instance on {$target} already present\n";
	$rebuild_rules = false;
}

/* --- 2..4. Rulesets and EVE output ------------------------------------- */

foreach ($a_rule as $i => $r) {
	$a_rule[$i]['enable_eve_log']   = 'on';
	$a_rule[$i]['eve_output_type']  = 'regular';
	foreach ($EVE_OFF as $k) {
		$a_rule[$i][$k] = 'off';
	}
	$a_rule[$i]['eve_log_alerts']  = 'on';
	$a_rule[$i]['eve_log_drops']   = 'on';
	$a_rule[$i]['eve_log_anomaly'] = 'on';

	if ($r['interface'] == $target) {
		$cur = explode('||', $r['rulesets']);
		$merged = array_values(array_unique(array_merge($cur, $ET_BASE)));
		sort($merged);
		if (count($merged) != count($cur)) {
			$rebuild_rules = true;
		}
		$a_rule[$i]['rulesets'] = implode('||', $merged);
		echo "Rulesets on {$target}: " . count($cur) . " -> " . count($merged) . "\n";
	}
}

/* --- 5. Suppress the stream-events category ---------------------------- */

$stream_rules = '/usr/local/share/suricata/rules/stream-events.rules';
if (file_exists($stream_rules)) {
	$sids = array();
	foreach (file($stream_rules) as $line) {
		if (preg_match('/\bsid:\s*(\d+)\s*;/', $line, $m)) {
			$sids[] = $m[1];
		}
	}
	$sids = array_values(array_unique($sids));
	sort($sids, SORT_NUMERIC);

	$body = "# Aura-SOC: suppress the stream-events category (gen_id 1).\n" .
		"# virtio NICs with TCP offload hand Suricata packets it never saw on the\n" .
		"# wire in one piece, so 'invalid ack' / 'out of window' are artefacts, not\n" .
		"# evasion. Measured ~200 alerts/s, 98% of all Suricata volume.\n";
	foreach ($sids as $sid) {
		$body .= "suppress gen_id 1, sig_id {$sid}\n";
	}

	$list = array(
		'name'             => 'stream-noise',
		'uuid'             => suricata_generate_id(),
		'detail'           => 'Aura-SOC: stream-events suppressed (virtio offload artefacts)',
		'suppresspassthru' => base64_encode($body),
	);

	$items = config_get_path('installedpackages/suricata/suppress/item', []);
	$found = false;
	foreach ($items as $i => $it) {
		if ($it['name'] == 'stream-noise') {
			$list['uuid'] = $it['uuid'];
			$items[$i] = $list;
			$found = true;
		}
	}
	if (!$found) {
		$items[] = $list;
	}
	config_set_path('installedpackages/suricata/suppress/item', $items);

	foreach ($a_rule as $i => $r) {
		$a_rule[$i]['suppresslistname'] = 'stream-noise';
	}
	echo "Suppressed " . count($sids) . " stream-events sids on all interfaces\n";
} else {
	echo "WARNING: {$stream_rules} missing, stream-events not suppressed\n";
}

config_set_path('installedpackages/suricata/rule', $a_rule);
write_config("Suricata pkg: Aura-SOC configuration for {$label} ({$target})");

/* Recreates the per-instance directories, rebuilds the rule files when
 * $rebuild_rules is set, and regenerates every suricata.yaml. */
sync_suricata_package_config();

echo "Done. Restart with: /usr/local/etc/rc.d/suricata.sh restart\n";
