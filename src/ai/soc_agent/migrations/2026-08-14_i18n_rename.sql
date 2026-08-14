-- Migration: rename French Postgres identifiers and enum-like values to
-- English, to match the i18n rewrite of soc_agent applied on 2026-08-14.
--
-- Run this ONCE against the production database, BEFORE deploying the
-- English soc_agent code (the new code reads/writes the English names; the
-- old code, if still running against a migrated database, will break — do
-- not run this against a database still served by the pre-i18n image).
--
--   docker exec -i socagent-db psql -U "$PGUSER" -d "$PGDATABASE" \
--     < src/ai/soc_agent/migrations/2026-08-14_i18n_rename.sql
--
-- ($PGUSER/$PGDATABASE default to "socagent" — cf. .env / docker-compose.yml.)
--
-- Idempotent: every rename is guarded so the script can be re-run safely if
-- it is interrupted partway (Postgres has no native "RENAME COLUMN IF
-- EXISTS", so each rename is wrapped in a DO block that checks
-- information_schema first).

BEGIN;

-- ---------------------------------------------------------------------
-- 1. Table renames
-- ---------------------------------------------------------------------

ALTER TABLE IF EXISTS capteur_pannes  RENAME TO sensor_outages;
ALTER TABLE IF EXISTS vulnerabilites  RENAME TO vulnerabilities;
ALTER TABLE IF EXISTS routage_sources RENAME TO routing_sources;

-- ---------------------------------------------------------------------
-- 2. Column renames, per table (all guarded — a rerun is a no-op)
-- ---------------------------------------------------------------------

DO $$
DECLARE row_ record;
BEGIN
    FOR row_ IN SELECT * FROM (VALUES
        ('triages','modele','model'),
        ('triages','duree_ms','duration_ms'),
        ('triages','incoherences','inconsistencies'),
        ('triages','injection_motifs','injection_patterns'),
        ('triages','garde_fous','guardrails'),
        ('labels','commentaire','comment'),
        ('labels','origine','origin'),
        ('labels','labellise_par','labeled_by'),
        ('mitigations','cible','target'),
        ('mitigations','statut','status'),
        ('mitigations','tentatives','attempts'),
        ('llm_calls','modele','model'),
        ('llm_calls','duree_ms','duration_ms'),
        ('llm_calls','erreur','error'),
        ('training_runs','jours','days'),
        ('incidents','priorite','priority'),
        ('incidents','severite','severity'),
        ('ueba_observations','valeur','value'),
        ('ueba_observations','jour','day'),
        ('ueba_observations','nb','count'),
        ('ueba_profiles','valeur','value'),
        ('ueba_scopes','distincts','distinct_values'),
        ('ueba_scopes','premiere_obs','first_obs'),
        ('ueba_scopes','derniere_obs','last_obs'),
        ('ueba_signals','debut','start_ts'),
        ('ueba_signals','fin','end_ts'),
        ('ueba_signals','motifs','patterns'),
        ('ueba_signals','statut','status'),
        ('alerts','ueba_vu','ueba_seen'),
        ('incidents','ueba_motifs','ueba_patterns'),
        ('sensor_outages','capteur','sensor'),
        ('sensor_outages','dernier_event','last_event'),
        ('sensor_outages','seuil_minutes','threshold_minutes'),
        ('sensor_outages','detectee_a','detected_at'),
        ('sensor_outages','retablie_a','recovered_at'),
        ('sensor_outages','statut','status'),
        ('iris_evidences','posee_a','placed_at'),
        ('assets','nom','name'),
        ('assets','groupes','groups'),
        ('assets','priorite','priority'),
        ('assets','priorite_source','priority_source'),
        ('assets','vu_a','seen_at'),
        ('assets','maj_a','updated_at'),
        ('vulnerabilities','paquet','package'),
        ('vulnerabilities','severite','severity'),
        ('vulnerabilities','score_base','base_score'),
        ('vulnerabilities','publiee_a','published_at'),
        ('vulnerabilities','vue_a','first_seen'),
        ('vulnerabilities','derniere_vue','last_seen'),
        ('vulnerabilities','corrigee_a','fixed_at'),
        ('vulnerabilities','statut','status'),
        ('vulnerabilities','os_nom','os_name'),
        ('vuln_scans','lance_a','started_at'),
        ('vuln_scans','agents_vus','agents_seen'),
        ('vuln_scans','vulns_vues','vulns_seen'),
        ('vuln_scans','nouvelles','new_count'),
        ('vuln_scans','corrigees','fixed_count'),
        ('vuln_scans','agents_muets','silent_agents'),
        ('cti_articles','traite_a','processed_at'),
        ('cti_articles','iocs_retenus','iocs_kept'),
        ('cti_articles','menace','threat'),
        ('cti_articles','motif','pattern'),
        ('routing_sources','critere_type','criterion_type'),
        ('routing_sources','critere_valeur','criterion_value'),
        ('routing_sources','statut','status'),
        ('routing_sources','nomme_par','named_by'),
        ('routing_sources','vue_a','last_seen'),
        ('routing_sources','exemple','example'),
        ('routing_sources','creee_a','created_at'),
        ('routing_sources','appliquee_a','applied_at'),
        ('archives_s3','periode','period'),
        ('archives_s3','cle','key'),
        ('archives_s3','cle_manifeste','manifest_key'),
        ('archives_s3','octets_clair','plain_bytes'),
        ('archives_s3','octets_objet','object_bytes'),
        ('archives_s3','sha256_clair','sha256_plain'),
        ('archives_s3','sha256_chiffre','sha256_encrypted'),
        ('archives_s3','chaine','chain'),
        ('archives_s3','destinataires','recipients'),
        ('archives_s3','champs_exclus','excluded_fields'),
        ('archives_s3','object_lock_jusqu_a','object_lock_until'),
        ('archives_s3','archivee_a','archived_at'),
        ('archives_s3','verifie_a','verified_at'),
        ('archives_s3','verif_etat','verify_state'),
        ('archives_s3','verif_complet','verify_full')
    ) AS t(tbl, old_col, new_col)
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = row_.tbl)
           AND EXISTS (SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'public' AND table_name = row_.tbl
                          AND column_name = row_.old_col)
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                             WHERE table_schema = 'public' AND table_name = row_.tbl
                               AND column_name = row_.new_col)
        THEN
            EXECUTE format('ALTER TABLE %I RENAME COLUMN %I TO %I',
                           row_.tbl, row_.old_col, row_.new_col);
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 3. Index renames (cosmetic — Postgres index renames never touch data)
-- ---------------------------------------------------------------------

DO $$
DECLARE row_ record;
BEGIN
    FOR row_ IN SELECT * FROM (VALUES
        ('alerts_ueba_a_voir','alerts_ueba_todo'),
        ('archives_s3_couverture','archives_s3_coverage'),
        ('assets_nom','assets_name'),
        ('assets_priorite','assets_priority'),
        ('capteur_pannes_recentes','sensor_outages_recent'),
        ('capteur_pannes_une_seule_ouverte','sensor_outages_single_open'),
        ('cti_articles_avec_iocs','cti_articles_with_iocs'),
        ('cti_articles_recents','cti_articles_recent'),
        ('incidents_priorite','incidents_priority'),
        ('routage_sources_appliquees','routing_sources_applied'),
        ('routage_sources_statut','routing_sources_status'),
        ('training_un_seul_run_actif','training_single_active_run'),
        ('ueba_obs_jour','ueba_obs_day'),
        ('ueba_profiles_flotte','ueba_profiles_fleet'),
        ('ueba_signals_statut','ueba_signals_status'),
        ('vuln_corrigees','vuln_fixed'),
        ('vuln_ouvertes','vuln_open'),
        ('vuln_scans_recents','vuln_scans_recent')
    ) AS t(old_idx, new_idx)
    LOOP
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = row_.old_idx AND relkind = 'i')
           AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = row_.new_idx AND relkind = 'i')
        THEN
            EXECUTE format('ALTER INDEX %I RENAME TO %I', row_.old_idx, row_.new_idx);
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 4. Enum-like value migrations (column names already renamed above, so
--    these UPDATEs use the NEW column names)
-- ---------------------------------------------------------------------

UPDATE labels SET origin = 'human' WHERE origin = 'humain';

UPDATE vulnerabilities SET status = 'open'  WHERE status = 'ouverte';
UPDATE vulnerabilities SET status = 'fixed' WHERE status = 'corrigee';

UPDATE incidents SET asset_role = 'sensor' WHERE asset_role = 'capteur';
UPDATE incidents SET status = 'case_open'     WHERE status = 'case_ouvert';
UPDATE incidents SET status = 'fp_classified' WHERE status = 'fp_classe';

UPDATE mitigations SET status = 'executed'      WHERE status = 'exécuté';
UPDATE mitigations SET status = 'confirmed'     WHERE status = 'confirmé';
UPDATE mitigations SET status = 'no_effect'     WHERE status = 'sans_effet';
UPDATE mitigations SET status = 'sent'          WHERE status = 'émis';
UPDATE mitigations SET status = 'agent_refused' WHERE status = 'refusé_agent';
UPDATE mitigations SET status = 'failed'        WHERE status = 'échec';
UPDATE mitigations SET status = 'canceled'      WHERE status = 'annulé';
UPDATE mitigations SET status = 'undo_failed'   WHERE status = 'annulation_impossible';

UPDATE assets SET priority_source = 'operator' WHERE priority_source = 'operateur';
UPDATE assets SET priority_source = 'group'    WHERE priority_source = 'groupe';
UPDATE assets SET priority_source = 'default'  WHERE priority_source = 'defaut';

UPDATE ueba_signals SET status = 'promoted' WHERE status = 'promu';
UPDATE ueba_signals SET status = 'pending'  WHERE status = 'en_attente';

UPDATE whitelist_rules SET source = 'analyst' WHERE source = 'analyste';

-- sensor_outages: sensor prefixes and status. Postgres has no equivalent of
-- Python's str.replace with a fixed prefix in a single UPDATE without
-- regexp, so this uses substring replacement guarded by a LIKE match.
UPDATE sensor_outages SET sensor = 'disk' WHERE sensor = 'disque';
UPDATE sensor_outages SET sensor = 'routing:' || substring(sensor from length('routage:') + 1)
    WHERE sensor LIKE 'routage:%';
UPDATE sensor_outages SET sensor = 'silent-source:' || substring(sensor from length('source-muette:') + 1)
    WHERE sensor LIKE 'source-muette:%';
UPDATE sensor_outages SET sensor = 'archiving:' || substring(sensor from length('archivage:') + 1)
    WHERE sensor LIKE 'archivage:%';
UPDATE sensor_outages SET status = 'open'      WHERE status = 'ouverte';
UPDATE sensor_outages SET status = 'recovered' WHERE status = 'retablie';

-- ueba_observations / ueba_profiles / ueba_scopes: the "trait" column names a
-- feature (fichier/pays/compte/heure/chaine_mitre) and "value" carries its
-- observed value. Both need translating; "value" only for the hour trait's
-- two enum values (all other traits carry free-form data — IP, account name,
-- country code, executable name — which is not translated).
UPDATE ueba_observations SET trait = 'file'        WHERE trait = 'fichier';
UPDATE ueba_observations SET trait = 'country'     WHERE trait = 'pays';
UPDATE ueba_observations SET trait = 'account'     WHERE trait = 'compte';
UPDATE ueba_observations SET trait = 'hour'        WHERE trait = 'heure';
UPDATE ueba_observations SET trait = 'mitre_chain' WHERE trait = 'chaine_mitre';
UPDATE ueba_observations SET value = 'business'  WHERE trait = 'hour' AND value = 'ouvre';
UPDATE ueba_observations SET value = 'off_hours' WHERE trait = 'hour' AND value = 'hors_ouvre';

UPDATE ueba_profiles SET trait = 'file'        WHERE trait = 'fichier';
UPDATE ueba_profiles SET trait = 'country'     WHERE trait = 'pays';
UPDATE ueba_profiles SET trait = 'account'     WHERE trait = 'compte';
UPDATE ueba_profiles SET trait = 'hour'        WHERE trait = 'heure';
UPDATE ueba_profiles SET trait = 'mitre_chain' WHERE trait = 'chaine_mitre';
UPDATE ueba_profiles SET value = 'business'  WHERE trait = 'hour' AND value = 'ouvre';
UPDATE ueba_profiles SET value = 'off_hours' WHERE trait = 'hour' AND value = 'hors_ouvre';

UPDATE ueba_scopes SET trait = 'file'        WHERE trait = 'fichier';
UPDATE ueba_scopes SET trait = 'country'     WHERE trait = 'pays';
UPDATE ueba_scopes SET trait = 'account'     WHERE trait = 'compte';
UPDATE ueba_scopes SET trait = 'hour'        WHERE trait = 'heure';
UPDATE ueba_scopes SET trait = 'mitre_chain' WHERE trait = 'chaine_mitre';

COMMIT;

-- ---------------------------------------------------------------------
-- Not covered by this script, and NOT to be migrated:
--
-- - cti.py's SQLite indicator cache (categorie/evenement/niveau_menace/
--   confiance -> category/event/threat_level/confidence, meta key
--   synchronise_a -> synced_at): it is a disposable cache file, not part of
--   this Postgres database. Deleting it lets the next `cti.sync()` rebuild
--   it from scratch with the new English schema — simpler than migrating it
--   in place. Same for custom-misp.py's own IOC cache on the Wazuh manager.
--
-- - Any French text still intentionally kept as CONTENT (not identifiers):
--   IRIS case titles/notes/tasks, the LLM prompts (prompts/*.md), the
--   anonymize.py token prefixes (HOTE/COMPTE/FICHIER/OBJET/DIVERS), the
--   retention.py ISM state names ("actif"/"suppression"), and the
--   rule_tuning.py "signature-canonique:" marker. These are display text or
--   external contracts, not renamed by design — see the project's i18n
--   conventions in the commit history for details.
