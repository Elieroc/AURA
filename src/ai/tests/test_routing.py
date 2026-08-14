"""Tests of the routing control logic (no indexer, no database, no LLM).

What is tested here is what DECIDES: validating an index name, rendering the
painless script (including its byte-for-byte stability, without which the
pipeline would be rewritten every two minutes), the insertion point in the
pipeline, and reading a simulation. Network calls have no branch to cover.
"""

import json

import pytest

from soc_agent import config, routing


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------

def test_generic_outside_vocabulary_is_refused():
    """The heart of the convention: a firewall is not named "pfsense".

    Without a closed vocabulary, every product opens its own index and the
    same question ("what did the firewall block?") requires querying as many
    indices as there are brands present in the estate.
    """
    assert routing._validate("generic", "pfsense", {"pfsense"}) is not None
    assert routing._validate("generic", "fortinet", {"fortinet"}) is not None
    assert routing._validate("generic", "firewall", set()) is None


def test_application_must_be_attested_by_the_data():
    """An application name nothing attests is a costly hallucination: the
    created index is not renamed, it is duplicated."""
    assert routing._validate("application", "jellyfin", {"jellyfin", "media"}) is None
    assert routing._validate("application", "grafana", {"jellyfin"}) is not None


def test_business_name_refused_as_an_application():
    """"web" is a family, not a product: accepting it as an application would
    bypass the closed vocabulary through the back door."""
    assert routing._validate("application", "web", {"web"}) is not None


def test_invalid_shapes():
    for suffix in ("", "a", "Web", "web-proxy", "proxy2", "x" * 21):
        assert routing._validate("generic", suffix, set()) is not None


def test_suffixes_reserved_by_the_stack():
    """`wazuh-alerts-*` or `wazuh-monitoring-*` already exist: a homonymous
    index set would swallow their content."""
    for suffix in ("alerts", "monitoring", "statistics", "ai", "voc"):
        assert routing._validate("generic", suffix, set()) is not None


def test_unknown_is_not_a_name():
    assert routing._validate("unknown", "", set()) is not None


def test_fallback_stays_deterministic_and_compliant():
    r = routing._fallback({"criterion_value": "npm-access"}, "pattern")
    assert r["index_base"] == "wazuh-npmaccess"
    assert r["named_by"] == "fallback"      # -> never auto-applied


# --------------------------------------------------------------------------
# Pipeline rendering
# --------------------------------------------------------------------------

ROUTES = [
    {"criterion_type": "decoder", "criterion_value": "npm-access",
     "index_base": "wazuh-proxy"},
    {"criterion_type": "groups", "criterion_value": "adguard",
     "index_base": "wazuh-dns"},
]


def test_learned_script_tests_decoder_before_groups():
    """The decoder identifies the source, the group only characterizes it. A
    Suricata alert carrying the `dns` group must go to the firewall — this is
    the trap the static routing already documents."""
    src = routing._learned_script(ROUTES)["script"]["source"]
    assert src.index("dn == 'npm-access'") < src.index("g.contains('adguard')")


def test_rendering_stable_byte_for_byte():
    """Two identical renders must produce NO difference: reconciliation
    compares the expected pipeline to the running one, and the slightest
    instability (order, spacing) would trigger a PUT every two minutes, on
    the pipeline that carries every SOC alert."""
    a = json.dumps(routing._learned_script(ROUTES), sort_keys=True)
    b = json.dumps(routing._learned_script(list(ROUTES)), sort_keys=True)
    assert a == b


def test_non_compliant_values_refused_before_generating_painless():
    """These values come from indexed data and end up in a quoted string in
    the middle of a script executed by the indexer."""
    for bad in ("npm'access", "a b", "x" * 65, "év", ""):
        with pytest.raises(ValueError):
            routing._learned_script([{"criterion_type": "decoder",
                                     "criterion_value": bad,
                                     "index_base": "wazuh-proxy"}])


def test_non_compliant_index_base_refused():
    with pytest.raises(ValueError):
        routing._learned_script([{"criterion_type": "decoder",
                                 "criterion_value": "npm-access",
                                 "index_base": "something-else"}])


PIPELINE = {
    "description": "Wazuh alerts pipeline",
    "processors": [
        {"json": {"field": "message", "add_to_root": True}},
        {"script": {"tag": "routing-static", "source": "..."}},
        {"script": {"description": "YARITRUST", "source": "..."}},
    ],
    "on_failure": [{"drop": {}}],
}


def test_insertion_after_static_routing():
    """Counter-intuitive, and verified on the prod pipeline: painless's
    `return` only exits the current script, not the pipeline. A learned
    branch placed BEFORE the static routing does write `ctx._index`, then the
    static script overwrites it right after — with no error at all. Measured
    on 2026-08-14: `pam -> wazuh-endpoint` kept landing back in
    wazuh-linux."""
    rendered = routing.render(PIPELINE, ROUTES)
    tags = [next(iter(p.values())).get("tag") for p in rendered["processors"]]
    assert tags.index(routing.TAG_LEARNED) > tags.index(routing.TAG_STATIC)
    assert len(rendered["processors"]) == len(PIPELINE["processors"]) + 1


def test_yara_script_keeps_the_last_word():
    """It is deliberately the last processor of the pipeline: YARA matches go
    out into wazuh-yara-* regardless of the source that produced them."""
    rendered = routing.render(PIPELINE, ROUTES)
    last = next(iter(rendered["processors"][-1].values()))
    assert "YARITRUST" in last["description"]


def test_insertion_falls_back_to_the_description():
    """Prod may still be running a pipeline that predates the tag."""
    no_tag = {**PIPELINE, "processors": [
        {"json": {}},
        {"script": {"description": "Aura-SOC: routes the agent alerts ..."}},
    ]}
    assert routing._insert_position(no_tag["processors"]) == 2


def test_refuses_to_insert_blindly():
    """No landmark found = no write. Inserting at random into the pipeline
    that carries every SOC alert cannot be undone."""
    with pytest.raises(RuntimeError):
        routing.render({"processors": [{"json": {}}]}, ROUTES)


def test_learned_processor_is_removable():
    """The baseline is the live pipeline MINUS our processor: that is what
    allows starting again from what filebeat actually pushed, without ever
    reading the file on disk."""
    rendered = routing.render(PIPELINE, ROUTES)
    assert routing._without_learned(rendered)["processors"] == PIPELINE["processors"]
    assert routing._without_learned(PIPELINE)["processors"] == PIPELINE["processors"]


# --------------------------------------------------------------------------
# Simulation
# --------------------------------------------------------------------------

def test_message_puts_back_the_prefix_erased_at_indexing():
    """`date_index_name` reads `fields.index_prefix` and it is the ONLY
    processor of the pipeline with `ignore_failure: false`: without this
    field, every simulated document goes into the `on_failure` `drop` and
    every witness comes back "lost". The field is erased by a `remove` before
    writing, so it is in no indexed document and cannot come from the
    witness."""
    m = routing._message({"timestamp": "2026-08-14T10:00:00.000+0000"})
    assert m["fields"]["index_prefix"] == routing.DEFAULT_PREFIX
    already = {"fields": {"index_prefix": "other-"}}
    assert routing._message(already)["fields"]["index_prefix"] == "other-"


def test_simulation_with_no_witness_blocks_nothing():
    assert routing.simulate({}, []) == []


def test_reading_a_simulation(monkeypatch):
    """Three verdicts to distinguish: routed as expected, routed elsewhere
    (the regression being hunted), and document lost (invalid painless)."""
    response = {
        "docs": [
            {"doc": {"_index": "wazuh-proxy-2026.08.14"}},
            {"doc": {"_index": "wazuh-alerts-4.x-2026.08.14"}},
            {"error": {"reason": "compile error"}},
        ]
    }

    class Fake:
        ok = True

        @staticmethod
        def json():
            return response

    monkeypatch.setattr(routing, "_indexer", lambda *a, **k: Fake())
    cases = [{"source_key": "decoder:npm-access", "index_base": "wazuh-proxy",
            "example": {}},
           {"source_key": "decoder:jellyfin", "index_base": "wazuh-jellyfin",
            "example": {}},
           {"source_key": "groups:adguard", "index_base": "wazuh-dns",
            "example": {}}]
    failures = routing.simulate({}, cases)
    assert len(failures) == 2
    assert "expected wazuh-jellyfin, got wazuh-alerts-4.x" in failures[0]
    assert "LOST" in failures[1]


def test_base_index_strips_the_date():
    assert routing._base_index("wazuh-linux-2026.08.14") == "wazuh-linux"
    assert routing._base_index("wazuh-voc-vulns") == "wazuh-voc-vulns"


# --------------------------------------------------------------------------
# What is not a log source
# --------------------------------------------------------------------------

def test_cross_cutting_noise_is_not_a_source():
    """FIM, SCA, rootcheck and agent state produce ~1,800 alerts a day in the
    default index, across ALL agents. Without this whitelist, the module
    would propose creating an index for them on the very first pass."""
    for d in ("ossec", "rootcheck", "sca", "wazuh"):
        assert d in routing.DECODERS_CROSS_CUTTING
    for g in ("syscheck", "sca", "virustotal", "vulnerability-detector"):
        assert g in routing.GROUPS_CROSS_CUTTING


def test_windows_eventchannel_is_not_treated_as_ambiguous():
    """Its alerts carry dozens of groups that would each become a false
    source for a single index — they are already routed by OS."""
    assert "windows_eventchannel" not in routing.DECODERS_AMBIGUOUS
    assert "json" in routing.DECODERS_AMBIGUOUS


# --------------------------------------------------------------------------
# Configuration guardrails
# --------------------------------------------------------------------------

def test_creation_cap_is_low():
    """Ten index sets created the same day is not ten index sets that are
    needed: it is a human who should look at what just changed in the
    estate."""
    assert 1 <= config.ROUTING_MAX_NEW_PER_DAY <= 3


def test_silence_threshold_is_in_days_not_minutes():
    """A log source is not a continuous sensor: a proxy may log nothing
    alertable for a whole night."""
    assert config.ROUTING_SILENCE_HOURS >= 24
