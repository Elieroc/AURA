"""CTI: IOC extraction from public articles.

The LLM is not tested here (it is called for real, or not at all): what is
covered is everything that SURROUNDS it, and that is where the quality of the
produced intelligence is decided:

- `test_ioc_invented_by_the_model_is_rejected`: the one failure mode that
  would fabricate indicators out of thin air. An IOC absent from the source
  text must be dropped, not discussed;
- `test_defanging_*`: without rewriting neutralised IOCs (hxxp, [.]), almost
  everything these sources publish stays invisible — the extraction would
  look like it works while never finding anything;
- `test_media_domain_never_kept` and the IP exclusions: a false IOC at level
  12 makes normal traffic alert, and the SOC's own IP as an IOC would make
  the SOC act against itself.
"""

import json
from datetime import datetime, timezone

import pytest

from soc_agent import cti, cti_articles as ca


# --- Defanging and candidates ------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("hxxp://evil.example/payload", "http://evil.example/payload"),
    ("hxxps://evil.example", "https://evil.example"),
    ("evil[.]com", "evil.com"),
    ("evil(.)com", "evil.com"),
    ("evil[dot]com", "evil.com"),
    ("192.0.2.1[:]8080", "192.0.2.1:8080"),
    ("contact[at]evil.com", "contact@evil.com"),
])
def test_defanging(raw, expected):
    assert ca.defanger(raw) == expected


def test_candidates_find_defanged_iocs():
    text = ("The loader contacts hxxp://malicious-c2[.]top/gate.php and "
             "resolves second-stage[.]xyz from 203.0.113.9, dropping a file "
             "with SHA256 " + "ab" * 32 + ".")
    found = ca.candidates(text)
    assert "http://malicious-c2.top/gate.php" in found["url"]
    assert "second-stage.xyz" in found["domain"]
    assert "ab" * 32 in found["hash"]
    # 203.0.113.0/24 is the DOCUMENTATION network (RFC 5737): reports use it
    # to illustrate without exposing a real target.
    assert "203.0.113.9" not in found["ip"]


def test_media_domain_never_kept():
    text = ("As reported by bleepingcomputer.com and confirmed on github.com, "
             "the group used real-c2-server.top for command and control.")
    found = ca.candidates(text)
    assert "real-c2-server.top" in found["domain"]
    assert not {"bleepingcomputer.com", "github.com"} & set(found["domain"])


def test_subdomain_of_a_media_outlet_excluded_too():
    # The exclusion is by SUFFIX: without that, it would only hold on the
    # bare domain and any CDN of the outlet would slip back in.
    found = ca.candidates("see cdn.bleepingcomputer.com and unit42.paloaltonetworks.com")
    assert found["domain"] == []


def test_private_ip_and_soc_infra_excluded(monkeypatch):
    monkeypatch.setattr(cti_config := ca.config, "SOC_INFRA_IPS", {"51.15.1.2"})
    assert cti_config.SOC_INFRA_IPS  # the test's own guardrail
    found = ca.candidates("hosts 10.0.0.5, 127.0.0.1, 51.15.1.2 and 45.77.1.9")
    assert found["ip"] == ["45.77.1.9"]


def test_plain_text_strips_scripts_and_tags():
    html_source = ("<html><head><script>var c2='fake-c2.top';</script></head>"
                   "<body><p>Real IOC: bad-domain.xyz</p>"
                   "<nav><a href='https://twitter.com/x'>x</a></nav></body></html>")
    text = ca.plain_text(html_source)
    # The content of <script> is code, not article text: any domain in it is
    # a page artefact.
    assert "fake-c2.top" not in text
    assert "bad-domain.xyz" in text


def test_truncate_keeps_the_start_and_the_end():
    # The "Indicators of Compromise" section is almost always at the END of
    # the body: a truncation that only kept the start would lose it
    # systematically.
    text = "START" + "x" * 50000 + "END"
    cut = ca.truncate(text, 1000)
    assert cut.startswith("START") and cut.endswith("END")
    assert len(cut) < 1200


# --- Validating the model's output -------------------------------------------

FOUND = {"ip": ["45.77.1.9"], "domain": ["bad-domain.xyz"], "url": [], "hash": []}


def test_ioc_invented_by_the_model_is_rejected():
    response = {"iocs": [
        {"value": "bad-domain.xyz", "type": "domain", "role": "C2"},
        # Never seen in the text: the model made it up.
        {"value": "invented-by-the-model.com", "type": "domain", "role": "C2"},
    ]}
    kept = ca.validate(response, FOUND)
    assert [i["value"] for i in kept] == ["bad-domain.xyz"]


def test_announced_type_wrong_is_corrected_from_the_value():
    # The announced type is not trusted: the value decides.
    kept = ca.validate(
        {"iocs": [{"value": "45.77.1.9", "type": "domain", "role": "C2"}]}, FOUND)
    assert kept[0]["type"] == "ip"


def test_duplicates_dropped():
    response = {"iocs": [{"value": "45.77.1.9", "type": "ip", "role": "C2"},
                        {"value": "45.77.1.9", "type": "ip", "role": "C2 again"}]}
    assert len(ca.validate(response, FOUND)) == 1


def test_empty_or_malformed_output_does_not_break_anything():
    assert ca.validate({}, FOUND) == []
    assert ca.validate({"iocs": None}, FOUND) == []
    assert ca.validate({"iocs": ["not an object"]}, FOUND) == []


# --- Batching -----------------------------------------------------------------

def test_batches_bounded_by_max_batches():
    found = {"ip": [f"45.77.1.{n}" for n in range(1, 255)],
               "domain": [], "url": [], "hash": []}
    batches = ca._batches(found)
    assert len(batches) <= ca.MAX_BATCHES
    assert all(len(batch) <= ca.BATCH_CANDIDATES for batch in batches)


def test_arbitration_survives_a_failed_batch(monkeypatch, tmp_path):
    # Measured for real: on a digest of 403 candidates, several batches
    # failed (budget exhausted by reasoning, network cut) and 148 valid IOCs
    # were still recovered. Without this tolerance: zero.
    calls = {"n": 0}

    def _completion(system, user, usage, max_tokens=0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("API timeout")
        return {"iocs": [{"value": "bad-domain.xyz", "type": "domain",
                          "role": "C2"}], "threat": "TestCampaign",
                "summary": "r", "confidence": "haute"}, {}

    monkeypatch.setattr(ca.llm, "completion", _completion)
    monkeypatch.setattr(ca, "BATCH_CANDIDATES", 1)
    article = {"url": "https://example/report", "title": "T", "text": "text",
               "context": ""}
    merge = ca.arbitrate(article, {"ip": ["45.77.1.9"],
                                   "domain": ["bad-domain.xyz"],
                                   "url": [], "hash": []})
    assert [i["value"] for i in merge["iocs"]] == ["bad-domain.xyz"]
    assert merge["threat"] == "TestCampaign"


def test_oversized_batch_gets_split(monkeypatch):
    # Exhausted budget is not a definitive failure: the batch is replayed in
    # two halves. Oversizing the budget of EVERY call for the rare ones that
    # overflow would cost far more.
    seen = []

    def _completion(system, user, usage, max_tokens=0):
        batch_candidates = user.split("CANDIDATS")[1]
        n = batch_candidates.count(".")
        seen.append(n)
        if n > 3:
            raise RuntimeError("no content in response (finish_reason=length, ...)")
        return {"iocs": [], "threat": "", "summary": "", "confidence": ""}, {}

    monkeypatch.setattr(ca.llm, "completion", _completion)
    monkeypatch.setattr(ca, "BATCH_CANDIDATES", 8)
    ca.arbitrate({"url": "u", "title": "t", "text": "x", "context": ""},
                {"ip": [f"45.77.1.{n}" for n in range(1, 9)],
                 "domain": [], "url": [], "hash": []})
    # The first call (whole batch) fails, then two calls on the halves.
    assert len(seen) >= 3


# --- MISP publication ---------------------------------------------------------

def test_event_carries_the_tag_that_downgrades_confidence(monkeypatch):
    sent = {}

    def _misp(method, path, body=None):
        sent.update({"method": method, "path": path, "body": body})
        return {"Event": {"id": "77"}}

    monkeypatch.setattr(cti, "_misp", _misp)
    article = {"url": "https://example/report", "title": "Report",
               "published": datetime(2026, 8, 12, tzinfo=timezone.utc), "context": ""}
    iocs = [{"value": "bad-domain.xyz", "type": "domain", "role": "C2 server"},
            {"value": "ab" * 32, "type": "hash", "role": "payload"}]
    event_id = ca.create_event(article, iocs, {"threat": "TestCampaign",
                                                  "summary": "r",
                                                  "confidence": "haute"},
                                  {"name": "thehackernews"})
    assert event_id == 77
    event = sent["body"]["Event"]
    tags = {t["name"] for t in event["Tag"]}
    # WITHOUT this tag, cti.py would classify the IOC as `curated`: an
    # automatic extraction from an article would fire at the same level as a
    # CERT-FR IOC.
    assert cti.TAG_EXTRACTION in tags
    assert "aura:feed:thehackernews" in tags
    # The link to the article is the first attribute: it is what lets one
    # judge whether the extraction was warranted.
    assert event["Attribute"][0]["type"] == "link"
    assert event["Attribute"][0]["value"] == "https://example/report"
    assert event["published"] is True
    types = {a["type"] for a in event["Attribute"][1:]}
    assert types == {"domain", "sha256"}
    assert all(a["to_ids"] for a in event["Attribute"][1:])


def test_extraction_tag_correctly_downgrades_confidence_on_reread(monkeypatch):
    """Full loop: the tag set here must be read back correctly by cti.py."""
    attributes = [{
        "type": "domain", "value": "bad-domain.xyz", "category": "Network activity",
        "event_id": "77", "to_ids": True,
        "Event": {"info": "[AURA/thehackernews] TestCampaign",
                  "threat_level_id": "2", "date": "2026-08-12",
                  "Orgc": {"name": "AURA"}},
        "Tag": [{"name": cti.TAG_EXTRACTION}, {"name": "tlp:clear"}],
    }]
    pages = [{"response": {"Attribute": attributes}}, {"response": {"Attribute": []}}]
    monkeypatch.setattr(cti, "_misp",
                        lambda m, c, body=None: pages.pop(0) if pages else
                        {"response": {"Attribute": []}})
    iocs = list(cti.misp_attributes())
    assert iocs[0]["confidence"] == cti.CONFIDENCE_EXTRACTED


def test_unreachable_warninglists_drop_nothing(monkeypatch):
    def _misp(*a, **k):
        raise RuntimeError("MISP unavailable")
    monkeypatch.setattr(cti, "_misp", _misp)
    # Filter nothing rather than drop everything: the loss would be invisible.
    assert ca.filter_warninglists(["bad-domain.xyz"]) == set()


def test_warninglists_drop_what_misp_knows(monkeypatch):
    monkeypatch.setattr(cti, "_misp", lambda m, c, body=None: {
        "1.1.1.1": ["List of known public DNS resolvers"], "bad-domain.xyz": []})
    assert ca.filter_warninglists(["1.1.1.1", "bad-domain.xyz"]) == {"1.1.1.1"}


# --- Sources ------------------------------------------------------------------

def test_shipped_catalog_declares_the_four_sources():
    names = {s["name"] for s in ca.sources()}
    assert names == {"thehackernews", "bleepingcomputer", "rst-cloud", "malpedia"}


def test_malpedia_only_returns_new_urls(monkeypatch):
    response = {"references": {
        "https://known-report/a.pdf": [{"type": "family", "common_name": "Emotet"}],
        "https://new-report/b.html": [{"type": "family", "common_name": "Qakbot"},
                                        {"type": "actor", "common_name": "TA577"}],
    }}

    class R:
        def json(self):
            return response

    monkeypatch.setattr(ca, "_http", lambda url: R())
    entries = ca.malpedia_entries({"name": "malpedia", "url": "u"},
                                  {"https://known-report/a.pdf"})
    assert [e["url"] for e in entries] == ["https://new-report/b.html"]
    # The attribution is Malpedia's own value: it goes to the model as
    # context, no article gives it on its own.
    assert entries[0]["context"] == "Qakbot, TA577"


def test_rss_date_real_formats():
    assert ca._rss_date("Tue, 12 Aug 2026 10:30:00 +0000").year == 2026
    assert ca._rss_date("2026-08-12T10:30:00Z").month == 8
    assert ca._rss_date("not a date at all") is None


def test_bootstrap_does_not_burn_the_rss_feeds(monkeypatch):
    # Bootstrapping only exists for sources WITHOUT a date (Malpedia). Marking
    # an RSS feed along the way would condemn its recent articles — exactly
    # the ones we want to process on the first real pass. Observed in
    # production on 2026-08-12: 40 articles lost on the first bootstrap.
    monkeypatch.setattr(ca, "rss_entries",
                        lambda source, since: [{"url": "https://new", "title": "t",
                                                 "published": None, "content": "",
                                                 "context": ""}])
    rss = ca.collect({"name": "thehackernews", "type": "rss"}, set(),
                       datetime.now(timezone.utc), 10, True, True)
    assert rss == []

    monkeypatch.setattr(ca, "malpedia_entries",
                        lambda source, already: [{"url": "https://report", "title": "",
                                               "published": None, "content": "",
                                               "context": "Emotet"}])
    malpedia = ca.collect({"name": "malpedia", "type": "malpedia_references"},
                            set(), datetime.now(timezone.utc), 10, True, True)
    assert [r["pattern"] for r in malpedia] == ["bootstrap"]
