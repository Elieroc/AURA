"""Measuring triage accuracy against human labels.

This report is what authorises — or not — leaving shadow mode. As long as the
number of labelled incidents stays low, it says so explicitly rather than
showing a flattering percentage computed on three cases.

Two measurements, of a different nature:

- **Accuracy**: does the verdict match the human label? Requires labels, hence
  analyst work.
- **Consistency**: does the model contradict itself between its verdict and its
  actions? Measurable **without labels**, over every triage. That is the warning
  signal available immediately, in particular after a prompt change.

    python -m soc_agent.evaluate

The computation lives in `report()`, which returns a dict; `show()` only
formats it (see report.py, same split, same reasons).
"""

import psycopg
from psycopg.rows import dict_row

from . import config

# Below this, an accuracy rate has no statistical meaning. The threshold is
# arbitrary but explicit: better refuse to conclude than produce a "100 %"
# computed on four incidents.
MINIMUM_USEFUL = 30

# Last triage per incident: earlier passes reflect prompts we have abandoned.
LAST = """
    SELECT DISTINCT ON (incident_id) *
      FROM triages ORDER BY incident_id, created_at DESC
"""


def report() -> dict:
    """Triage consistency and accuracy, as raw data.

    Keys always present: `n_triages`, `consistency`, `accuracy`. `consistency`
    and `accuracy` are `None` when the measurement makes no sense (no triage, no
    label) — that is a refusal to conclude, not a zero.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        n_triages = conn.execute("SELECT count(*) n FROM triages").fetchone()["n"]
        if not n_triages:
            return {"n_triages": 0, "consistency": None, "accuracy": None}

        lines = conn.execute(LAST).fetchall()
        inconsistent = [r for r in lines if r["inconsistencies"]]
        consistency = {
            "n_last_triages": len(lines),
            "n_inconsistent": len(inconsistent),
            "inconsistent_pct": 100 * len(inconsistent) / len(lines),
            "inconsistent": [
                {"incident_id": r["incident_id"], "patterns": r["inconsistencies"]}
                for r in inconsistent
            ],
            "models": [
                {"model": m["model"], "n": m["n"],
                 "mean_duration_s": float(m["s"]),
                 "mean_prompt_tokens": float(m["tok"])}
                for m in conn.execute(
                    f"SELECT model, count(*) n, avg(duration_ms)/1000 s, "
                    f"avg(prompt_tokens) tok FROM ({LAST}) d GROUP BY model")
            ],
        }

        matched = conn.execute(f"""
            SELECT d.incident_id, d.verdict AS model, d.actions AS model_actions,
                   l.verdict AS human, l.actions AS human_actions, l.origin
              FROM ({LAST}) d
              JOIN labels l ON l.incident_id = d.incident_id
        """).fetchall()
        n_incidents = conn.execute(
            "SELECT count(*) n FROM incidents").fetchone()["n"]

    if not matched:
        return {"n_triages": n_triages, "consistency": consistency,
                "accuracy": {"n_labelled": 0, "n_incidents": n_incidents,
                             "rate_pct": None, "disagreements": [],
                             "tp_marked_fp": 0, "conclusion": "no_label"}}

    correct = [r for r in matched if r["model"] == r["human"]]
    rate = len(correct) / len(matched)
    # A false positive labelled true positive wastes time; the other way round
    # lets an intrusion through. The two errors do not cost the same.
    misses = [r for r in matched
              if r["human"] == "true_positive" and r["model"] == "false_positive"]

    if len(matched) < MINIMUM_USEFUL:
        conclusion = "sample_too_small"
    elif rate < 0.9:
        conclusion = "shadow"
    else:
        conclusion = "automatable"

    return {
        "n_triages": n_triages,
        "consistency": consistency,
        "accuracy": {
            "n_labelled": len(matched),
            "n_incidents": n_incidents,
            "n_correct": len(correct),
            "rate_pct": 100 * rate,
            "minimum_useful": MINIMUM_USEFUL,
            "disagreements": [
                {"incident_id": r["incident_id"], "model": r["model"],
                 "human": r["human"]}
                for r in matched if r["model"] != r["human"]
            ],
            "tp_marked_fp": len(misses),
            "conclusion": conclusion,
        },
    }


CONCLUSIONS = {
    "no_label": None,  # handled separately: it needs the incident count
    "sample_too_small":
        "  SAMPLE TOO SMALL ({n} < {mini}). The percentage above has no "
        "statistical value.\n  Stay in shadow mode.",
    "shadow": "  Accuracy below 90 %: stay in shadow mode.",
    "automatable":
        "  Accuracy good enough on a usable sample.\n"
        "  Automation can be enabled, per configurable autonomy level — once "
        "active, actions fire on their own (no human validation per action).",
}


def show(r: dict) -> None:
    if not r["n_triages"]:
        print("No triage recorded — run soc_agent.triage.")
        return

    c = r["consistency"]
    print("=" * 68)
    print("CONSISTENCY  (label-free — available immediately)")
    print("=" * 68)
    print(f"  Triages (last per incident) : {c['n_last_triages']}")
    print(f"  Inconsistent outputs        : {c['n_inconsistent']} "
          f"({c['inconsistent_pct']:.0f} %)")
    for i in c["inconsistent"]:
        print(f"    #{i['incident_id']} : {'; '.join(i['patterns'])}")
    print()
    for m in c["models"]:
        print(f"  {m['model']} : {m['n']} triages, "
              f"{m['mean_duration_s']:.1f} s on average, "
              f"{m['mean_prompt_tokens']:.0f} prompt tokens")

    a = r["accuracy"]
    print()
    print("=" * 68)
    print("ACCURACY  (against human labels)")
    print("=" * 68)

    if a["conclusion"] == "no_label":
        print(f"  No labelled incident (out of {a['n_incidents']}).")
        print()
        print("  Accuracy cannot be measured. Label with:")
        print("    python -m soc_agent.label --list")
        print("    python -m soc_agent.label <id> --show")
        print("    python -m soc_agent.label <id> --verdict true_positive")
        return

    print(f"  Labelled incidents : {a['n_labelled']} / {a['n_incidents']}")
    print(f"  Correct verdicts   : {a['n_correct']}/{a['n_labelled']} "
          f"({a['rate_pct']:.0f} %)")
    if a["disagreements"]:
        print("\n  Disagreements:")
        for d in a["disagreements"]:
            print(f"    #{d['incident_id']} : model {d['model']}, "
                  f"human {d['human']}")
    if a["tp_marked_fp"]:
        print(f"\n  /!\\ {a['tp_marked_fp']} true positive(s) marked false "
              f"positive — that is the error which lets an intrusion through.")
    print()
    print(CONCLUSIONS[a["conclusion"]].format(
        n=a["n_labelled"], mini=a["minimum_useful"]))


def main() -> None:
    show(report())


if __name__ == "__main__":
    main()
