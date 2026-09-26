"""Train and evaluate a reproducible, explainable baseline e-mail TEXT model.

    python scripts/email_dataset/train_email_baseline.py [--include-spam-as-positive] [--max-per-source 20000]

Refuses to run unless audited/audit_summary.json lists real tables.
Positive class = phishing + fraud_scam (see LABEL_MAPPING.md); spam is excluded by default.
Evaluation = GroupKFold over near-duplicate template groups (campaign-aware) + a
leave-one-ham-source-out false-positive check (source-shift). Outputs:
  model/email_intelligence/email_text_model.pkl + email_model_card.json
  datasets/email_intelligence/{deduplicated,splits,features}/...
  datasets/email_intelligence/reports/MODEL_EVALUATION_REPORT.md
The model is loaded by the app ONLY if both the .pkl and the card exist."""
import argparse
import json
import os
import re
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import Pipeline

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import ROOT, RAW, EXTRACTED, AUDITED, REPORTS, DEDUP, SPLITS, FEATURES, now, log_step  # noqa: E402
from audit_datasets import near_key, read_table  # noqa: E402

MODEL_DIR = os.path.join(ROOT, "model", "email_intelligence")
POS_SOURCES = {"nazario": "phishing", "nigerian": "fraud_scam"}
SPAM_SOURCES = ("enron", "ling", "spamassassin", "trec", "ceas")
EXCLUDE = ("merged_dataset", "balanced_dataset")


def map_label(stem, y):
    s = stem.lower()
    if any(x in s for x in EXCLUDE):
        return None
    try:
        y = int(float(y))
    except Exception:
        return None
    if y == 0:
        return "legitimate"
    for k, v in POS_SOURCES.items():
        if k in s:
            return v
    if any(k in s for k in SPAM_SOURCES):
        return "spam"
    return None  # undocumented source/label → not used


def metrics(y, p, thr=0.5):
    yhat = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    return {"precision": precision_score(y, yhat, zero_division=0), "recall": recall_score(y, yhat, zero_division=0),
            "f1": f1_score(y, yhat, zero_division=0), "roc_auc": roc_auc_score(y, p) if len(set(y)) > 1 else None,
            "pr_auc": average_precision_score(y, p) if len(set(y)) > 1 else None,
            "false_positive_rate": fp / (fp + tn) if (fp + tn) else None, "false_negative_rate": fn / (fn + tp) if (fn + tp) else None,
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]], "n": int(len(y))}


def build_pipeline():
    return Pipeline([("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=3, max_df=0.9, max_features=100000,
                                               sublinear_tf=True, strip_accents="unicode")),
                     ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced"))])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-spam-as-positive", action="store_true")
    ap.add_argument("--max-per-source", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    summ_path = os.path.join(AUDITED, "audit_summary.json")
    if not os.path.exists(summ_path):
        sys.exit("REFUSED: run audit_datasets.py first (no audited/audit_summary.json).")
    summary = json.load(open(summ_path))
    tables = [t for t in summary.get("tables", []) if t.get("label_column") and t.get("body_column")]
    if not tables:
        sys.exit("REFUSED: the audit lists no labelled text tables. Download datasets and re-run the audit.")

    frames = []
    for t in tables:
        path = os.path.join(RAW, t["file"])
        if not os.path.exists(path):
            path = os.path.join(EXTRACTED, t["file"]) if os.path.exists(os.path.join(EXTRACTED, t["file"])) else None
        if not path:
            continue
        df = read_table(path)
        stem = os.path.basename(t["file"])
        subj = df[[c for c in df.columns if str(c).lower() == "subject"][0]].fillna("").astype(str) if any(str(c).lower() == "subject" for c in df.columns) else ""
        text = (subj + "\n" if isinstance(subj, pd.Series) else "") + df[t["body_column"]].fillna("").astype(str)
        out = pd.DataFrame({"text": text, "orig_label": df[t["label_column"]], "source_file": stem})
        out["mapped"] = [map_label(stem, y) for y in out["orig_label"]]
        frames.append(out.head(a.max_per_source * 3))
    data = pd.concat(frames, ignore_index=True)
    before = len(data)
    data = data[data["mapped"].notna() & (data["text"].str.strip().str.len() > 20)]
    positives = {"phishing", "fraud_scam"} | ({"spam"} if a.include_spam_as_positive else set())
    data = data[data["mapped"].isin(positives | {"legitimate"})].copy()
    data["y"] = data["mapped"].isin(positives).astype(int)
    data["group"] = data["text"].map(near_key)
    # exact + near-duplicate removal: keep one row per (template group, label)
    dd = data.drop_duplicates(subset=["group", "y"])
    conflicting = dd.groupby("group")["y"].nunique()
    dd = dd[~dd["group"].isin(conflicting[conflicting > 1].index)]
    dd = dd.sample(frac=1.0, random_state=a.seed).groupby("source_file").head(a.max_per_source).reset_index(drop=True)
    os.makedirs(DEDUP, exist_ok=True)
    dd[["source_file", "orig_label", "mapped", "y", "group"]].to_csv(os.path.join(DEDUP, "training_index.csv"), index=False)
    log_step("dedupe+map", sorted(data["source_file"].unique().tolist()), "Label mapping per LABEL_MAPPING.md; drop empty; near-duplicate & conflicting-label removal",
             rows_before=before, rows_after=len(dd), removed={"unmapped_or_empty": before - len(data), "duplicates_or_conflicts": len(data) - len(dd)},
             outputs=["deduplicated/training_index.csv"], code="scripts/email_dataset/train_email_baseline.py")
    if dd["y"].nunique() < 2:
        sys.exit("REFUSED: after mapping, only one class remains — cannot train a meaningful model.")

    X, y, groups = dd["text"].values, dd["y"].values, dd["group"].values
    oof = np.zeros(len(dd))
    gkf = GroupKFold(n_splits=5)
    fold_ids = np.zeros(len(dd), dtype=int)
    for k, (tr, te) in enumerate(gkf.split(X, y, groups)):
        m = build_pipeline().fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
        fold_ids[te] = k
    os.makedirs(SPLITS, exist_ok=True)
    pd.DataFrame({"group": groups, "fold": fold_ids}).to_csv(os.path.join(SPLITS, "groupkfold_assignments.csv"), index=False)
    overall = metrics(y, oof)
    per_source = {}
    for s, g in dd.assign(p=oof).groupby("source_file"):
        per_source[s] = metrics(g["y"].values, g["p"].values)
    # source-shift: hold out each ham source entirely
    shift = {}
    ham_sources = sorted(dd.loc[dd["y"] == 0, "source_file"].unique())
    for hs in ham_sources:
        te = (dd["source_file"] == hs) & (dd["y"] == 0)
        tr = ~(dd["source_file"] == hs)
        if te.sum() < 50 or dd.loc[tr, "y"].nunique() < 2:
            continue
        m = build_pipeline().fit(X[tr.values], y[tr.values])
        p = m.predict_proba(X[te.values])[:, 1]
        shift[hs] = {"held_out_ham": int(te.sum()), "false_positive_rate": float((p >= 0.5).mean())}

    final = build_pipeline().fit(X, y)
    vocab = final.named_steps["tfidf"].get_feature_names_out()
    coefs = final.named_steps["clf"].coef_[0]
    top_pos = [vocab[i] for i in np.argsort(coefs)[-25:][::-1]]
    top_neg = [vocab[i] for i in np.argsort(coefs)[:25]]
    os.makedirs(FEATURES, exist_ok=True)
    with open(os.path.join(FEATURES, "text_model_top_terms.json"), "w", encoding="utf-8") as f:
        json.dump({"top_positive_terms": top_pos, "top_negative_terms": top_neg}, f, indent=2)

    version = "email-text-lr-" + now()[:10]
    card = {"model_version": version, "trained_at": now(), "positive_class": "+".join(sorted(positives)),
            "training_sources": sorted(dd["source_file"].unique().tolist()), "rows": int(len(dd)),
            "class_balance": {"positive": int(y.sum()), "negative": int((1 - y).sum())},
            "evaluation": "5-fold GroupKFold over near-duplicate template groups (out-of-fold)",
            "headline_metrics": {k: (round(v, 4) if isinstance(v, float) else v) for k, v in overall.items()},
            "per_source": per_source, "source_shift_false_positive_rates": shift,
            "limitations": ["Text-only: no headers, links or attachments.", "Corpora are 1998–2008 era; modern phishing differs.",
                            "Positive and negative examples come from different collections, so the model may learn source style."]}
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(final, os.path.join(MODEL_DIR, "email_text_model.pkl"))
    with open(os.path.join(MODEL_DIR, "email_model_card.json"), "w", encoding="utf-8") as f:
        json.dump(card, f, indent=2, default=float)

    R = ["# MODEL_EVALUATION_REPORT — Email text baseline", "", f"Model: `{version}` · TF-IDF (1–2 grams) + L2 logistic regression, class-balanced", "",
         f"Training rows after mapping/dedup: {len(dd):,} (positive {int(y.sum()):,} / negative {int((1 - y).sum()):,})",
         f"Positive class: {card['positive_class']} · Sources: {', '.join(card['training_sources'])}", "",
         "## Out-of-fold (GroupKFold, campaign-aware)", "", "| Metric | Value |", "|---|---|"]
    R += [f"| {k} | {v if not isinstance(v, float) else round(v, 4)} |" for k, v in overall.items()]
    R += ["", "## Per source (out-of-fold)", "", "| Source | n | precision | recall | F1 | FPR |", "|---|---|---|---|---|---|"]
    fmt = lambda v: "n/a" if v is None else f"{v:.3f}"
    for s_, m in per_source.items():
        single = m["confusion_matrix"][1] == [0, 0] or m["confusion_matrix"][0] == [0, 0]
        R.append(f"| {s_} | {m['n']} | {'n/a (one class)' if single else fmt(m['precision'])} | {'n/a' if single else fmt(m['recall'])} | "
                 f"{'n/a' if single else fmt(m['f1'])} | {fmt(m['false_positive_rate'])} |")
    R += ["", "## Source-shift check (held-out ham source)", ""] + ([f"- {s}: FPR {v['false_positive_rate']:.3f} on {v['held_out_ham']} held-out ham" for s, v in shift.items()] or ["- not enough data"])
    R += ["", "## Limitations", ""] + [f"- {x}" for x in card["limitations"]] + ["- These are offline benchmark numbers, not real-world accuracy.", ""]
    open(os.path.join(REPORTS, "MODEL_EVALUATION_REPORT.md"), "w", encoding="utf-8").write("\n".join(R))
    log_step("train", card["training_sources"], "Train TF-IDF+LR; GroupKFold evaluation; source-shift check",
             outputs=["model/email_intelligence/email_text_model.pkl", "model/email_intelligence/email_model_card.json", "reports/MODEL_EVALUATION_REPORT.md"])
    print(json.dumps(card["headline_metrics"], indent=2, default=float))


if __name__ == "__main__":
    main()
