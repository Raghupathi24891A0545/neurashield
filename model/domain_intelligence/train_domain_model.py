"""
NEURASHIELD — DOMAIN INTELLIGENCE ML MODEL TRAINING
Evaluates multiple models, uses domain-level splits, prioritizes cybersecurity metrics.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report
)
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline


# ─── Feature columns for the domain model ────────────────────────────────────
DOMAIN_MODEL_FEATURES = [
    'dns_resolution', 'a_record_count', 'aaaa_record_count',
    'mx_record_count', 'ns_record_count', 'txt_record_count',
    'ip_count', 'has_mx', 'has_multiple_ips',
    'domain_age_days', 'domain_remaining_days',
    'registrar_present', 'expiration_available',
    'nameserver_count', 'nameserver_diversity',
    'ssl_available', 'ssl_valid',
    'certificate_age_days', 'certificate_remaining_days',
    'certificate_san_count', 'certificate_hostname_match',
    'certificate_is_wildcard',
    'tld_length', 'domain_name_length', 'domain_name_entropy',
    'domain_has_digits', 'domain_digit_ratio', 'domain_hyphen_count',
    'dns_collection_success', 'whois_collection_success', 'ssl_collection_success',
    'evidence_coverage',
]


def train_and_evaluate(dataset_path: str, output_dir: str) -> dict:
    """
    Train domain intelligence models, evaluate, and save the best one.
    """
    print(f"[DomainML] Loading dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)

    # Filter to labeled rows only
    df = df[df['label'].notna()].copy()
    df['label'] = df['label'].astype(int)
    print(f"[DomainML] Labeled rows: {len(df)}")
    print(f"[DomainML] Class distribution: {dict(df['label'].value_counts())}")

    # Available features (intersection with what's in the dataset)
    available_features = [f for f in DOMAIN_MODEL_FEATURES if f in df.columns]
    print(f"[DomainML] Available features: {len(available_features)}")

    X = df[available_features].copy()
    y = df['label'].copy()

    # Domain-level split: ensure no domain appears in both train and test
    domains = df['domain'].values
    unique_domains = df['domain'].unique()
    np.random.seed(42)
    np.random.shuffle(unique_domains)
    split_idx = int(len(unique_domains) * 0.8)
    train_domains = set(unique_domains[:split_idx])
    test_domains = set(unique_domains[split_idx:])

    train_mask = df['domain'].isin(train_domains)
    test_mask = df['domain'].isin(test_domains)

    X_train, X_test = X[train_mask], X[test_mask]
    y_train, y_test = y[train_mask], y[test_mask]

    print(f"[DomainML] Train: {len(X_train)} | Test: {len(X_test)}")
    print(f"[DomainML] Train domains: {len(train_domains)} | Test domains: {len(test_domains)}")

    # ─── Define Models ───────────────────────────────────────────────────
    models = {
        'LogisticRegression': Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(random_state=42, max_iter=1000, class_weight='balanced')),
        ]),
        'RandomForest': Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('clf', RandomForestClassifier(
                n_estimators=200, random_state=42, class_weight='balanced',
                max_depth=15, min_samples_leaf=5,
            )),
        ]),
        'HistGradientBoosting': Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('clf', HistGradientBoostingClassifier(
                random_state=42, max_iter=200, max_depth=8,
                learning_rate=0.1, class_weight='balanced',
            )),
        ]),
    }

    # ─── Cross-validation on training data ───────────────────────────────
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_results = {}

    for name, pipeline in models.items():
        print(f"\n[DomainML] Cross-validating: {name}")
        try:
            scores = cross_validate(
                pipeline, X_train, y_train, cv=cv,
                scoring=['accuracy', 'precision', 'recall', 'f1', 'roc_auc'],
                return_train_score=False,
            )
            cv_results[name] = {
                'accuracy': round(float(np.mean(scores['test_accuracy'])), 4),
                'precision': round(float(np.mean(scores['test_precision'])), 4),
                'recall': round(float(np.mean(scores['test_recall'])), 4),
                'f1': round(float(np.mean(scores['test_f1'])), 4),
                'roc_auc': round(float(np.mean(scores['test_roc_auc'])), 4),
            }
            print(f"  CV F1: {cv_results[name]['f1']}, AUC: {cv_results[name]['roc_auc']}")
        except Exception as e:
            print(f"  Error: {e}")
            cv_results[name] = {'error': str(e)}

    # ─── Select best model (by F1 — cybersecurity priority) ──────────────
    valid_models = {k: v for k, v in cv_results.items() if 'f1' in v}
    if not valid_models:
        print("[DomainML] ERROR: No models succeeded!")
        return {'error': 'All models failed'}

    best_name = max(valid_models, key=lambda k: valid_models[k]['f1'])
    print(f"\n[DomainML] Best model: {best_name} (F1={valid_models[best_name]['f1']})")

    # ─── Train best model on full training set ───────────────────────────
    best_pipeline = models[best_name]
    best_pipeline.fit(X_train, y_train)

    # ─── Evaluate on held-out test set ───────────────────────────────────
    y_pred = best_pipeline.predict(X_test)
    y_proba = None
    try:
        y_proba = best_pipeline.predict_proba(X_test)[:, 1]
    except Exception:
        pass

    test_metrics = {
        'accuracy': round(float(accuracy_score(y_test, y_pred)), 4),
        'precision': round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        'recall': round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        'f1': round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
    }

    if y_proba is not None:
        try:
            test_metrics['roc_auc'] = round(float(roc_auc_score(y_test, y_proba)), 4)
        except Exception:
            test_metrics['roc_auc'] = None
        try:
            test_metrics['pr_auc'] = round(float(average_precision_score(y_test, y_proba)), 4)
        except Exception:
            test_metrics['pr_auc'] = None

    cm = confusion_matrix(y_test, y_pred)
    test_metrics['confusion_matrix'] = cm.tolist()
    test_metrics['true_negatives'] = int(cm[0][0])
    test_metrics['false_positives'] = int(cm[0][1])
    test_metrics['false_negatives'] = int(cm[1][0])
    test_metrics['true_positives'] = int(cm[1][1])

    print(f"\n[DomainML] === Test Set Results ({best_name}) ===")
    print(f"  Accuracy:  {test_metrics['accuracy']}")
    print(f"  Precision: {test_metrics['precision']}")
    print(f"  Recall:    {test_metrics['recall']}")
    print(f"  F1:        {test_metrics['f1']}")
    print(f"  ROC-AUC:   {test_metrics.get('roc_auc', 'N/A')}")
    print(f"  PR-AUC:    {test_metrics.get('pr_auc', 'N/A')}")
    print(f"  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Phishing']))

    # ─── Feature Importance ──────────────────────────────────────────────
    feature_importance = {}
    try:
        clf = best_pipeline.named_steps.get('clf')
        if hasattr(clf, 'feature_importances_'):
            importances = clf.feature_importances_
            for feat, imp in sorted(zip(available_features, importances), key=lambda x: -x[1]):
                feature_importance[feat] = round(float(imp), 6)
        elif hasattr(clf, 'coef_'):
            coefs = clf.coef_[0]
            for feat, coef in sorted(zip(available_features, coefs), key=lambda x: -abs(x[1])):
                feature_importance[feat] = round(float(coef), 6)
    except Exception:
        pass

    # ─── Save Model ──────────────────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, 'domain_model.pkl')
    joblib.dump(best_pipeline, model_path)
    print(f"\n[DomainML] Model saved: {model_path}")

    # Save feature schema
    schema = {
        'features': available_features,
        'feature_count': len(available_features),
        'model_name': best_name,
        'model_version': '2.0.0',
        'training_timestamp': datetime.now().isoformat(),
        'training_samples': len(X_train),
        'test_samples': len(X_test),
    }
    schema_path = os.path.join(output_dir, 'feature_schema.json')
    with open(schema_path, 'w') as f:
        json.dump(schema, f, indent=2)

    # ─── Save Full Report ────────────────────────────────────────────────
    full_report = {
        'model_name': best_name,
        'cv_results': cv_results,
        'test_metrics': test_metrics,
        'feature_importance': feature_importance,
        'schema': schema,
        'training_timestamp': datetime.now().isoformat(),
    }

    report_path = os.path.join(output_dir, 'training_report.json')
    with open(report_path, 'w') as f:
        json.dump(full_report, f, indent=2, default=str)
    print(f"[DomainML] Report saved: {report_path}")

    return full_report


if __name__ == '__main__':
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    dataset_path = os.path.join(project_root, 'data', 'domain_intelligence', 'dataset2_features.csv')
    output_dir = os.path.join(project_root, 'model', 'domain_intelligence')

    if not os.path.exists(dataset_path):
        print(f"[DomainML] Dataset not found: {dataset_path}")
        print("[DomainML] Run feature collection and engineering first.")
        sys.exit(1)

    train_and_evaluate(dataset_path, output_dir)
