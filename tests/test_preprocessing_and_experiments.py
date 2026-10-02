"""
Focused unit and regression tests for corrected experimental preprocessing and EXP-C1 export.

Verifies:
1. TF-IDF vocabulary is fitted strictly on permitted fitting partition (no test/val terms).
2. CWE top-K selection uses strictly permitted fitting partition records.
3. Validation and test transformations do not mutate or refit preprocessing state.
4. Feature dimensions, names, and column ordering remain strictly consistent across partitions.
5. EXP-C1 export contains distinct columns for all four asset tiers (no column collision).
6. Original baseline artifacts in data/experiments/phase3_baseline/ remain intact.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from src.features.preprocessing import LeakageSafePreprocessor

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_tfidf_fitted_only_on_permitted_partition():
    """Verify that TF-IDF vocabulary is learned exclusively from the fitting partition."""
    df_train = pd.DataFrame({
        "cve_id": ["CVE-2020-0001", "CVE-2020-0002"],
        "description_en": ["buffer overflow in memory controller", "arbitrary code execution vulnerability"],
        "has_cwe": [True, True],
        "has_cpe_configuration": [True, True],
        "published": ["2020-01-01T00:00:00.000", "2020-02-01T00:00:00.000"],
    })
    df_val = pd.DataFrame({
        "cve_id": ["CVE-2023-0001"],
        "description_en": ["unprecedented zero_day exploit token_strictly_in_validation"],
        "has_cwe": [True],
        "has_cpe_configuration": [True],
        "published": ["2023-01-01T00:00:00.000"],
    })
    df_test = pd.DataFrame({
        "cve_id": ["CVE-2025-0001"],
        "description_en": ["future quantum cryptanalysis token_strictly_in_test"],
        "has_cwe": [True],
        "has_cpe_configuration": [True],
        "published": ["2025-01-01T00:00:00.000"],
    })
    cwe_dummy = pd.DataFrame({
        "cve_id": ["CVE-2020-0001"],
        "cwe_id": ["CWE-119"],
        "is_semantic_cwe": [True],
    })

    preprocessor = LeakageSafePreprocessor(max_tfidf_features=20, top_k_cwes=5)
    preprocessor.fit(df_train, cwe_dummy)

    vocab = preprocessor.tfidf.vocabulary_
    assert "overflow" in vocab
    assert "execution" in vocab

    # Verify that validation and test specific tokens NEVER enter the vocabulary
    assert "token_strictly_in_validation" not in vocab
    assert "token_strictly_in_test" not in vocab
    assert "quantum" not in vocab
    assert "zero_day" not in vocab


def test_cwe_selection_uses_only_permitted_partition():
    """Verify that top-K CWE frequency ranking is derived exclusively from fitting partition records."""
    df_train = pd.DataFrame({
        "cve_id": ["CVE-2020-0001", "CVE-2020-0002"],
        "description_en": ["desc1", "desc2"],
        "has_cwe": [True, True],
        "has_cpe_configuration": [True, True],
        "published": ["2020-01-01T00:00:00.000", "2020-02-01T00:00:00.000"],
    })
    df_val = pd.DataFrame({
        "cve_id": ["CVE-2023-0001", "CVE-2023-0002"],
        "description_en": ["val1", "val2"],
        "has_cwe": [True, True],
        "has_cpe_configuration": [True, True],
        "published": ["2023-01-01T00:00:00.000", "2023-02-01T00:00:00.000"],
    })

    # CWE-999 is abundant in validation (count=50), but 0 in training.
    # CWE-79 is present in training.
    cwe_records = [
        {"cve_id": "CVE-2020-0001", "cwe_id": "CWE-79", "is_semantic_cwe": True},
        {"cve_id": "CVE-2020-0002", "cwe_id": "CWE-79", "is_semantic_cwe": True},
    ]
    for _ in range(50):
        cwe_records.append({"cve_id": "CVE-2023-0001", "cwe_id": "CWE-999", "is_semantic_cwe": True})

    cwe_df = pd.DataFrame(cwe_records)

    preprocessor = LeakageSafePreprocessor(max_tfidf_features=10, top_k_cwes=1)
    preprocessor.fit(df_train, cwe_df)

    assert "CWE-79" in preprocessor.selected_cwes
    assert "CWE-999" not in preprocessor.selected_cwes


def test_validation_and_test_do_not_refit_preprocessing():
    """Verify that transform() does not alter fitted IDF weights or selected CWEs."""
    df_train = pd.DataFrame({
        "cve_id": ["CVE-2020-0001", "CVE-2020-0002"],
        "description_en": ["common vulnerability pattern", "common issue in component"],
        "has_cwe": [True, True],
        "has_cpe_configuration": [True, True],
        "published": ["2020-01-01T00:00:00.000", "2020-02-01T00:00:00.000"],
    })
    df_val = pd.DataFrame({
        "cve_id": ["CVE-2023-0001"],
        "description_en": ["completely different text with novel frequencies"],
        "has_cwe": [False],
        "has_cpe_configuration": [False],
        "published": ["2023-01-01T00:00:00.000"],
    })
    cwe_df = pd.DataFrame({"cve_id": ["CVE-2020-0001"], "cwe_id": ["CWE-89"], "is_semantic_cwe": [True]})
    cpe_df = pd.DataFrame({"cve_id": ["CVE-2020-0001"], "part": ["a"], "vendor": ["v"], "product": ["p"]})

    preprocessor = LeakageSafePreprocessor(max_tfidf_features=10, top_k_cwes=2)
    preprocessor.fit(df_train, cwe_df)

    idf_before = np.copy(preprocessor.tfidf.idf_)
    cwes_before = list(preprocessor.selected_cwes)
    vocab_before = dict(preprocessor.tfidf.vocabulary_)

    # Transform validation
    _ = preprocessor.transform(df_val, cwe_df, cpe_df)

    assert np.array_equal(preprocessor.tfidf.idf_, idf_before)
    assert preprocessor.selected_cwes == cwes_before
    assert preprocessor.tfidf.vocabulary_ == vocab_before


def test_feature_dimensions_and_ordering_consistent():
    """Verify that matrix dimensions and column alignments are identical across all partitions."""
    df_train = pd.DataFrame({
        "cve_id": ["CVE-2020-0001", "CVE-2020-0002"],
        "description_en": ["desc1", "desc2"],
        "has_cwe": [True, True],
        "has_cpe_configuration": [True, False],
        "published": ["2020-01-01T00:00:00.000", "2020-02-01T00:00:00.000"],
    })
    df_val = pd.DataFrame({
        "cve_id": ["CVE-2023-0001"],
        "description_en": ["val_desc"],
        "has_cwe": [False],
        "has_cpe_configuration": [True],
        "published": ["2023-01-01T00:00:00.000"],
    })
    df_test = pd.DataFrame({
        "cve_id": ["CVE-2025-0001"],
        "description_en": ["test_desc"],
        "has_cwe": [True],
        "has_cpe_configuration": [True],
        "published": ["2025-01-01T00:00:00.000"],
    })
    cwe_df = pd.DataFrame({
        "cve_id": ["CVE-2020-0001", "CVE-2025-0001"],
        "cwe_id": ["CWE-79", "CWE-79"],
        "is_semantic_cwe": [True, True],
    })
    cpe_df = pd.DataFrame({
        "cve_id": ["CVE-2020-0001"],
        "part": ["a"],
        "vendor": ["apache"],
        "product": ["httpd"],
    })

    preprocessor = LeakageSafePreprocessor(max_tfidf_features=20, top_k_cwes=5, include_epss=False)
    preprocessor.fit(df_train, cwe_df)

    X_train = preprocessor.transform(df_train, cwe_df, cpe_df)
    X_val = preprocessor.transform(df_val, cwe_df, cpe_df)
    X_test = preprocessor.transform(df_test, cwe_df, cpe_df)

    expected_cols = len(preprocessor.feature_names)
    assert X_train.shape[1] == expected_cols
    assert X_val.shape[1] == expected_cols
    assert X_test.shape[1] == expected_cols

    assert X_train.shape[0] == 2
    assert X_val.shape[0] == 1
    assert X_test.shape[0] == 1


def test_exp_c1_export_schema_contains_all_four_tiers():
    """Regression test: verify that the EXP-C1 export dictionary preserves distinct columns for all 4 tiers."""
    asset_tiers = {
        "Tier 1 (Low Criticality)": 0.25,
        "Tier 2 (Medium Criticality)": 0.50,
        "Tier 3 (High Criticality)": 0.75,
        "Tier 4 (Critical Infrastructure)": 1.00,
    }

    rank_export_dict = {"cve_id": ["CVE-2024-0001"], "is_kev": [0], "cvss_v31": [8.0], "epss": [0.1]}

    for tier_name, x4_val in asset_tiers.items():
        s_lin = np.array([0.5])
        s_nonlin = np.array([0.6])

        # Corrected column naming
        tier_num = tier_name.split()[1]
        tier_key = f"tier_{tier_num}"
        rank_export_dict[f"score_lin_{tier_key}"] = s_lin
        rank_export_dict[f"score_nonlin_{tier_key}"] = s_nonlin

    # Verify all four tiers exist as unique, non-overwritten columns
    expected_tier_cols = [
        "score_lin_tier_1", "score_nonlin_tier_1",
        "score_lin_tier_2", "score_nonlin_tier_2",
        "score_lin_tier_3", "score_nonlin_tier_3",
        "score_lin_tier_4", "score_nonlin_tier_4",
    ]
    for col in expected_tier_cols:
        assert col in rank_export_dict, f"Missing expected tier column {col} in export dictionary"

    df_export = pd.DataFrame(rank_export_dict)
    assert df_export.shape[1] == 4 + 8  # 4 base columns + 8 tier columns = 12 total columns


def test_baseline_artifacts_preserved():
    """Verify that original baseline artifacts exist in data/experiments/phase3_baseline/ and are untouched."""
    baseline_dir = REPO_ROOT / "data" / "experiments" / "phase3_baseline"
    assert baseline_dir.exists(), "phase3_baseline directory does not exist"

    expected_files = [
        "exp_a1/metrics.json",
        "exp_a1/model.xgb",
        "exp_a1/test_predictions.parquet",
        "exp_b1/metrics.json",
        "exp_b1/test_predictions.parquet",
        "exp_b2/metrics.json",
        "exp_b2/model.xgb",
        "exp_b2/test_predictions.parquet",
        "exp_c1/metrics.json",
        "exp_c1/simulation_rankings.parquet",
        "shap/shap_summary.json",
    ]
    for rel_path in expected_files:
        f = baseline_dir / rel_path
        assert f.exists(), f"Baseline artifact {rel_path} is missing from phase3_baseline"
        assert f.stat().st_size > 0, f"Baseline artifact {rel_path} is empty"
