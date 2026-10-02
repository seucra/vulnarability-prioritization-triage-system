"""
Leakage-Safe Preprocessing Pipeline for VTS Research Experiments (EXP-A1, EXP-B2, EXP-B1).

Strictly enforces temporal partition isolation:
1. TF-IDF vocabulary and IDF weights are fit exclusively on the designated fitting partition.
2. Top-K semantic CWE indicators are selected exclusively from the designated fitting partition.
3. Validation and test partitions are transformed using the already-fitted preprocessor without refitting.
4. Consistent feature ordering and dimensions are guaranteed across all partitions.
"""

from typing import List, Optional, Tuple, Set
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer


class LeakageSafePreprocessor:
    """
    Leakage-safe tabular and textual preprocessor.
    Guarantees strict separation between fitting partition and transformation partitions.
    """

    def __init__(
        self,
        max_tfidf_features: int = 500,
        top_k_cwes: int = 20,
        include_epss: bool = False,
        random_state: int = 42,
    ):
        self.max_tfidf_features = max_tfidf_features
        self.top_k_cwes = top_k_cwes
        self.include_epss = include_epss
        self.random_state = random_state

        self.tfidf: Optional[TfidfVectorizer] = None
        self.selected_cwes: List[str] = []
        self.feature_names: List[str] = []
        self.is_fitted: bool = False

    def fit(self, df_fit: pd.DataFrame, cwe_df: pd.DataFrame) -> "LeakageSafePreprocessor":
        """
        Fit TF-IDF vocabulary and select top-K CWE features exclusively on df_fit.
        """
        # 1. Fit TF-IDF on fitting descriptions only
        self.tfidf = TfidfVectorizer(
            max_features=self.max_tfidf_features,
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True,
        )
        fit_descriptions = df_fit["description_en"].fillna("")
        self.tfidf.fit(fit_descriptions)

        # 2. Select top-K semantic CWEs from fitting partition only
        fit_cves: Set[str] = set(df_fit["cve_id"])
        cwe_fit = cwe_df[cwe_df["cve_id"].isin(fit_cves) & cwe_df["is_semantic_cwe"]]
        self.selected_cwes = (
            cwe_fit["cwe_id"].value_counts().head(self.top_k_cwes).index.tolist()
        )

        # 3. Construct authoritative feature name schema
        tfidf_names = [f"tfidf_{w}" for w in self.tfidf.get_feature_names_out()]
        tabular_names = ["has_cwe", "has_cpe_configuration"]

        if self.include_epss:
            tabular_names.extend(["epss", "epss_percentile"])

        tabular_names.extend(["cwe_count", "semantic_cwe_count"])
        tabular_names.extend(self.selected_cwes)
        tabular_names.extend(
            [
                "cpe_count",
                "cpe_part_a",
                "cpe_part_h",
                "cpe_part_o",
                "vendor_count",
                "product_count",
                "pub_month",
            ]
        )

        self.feature_names = tfidf_names + tabular_names
        self.is_fitted = True
        return self

    def transform(
        self,
        df_target: pd.DataFrame,
        cwe_df: pd.DataFrame,
        cpe_df: pd.DataFrame,
    ) -> csr_matrix:
        """
        Transform target partition using the previously fitted preprocessing objects.
        Does not refit TF-IDF or re-rank CWE frequencies.
        """
        if not self.is_fitted or self.tfidf is None:
            raise ValueError("LeakageSafePreprocessor must be fitted before calling transform.")

        # 1. Transform text using fitted TF-IDF
        target_descriptions = df_target["description_en"].fillna("")
        X_text = self.tfidf.transform(target_descriptions)

        # 2. Build tabular features
        target_cve_ids = df_target["cve_id"].values
        target_set = set(target_cve_ids)

        cwe_sub = cwe_df[cwe_df["cve_id"].isin(target_set)]
        cpe_sub = cpe_df[cpe_df["cve_id"].isin(target_set)]

        feat_df = pd.DataFrame(index=pd.Index(target_cve_ids, name="cve_id"))
        feat_df["has_cwe"] = df_target["has_cwe"].astype(int).values
        feat_df["has_cpe_configuration"] = df_target["has_cpe_configuration"].astype(int).values

        if self.include_epss:
            feat_df["epss"] = df_target["epss"].fillna(0.0).values
            percentile_col = "percentile" if "percentile" in df_target.columns else "epss_percentile"
            feat_df["epss_percentile"] = df_target[percentile_col].fillna(0.0).values

        # CWE counts
        cwe_counts = cwe_sub.groupby("cve_id").size().rename("cwe_count")
        semantic_counts = (
            cwe_sub[cwe_sub["is_semantic_cwe"]].groupby("cve_id").size().rename("semantic_cwe_count")
        )
        feat_df = feat_df.join(cwe_counts, how="left").fillna({"cwe_count": 0})
        feat_df = feat_df.join(semantic_counts, how="left").fillna({"semantic_cwe_count": 0})

        # Selected top-K CWE indicators
        cwe_top_matches = cwe_sub[cwe_sub["cwe_id"].isin(self.selected_cwes)]
        if not cwe_top_matches.empty:
            cwe_pivot = cwe_top_matches.groupby(["cve_id", "cwe_id"]).size().unstack(fill_value=0)
            cwe_pivot = (cwe_pivot > 0).astype(int)
        else:
            cwe_pivot = pd.DataFrame(index=pd.Index([], name="cve_id"))

        for cwe_id in self.selected_cwes:
            if cwe_id in cwe_pivot.columns:
                feat_df = feat_df.join(cwe_pivot[[cwe_id]], how="left").fillna({cwe_id: 0})
            else:
                feat_df[cwe_id] = 0

        # CPE features
        cpe_counts = cpe_sub.groupby("cve_id").size().rename("cpe_count")
        feat_df = feat_df.join(cpe_counts, how="left").fillna({"cpe_count": 0})

        if not cpe_sub.empty:
            cpe_parts = cpe_sub.groupby(["cve_id", "part"]).size().unstack(fill_value=0)
            cpe_parts.columns = [f"cpe_part_{col}" for col in cpe_parts.columns]
        else:
            cpe_parts = pd.DataFrame(index=pd.Index([], name="cve_id"))

        for part_col in ["cpe_part_a", "cpe_part_h", "cpe_part_o"]:
            if part_col in cpe_parts.columns:
                feat_df = feat_df.join(cpe_parts[[part_col]], how="left").fillna({part_col: 0})
            else:
                feat_df[part_col] = 0

        vendor_counts = cpe_sub.groupby("cve_id")["vendor"].nunique().rename("vendor_count")
        product_counts = cpe_sub.groupby("cve_id")["product"].nunique().rename("product_count")
        feat_df = feat_df.join(vendor_counts, how="left").fillna({"vendor_count": 0})
        feat_df = feat_df.join(product_counts, how="left").fillna({"product_count": 0})

        # Publication month
        pub_dt = pd.to_datetime(df_target["published"], errors="coerce")
        feat_df["pub_month"] = pub_dt.dt.month.fillna(1).values

        # Ensure exact column alignment
        expected_tabular_cols = [c for c in self.feature_names if not c.startswith("tfidf_")]
        feat_df = feat_df[expected_tabular_cols]

        X_num = csr_matrix(feat_df.values.astype(np.float32))
        X_combined = hstack([X_text, X_num]).tocsr()
        return X_combined

    def fit_transform(
        self,
        df_fit: pd.DataFrame,
        cwe_df: pd.DataFrame,
        cpe_df: pd.DataFrame,
    ) -> csr_matrix:
        """
        Fit on df_fit and return transformed matrix.
        """
        self.fit(df_fit, cwe_df)
        return self.transform(df_fit, cwe_df, cpe_df)
