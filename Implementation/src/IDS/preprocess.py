import pandas as pd
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
import joblib
import os
from typing import Optional, Dict, List, Any, Tuple
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Calculate base directory relative to this file
# This file is at: Implementation/src/IDS/preprocess.py
# Base project directory is 3 levels up
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

def _safe_entropy_from_series(values: pd.Series) -> float:
    """Compute Shannon entropy (base2) for a pandas Series."""
    try:
        if values is None or len(values) == 0:
            return 0.0
        vc = values.astype(str).value_counts(dropna=False)
        probs = (vc / vc.sum()).to_numpy(dtype=float)
        # Avoid log2(0)
        probs = probs[probs > 0]
        if probs.size == 0:
            return 0.0
        return float(-(probs * np.log2(probs)).sum())
    except Exception:
        return 0.0

class EntropyWindowFeatures(BaseEstimator, TransformerMixin):
    """
    Add Lakhina-style window entropy features.

    Computes per-time-window entropy over selected categorical fields and
    attaches them as numeric columns to every row in the window.
    """

    def __init__(
        self,
        window_seconds: int = 10,
        timestamp_col: str = "Timestamp",
        enable: bool = False,
    ):
        self.window_seconds = int(window_seconds)
        self.timestamp_col = timestamp_col
        self.enable = bool(enable)

        # Columns to consider (if present)
        self.src_ip_col = "IPV4_SRC_ADDR"
        self.dst_ip_col = "IPV4_DST_ADDR"
        self.src_port_col = "L4_SRC_PORT"
        self.dst_port_col = "L4_DST_PORT"
        self.proto_col = "PROTOCOL"
        self.l7_col = "L7_PROTO"

        # Numeric column to bin for entropy (if present)
        self.pkt_len_col = "LONGEST_FLOW_PKT"

    def fit(self, X: pd.DataFrame, y=None):
        return self

    def _get_window_key(self, df: pd.DataFrame) -> pd.Series:
        if self.timestamp_col not in df.columns:
            return pd.Series(np.zeros(len(df), dtype=np.int64), index=df.index)

        ts = df[self.timestamp_col]
        # Try numeric timestamps first
        ts_num = pd.to_numeric(ts, errors="coerce")
        if ts_num.notna().any():
            # Heuristic: if values look like ms since epoch, scale down
            median = float(ts_num.dropna().median()) if ts_num.notna().any() else 0.0
            if median > 1e12:
                ts_sec = (ts_num / 1000.0).fillna(0.0)
            elif median > 1e10:
                ts_sec = (ts_num / 1000.0).fillna(0.0)
            else:
                ts_sec = ts_num.fillna(0.0)
            return (ts_sec // max(self.window_seconds, 1)).astype(np.int64)

        # Fallback: parse datetime-like strings
        ts_dt = pd.to_datetime(ts, errors="coerce", utc=True)
        if ts_dt.notna().any():
            ts_sec = (ts_dt.view("int64") / 1e9).fillna(0.0)
            return (ts_sec // max(self.window_seconds, 1)).astype(np.int64)

        return pd.Series(np.zeros(len(df), dtype=np.int64), index=df.index)

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not self.enable:
            return X if isinstance(X, pd.DataFrame) else pd.DataFrame(X)
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)

        df = X.copy()
        if df.empty:
            return df

        window_key = self._get_window_key(df)
        df["_entropy_window"] = window_key.values

        # Packet length bin for entropy
        if self.pkt_len_col in df.columns:
            pkt = pd.to_numeric(df[self.pkt_len_col], errors="coerce").fillna(0.0)
            # Fixed bins: small->large
            df["_pkt_len_bin"] = pd.cut(
                pkt,
                bins=[-np.inf, 128, 256, 512, 1024, 1514, np.inf],
                labels=["0_128", "128_256", "256_512", "512_1024", "1024_1514", "gt_1514"],
            ).astype(str)
        else:
            df["_pkt_len_bin"] = "unknown"

        group = df.groupby("_entropy_window", sort=False)

        def _entropy_for_col(col: str) -> pd.Series:
            if col not in df.columns:
                # broadcast 0 entropy
                return group.size().astype(float).apply(lambda _: 0.0)
            return group[col].apply(_safe_entropy_from_series)

        ent_src_ip = _entropy_for_col(self.src_ip_col)
        ent_dst_ip = _entropy_for_col(self.dst_ip_col)
        ent_src_port = _entropy_for_col(self.src_port_col)
        ent_dst_port = _entropy_for_col(self.dst_port_col)
        ent_proto = _entropy_for_col(self.proto_col)
        ent_l7 = _entropy_for_col(self.l7_col)
        ent_pktbin = group["_pkt_len_bin"].apply(_safe_entropy_from_series)

        # Basic window context
        window_flow_count = group.size().astype(float)

        ent_frame = pd.DataFrame(
            {
                "ENT_SRC_IP": ent_src_ip,
                "ENT_DST_IP": ent_dst_ip,
                "ENT_SRC_PORT": ent_src_port,
                "ENT_DST_PORT": ent_dst_port,
                "ENT_PROTOCOL": ent_proto,
                "ENT_L7_PROTO": ent_l7,
                "ENT_PKT_LEN_BIN": ent_pktbin,
                "WINDOW_FLOW_COUNT": window_flow_count,
            }
        )

        # Merge back to rows
        df = df.join(ent_frame, on="_entropy_window")
        df.drop(columns=["_entropy_window", "_pkt_len_bin"], inplace=True, errors="ignore")
        return df


# ============================================================================
# Custom Transformers for Preprocessing Pipeline
# ============================================================================

class ColumnDropper(BaseEstimator, TransformerMixin):
    """Drop columns with excessive NaN values or specific unwanted columns."""
    
    def __init__(self, nan_threshold: float = 0.5, columns_to_drop: List[str] = None):
        self.nan_threshold = nan_threshold
        self.columns_to_drop = columns_to_drop or []
        self.detected_drop_cols = []
    
    def fit(self, X: pd.DataFrame, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        # Identify columns with too many NaNs
        nan_ratio = X.isna().sum() / len(X)
        self.detected_drop_cols = nan_ratio[nan_ratio > self.nan_threshold].index.tolist()
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        # Combine predefined drop columns with detected ones
        all_drop_cols = list(set(self.columns_to_drop + self.detected_drop_cols))
        
        # Only drop columns that actually exist
        existing_drop_cols = [c for c in all_drop_cols if c in X.columns]
        
        if existing_drop_cols:
            X = X.drop(columns=existing_drop_cols, errors='ignore')
            
        # Also ensure we don't have both 'Attack' and 'Label'
        # If both exist, drop 'Label' and keep 'Attack' (or vice versa, but Attack is preferred)
        if 'Attack' in X.columns and 'Label' in X.columns:
            X = X.drop(columns=['Label'], errors='ignore')
            
        return X


class DuplicateRemover(BaseEstimator, TransformerMixin):
    """Remove duplicate rows."""
    
    def fit(self, X: pd.DataFrame, y=None):
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        return X.drop_duplicates().reset_index(drop=True)


class LabelFilter(BaseEstimator, TransformerMixin):
    """Filter out specific label values."""
    
    def __init__(self, labels_to_remove: List[str] = None):
        self.labels_to_remove = labels_to_remove or []
        self.label_col = None
    
    def fit(self, X: pd.DataFrame, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        # Find label column (Attack or Label)
        self.label_col = next((c for c in X.columns if c.lower() in ['attack', 'label']), None)
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        if self.label_col and self.label_col in X.columns and self.labels_to_remove:
            for label in self.labels_to_remove:
                X = X[X[self.label_col] != label]
        return X.reset_index(drop=True)


class DataBalancer(BaseEstimator, TransformerMixin):
    """Balance dataset by downsampling majority class."""
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.label_col = None
    
    def fit(self, X: pd.DataFrame, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        self.label_col = next((c for c in X.columns if c.lower() in ['attack', 'label']), None)
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        if self.label_col and self.label_col in X.columns:
            # Normalize to uppercase for comparison
            is_benign = X[self.label_col].astype(str).str.upper() == 'BENIGN'
            # Also handle 0/1 labels if applicable (0 is usually benign)
            if X[self.label_col].dtype == 'int64' or X[self.label_col].dtype == 'int32':
                 is_benign = X[self.label_col] == 0

            benign = X[is_benign]
            malicious = X[~is_benign]
            
            if len(benign) > 0 and len(malicious) > 0:
                # Downsample benign to match malicious count (or a factor of it)
                # For large datasets, we might want to keep more benign, but let's stick to 1:1 or similar
                min_size = min(len(malicious), len(benign))
                # Ensure we don't drop too much if malicious is tiny
                target_size = max(min_size, 10000) 
                if len(benign) > target_size:
                     benign_down = benign.sample(target_size, random_state=self.random_state)
                     X = pd.concat([benign_down, malicious])
                else:
                     X = pd.concat([benign, malicious])
        
        return X.reset_index(drop=True)


class CategoricalEncoder(BaseEstimator, TransformerMixin):
    """Encode categorical columns using LabelEncoder."""
    
    def __init__(self, save_dir: Optional[str] = None):
        self.save_dir = save_dir
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.categorical_columns: List[str] = []
        self.numeric_columns: List[str] = []
    
    def fit(self, X: pd.DataFrame, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        self.label_encoders = {}
        self.categorical_columns = []
        self.numeric_columns = []
        
        for col in X.columns:
            # Skip label columns for feature encoding
            if col.lower() in ['attack', 'label']:
                continue

            if X[col].dtype == 'object':
                # Try to coerce to numeric
                converted = pd.to_numeric(X[col], errors='coerce')
                nan_ratio = converted.isna().sum() / len(X)
                
                if nan_ratio < 0.9:  # Mostly numeric
                    self.numeric_columns.append(col)
                else:  # Categorical
                    le = LabelEncoder()
                    le.fit(X[col].astype(str))
                    self.label_encoders[col] = le
                    self.categorical_columns.append(col)
                    
                    # Save encoder if save_dir is provided
                    if self.save_dir:
                        os.makedirs(self.save_dir, exist_ok=True)
                        joblib.dump(le, os.path.join(self.save_dir, f"{col}_encoder.joblib"))
            else:
                self.numeric_columns.append(col)
        
        self.fitted_ = True
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        X = X.copy()
        
        # Encode categorical columns
        for col in self.categorical_columns:
            if col in X.columns:
                try:
                    X[col] = self.label_encoders[col].transform(X[col].astype(str))
                except (ValueError, KeyError):
                    # Handle unknown categories by using most frequent class (index 0)
                    X[col] = 0
        
        # Convert numeric columns
        for col in self.numeric_columns:
            if col in X.columns and X[col].dtype == 'object':
                X[col] = pd.to_numeric(X[col], errors='coerce')
        
        return X


class InfiniteValueHandler(BaseEstimator, TransformerMixin):
    """Replace infinite values with NaN."""
    
    def fit(self, X: pd.DataFrame, y=None):
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        return X.replace([np.inf, -np.inf], np.nan)


class MissingValueImputer(BaseEstimator, TransformerMixin):
    """Fill missing values with column means."""
    
    def __init__(self):
        self.column_means: Dict[str, float] = {}
    
    def fit(self, X: pd.DataFrame, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        self.column_means = X[numeric_cols].mean().to_dict()
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        X = X.copy()
        for col, mean_val in self.column_means.items():
            if col in X.columns:
                # Fix for FutureWarning: A value is trying to be set on a copy of a DataFrame or Series through chained assignment
                X[col] = X[col].fillna(mean_val)
        
        # Fill any remaining NaNs with 0
        X = X.fillna(0)
        return X


class OutlierClipper(BaseEstimator, TransformerMixin):
    """Clip extreme outliers to avoid overflow."""
    
    def __init__(self, lower: float = -1e10, upper: float = 1e10):
        self.lower = lower
        self.upper = upper
    
    def fit(self, X: pd.DataFrame, y=None):
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        # Only clip numeric columns
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X[numeric_cols] = X[numeric_cols].clip(lower=self.lower, upper=self.upper)
        return X


class FeatureScaler(BaseEstimator, TransformerMixin):
    """Scale features using StandardScaler."""
    
    def __init__(self, save_dir: Optional[str] = None):
        self.save_dir = save_dir
        self.scaler = StandardScaler()
        self.label_col = None
        self.feature_cols: List[str] = []
    
    def fit(self, X: pd.DataFrame, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        # Identify label column
        self.label_col = next((c for c in X.columns if c.lower() in ['attack', 'label']), None)
        self.feature_cols = [c for c in X.columns if c != self.label_col]
        
        # Fit scaler on features only
        if self.feature_cols:
            self.scaler.fit(X[self.feature_cols])
            
            # Save scaler if save_dir is provided
            if self.save_dir:
                os.makedirs(self.save_dir, exist_ok=True)
                joblib.dump(self.scaler, os.path.join(self.save_dir, "scaler.joblib"))
                
                # Save feature names for inference
                feature_names_path = os.path.join(self.save_dir, "feature_names.txt")
                with open(feature_names_path, 'w') as f:
                    for col in self.feature_cols:
                        f.write(f"{col}\n")
        
        self.fitted_ = True
        return self
    
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        
        X = X.copy()
        
        # Scale only feature columns
        if self.feature_cols:
            feature_data = X[self.feature_cols]
            scaled_features = self.scaler.transform(feature_data)
            X[self.feature_cols] = scaled_features
        
        return X


# ============================================================================
# Preprocessing Pipeline Factory
# ============================================================================

def create_preprocessing_pipeline(
    save_dir: Optional[str] = None,
    *,
    enable_entropy: bool = False,
    entropy_window_seconds: int = 10,
) -> Pipeline:
    """
    Create a preprocessing pipeline for IDS data.
    
    Args:
        save_dir: Directory to save encoders and scaler
        
    Returns:
        sklearn Pipeline object
    """
    # Columns to drop for NF-UQ-NIDS-v2 to avoid overfitting to specific hosts/sessions
    drop_cols = [
        'IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_SRC_PORT', 'L4_DST_PORT', 
        'Dataset', 'DNS_QUERY_ID', 'DNS_QUERY_TYPE'
    ]

    pipeline = Pipeline([
        ('entropy_features', EntropyWindowFeatures(window_seconds=entropy_window_seconds, enable=enable_entropy)),
        ('drop_columns', ColumnDropper(nan_threshold=0.5, columns_to_drop=drop_cols)),
        ('remove_duplicates', DuplicateRemover()),
        # ('filter_labels', LabelFilter(labels_to_remove=['Infiltration'])), # Removed filter for now
        # ('balance_data', DataBalancer(random_state=42)), # Moved to chunk processing
        ('encode_categorical', CategoricalEncoder(save_dir=save_dir)),
        ('handle_infinite', InfiniteValueHandler()),
        ('impute_missing', MissingValueImputer()),
        ('clip_outliers', OutlierClipper(lower=-1e10, upper=1e10)),
        ('scale_features', FeatureScaler(save_dir=save_dir))
    ])
    
    return pipeline


def preprocess_data(path: str, save_dir: Optional[str] = None) -> pd.DataFrame:
    """
    Preprocess data using the preprocessing pipeline.
    
    Args:
        path: Path to the CSV file
        save_dir: Directory to save encoders and scaler (default: Models/)
        
    Returns:
        Preprocessed DataFrame
    """
    if save_dir is None:
        save_dir = os.path.join(_BASE_DIR, "Models")
    os.makedirs(save_dir, exist_ok=True)
    
    logger.info("Loading data...")
    df = pd.read_csv(path, low_memory=False)
    logger.info(f"Initial shape: {df.shape}")
    logger.info("✅ Data loaded successfully.")
    
    # Identify label column (prefer Attack, then Label)
    label_col = 'Attack' if 'Attack' in df.columns else 'Label' if 'Label' in df.columns else None
    
    if label_col:
        logger.info(f"Target Label Column: {label_col}")
        logger.info(f"\n{df[label_col].value_counts()}")
    
    # Save label encoder for output labels (before preprocessing)
    if label_col:
        label_encoder = LabelEncoder()
        label_encoder.fit(df[label_col].astype(str))
        joblib.dump(label_encoder, os.path.join(save_dir, "label_encoder.joblib"))
        logger.info(f"✅ Label encoder saved with {len(label_encoder.classes_)} classes.")
    
    # Create and fit the preprocessing pipeline
    logger.info("\nRunning preprocessing pipeline...")
    pipeline = create_preprocessing_pipeline(save_dir=save_dir)
    df_processed = pipeline.fit_transform(df)
    
    logger.info(f"After preprocessing: {df_processed.shape}")
    if label_col and label_col in df_processed.columns:
        logger.info(f"\n{df_processed[label_col].value_counts()}")
    logger.info("✅ Preprocessing complete.")
    
    return df_processed


# ============================================================================
# Chunked Processing Utilities
# ============================================================================

def get_unique_labels(path_pattern: str, chunksize: int = 100000) -> List[str]:
    """Find all unique attack labels across multiple CSV part files."""
    import glob
    paths = sorted(glob.glob(path_pattern))
    if not paths:
        return []

    print(f"Scanning labels in {len(paths)} files...")
    unique_labels = set()
    
    # 1. Capture columns and schema from the VERY first file
    header_df = pd.read_csv(paths[0], nrows=0)
    all_columns = header_df.columns.tolist()
    label_col = 'Attack' if 'Attack' in all_columns else 'Label' if 'Label' in all_columns else None
    
    if not label_col:
        raise ValueError(f"Could not find 'Attack' or 'Label' column in {paths[0]}")

    for i, p in enumerate(paths):
        print(f"  Scanning {os.path.basename(p)}...")
        try:
            # For the first file, use the header. 
            # For subsequent files, treat as headerless and skip the first line (potential corruption).
            if i == 0:
                reader = pd.read_csv(p, usecols=[label_col], chunksize=chunksize)
            else:
                # Use names and header=None, skip initial corrupted partial row if it's byte-split
                reader = pd.read_csv(p, header=None, names=all_columns, 
                                     usecols=[label_col], chunksize=chunksize, 
                                     skiprows=1, on_bad_lines='skip')
            
            for chunk in reader:
                unique_labels.update(chunk[label_col].astype(str).unique())
        except Exception as e:
            print(f"    Warning: Error reading {os.path.basename(p)}: {e}. Skipping...")

    final_labels = sorted(list(unique_labels))
    print(f"Found {len(final_labels)} unique labels: {final_labels}")
    return final_labels


def fit_pipeline_and_encoder(
    path_pattern: str,
    sample_size: int = 500000,
    save_dir: Optional[str] = None,
    *,
    enable_entropy: bool = False,
    entropy_window_seconds: int = 10,
):
    """
    Fit preprocessing pipeline and label encoder using a sample of the data.
    """
    import glob
    paths = sorted(glob.glob(path_pattern))
    if not paths:
        raise FileNotFoundError(f"No files found matching {path_pattern}")

    if save_dir is None:
        save_dir = os.path.join(_BASE_DIR, "Models")
    os.makedirs(save_dir, exist_ok=True)
    
    # 1. Get all unique labels first
    all_labels = get_unique_labels(path_pattern)
    label_encoder = LabelEncoder()
    label_encoder.fit(all_labels)
    joblib.dump(label_encoder, os.path.join(save_dir, "label_encoder.joblib"))
    
    # 2. Load a sample from the first part for fitting pipeline (faster)
    print(f"Loading sample of {sample_size} rows from {os.path.basename(paths[0])} for fitting pipeline...")
    df_sample = pd.read_csv(paths[0], nrows=sample_size, low_memory=False)
    
    # 3. Fit pipeline
    print("Fitting preprocessing pipeline on sample...")
    pipeline = create_preprocessing_pipeline(
        save_dir=save_dir,
        enable_entropy=enable_entropy,
        entropy_window_seconds=entropy_window_seconds,
    )
    pipeline.fit(df_sample)
    
    print("✅ Pipeline and encoder fitted and saved.")
    return pipeline, label_encoder


def process_data_chunks(path_pattern: str, pipeline, label_encoder, chunksize: int = 50000, split: str = 'train', split_ratio: tuple = (0.8, 0.1, 0.1)):
    """
    Generator that yields processed batches (X, y) from multiple partitioned CSVs.
    Handles headerless subsequent files and potentially corrupted boundary rows.
    """
    import glob
    paths = sorted(glob.glob(path_pattern))
    if not paths:
        raise FileNotFoundError(f"No files found matching {path_pattern}")

    # Capture schema from the first file
    header_df = pd.read_csv(paths[0], nrows=0)
    all_columns = header_df.columns.tolist()
    label_col = 'Attack' if 'Attack' in all_columns else 'Label' if 'Label' in all_columns else None
    
    if not label_col:
        raise ValueError("Could not find label column (Attack or Label)")

    # Identify numerical columns for safety cleaning
    exclude_cols = ['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_SRC_PORT', 'L4_DST_PORT', 
                    'PROTOCOL', 'L7_PROTO', 'Timestamp', 'Label', 'Attack', 'Dataset']
    num_cols = [c for c in all_columns if c not in exclude_cols]

    global_chunk_idx = 0
    for i, p in enumerate(paths):
        print(f"📖 Processing file: {os.path.basename(p)}")
        try:
            # First file has header; others don't and might have corrupted first rows
            if i == 0:
                reader = pd.read_csv(p, chunksize=chunksize, low_memory=False)
            else:
                reader = pd.read_csv(p, header=None, names=all_columns, 
                                     chunksize=chunksize, skiprows=1, 
                                     on_bad_lines='skip', low_memory=False)

            for chunk in reader:
                # Deterministic split based on global chunk index
                cycle_idx = global_chunk_idx % 10
                
                is_train = cycle_idx < 8
                is_val = cycle_idx == 8
                is_test = cycle_idx == 9
                
                current_split = 'train' if is_train else 'val' if is_val else 'test'
                
                if current_split != split:
                    global_chunk_idx += 1
                    continue
                
                # Robust numeric cleaning (handle noise from boundary issues)
                for col in num_cols:
                    if col in chunk.columns:
                        chunk[col] = pd.to_numeric(chunk[col], errors='coerce').fillna(0)

                # Process this chunk
                if split == 'train':
                     balancer = DataBalancer(random_state=42)
                     balancer.fit(chunk)
                     chunk = balancer.transform(chunk)
                
                chunk = chunk.sample(frac=1, random_state=42).reset_index(drop=True)

                # 2. Filter out rows with unseen labels (corruption or boundary noise)
                known_labels = set(label_encoder.classes_.astype(str))
                valid_mask = chunk[label_col].astype(str).isin(known_labels)
                if not valid_mask.all():
                    removed = len(chunk) - valid_mask.sum()
                    # print(f"  (Filtered {removed} unknown labels in chunk)")
                    chunk = chunk[valid_mask].reset_index(drop=True)
                
                if chunk.empty:
                    global_chunk_idx += 1
                    continue

                processed_chunk = pipeline.transform(chunk)
                
                if label_col in processed_chunk.columns:
                    y_chunk = processed_chunk[label_col]
                    X_chunk = processed_chunk.drop(columns=[label_col])
                    
                    try:
                        y_encoded = label_encoder.transform(y_chunk.astype(str))
                        X_values = X_chunk.values.astype(np.float32)
                        y_values = y_encoded.astype(np.int64)
                        yield X_values, y_values
                    except Exception as e:
                        print(f"  Warning: Transformation failed for chunk in {os.path.basename(p)}: {e}")
                    
                global_chunk_idx += 1
        except Exception as e:
            print(f"⚠️ Error reading file {os.path.basename(p)}: {e}")


# ============================================================================
# Inference Pipeline (for prediction)
# ============================================================================

class InferencePreprocessor:
    """
    Preprocessor for inference that uses saved encoders and scaler.
    """
    
    def __init__(self, artifacts_dir: Optional[str] = None):
        """
        Initialize inference preprocessor.
        
        Args:
            artifacts_dir: Directory containing saved encoders and scaler
        """
        if artifacts_dir is None:
            artifacts_dir = os.path.join(_BASE_DIR, "Models")
        
        self.artifacts_dir = artifacts_dir
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self._load_artifacts()
    
    def _load_artifacts(self):
        """Load saved encoders and scaler."""
        # Load label encoders
        for f in os.listdir(self.artifacts_dir):
            if f.endswith("_encoder.joblib") and f != "label_encoder.joblib":
                col_name = f.replace("_encoder.joblib", "")
                encoder_path = os.path.join(self.artifacts_dir, f)
                self.label_encoders[col_name] = joblib.load(encoder_path)
        
        # Load scaler
        scaler_path = os.path.join(self.artifacts_dir, "scaler.joblib")
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
        
        # Load feature names
        feature_names_path = os.path.join(self.artifacts_dir, "feature_names.txt")
        if os.path.exists(feature_names_path):
            with open(feature_names_path, 'r') as f:
                self.feature_names = [line.strip() for line in f.readlines()]
        elif hasattr(self.scaler, 'feature_names_in_'):
            self.feature_names = list(self.scaler.feature_names_in_)
        elif hasattr(self.scaler, 'n_features_in_'):
            raise ValueError("Cannot determine feature names. Please ensure feature_names.txt exists.")
    
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transform input data for inference efficiently.
        """
        # 1. Create a copy with only relevant columns or reindex
        # Using reindex is efficient for handling missing columns
        processed_df = df.reindex(columns=self.feature_names, fill_value=0)
        
        # 2. Encode categorical features in bulk where possible
        for col, le in self.label_encoders.items():
            if col in df.columns:
                # Vectorized transformation
                # Handle unknown categories by mapping them to 0 (or some default)
                # This depends on how the LabelEncoder was fitted
                try:
                    # We use a helper to handle mapping safely
                    s = df[col].astype(str)
                    # Check which values are in the encoder classes
                    mask = s.isin(le.classes_)
                    # For known values, transform. For unknown, set to 0
                    vals = np.zeros(len(s), dtype=int)
                    if mask.any():
                        vals[mask] = le.transform(s[mask])
                    processed_df[col] = vals
                except Exception:
                    processed_df[col] = 0
        
        # 3. Bulk numeric conversion for non-categorical columns
        numeric_cols = [c for c in self.feature_names if c not in self.label_encoders]
        if numeric_cols:
            # Convert only columns that were in the original DF to avoid overwriting 0s
            cols_to_convert = [c for c in numeric_cols if c in df.columns]
            if cols_to_convert:
                processed_df[cols_to_convert] = df[cols_to_convert].apply(pd.to_numeric, errors='coerce').fillna(0)
        
        # 4. Fill missing values using pre-calculated means
        if self.scaler is not None and hasattr(self.scaler, 'mean_'):
            # Only fill NaNs that might have been introduced by to_numeric
            # processed_df is already mostly filled with 0s or converted values
            # Using fillna with a Series of means is vectorized
            means_series = pd.Series(self.scaler.mean_, index=self.feature_names)
            processed_df = processed_df.fillna(means_series)
            
        # Final safety fill for anything else
        processed_df.fillna(0, inplace=True)
        
        # 5. Clip extreme values (vectorized)
        # Using .values.clip is faster than .clip for large arrays
        processed_df = processed_df.clip(lower=-1e10, upper=1e10)
        
        # 6. Scale features (vectorized via sklearn)
        if self.scaler:
            # Final safeguard: ensure exact columns and order expected by scaler
            processed_df = processed_df[self.feature_names]
            
            # Return new DataFrame to keep feature names and index
            scaled_values = self.scaler.transform(processed_df)
            processed_df = pd.DataFrame(
                scaled_values,
                columns=self.feature_names,
                index=processed_df.index
            )
        
        return processed_df


if __name__ == "__main__":
    data_path = os.path.join(_BASE_DIR, "Data", "NF-UQ-NIDS-v2.csv")
    if not os.path.exists(data_path):
         print(f"Warning: {data_path} not found. Using default path.")
         data_path = os.path.join(_BASE_DIR, "Data", "Preprocessed_CICIDS2018.csv")
         
    df = preprocess_data(data_path)
    print(df.info())
    print(df.head())
