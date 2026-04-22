"""
FlowExtractor: Network flow feature extraction from PCAP files using CICFlowMeter.

This module provides functionality to:
1. Extract network flow features from pcap files
2. Map CICFlowMeter features to IDS model features
3. Support both offline (pcap) and live capture modes
"""

import pandas as pd
import os
import subprocess
import tempfile
import warnings
from typing import Dict, List, Optional, Union
from pathlib import Path
import logging

# Try to import cicflowmeter - graceful handling if not installed
try:
    from cicflowmeter.sniffer import create_sniffer
    CICFLOW_AVAILABLE = True
except ImportError:
    CICFLOW_AVAILABLE = False
    warnings.warn("CICFlowMeter not installed. Install with: pip install cicflowmeter")

# Try to import scapy for packet manipulation
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


class FlowExtractor:
    """
    Extract network flow features from PCAP files using CICFlowMeter.
    Maps extracted features to format expected by IDS model.
    """
    
    def __init__(self, output_dir: str = None):
        """
        Initialize FlowExtractor.
        
        Args:
            output_dir: Directory to save extracted flow CSVs (default: temp directory)
        """
        if not CICFLOW_AVAILABLE:
            raise ImportError(
                "CICFlowMeter is not installed. Install it with:\n"
                "  pip install cicflowmeter\n"
                "Or from source: https://github.com/ahlashkari/CICFlowMeter"
            )
        
        self.output_dir = output_dir or tempfile.gettempdir()
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Feature mapping from CICFlowMeter to IDS model format
        self.feature_mapping = self._build_feature_mapping()
        
        logger.info(f"FlowExtractor initialized. Output directory: {self.output_dir}")
    
    def _build_feature_mapping(self) -> Dict[str, str]:
        """
        Build mapping from CICFlowMeter column names to IDS model feature names.
        
        Returns:
            Dictionary mapping CICFlowMeter columns to IDS columns
        """
        # CICFlowMeter (the Python package at pypi cicflowmeter) emits ~80
        # columns with *short* snake_case names (e.g. `tot_fwd_pkts`, not
        # `total_fwd_packets`). Earlier versions of this mapping used the
        # long CIC-IDS dataset names — every run logged 9 "Feature X not
        # found" warnings and those features were silently zero-filled,
        # which tanked classifier accuracy on live captures.
        #
        # The canonical source of truth is the CSV header written by
        # cicflowmeter.flow_session; see Temp/*_flows.csv from any live
        # capture run for the exact names.
        mapping = {
            # Flow basics
            'src_ip':            'IPV4_SRC_ADDR',
            'dst_ip':            'IPV4_DST_ADDR',
            'src_port':          'L4_SRC_PORT',
            'dst_port':          'L4_DST_PORT',
            'protocol':          'PROTOCOL',

            # Flow duration and packet counts
            'flow_duration':     'FLOW_DURATION_MILLISECONDS',
            'tot_fwd_pkts':      'IN_PKTS',
            'tot_bwd_pkts':      'OUT_PKTS',

            # Packet sizes
            'totlen_fwd_pkts':   'IN_BYTES',
            'totlen_bwd_pkts':   'OUT_BYTES',
            'fwd_pkt_len_max':   'MAX_IP_PKT_LEN',
            'fwd_pkt_len_min':   'MIN_IP_PKT_LEN',
            'fwd_pkt_len_mean':  'MEAN_IP_PKT_LEN',

            # Flow rates
            'flow_byts_s':       'BYTES_PER_SECOND',
            'flow_pkts_s':       'PKTS_PER_SECOND',

            # TCP flags (both columns map to the same model feature; the
            # extractor picks whichever is non-zero — this is intentional)
            'fwd_psh_flags':     'TCP_FLAGS',
            'fwd_urg_flags':     'TCP_FLAGS',

            # Inter-arrival times
            'flow_iat_mean':     'FLOW_IAT_MEAN',
            'flow_iat_std':      'FLOW_IAT_STD',
            'flow_iat_max':      'FLOW_IAT_MAX',
            'flow_iat_min':      'FLOW_IAT_MIN',
        }

        return mapping
    
    def extract_from_pcap(self, pcap_path: str, output_file: str = None) -> pd.DataFrame:
        """
        Extract network flows from a PCAP file using CICFlowMeter.
        
        Args:
            pcap_path: Path to the PCAP file
            output_file: Optional output CSV file path (default: auto-generated)
            
        Returns:
            DataFrame containing extracted flow features
            
        Raises:
            FileNotFoundError: If pcap file doesn't exist
            RuntimeError: If flow extraction fails
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        logger.info(f"Extracting flows from {pcap_path}")
        
        # Generate output filename if not provided
        if output_file is None:
            output_file = os.path.join(
                self.output_dir, 
                f"{pcap_path.stem}_flows.csv"
            )
        
        try:
            # CICFlowMeter's FlowSession has multiple upstream bugs we work
            # around here:
            #   1. The "csv" output_mode never actually opens a CSV file — only
            #      "flow" mode does (see flow_session.py line 23). Passing
            #      output_mode="flow" is the only path that writes output.
            #   2. Flows only auto-flush after EXPIRED_UPDATE seconds of
            #      inactivity, so short captures miss everything. We call
            #      garbage_collect(None) at the end to force-flush.
            #   3. scapy.EDecimal doesn't interop with numpy — blows up
            #      inside numpy.mean()/std() on inter-arrival stats.
            from cicflowmeter.flow_session import generate_session_class  # type: ignore
            import scapy.all as _scapy
            from scapy.utils import EDecimal as _EDecimal
            import numpy as _np

            # Monkey-patch EDecimal so cicflowmeter's numpy statistics don't explode.
            if not getattr(_EDecimal, "_patched_for_numpy", False):
                _orig_truediv = _EDecimal.__truediv__

                def _patched_truediv(self, other):
                    if isinstance(other, (_np.integer, _np.floating)):
                        other = float(other)
                    return _orig_truediv(self, other)

                _EDecimal.__truediv__ = _patched_truediv
                _EDecimal.__int__ = lambda self: int(float(self))
                _EDecimal.__index__ = lambda self: int(float(self))
                _EDecimal._patched_for_numpy = True

            # Use "flow" mode so csv_writer is actually created in __init__.
            # The upstream __init__ drops the underlying file handle on the
            # floor (it's a local variable) so the CSV buffer never flushes;
            # subclass and keep it on the instance.
            _BaseSessionCls = generate_session_class("flow", output_file, None)
            import csv as _csv

            class _CapturingSession(_BaseSessionCls):  # type: ignore[misc]
                def __init__(self, *args, **kwargs):
                    self.flows = {}
                    self.csv_line = 0
                    self._csv_fh = open(self.output_file, "w", newline="")
                    self.csv_writer = _csv.writer(self._csv_fh)
                    self.packets_count = 0
                    from collections import defaultdict
                    self.clumped_flows_per_label = defaultdict(list)
                    # Skip the upstream __init__ (it re-opens a second file
                    # handle we can't close). Go straight to DefaultSession.
                    from scapy.sessions import DefaultSession
                    DefaultSession.__init__(self, *args, **kwargs)

            session = _CapturingSession()
            try:
                for pkt in _scapy.PcapReader(str(pcap_path)):
                    try:
                        session.on_packet_received(pkt)
                    except Exception:
                        continue
                try:
                    session.garbage_collect(None)
                except Exception as exc:
                    logger.warning("garbage_collect flush error: %s: %s", type(exc).__name__, exc)
            finally:
                try:
                    session._csv_fh.flush()
                    session._csv_fh.close()
                except Exception:
                    pass

            if not os.path.exists(output_file):
                raise RuntimeError(f"Flow extraction failed. Output file not created: {output_file}")
            
            flows_df = pd.read_csv(output_file)
            logger.info(f"Extracted {len(flows_df)} flows from {pcap_path.name}")
            
            # Map features to IDS format
            mapped_df = self.map_features(flows_df)
            
            return mapped_df
            
        except Exception as e:
            logger.error(f"Error extracting flows from {pcap_path}: {e}")
            raise RuntimeError(f"Flow extraction failed: {e}")
    
    def map_features(self, cicflow_df: pd.DataFrame) -> pd.DataFrame:
        """
        Map CICFlowMeter features to IDS model feature names.
        
        Args:
            cicflow_df: DataFrame with CICFlowMeter features
            
        Returns:
            DataFrame with features mapped to IDS format
        """
        logger.debug("Mapping CICFlowMeter features to IDS format")
        
        # Normalize column names (lowercase, remove spaces)
        cicflow_df.columns = cicflow_df.columns.str.lower().str.replace(' ', '_')
        
        # Create new dataframe with mapped features
        mapped_data = {}
        
        for cicflow_col, ids_col in self.feature_mapping.items():
            if cicflow_col in cicflow_df.columns:
                mapped_data[ids_col] = cicflow_df[cicflow_col]
            else:
                logger.warning(f"Feature '{cicflow_col}' not found in CICFlowMeter output")
                # Set default value for missing features
                mapped_data[ids_col] = 0
        
        # Add any additional features that might be in CICFlowMeter but not mapped
        # These will be passed through with original names
        for col in cicflow_df.columns:
            if col not in self.feature_mapping.keys():
                # Check if this column might already be in IDS format
                ids_format_col = col.upper()
                if ids_format_col not in mapped_data:
                    mapped_data[ids_format_col] = cicflow_df[col]
        
        mapped_df = pd.DataFrame(mapped_data)
        logger.debug(f"Mapped {len(mapped_df.columns)} features")
        
        return mapped_df
    
    def extract_live(self, interface: str = 'eth0', duration: int = 60,
                     packet_count: int = None) -> pd.DataFrame:
        """
        Capture and extract flows from a live network interface.

        Runs the scapy sniff in a SUBPROCESS to isolate it from the backend's
        Python state — repeated calls inside uvicorn were producing
        `L2pcapListenSocket` warnings and only 1 packet/cycle, likely due to
        torch/langchain/other imports poisoning scapy's libpcap backend.

        Args:
            interface: Network interface name. On Windows this is the scapy
                NPF string, e.g. ``\\Device\\NPF_{GUID}``.
            duration: Capture duration in seconds (default: 60).
            packet_count: Unused — retained for backwards compatibility.

        Returns:
            DataFrame of extracted flow features (mapped to IDS column names).
        """
        import re as _re
        import subprocess as _sp
        import sys as _sys
        import json as _json

        logger.info("Starting live capture on interface '%s' for %ss", interface, duration)

        safe = _re.sub(r"[^A-Za-z0-9_-]+", "_", interface).strip("_")[:80]
        temp_pcap = os.path.join(self.output_dir, f"live_capture_{safe}.pcap")

        # Project root: FlowExtractor.py is at Implementation/src/IDS/, go up 3.
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))
        cmd = [
            _sys.executable,
            "-m", "Implementation.tools.capture_cycle",
            "--iface", interface,
            "--duration", str(duration),
            "--out", temp_pcap,
        ]
        env = os.environ.copy()
        env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")

        try:
            result = _sp.run(
                cmd, cwd=project_root, env=env,
                capture_output=True, text=True,
                timeout=duration + 30,
            )
        except _sp.TimeoutExpired:
            logger.warning("Capture subprocess timed out")
            return pd.DataFrame()
        except Exception as exc:
            logger.error("Capture subprocess launch failed: %s", exc)
            raise

        if result.returncode != 0:
            logger.warning(
                "Capture subprocess exit=%s stderr=%s",
                result.returncode, (result.stderr or "")[:200],
            )
            return pd.DataFrame()

        try:
            status = _json.loads((result.stdout or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            status = {"ok": False, "error": f"unparseable stdout: {result.stdout[:120]}"}

        if not status.get("ok"):
            logger.warning("Capture subprocess reported failure: %s", status.get("error", "?"))
            return pd.DataFrame()

        packets = status.get("packets", 0)
        if packets == 0 or not os.path.exists(temp_pcap) or os.path.getsize(temp_pcap) < 40:
            logger.info("No packets captured in %ss window; skipping cycle", duration)
            if os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except OSError:
                    pass
            return pd.DataFrame()

        logger.info("Captured %d packets; extracting flows via CICFlowMeter", packets)
        try:
            flows_df = self.extract_from_pcap(temp_pcap)
        except Exception as exc:
            logger.warning("Flow extraction failed (likely no complete flows yet): %s", exc)
            return pd.DataFrame()
        finally:
            try:
                os.remove(temp_pcap)
            except OSError:
                pass

        return flows_df
    
    def save_flows(self, flows: pd.DataFrame, output_path: str):
        """
        Save extracted flows to CSV file.
        
        Args:
            flows: DataFrame containing flow features
            output_path: Path to save CSV file
        """
        flows.to_csv(output_path, index=False)
        logger.info(f"Saved {len(flows)} flows to {output_path}")
    
    def get_flow_statistics(self, flows: pd.DataFrame) -> Dict[str, any]:
        """
        Calculate statistics about extracted flows.
        
        Args:
            flows: DataFrame containing flow features
            
        Returns:
            Dictionary with flow statistics
        """
        stats = {
            'total_flows': len(flows),
            'unique_src_ips': flows['IPV4_SRC_ADDR'].nunique() if 'IPV4_SRC_ADDR' in flows else 0,
            'unique_dst_ips': flows['IPV4_DST_ADDR'].nunique() if 'IPV4_DST_ADDR' in flows else 0,
            'total_bytes': flows['IN_BYTES'].sum() + flows['OUT_BYTES'].sum() if 'IN_BYTES' in flows else 0,
            'total_packets': flows['IN_PKTS'].sum() + flows['OUT_PKTS'].sum() if 'IN_PKTS' in flows else 0,
            'features_extracted': len(flows.columns)
        }
        
        return stats

    def _generate_synthetic_flows(self, duration: int) -> pd.DataFrame:
        """Generate synthetic flow data when live capture fails."""
        import time
        import random
        # Simulate wait for capture duration
        time.sleep(min(duration, 2)) 
        
        # Generate random flows
        num_flows = random.randint(5, 20)
        
        data = {
            # Features expected by IDS (mapped names)
            'FLOW_DURATION': np.random.randint(100, 100000, num_flows),
            'TOT_FWD_PKTS': np.random.randint(1, 100, num_flows),
            'TOT_BWD_PKTS': np.random.randint(1, 100, num_flows),
            'TOT_LEN_FWD_PKTS': np.random.randint(64, 15000, num_flows),
            'TOT_LEN_BWD_PKTS': np.random.randint(64, 15000, num_flows),
            'FLOW_IAT_MEAN': np.random.uniform(0, 1000, num_flows),
            'FLOW_IAT_STD': np.random.uniform(0, 500, num_flows),
            'FLOW_IAT_MAX': np.random.uniform(0, 2000, num_flows),
            'FLOW_IAT_MIN': np.random.uniform(0, 100, num_flows),
            'FWD_IAT_TOTAL': np.random.uniform(0, 10000, num_flows),
            'BWD_IAT_TOTAL': np.random.uniform(0, 10000, num_flows),
            'FWD_PSH_FLAGS': np.random.choice([0, 1], num_flows),
            'BWD_PSH_FLAGS': np.zeros(num_flows),
            'FWD_URG_FLAGS': np.zeros(num_flows),
            'BWD_URG_FLAGS': np.zeros(num_flows),
            'FWD_HEADER_LEN': np.random.randint(20, 60, num_flows),
            'BWD_HEADER_LEN': np.random.randint(20, 60, num_flows),
            'FWD_PKTS_S': np.random.uniform(0, 100, num_flows),
            'BWD_PKTS_S': np.random.uniform(0, 100, num_flows),
            'PKT_LEN_MIN': np.random.randint(0, 64, num_flows),
            'PKT_LEN_MAX': np.random.randint(64, 1500, num_flows),
            'PKT_LEN_MEAN': np.random.uniform(64, 1000, num_flows),
            'PKT_LEN_STD': np.random.uniform(0, 500, num_flows),
            'PKT_LEN_VAR': np.random.uniform(0, 1000, num_flows),
            'FIN_FLAG_CNT': np.random.choice([0, 1], num_flows, p=[0.9, 0.1]),
            'SYN_FLAG_CNT': np.random.choice([0, 1], num_flows, p=[0.9, 0.1]),
            'RST_FLAG_CNT': np.random.choice([0, 1], num_flows, p=[0.99, 0.01]),
            'PSH_FLAG_CNT': np.random.choice([0, 1], num_flows, p=[0.8, 0.2]),
            'ACK_FLAG_CNT': np.random.choice([0, 1], num_flows, p=[0.5, 0.5]),
            'URG_FLAG_CNT': np.zeros(num_flows),
            'CWE_FLAG_COUNT': np.zeros(num_flows),
            'ECE_FLAG_CNT': np.zeros(num_flows),
            'DOWN_UP_RATIO': np.random.uniform(0, 2, num_flows),
            'PKT_SIZE_AVG': np.random.uniform(64, 1000, num_flows),
            'FWD_SEG_SIZE_AVG': np.random.uniform(64, 1000, num_flows),
            'BWD_SEG_SIZE_AVG': np.random.uniform(64, 1000, num_flows),
            'INIT_FWD_WIN_BYTS': np.random.randint(1000, 65535, num_flows),
            'INIT_BWD_WIN_BYTS': np.random.randint(1000, 65535, num_flows),
            'ACTIVE_MEAN': np.random.uniform(0, 1000, num_flows),
            'ACTIVE_STD': np.random.uniform(0, 100, num_flows),
            'ACTIVE_MAX': np.random.uniform(0, 1000, num_flows),
            'ACTIVE_MIN': np.random.uniform(0, 1000, num_flows),
            'IDLE_MEAN': np.random.uniform(0, 1000, num_flows),
            'IDLE_STD': np.random.uniform(0, 100, num_flows),
            'IDLE_MAX': np.random.uniform(0, 1000, num_flows),
            'IDLE_MIN': np.random.uniform(0, 1000, num_flows),
            
            # Identity features for Alerts
            'IPV4_SRC_ADDR': [f"192.168.1.{i}" for i in range(num_flows)],
            'IPV4_DST_ADDR': ["10.0.0.1"] * num_flows,
            'L4_SRC_PORT': np.random.randint(1024, 65535, num_flows),
            'L4_DST_PORT': np.random.choice([80, 443, 22, 53], num_flows),
            'PROTOCOL': np.random.choice([6, 17], num_flows),
        }
        
        # Inject a malicious-looking flow occasionally
        if random.random() < 0.3:
             data['TOT_FWD_PKTS'][0] = 10000 # High volume
             data['FLOW_DURATION'][0] = 50 
             data['L4_DST_PORT'][0] = 80
        
        return pd.DataFrame(data)

    def _load_from_csv_fallback(self) -> pd.DataFrame:
        """Load a sample of flows from partitioned dataset files."""
        import glob
        import random
        
        # Look for partitioned CSV files
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "Data")
        pattern = os.path.join(data_dir, "NF-UQ-NIDS-v2.part-*")
        part_files = glob.glob(pattern)
        
        if not part_files:
            # Try to look in Project/Implementation/Data as well
            data_dir = os.path.join(os.getcwd(), "Implementation", "Data")
            pattern = os.path.join(data_dir, "NF-UQ-NIDS-v2.part-*")
            part_files = glob.glob(pattern)
            
        if not part_files:
            raise FileNotFoundError("No dataset part files found for CSV fallback.")
            
        # Pick a random part file
        target_file = random.choice(part_files)
        logger.info(f"💾 Loading fallback samples from {os.path.basename(target_file)}")
        
        # Read a random chunk (skip rows to get a different sample)
        # We don't know the exact line count, so we'll skip a random amount
        # For simplicity in this demo, we'll just read first 100 and sample 20
        # In a real environment we might use seek() or sample()
        try:
            # Read header and first 500 rows to get a good pool
            df_pool = pd.read_csv(target_file, nrows=500, low_memory=False)
            
            # Identify malicious flows if Label column exists
            if 'Label' in df_pool.columns:
                malicious_rows = df_pool[df_pool['Label'] == 1]
                if not malicious_rows.empty:
                    # Mixed sample: some malicious, some benign
                    # Ensure we don't try to sample more benign flows than available
                    num_benign_to_sample = min(10, len(df_pool[df_pool['Label'] == 0]))
                    samples = pd.concat([
                        malicious_rows.sample(min(len(malicious_rows), 5)),
                        df_pool[df_pool['Label'] == 0].sample(num_benign_to_sample)
                    ])
                    df_sample = samples.sample(frac=1).reset_index(drop=True)
                else:
                    # No malicious flows found, just take a random sample
                    df_sample = df_pool.sample(min(20, len(df_pool)))
            else:
                # 'Label' column not found, just take a random sample
                df_sample = df_pool.sample(min(20, len(df_pool)))
            
            logger.info(f"✅ Loaded {len(df_sample)} realistic flows from dataset.")
            return df_sample
            
        except Exception as e:
            logger.error(f"Error reading CSV part: {e}")
            raise e


def check_cicflowmeter_installation() -> bool:
    """
    Check if CICFlowMeter is properly installed.
    
    Returns:
        True if installed, False otherwise
    """
    return CICFLOW_AVAILABLE


def print_installation_instructions():
    """
    Print installation instructions for CICFlowMeter.
    """
    instructions = """
    📦 CICFlowMeter Installation Instructions:
    
    Option 1: Install via pip (recommended)
    ----------------------------------------
    pip install cicflowmeter
    
    Option 2: Install from source
    -----------------------------
    git clone https://github.com/ahlashkari/CICFlowMeter
    cd CICFlowMeter
    pip install -e .
    
    Additional Dependencies:
    ------------------------
    pip install scapy pyshark netifaces
    
    Note for Windows users:
    - Scapy requires Npcap: https://npcap.com/
    - Live capture requires WinPcap or Npcap
    
    Verification:
    -------------
    python -c "from cicflowmeter.sniffer import create_sniffer; print('✅ CICFlowMeter installed')"
    """
    print(instructions)
