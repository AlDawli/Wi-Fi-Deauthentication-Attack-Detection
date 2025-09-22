#!/usr/bin/env python3
"""
wifi_deauth_detector_safe.py

Passive Wi-Fi deauthentication / disassociation detection (offline).
Reads PCAPs, detects suspicious sources/windows, produces:
 - text + JSON report
 - optional visualization images
 - PCAP slices for suspicious windows (for forensic handoff)

THIS TOOL IS PASSIVE: it only reads PCAP files. Do NOT run this on captures you
are not authorized to analyze. Do NOT use for generating or sending deauth frames.
"""

import argparse
import json
import logging
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from scapy.all import PcapReader, rdpcap, Dot11, Dot11Deauth, Dot11Disas, RadioTap, Dot11Beacon, wrpcap

# ---------- Config / defaults ----------
DEFAULTS = {
    "time_window_seconds": 60,
    "deauth_threshold": 10,
    "burst_threshold": 5,
    "burst_window_seconds": 5,
    "min_rssi_change": 20,
    "sequence_repeat_threshold": 3,
    "statistical_z_threshold": 2.5,
    "visualization": True,
    "output_dir": "deauth_analysis",
    "log_level": "INFO"
}

# ---------- Helpers ----------
def safe_rssi_from_radiotap(pkt) -> Optional[int]:
    """Try a few ways to get RSSI / dBm from RadioTap; return None if unavailable."""
    if not pkt.haslayer(RadioTap):
        return None
    rt = pkt.getlayer(RadioTap)
    # Common field names: dBm_AntSignal, dBm_antsignal, not always present
    for field in ("dBm_AntSignal", "dBm_antsignal", "DBMAntSignal", "dbm_antsignal"):
        try:
            v = getattr(rt, field)
            if isinstance(v, (int, float)):
                return int(v)
        except Exception:
            pass
    # try raw fields fallback
    try:
        # Some scapy versions allow rt.dBm_AntSignal
        return int(rt.fields.get("dBm_AntSignal")) if "dBm_AntSignal" in rt.fields else None
    except Exception:
        return None

def timestamp_to_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(float(ts))

# ---------- Core classes ----------
class DeauthEvent:
    def __init__(self, timestamp: float, src_mac: str, dst_mac: str, bssid: str,
                 reason_code: Optional[int], rssi: Optional[int], seq_num: Optional[int],
                 frame_type: str):
        self.timestamp = float(timestamp)
        self.src_mac = src_mac or "unknown"
        self.dst_mac = dst_mac or "unknown"
        self.bssid = bssid or "unknown"
        self.reason_code = reason_code
        self.rssi = rssi
        self.seq_num = seq_num
        self.frame_type = frame_type

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "datetime": timestamp_to_dt(self.timestamp).isoformat(),
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "bssid": self.bssid,
            "reason_code": self.reason_code,
            "rssi": self.rssi,
            "seq_num": self.seq_num,
            "frame_type": self.frame_type
        }

class WiFiDeauthDetector:
    def __init__(self, config: Dict = None):
        self.config = {**DEFAULTS, **(config or {})}
        logging.basicConfig(level=getattr(logging, self.config.get("log_level", "INFO")),
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger("WiFiDeauthDetector")
        self.events: List[DeauthEvent] = []
        self.ap_info: Dict[str, Dict] = {}
        self.stats = {"total_frames": 0, "deauth_frames": 0, "disassoc_frames": 0,
                      "unique_sources": set(), "unique_destinations": set(), "timespan": None}

    def load_pcap_stream(self, pcap_file: str) -> bool:
        """Stream-parse pcap to extract management deauth/disassoc events and beacons."""
        self.logger.info(f"Streaming PCAP: {pcap_file}")
        try:
            with PcapReader(pcap_file) as reader:
                for i, pkt in enumerate(reader):
                    self.stats["total_frames"] += 1
                    if i % 20000 == 0 and i > 0:
                        self.logger.info(f"Processed {i} packets...")
                    if not pkt.haslayer(Dot11):
                        continue
                    dot11 = pkt.getlayer(Dot11)
                    ts = float(getattr(pkt, "time", 0.0))
                    rssi = safe_rssi_from_radiotap(pkt)
                    # deauth
                    if pkt.haslayer(Dot11Deauth):
                        de = pkt.getlayer(Dot11Deauth)
                        ev = DeauthEvent(ts, dot11.addr2, dot11.addr1, dot11.addr3,
                                         getattr(de, "reason", None), rssi, getattr(dot11, "SC", None), "deauth")
                        self.events.append(ev)
                        self.stats["deauth_frames"] += 1
                        self.stats["unique_sources"].add(ev.src_mac); self.stats["unique_destinations"].add(ev.dst_mac)
                    # disassoc
                    elif pkt.haslayer(Dot11Disas):
                        dis = pkt.getlayer(Dot11Disas)
                        ev = DeauthEvent(ts, dot11.addr2, dot11.addr1, dot11.addr3,
                                         getattr(dis, "reason", None), rssi, getattr(dot11, "SC", None), "disassoc")
                        self.events.append(ev)
                        self.stats["disassoc_frames"] += 1
                        self.stats["unique_sources"].add(ev.src_mac); self.stats["unique_destinations"].add(ev.dst_mac)
                    elif pkt.haslayer(Dot11Beacon):
                        beacon = pkt.getlayer(Dot11Beacon)
                        bssid = dot11.addr3
                        if bssid and bssid not in self.ap_info:
                            ssid = None
                            try:
                                ssid = beacon.info.decode(errors="ignore")
                            except Exception:
                                ssid = None
                            self.ap_info[bssid] = {"ssid": ssid, "first_seen": ts}
            if self.events:
                ts_list = [e.timestamp for e in self.events]
                self.stats["timespan"] = (min(ts_list), max(ts_list))
            self.logger.info(f"Loaded {len(self.events)} deauth/disassoc events from {self.stats['total_frames']} frames")
            return True
        except Exception as e:
            self.logger.error(f"Error reading PCAP: {e}")
            return False

    # ---------- Efficient sliding window rate detection ----------
    def detect_rate_attacks(self) -> Dict:
        cfg = self.config
        window_s = cfg["time_window_seconds"]
        threshold = cfg["deauth_threshold"]

        results = {"suspicious_sources": [], "rate_violations": []}
        if not self.events:
            return results

        # Group timestamps by source (only timestamps needed)
        source_times = defaultdict(list)
        for ev in self.events:
            source_times[ev.src_mac].append(ev.timestamp)

        for src, times in source_times.items():
            if len(times) < threshold:
                continue
            times.sort()
            dq = deque()
            for t in times:
                dq.append(t)
                # pop from left until window satisfied
                while dq and (t - dq[0]) > window_s:
                    dq.popleft()
                if len(dq) >= threshold:
                    # record violation window (start->end)
                    start = dq[0]; end = dq[-1]
                    unique_targets = len({e.dst_mac for e in self.events if e.src_mac == src and start <= e.timestamp <= end})
                    results["suspicious_sources"].append(src)
                    results["rate_violations"].append({
                        "source": src, "count": len(dq),
                        "window_start": timestamp_to_dt(start), "window_end": timestamp_to_dt(end),
                        "unique_targets": unique_targets
                    })
                    break
        return results

    def detect_bursts(self) -> Dict:
        cfg = self.config
        burst_w = cfg["burst_window_seconds"]
        burst_thr = cfg["burst_threshold"]
        results = {"burst_sources": [], "burst_periods": []}
        if not self.events:
            return results
        source_times = defaultdict(list)
        for ev in self.events:
            source_times[ev.src_mac].append(ev.timestamp)
        for src, times in source_times.items():
            times.sort()
            dq = deque()
            for t in times:
                dq.append(t)
                while dq and (t - dq[0]) > burst_w:
                    dq.popleft()
                if len(dq) >= burst_thr:
                    start = dq[0]; end = dq[-1]
                    unique_targets = len({e.dst_mac for e in self.events if e.src_mac == src and start <= e.timestamp <= end})
                    results["burst_sources"].append(src)
                    results["burst_periods"].append({
                        "source": src,
                        "start_time": timestamp_to_dt(start),
                        "end_time": timestamp_to_dt(end),
                        "event_count": len(dq),
                        "unique_targets": unique_targets
                    })
                    # skip forward past this burst to reduce duplicates
                    # find first index > end
                    break
        return results

    def detect_spoofing(self) -> Dict:
        results = {"rssi_anomalies": [], "sequence_anomalies": []}
        src_rssi = defaultdict(list)
        src_seq = defaultdict(list)
        for e in self.events:
            if e.rssi is not None:
                src_rssi[e.src_mac].append(e.rssi)
            if e.seq_num is not None:
                src_seq[e.src_mac].append(e.seq_num)
        for src, rlist in src_rssi.items():
            if len(rlist) < 2:
                continue
            rrange = max(rlist) - min(rlist)
            if rrange > self.config["min_rssi_change"]:
                results["rssi_anomalies"].append({"source": src, "rssi_range": rrange, "min": min(rlist), "max": max(rlist), "samples": len(rlist)})
        for src, slist in src_seq.items():
            cnts = defaultdict(int)
            for s in slist:
                cnts[s] += 1
            reps = [(s,c) for s,c in cnts.items() if c >= self.config["sequence_repeat_threshold"]]
            if reps:
                results["sequence_anomalies"].append({"source": src, "repeats": reps})
        return results

    def statistical_detect(self) -> Dict:
        results = {"anomalous_sources": [], "z_scores": {}, "baseline_stats": {}}
        if len(self.events) < 10:
            return results
        df = pd.DataFrame([{"timestamp": timestamp_to_dt(e.timestamp), "src": e.src_mac} for e in self.events])
        df.set_index("timestamp", inplace=True)
        src_counts = df.groupby(['src', pd.Grouper(freq='1Min')]).size().unstack(fill_value=0)
        for src in src_counts.index:
            vals = src_counts.loc[src].values
            mean = vals.mean(); std = vals.std()
            if std > 0:
                z = np.abs((vals - mean) / std)
                maxz = z.max()
                results["z_scores"][src] = float(maxz)
                if maxz > self.config["statistical_z_threshold"]:
                    results["anomalous_sources"].append({"source": src, "max_z": float(maxz), "mean_rate": float(mean), "max_rate": float(vals.max())})
        results["baseline_stats"] = {
            "total_events": len(self.events),
            "avg_events_per_minute": len(self.events) / max(1, len(src_counts.columns)),
            "unique_sources": len(self.stats["unique_sources"]),
            "unique_destinations": len(self.stats["unique_destinations"])
        }
        return results

    def analyze(self):
        self.logger.info("Running analysis...")
        rate = self.detect_rate_attacks()
        burst = self.detect_bursts()
        spoof = self.detect_spoofing()
        stat = self.statistical_detect()
        suspicious = set(rate["suspicious_sources"]) | set(burst["burst_sources"]) | {r["source"] for r in stat.get("anomalous_sources", [])}
        # simple anomaly score
        score = 0.0
        score += min(30, len(rate["suspicious_sources"]) * 10)
        score += min(25, len(spoof["rssi_anomalies"]) * 8 + len(spoof["sequence_anomalies"]) * 5)
        score += min(25, len(burst["burst_sources"]) * 8)
        if stat["anomalous_sources"]:
            score += min(20, max(a["max_z"] for a in stat["anomalous_sources"]) * 4)
        score = min(100.0, score)
        results = {
            "total_deauths": len(self.events),
            "suspicious_sources": sorted(list(suspicious)),
            "rate": rate, "burst": burst, "spoof": spoof, "statistical": stat,
            "anomaly_score": score
        }
        return results

    # ---------- PCAP slice export ----------
    def export_pcap_slices(self, pcap_file: str, windows: List[Tuple[datetime, datetime]], output_dir: Optional[str] = None) -> List[str]:
        """Export PCAP slices (raw packets from original PCAP) that fall within windows.
        Returns list of saved filenames."""
        output_dir = (output_dir or self.config["output_dir"])
        os.makedirs(output_dir, exist_ok=True)
        saved = []
        # read full pcap once (rdpcap may require memory; for very large files, implement streaming + write)
        self.logger.info("Loading original PCAP for slicing (rdpcap). This may use memory for large files.")
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            self.logger.error(f"Failed to read pcap for slicing: {e}")
            return saved
        for idx, (start_dt, end_dt) in enumerate(windows, 1):
            start_ts = start_dt.timestamp()
            end_ts = end_dt.timestamp()
            slice_pkts = [p for p in packets if getattr(p, "time", 0.0) >= start_ts and getattr(p, "time", 0.0) <= end_ts]
            fname = os.path.join(output_dir, f"slice_{idx}_{start_dt.strftime('%Y%m%dT%H%M%S')}_to_{end_dt.strftime('%Y%m%dT%H%M%S')}.pcap")
            if slice_pkts:
                wrpcap(fname, slice_pkts)
                saved.append(fname)
                self.logger.info(f"Saved slice: {fname} ({len(slice_pkts)} packets)")
            else:
                self.logger.info(f"No packets found in window {start_dt} - {end_dt}, skipping slice file.")
        return saved

    # ---------- Visualizations (basic) ----------
    def generate_visualizations(self, output_dir: Optional[str] = None):
        if not self.config["visualization"] or not self.events:
            return False
        output_dir = (output_dir or self.config["output_dir"])
        os.makedirs(output_dir, exist_ok=True)
        df = pd.DataFrame([{"ts": timestamp_to_dt(e.timestamp), "src": e.src_mac, "type": e.frame_type, "rssi": e.rssi} for e in self.events])
        df.set_index("ts", inplace=True)
        # timeline
        try:
            events_per_min = df.resample("1Min").size()
            plt.figure(figsize=(12,4)); events_per_min.plot(title="Deauth/Disassoc Events per Minute"); plt.tight_layout()
            plt.savefig(os.path.join(output_dir, "timeline.png"), dpi=200); plt.close()
            # heatmap-like table: top source->dest counts
            sd = defaultdict(int)
            for e in self.events:
                sd[(e.src_mac[-8:], e.dst_mac[-8:])] += 1
            # quick bar: top sources
            src_counts = pd.Series([v for (k,v) in [(s, sum(1 for e in self.events if e.src_mac==s)) for s in set([e.src_mac for e in self.events])]])
            top_sources = sorted(((s, sum(1 for e in self.events if e.src_mac==s)) for s in set([e.src_mac for e in self.events])), key=lambda x: x[1], reverse=True)[:15]
            if top_sources:
                labels, counts = zip(*top_sources)
                plt.figure(figsize=(8,6)); plt.barh(range(len(counts)), counts); plt.yticks(range(len(labels)), [l[-8:] for l in labels]); plt.title("Top sources (last 8 chars)"); plt.tight_layout()
                plt.savefig(os.path.join(output_dir, "top_sources.png"), dpi=200); plt.close()
            return True
        except Exception as e:
            self.logger.warning(f"Visualization generation failed: {e}")
            return False

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Passive Wi-Fi Deauth/Disassoc detector (offline; read-only)")
    parser.add_argument("-f", "--file", required=True, help="Input PCAP file")
    parser.add_argument("--threshold", type=int, default=DEFAULTS["deauth_threshold"], help="Deauths per window threshold")
    parser.add_argument("--window", type=int, default=DEFAULTS["time_window_seconds"], help="Sliding window (seconds)")
    parser.add_argument("--burst-threshold", type=int, default=DEFAULTS["burst_threshold"], help="Burst threshold")
    parser.add_argument("--no-viz", action="store_true", help="Disable visualizations")
    parser.add_argument("--output", default=DEFAULTS["output_dir"], help="Output directory")
    parser.add_argument("--export-json", action="store_true", help="Export analysis as JSON")
    parser.add_argument("--export-slices", action="store_true", help="Export PCAP slices for detected windows")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    cfg = {
        "deauth_threshold": args.threshold,
        "time_window_seconds": args.window,
        "burst_threshold": args.burst_threshold,
        "visualization": not args.no_viz,
        "output_dir": args.output,
        "log_level": "DEBUG" if args.verbose else "INFO"
    }

    detector = WiFiDeauthDetector(cfg)
    ok = detector.load_pcap_stream(args.file)
    if not ok:
        print("Failed to load pcap file.")
        return
    if not detector.events:
        print("No deauth/disassoc events found.")
        return

    results = detector.analyze()
    outdir = cfg["output_dir"]
    os.makedirs(outdir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # text summary
    summary_path = os.path.join(outdir, f"summary_{timestamp}.txt")
    with open(summary_path, "w") as f:
        f.write("Wi-Fi Deauth Analysis Summary\n")
        f.write("="*60 + "\n")
        f.write(f"Total events: {results['total_deauths']}\n")
        f.write(f"Anomaly score: {results['anomaly_score']:.1f}\n")
        f.write(f"Suspicious sources: {len(results['suspicious_sources'])}\n\n")
        f.write("Top recommendations (example):\n")
        f.write("- Enable 802.11w (PMF) where supported.\n- Implement AP-side management frame rate limiting.\n- Integrate alerts with SIEM and perform forensic slice export.\n")
    print(f"Summary written to: {summary_path}")

    if args.export_json:
        json_path = os.path.join(outdir, f"analysis_{timestamp}.json")
        with open(json_path, "w") as j:
            json.dump(results, j, indent=2, default=str)
        print(f"JSON report: {json_path}")

    # export slices if requested (use windows from rate + burst)
    if args.export_slices:
        windows = []
        for v in results["rate"]["rate_violations"]:
            windows.append((v["window_start"], v["window_end"]))
        for b in results["burst"]["burst_periods"]:
            windows.append((b["start_time"], b["end_time"]))
        if windows:
            slices = detector.export_pcap_slices(args.file, windows, outdir)
            print(f"Exported {len(slices)} pcap slice(s)")
        else:
            print("No suspicious windows to slice.")

    if cfg["visualization"]:
        if detector.generate_visualizations(outdir):
            print(f"Visualizations saved to {outdir}")
        else:
            print("Visualization generation failed or skipped.")

    print("Analysis complete.")

if __name__ == "__main__":
    main()

