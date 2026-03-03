"""
Process PCAP Files - CLI Tool for Network Traffic Analysis

This tool processes PCAP files through the IDS system to detect intrusions.

Usage:
    python process_pcap.py --pcap traffic.pcap
    python process_pcap.py --pcap traffic.pcap --output results.json
    python process_pcap.py --pcap traffic.pcap --report
"""

import argparse
import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Implementation.src.IDS.IDS import IDSPredictor
from Implementation.src.IDS.FlowExtractor import check_cicflowmeter_installation, print_installation_instructions


def print_banner():
    """Print tool banner."""
    banner = """
╔═══════════════════════════════════════════════╗
║     SOC Network Traffic Analyzer (PCAP)      ║
║         Powered by CICFlowMeter + IDS         ║
╚═══════════════════════════════════════════════╝
"""
    print(banner)


def print_summary(result: dict):
    """
    Print a human-readable summary of analysis results.
    
    Args:
        result: Analysis result dictionary
    """
    print("\n" + "="*60)
    print("   ANALYSIS SUMMARY")
    print("="*60)
    
    print(f"\n📁 PCAP File: {result['pcap_file']}")
    print(f"📊 Total Flows: {result['total_flows']}")
    print(f"✅ Benign Flows: {result['benign_flows']}")
    print(f"⚠️  Attacks Detected: {result['attacks_detected']}")
    
    if result['attack_summary']:
        print(f"\n🚨 ATTACK BREAKDOWN:")
        print("-" * 60)
        for attack_type, count in sorted(result['attack_summary'].items(), 
                                         key=lambda x: x[1], reverse=True):
            percentage = (count / result['total_flows']) * 100
            print(f"   {attack_type:20s}: {count:5d} flows ({percentage:5.2f}%)")
    
    print("\n" + "="*60)
    
    # Show top malicious flows
    malicious_flows = [p for p in result['predictions'] if p.get('predicted_label') != 'BENIGN']
    if malicious_flows:
        print("\n🔍 TOP MALICIOUS FLOWS:")
        print("-" * 60)
        
        # Sort by confidence
        top_malicious = sorted(malicious_flows, key=lambda x: x.get('confidence', 0), reverse=True)[:5]
        
        for i, flow in enumerate(top_malicious, 1):
            print(f"\n   #{i} Flow Index: {flow.get('flow_index', 'N/A')}")
            print(f"      Attack Type: {flow.get('predicted_label', 'UNKNOWN')}")
            print(f"      Confidence: {flow.get('confidence', 0)*100:.2f}%")


def save_results(result: dict, output_path: str):
    """
    Save analysis results to JSON file.
    
    Args:
        result: Analysis result dictionary
        output_path: Path to save JSON file
    """
    # Convert DataFrame to dict for JSON serialization
    output_data = result.copy()
    if 'flows' in output_data:
        output_data['flows'] = output_data['flows'].to_dict(orient='records')
    
    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=2, default=str)
    
    print(f"\n💾 Results saved to: {output_path}")


def generate_report(result: dict, output_path: str = None):
    """
    Generate a detailed markdown report.
    
    Args:
        result: Analysis result dictionary
        output_path: Path to save report (default: auto-generated)
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"pcap_analysis_report_{timestamp}.md"
    
    report_lines = []
    report_lines.append("# Network Traffic Analysis Report\n")
    report_lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report_lines.append(f"**PCAP File:** `{result['pcap_file']}`\n")
    report_lines.append("\n---\n")
    
    report_lines.append("## Executive Summary\n")
    report_lines.append(f"- **Total Flows Analyzed:** {result['total_flows']}\n")
    report_lines.append(f"- **Benign Traffic:** {result['benign_flows']} flows\n")
    report_lines.append(f"- **Attacks Detected:** {result['attacks_detected']} flows\n")
    
    if result['attack_summary']:
        report_lines.append("\n## Attack Breakdown\n")
        report_lines.append("| Attack Type | Count | Percentage |\n")
        report_lines.append("|-------------|-------|------------|\n")
        
        for attack_type, count in sorted(result['attack_summary'].items(), 
                                         key=lambda x: x[1], reverse=True):
            percentage = (count / result['total_flows']) * 100
            report_lines.append(f"| {attack_type} | {count} | {percentage:.2f}% |\n")
    
    report_lines.append("\n## Network Statistics\n")
    stats = result['statistics']
    report_lines.append(f"- **Unique Source IPs:** {stats.get('unique_src_ips', 'N/A')}\n")
    report_lines.append(f"- **Unique Destination IPs:** {stats.get('unique_dst_ips', 'N/A')}\n")
    report_lines.append(f"- **Total Bytes:** {stats.get('total_bytes', 'N/A'):,}\n")
    report_lines.append(f"- **Total Packets:** {stats.get('total_packets', 'N/A'):,}\n")
    
    # Malicious flows details
    malicious_flows = [p for p in result['predictions'] if p.get('predicted_label') != 'BENIGN']
    if malicious_flows:
        report_lines.append("\n## Detailed Malicious Flows\n")
        
        for flow in malicious_flows[:20]:  # Top 20
            report_lines.append(f"\n### Flow #{flow.get('flow_index', 'N/A')}\n")
            report_lines.append(f"- **Attack Type:** {flow.get('predicted_label', 'UNKNOWN')}\n")
            report_lines.append(f"- **Confidence:** {flow.get('confidence', 0)*100:.2f}%\n")
    
    report_lines.append("\n---\n")
    report_lines.append("*Report generated by SOC PCAP Analyzer*\n")
    
    with open(output_path, 'w') as f:
        f.writelines(report_lines)
    
    print(f"\n📄 Report saved to: {output_path}")


def main():
    """Main entry point for CLI tool."""
    parser = argparse.ArgumentParser(
        description='Analyze PCAP files for network intrusions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Process a PCAP file:
    python process_pcap.py --pcap traffic.pcap
  
  Save results to JSON:
    python process_pcap.py --pcap traffic.pcap --output results.json
  
  Generate detailed report:
    python process_pcap.py --pcap traffic.pcap --report
        """
    )
    
    parser.add_argument('--pcap', type=str, required=True,
                        help='Path to PCAP file to analyze')
    parser.add_argument('--output', type=str,
                        help='Path to save JSON results (optional)')
    parser.add_argument('--report', action='store_true',
                        help='Generate detailed markdown report')
    parser.add_argument('--report-file', type=str,
                        help='Path for markdown report (default: auto-generated)')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress summary output (only save to file)')
    
    args = parser.parse_args()
    
    # Print banner
    if not args.quiet:
        print_banner()
    
    # Check if CICFlowMeter is installed
    if not check_cicflowmeter_installation():
        print("\n❌ CICFlowMeter is not installed!")
        print_installation_instructions()
        sys.exit(1)
    
    # Check if PCAP file exists
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"\n❌ Error: PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    try:
        # Initialize IDS
        print(f"\n🔧 Initializing IDS...")
        predictor = IDSPredictor()
        
        # Process PCAP
        print(f"📦 Processing PCAP file: {args.pcap}")
        print("   This may take a while for large files...\n")
        
        result = predictor.predict_from_pcap(str(pcap_path))
        
        # Print summary
        if not args.quiet:
            print_summary(result)
        
        # Save JSON results
        if args.output:
            save_results(result, args.output)
        
        # Generate report
        if args.report:
            generate_report(result, args.report_file)
        
        # Exit code based on attacks detected
        if result['attacks_detected'] > 0:
            print(f"\n⚠️  WARNING: {result['attacks_detected']} attacks detected!")
            sys.exit(2)  # Exit code 2 indicates attacks found
        else:
            print("\n✅ No attacks detected. Traffic appears benign.")
            sys.exit(0)
            
    except Exception as e:
        print(f"\n❌ Error processing PCAP: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
