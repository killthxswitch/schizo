import json

def generate_report_to_json(results, output_file="scan_report.json"):
    """Export the scan results to a JSON file."""
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Report saved to {output_file}")
