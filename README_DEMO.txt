DIGITAL FORENSICS INVESTIGATION TOOLKIT - FINAL DEMO

This educational Python toolkit performs read-only analysis of a selected folder.
Requires Python 3.9+; no third-party packages.

Mac terminal:
  cd /path/to/Forensics_Final_Project
  python3 forensics_toolkit.py sample_evidence --events sample_events.csv --output demo_results

Windows PowerShell:
  cd C:\path\to\Forensics_Final_Project
  py forensics_toolkit.py sample_evidence --events sample_events.csv --output demo_results

Open demo_results/report.json and demo_results/timeline.csv.
Event CSV rows are simulated Windows event records, NOT live Windows Event Log acquisition.
A flagged extension is not a malware verdict. Timestamps are metadata, not definitive evidence of an action.
Do not modify original evidence when comparing hashes.
