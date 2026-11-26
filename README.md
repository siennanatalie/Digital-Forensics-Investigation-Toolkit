# Digital-Forensics-Investigation-Toolkit

## Project Overview

The Digital Forensics Investigation Toolkit is a Python-based command-line application developed as an individual cybersecurity project. The toolkit assists with basic digital forensic investigations by examining files, verifying evidence integrity through SHA-256 hashing, identifying potentially suspicious files, and organizing collected evidence into investigation reports.

## Features

- File metadata analysis
- SHA-256 hash generation
- Suspicious file extension identification
- Windows security event CSV analysis
- Chronological timeline generation
- JSON investigation reporting
- CSV timeline reporting
- Basic evidence protection and error handling

## Requirements

- Python 3
- Windows, macOS, or Linux
- No additional Python packages required

The toolkit uses Python's built-in libraries, so additional dependencies do not need to be installed.

## Installation

Download or clone this repository and open the project folder in Terminal or Command Prompt.

Verify that Python is installed using:

`python3 --version`

## Running the Toolkit

Run the following command from the project directory:

`python3 forensics_toolkit.py sample_evidence --events sample_events.csv --output demo_results`

On Windows, use `python` instead of `python3` if necessary.

## Investigation Results

After running the toolkit, the demo_results directory will contain:

- report.json: Contains file metadata, SHA-256 hashes, suspicious file flags, Windows events, and investigation findings.
- timeline.csv: Contains a chronological timeline of collected file and event information.

## Demonstration Scenario

The project includes three harmless sample evidence files and three simulated Windows security events. The demonstration illustrates how the toolkit can analyze files, calculate hashes, flag potentially suspicious file extensions, and organize evidence into a timeline.

## Security Considerations

The toolkit opens evidence files in read mode and does not execute suspicious files. Generated reports are stored separately from the original evidence directory to reduce the possibility of accidental evidence modification.

SHA-256 hashes can be compared against previously recorded values to help verify evidence integrity.

## Limitations

The toolkit is designed for educational purposes and basic forensic analysis. It does not directly collect Windows Event Logs, perform advanced malware analysis, recover deleted files, or create forensic disk images.

Windows event information used in the demonstration is simulated and provided through a CSV file.

## Future Improvements

Potential future improvements include native Windows Event Log analysis, automated hash comparison, chain-of-custody logging, a graphical user interface, and additional forensic artifact analysis.

## Project Purpose

This project was developed as an individual university cybersecurity project to demonstrate fundamental digital forensic techniques and the importance of evidence integrity during security investigations.
