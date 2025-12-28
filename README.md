# Cybersecurity Suite

A Python-based security analysis tool for detecting suspicious network behavior, particularly SSH brute-force attacks and authentication anomalies.

## Features

- **Brute-Force Detection**: Analyzes SSH authentication logs to identify and flag suspicious login patterns
- **Configurable Thresholds**: Customize detection sensitivity with configurable attempt limits and time windows
- **IP-based Analysis**: Groups attempts by IP address to detect coordinated attacks
- **User-friendly GUI**: Tkinter-based interface for easy log file selection and analysis

## Installation

1. Clone this repository
2. Ensure you have Python 3.x installed
3. No external dependencies required (uses built-in libraries)

## Usage

Run the main application:

```bash
python main.py
```

currently, the GUI allows you to:

Select SSH log files for analysis
View brute-force detection results
Analyze authentication attempts by IP and username

This is very early days and I will update this frequently
