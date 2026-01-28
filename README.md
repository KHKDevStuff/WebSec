# WebScrub

A Cyberpunk-themed Web Vulnerability Scanner using Python (Flask), Requests, BeautifulSoup4, and DNSPython.

## Installation

1.  Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  Run the application using the batch script:
    ```bash
    run_scanner.bat
    ```
    Or manually:
    ```bash
    python app.py
    ```
2.  Open your browser to `http://127.0.0.1:5000`.

## Features
*   **Web Vulnerability Scanning**: Simple XSS and Header analysis.
*   **DNS Reconnaissance**: Fetches A, MX, NS, and TXT records.
*   **SSL/TLS Verification**: Checks for valid certificates.
*   **Information Leakage**: Scrapes HTML comments for sensitive notes.
*   **PDF Export**: Download professional security reports.
