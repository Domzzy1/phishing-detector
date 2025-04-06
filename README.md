Phishing Detector
Description

The Phishing Detector is a Python-based tool designed to analyze URLs and identify potential phishing attempts. By examining various components of a URL such as the domain, subdomains, TLDs (Top-Level Domains), and query parameters, the tool highlights any suspicious activity that could indicate a phishing site.
Key Features:

TLD Analysis: Detects suspicious and commonly used TLDs (e.g., .tk, .ga, .gq) that are often associated with phishing sites.

Typosquatting Detection: Identifies domain names that closely resemble trusted brands and are often used for phishing attacks.

Subdomain Examination: Analyzes subdomains for potentially malicious or excessive subdomain use.

Query Parameters Check: Scans URL query parameters for suspicious keywords like "id", "auth", or "token" that may suggest malicious intent.

Phishing Risk Detection: Flags URLs containing common phishing keywords such as "login", "verify", or "signin".

How It Works:

URL Parsing: The tool uses Python's urllib and tldextract libraries to break down the URL into its components: domain, subdomain, path, and query parameters.

Detection Logic: The tool cross-references these components with a predefined list of suspicious TLDs, known typosquatted domains, and other malicious indicators.

Phishing Alert: If a URL shows signs of phishing (based on any of the checks), a warning is displayed to inform the user.

How to Use:

Clone or download the repository.

Run the Detect.py script.

Input a URL when prompted, and the tool will analyze it and display the results.

Installation:

Make sure you have Python 3 installed. You can install the required libraries with:

pip install -r requirements.txt

Use Case:

Ideal for security analysts, web developers, and cybersecurity enthusiasts looking to automate the detection of phishing websites.

Helps in preventing phishing attacks by quickly flagging suspicious URLs in emails, messages, or websites.
