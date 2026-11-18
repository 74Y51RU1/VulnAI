# 🛡️ VulnAI

**AI-Assisted Infrastructure and Website Security Assessment Tool**

VulnAI is a Python-based cybersecurity assessment application that combines network scanning, HTTP security configuration checks, and local AI-assisted analysis in an interactive Streamlit dashboard.

The project aims to make security assessment findings easier to understand, compare, and document while maintaining a clear distinction between observed evidence, potential risks, and confirmed vulnerabilities.

## Features

### Infrastructure Assessment
- Performs Nmap-based TCP port and service discovery on authorised laboratory targets.
- Identifies observed open ports and reported services.
- Generates evidence-based security observations.

### Web Assessment
- Assesses authorised local web applications.
- Combines Nmap evidence with HTTP security configuration checks.
- Reviews security headers, cookies, and CORS-related configurations.

### Public Website Assessment
- Performs read-only HTTP security configuration checks.
- Does not perform Nmap scanning or exploitation.
- Reports observable configuration findings without claiming comprehensive security coverage.

### AI-Assisted Analysis
- Integrates Ollama with the `qwen3:4b` language model.
- Analyses collected assessment evidence.
- Produces observations, potential risks, recommended verification steps, remediation guidance, and conclusions.
- Distinguishes unverified findings from confirmed vulnerabilities.

### Assessment History and Comparison
- Stores assessment results locally using SQLite.
- Allows users to review previous assessments.
- Compares infrastructure assessments to identify observed port and service changes.
- Compares website assessments to identify changes in security findings.

### PDF Reporting
- Generates downloadable security assessment reports.
- Includes assessment summaries, technical evidence, AI analysis, and limitations.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application development |
| Streamlit | Interactive dashboard |
| Nmap | Infrastructure and local web scanning |
| Ollama | Local AI inference |
| Qwen3 4B | AI-assisted security analysis |
| Requests | HTTP requests and configuration checks |
| SQLite | Local assessment history |
| ReportLab | PDF report generation |
| OWASP Juice Shop | Authorised web application testing environment |

## Architecture

```text
                  User
                   |
             Streamlit Dashboard
                   |
          Assessment Mode Selection
                   |
       +-----------+-----------+
       |           |           |
 Infrastructure   Web       Public Website
 Assessment    Assessment    Assessment
       |           |           |
     Nmap      Nmap + HTTP   HTTP Checks
       |           |           |
       +-----------+-----------+
                   |
          Structured Evidence
                   |
            Security Checks
                   |
          Ollama / Qwen3 4B
                   |
         AI-Assisted Analysis
                   |
       +-----------+-----------+
       |           |           |
   Dashboard    SQLite       PDF Report
    Results     History      Generation
```

## Installation

### Prerequisites

- Python 3
- Nmap
- Ollama
- Qwen3 4B model

### 1. Clone the Repository

```bash
git clone https://github.com/74Y51RU1/VulnAI.git
cd VulnAI
```

Replace `74Y51RU1` with your GitHub username.

### 2. Create a Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Nmap

On Kali Linux or another Debian-based distribution:

```bash
sudo apt install nmap
```

### 5. Configure Ollama

Install Ollama from https://ollama.com and download the model:

```bash
ollama pull qwen3:4b
```

By default, VulnAI connects to Ollama at:

```text
http://localhost:11434
```

If Ollama runs on another machine, configure the server address before launching VulnAI:

```bash
export OLLAMA_HOST="http://YOUR_OLLAMA_SERVER_IP:11434"
```

Ensure that the Ollama server is reachable and configured to accept the intended connection.

### 6. Launch VulnAI

```bash
streamlit run dashboard.py
```

Open the dashboard at:

```text
http://localhost:8501
```

## Testing Environment

VulnAI was developed and tested using:

- Kali Linux in Oracle VirtualBox
- Windows-hosted Ollama
- Qwen3 4B
- OWASP Juice Shop running in Docker
- Local laboratory infrastructure

## Security and Ethical Use

VulnAI is intended for educational purposes and authorised security assessments.

- Only assess systems you own or have explicit permission to test.
- Infrastructure and local web scanning are intended for approved laboratory targets.
- Public website assessments use read-only HTTP configuration checks.
- Assessment findings are not automatically confirmed vulnerabilities.
- AI-generated analysis should be independently reviewed.

VulnAI is not a replacement for comprehensive penetration testing or professional security assessment.

## Limitations

- Infrastructure scanning covers a selected set of TCP ports rather than every possible port.
- Nmap service identification may require independent verification.
- HTTP configuration findings do not establish exploitability.
- Public website assessments provide limited configuration visibility.
- AI-generated recommendations may be incomplete or inaccurate.
- Assessment history is stored locally.

## Future Improvements

- Expanded automated testing
- Additional security configuration checks
- Improved assessment visualisations
- Enhanced reporting and comparison capabilities

## Author

Developed as a personal cybersecurity portfolio project to demonstrate practical skills in Python development, network security assessment, web security analysis, AI integration, and security reporting.
