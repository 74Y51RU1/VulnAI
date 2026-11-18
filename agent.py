import json
import os
from ollama import Client

# Configure the Ollama server using an environment variable.
# Defaults to localhost when Ollama runs on the same machine.
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

client = Client(host=OLLAMA_HOST)

MODEL = "qwen3:4b"

SYSTEM_PROMPT = """
You are VulnAI, an evidence-based cybersecurity assessment assistant.

Analyse ONLY the supplied scan evidence.

ACCURACY RULES:
- Never invent vulnerabilities, services, versions, or evidence.
- Never claim a vulnerability is confirmed without direct proof.
- An open TCP port is an observation, not a vulnerability.
- Nmap service names and versions are unverified unless supported
  by additional evidence.
- A missing security header is a configuration observation,
  not proof of exploitation.
- Missing CSP does not prove cross-site scripting (XSS).
- Missing X-Frame-Options does not prove clickjacking.
- A frame-ancestors CSP directive may provide framing protection.
- Missing X-Content-Type-Options does not prove MIME sniffing attacks.
- Missing HSTS does not prove a vulnerability. Recommend reviewing
  HSTS only when appropriate for the HTTPS deployment.
- Access-Control-Allow-Origin: * does not alone prove an
  exploitable CORS vulnerability.
- No Set-Cookie header means no cookies were observed in that
  response. It does not mean cookies are insecure.
- Do not assume authentication, sensitive information exposure,
  or successful exploitation without evidence.
- Do not mistake HTTP 200 for proof that a site is secure.
- Do not recommend changing configurations without sufficient
  context.
- Recommend only safe, read-only follow-up checks.
- Do not suggest exploitation or intrusive testing.
- Clearly distinguish observations from potential risks.
- Do not reproduce the entire scan evidence.
- Do not include internal reasoning or planning.

OUTPUT RULES:
Return a JSON object containing exactly these five fields:

observations:
  A concise paragraph of 2-3 sentences describing observed facts.

potential_risks:
  A concise paragraph describing plausible, conditional risks.
  If no specific risk is supported, say:
  "No specific security risk can be established from this evidence."

recommended_checks:
  An array containing 0-2 short, safe, read-only verification steps.
  Each array item must contain one complete recommendation.

remediation:
  An array containing 0-2 evidence-based recommendations.
  Do not recommend fixes for unconfirmed vulnerabilities.
  If remediation cannot be justified, return an empty array.

conclusion:
  A short statement explaining whether a vulnerability was confirmed.
  If none, write exactly:
  "No specific vulnerabilities confirmed by this scan."

Use professional, clear English.
Be concise and avoid exaggerated risk statements.
"""


REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "observations": {"type": "string"},
        "potential_risks": {"type": "string"},
        "recommended_checks": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 2
        },
        "remediation": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 2
        },
        "conclusion": {"type": "string"}
    },
    "required": [
        "observations",
        "potential_risks",
        "recommended_checks",
        "remediation",
        "conclusion"
    ],
    "additionalProperties": False
}


def format_steps(items, empty_message):
    """Format structured recommendations as Markdown bullets."""

    if not isinstance(items, list):
        return empty_message

    cleaned = [
        item.strip()
        for item in items
        if isinstance(item, str) and item.strip()
    ]

    if not cleaned:
        return empty_message

    return "\n".join(f"- {item}" for item in cleaned[:2])


def analyse_finding(evidence):
    """Analyse supplied evidence and return formatted Markdown."""

    if not isinstance(evidence, str):
        evidence = json.dumps(evidence, indent=2, default=str)

    response = client.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": evidence}
        ],
        format=REPORT_SCHEMA,
        options={
            "temperature": 0,
            "num_predict": 700,
            "num_ctx": 4096
        },
        think=False
    )

    data = json.loads(response.message.content)

    observations = data["observations"].strip()
    potential_risks = data["potential_risks"].strip()

    recommended_checks = format_steps(
        data["recommended_checks"],
        "No additional verification steps identified."
    )

    remediation = format_steps(
        data["remediation"],
        "Further verification is needed before recommending remediation."
    )

    # Keep the final conclusion conservative.
    # The language model must not independently certify a vulnerability.
    conclusion = (
        "No specific vulnerabilities confirmed by this scan. "
        "Any suspected issue requires independent verification."
    )

    return (
        f"### Observations\n\n{observations}\n\n"
        f"### Potential Risks\n\n{potential_risks}\n\n"
        f"### Recommended Checks\n\n{recommended_checks}\n\n"
        f"### Remediation\n\n{remediation}\n\n"
        f"### Conclusion\n\n{conclusion}"
    )
