from rules import *
from uagents import Agent, Context, Model
from uagents_core.contrib.protocols.chat import ChatMessage, ChatAcknowledgement
from openai import OpenAI
import os
from type_agent import *

def load_metta_rules():
    rules = {}
    buffer = ""
    for line in rulesMetta.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        buffer += " " + line  # concaténer les lignes multi-lignes
        if buffer.endswith("))"):
            parts = buffer.split('"')
            if len(parts) >= 4:
                vuln = parts[1].strip()
                rec = parts[3].strip()
                rules[vuln] = rec
            else:
                print(f"⚠️ Ligne ignorée (format inattendu): {buffer}")
            buffer = ""  # reset
    return rules

client = OpenAI(
    base_url="https://api.asi1.ai/v1",
    api_key=os.getenv("ASI_API_KEY"),
)

METTA_RULES = load_metta_rules()

reasoner_agent = Agent()

def _map_check_to_vuln_type(check: str) -> str:
    if not check:
        return "Unknown"
    normalized = check.lower().strip()
    return CHECK_TO_VULN.get(
        normalized,
        normalized.replace("-", " ").title().replace(" ", "")
    )

def _extract_line_from_elements(elements):
    """Récupère la première ligne de code associée à une vulnérabilité"""
    try:
        if elements and isinstance(elements, list):
            sm = elements[0].get("source_mapping", {})
            lines = sm.get("lines", [])
            if isinstance(lines, list) and lines:
                return lines[0]
    except Exception:
        pass
    return None

def parse_vulns_from_slither(slither_data: dict):
    """
    Supporte à la fois :
      - le format custom : {"vulnerabilities": [{type,line,message}]}
      - le format Slither officiel : {"results": {"detectors": [...]}}
    """
    out = []

    if not isinstance(slither_data, dict):
        return out

    # --- Format custom
    vulns_list = slither_data.get("vulnerabilities")
    if isinstance(vulns_list, list):
        for v in vulns_list:
            if not isinstance(v, dict):
                continue
            out.append({
                "type": v.get("type"),
                "line": v.get("line"),
                "detail": v.get("message") or v.get("detail", "")
            })
        return out

    # --- Format Slither standard
    detectors = slither_data.get("results", {}).get("detectors", [])
    if not detectors and "detectors" in slither_data:
        detectors = slither_data["detectors"]

    for d in detectors:
        if not isinstance(d, dict):
            continue
        check = d.get("check", "")
        vtype = _map_check_to_vuln_type(check)
        detail = d.get("description", "")
        line = _extract_line_from_elements(d.get("elements", []))
        out.append({
            "type": vtype,
            "line": line,
            "detail": detail
        })
    return out

def generate_reasoning_with_ai(vulns, solidity_code, user_message):
    # Build prompt without multiline f-strings
    parts = []
    parts.append("You are an advanced smart contract security auditor specialized in Ethereum and Solidity.")
    parts.append("You are analyzing a Solidity codebase and a list of vulnerabilities automatically detected by Slither.")
    parts.append("")
    parts.append("Your mission is to write a clear, technical, and contextualized report that helps the developer fix their code securely.")
    parts.append("")
    parts.append("### Instructions:")
    parts.append("1. For each detected vulnerability:")
    parts.append("   - Explain in detail **why** it is a problem and **where** it occurs in the code.")
    parts.append("   - Reference the exact function or line number when possible.")
    parts.append("   - Include the relevant Solidity code snippet between triple backticks using ```solidity ... ``` for clarity.")
    parts.append("   - Provide a **precise recommendation** on how to fix or mitigate the issue.")
    parts.append("")
    parts.append("2. After listing all vulnerabilities, provide an **overall risk summary**, assessing the general security level of the contract (Low / Medium / High).")
    parts.append("3. If the Slither report shows no issues, still verify the code for potential logic or security flaws and note your findings.")
    parts.append("4. Keep the tone professional and educational, suitable for a security audit report.")
    parts.append("")
    parts.append("### Detected Issues (from Slither):")
    parts.append(json.dumps(vulns, indent=2))
    parts.append("")
    parts.append("### Solidity Code:")
    parts.append("```solidity")
    parts.append(solidity_code or "")
    parts.append("```")
    parts.append("")
    parts.append("### User Context (if any):")
    parts.append(user_message or "None")
    parts.append("")
    parts.append("### Security Rules Knowledge Base (for reference):")
    parts.append(json.dumps(METTA_RULES, indent=2))
    parts.append("")
    parts.append("### Output Format:")
    parts.append("Your final answer must be structured in this format: ")
    parts.append("")
    parts.append("**Vulnerability:** <Name>")
    parts.append("**Severity:** <Low / Medium / High>")
    parts.append("**Explanation:** <Detailed reasoning>")
    parts.append("**Code Example:** ```solidity <relevant code> ```")
    parts.append("**Recommendation:** <Concrete fix or mitigation>")
    parts.append("")
    parts.append("After all vulnerabilities, include:")
    parts.append("**Overall Risk Summary:** <Short summary of total contract risk>")
    parts.append("")
    parts.append("Be concise but thorough. Use markdown formatting for readability and always wrap Solidity code in ```solidity ... ``` blocks.")

    prompt = "\n".join(parts)

    completion = client.chat.completions.create(
        model="asi1-mini",
        messages=[
            {"role": "system", "content": "You are a Solidity security auditor and vulnerability reasoning agent."},
            {"role": "user", "content": prompt},
        ],
    )
    return completion.choices[0].message.content.strip()

@reasoner_agent.on_message(model=AuditReport)
async def handle_audit(ctx: Context, sender: str, msg: AuditReport):
    ctx.logger.info(f"Received audit report for reasoning from {sender}")

    try:
        # Try to parse normally
        slither_data = json.loads(msg.slither)
    except Exception:
        try:
            # If it's a JSON string containing another JSON, unescape once
            slither_data = json.loads(json.loads(msg.slither))
        except Exception as e:
            ctx.logger.error(f"Invalid Slither JSON after double parsing: {e}")
            return

    vulns = parse_vulns_from_slither(slither_data)
    vulnerabilities = []
    suggestions = []
    
    if not vulns:
        ctx.logger.warning("No vulnerabilities detected or parsed from the Slither report.")

    for v in vulns:
        vtype = v.get("type") or "Unknown"
        detail = v.get("detail", "")
        line = v.get("line")

        # --- Appliquer la règle MeTTa ---
        recommendation = METTA_RULES.get(vtype, "No specific rule found.")
        vulnerabilities.append({
            "type": vtype,
            "line": line,
            "detail": detail,
        })
        suggestions.append({
            "vulnerability": vtype,
            "recommendation": recommendation
        })

    try:
        reasoning_text = generate_reasoning_with_ai(vulnerabilities, msg.solidity, msg.user)
    except Exception as e:
        ctx.logger.error(f"⚠️ AI reasoning failed: {e}")
        reasoning_text = (
            "Detected vulnerabilities match known security patterns. "
            "Reentrancy occurs when state updates happen after external calls. "
            "Each recommendation is derived from the MeTTa ruleset."
        )

    analysis = ReasonedAnalysis(
        vulnerabilities=vulnerabilities,
        reasoning=reasoning_text,
        suggestions=suggestions
    )

    ctx.logger.info("Sending structured analysis to KnowledgeAgent...")
    await ctx.send(sender, analysis)

@reasoner_agent.on_event('startup')
async def introduce_agent(ctx: Context):
    ctx.logger.info(f"Hello World !")

@reasoner_agent.on_message(model=ChatMessage)
async def handle_chat_return(ctx: Context, sender: str, msg: ChatMessage):
    ctx.logger.info(f"💬 ChatMessage reçu du chat (ignoré) : {msg.content}")

@reasoner_agent.on_message(model=ChatAcknowledgement)
async def handle_chat_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    ctx.logger.info(f"✅ Ack reçu (ignoré) : {msg.status}")
