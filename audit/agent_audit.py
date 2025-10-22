from uagents import Agent, Context, Model
from uagents import Protocol
from uagents_core.contrib.protocols.chat import ChatMessage, ChatAcknowledgement, TextContent, chat_protocol_spec
from openai import OpenAI
import os
from parser import *
from prompt import *
from dotenv import load_dotenv
from type_agent import *

load_dotenv()

audit_agent : Agent = Agent(name="Vigil3Audit",
                            endpoint="http://localhost:8500",
                             port=8500)

client = OpenAI(
    base_url="https://api.asi1.ai/v1",
    api_key=os.getenv("API_KEY")
)

chat_protocol = Protocol(spec=chat_protocol_spec)
conversations = {}
slither_report = None
solidity_code = None

@audit_agent.on_rest_post("/message", AuditReport, ReasonedAnalysis)
async def handle_post(ctx: Context, req: AuditReport) -> ReasonedAnalysis:
    ctx.logger.info("📩 Received Solidity audit request")

    slither_report = req.slither
    solidity_code = req.solidity

    reply, status = await ctx.send_and_receive(
        "agent1qgtf9zhyyeu7clzzxpyr5au4ru37vgywlppekm3q0ruf9n9c8jhmue93cd6",
        AuditReport(
            slither=slither_report if isinstance(slither_report, str) else json.dumps(slither_report),
            solidity=solidity_code,
        ),
        response_type=ReasonedAnalysis
    )

    ctx.logger.info("✅ AuditReport envoyé à SlitherPro !")

    if status != 200:
        ctx.logger.error(f"Erreur lors de l'envoie au Reasoner: {reply}")
        return ReasonedAnalysis(vulnerabilities=[], reasoning="Error during analysis", suggestions=[])
    
    return reply



@audit_agent.on_message(model=ReasonedAnalysis)
async def handle_reasoned_analysis(ctx: Context, sender: str, msg: ReasonedAnalysis):
    ctx.logger.info(f"📦 Received ReasonedAnalysis from {sender}")
    ctx.logger.info(f"🧠 Reasoning: {msg.reasoning}")

    # mise en forme des listes
    if msg.vulnerabilities:
        formatted_vulns = [
            f"- **{v.get('type','?')}** (line {v.get('line','?')}): {v.get('detail','')}"
            for v in msg.vulnerabilities
        ]
    else:
        formatted_vulns = ["- No issues detected. 🎉"]

    if msg.suggestions:
        formatted_suggestions = [
            f"- **{s.get('vulnerability','?')}** → {s.get('recommendation','')}"
            for s in msg.suggestions
        ]
    else:
        formatted_suggestions = ["- No specific recommendations."]

    # construire la réponse SANS f-string multi-ligne
    lines = []
    lines.append("🧩 **Security Analysis Results**")
    lines.append("")
    lines.append("🧠 **Reasoning:**")
    lines.append(str(msg.reasoning or ""))
    lines.append("")
    lines.append("🚨 **Vulnerabilities Detected:**")
    lines.extend(formatted_vulns)
    lines.append("")
    lines.append("✅ **Recommendations:**")
    lines.extend(formatted_suggestions)

    response_text = "\n".join(lines)

    chat_target = None
    try:
        chat_target = ctx.storage.get("last_chat_sender")
        if chat_target:
            ctx.logger.info(f"↩️ Envoi via storage: {chat_target}")
    except Exception as e:
        ctx.logger.warning(f"⚠️ Lecture storage impossible: {e}")

    await ctx.send(chat_target, ChatMessage(content=[TextContent(text=response_text)]))


audit_agent.include(chat_protocol)

if __name__ == "__main__":
    audit_agent.run()
    

