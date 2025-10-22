from uagents import Agent, Context, Model
from uagents import Protocol
from uagents_core.contrib.protocols.chat import ChatMessage, ChatAcknowledgement, TextContent, chat_protocol_spec
from openai import OpenAI
import os
from parser import *
from prompt import *
from dotenv import load_dotenv

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

class ReasonedAnalysis(Model):
    vulnerabilities: list
    reasoning: str
    suggestions: list

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
            user="vscode_audit_request" 
        ),
        response_type=ReasonedAnalysis
    )

    ctx.logger.info("✅ AuditReport envoyé à SlitherPro !")

    if status != 200:
        ctx.logger.error(f"Erreur lors de l'envoie au Reasoner: {reply}")
        return ReasonedAnalysis(vulnerabilities=[], reasoning="Error during analysis", suggestions=[])
    
    return reply


@chat_protocol.on_message(model=ChatMessage)
async def handle_chat(ctx: Context, sender: str, msg: ChatMessage):
    global slither_report, solidity_code
    ctx.logger.info(audit_agent)
    try:
        ctx.storage.set("last_chat_sender", sender)
        ctx.logger.info(f"💾 Chat sender enregistré (storage) : {sender}")
    except Exception as e:
        ctx.logger.warning(f"⚠️ Impossible d’enregistrer dans storage, fallback mémoire: {e}")
        conversations["last_chat"] = sender
        ctx.logger.info(f"💾 Chat sender enregistré (mémoire) : {sender}")

    texts = [c.text for c in msg.content if hasattr(c, "text")]
    ctx.logger.info(f"Chat message received : {msg.content}")

    if texts:
        for text in texts:
            ctx.logger.info(f"💬 Message received : {text}")
            json = None
            conv = conversations.setdefault(sender, [])

            while json == None :
                completion = client.chat.completions.create(
                    model="asi1-mini",
                    messages= ON_MESSAGE(text),
                )

                plan = completion.choices[0].message.content
                ctx.logger.info(plan)

                try:
                    json = get_json_from_message(plan)
                except Exception as e:
                    ctx.logger.error(f"Erreur parsing JSON: {e}")
                    json = None

            ctx.logger.info("json trouvé")

            if json["json"] != None :
                slither_report = json["json"]

            if json["solidity"] != None :
                solidity_code = json["solidity"]

            if solidity_code == None or slither_report == None:
                completion = client.chat.completions.create(
                        model="asi1-mini",
                        messages= failed_launch(json, text)
                    )
                response = completion.choices[0].message.content
                await ctx.send(sender, ChatMessage(content=[TextContent(text=response)]))

            
            else :
                try:
                    ctx.logger.info("🚀 Rapport complet détecté, envoi à ReasonerAgent...")

                    await ctx.send(
                        "agent1qgtf9zhyyeu7clzzxpyr5au4ru37vgywlppekm3q0ruf9n9c8jhmue93cd6",
                        AuditReport(
                            slither=slither_report if isinstance(slither_report, str) else json.dumps(slither_report),
                            solidity=solidity_code,
                            user=text  # ou json_data.get("question", text)
                        )
                    )

                    ctx.logger.info("✅ AuditReport envoyé à SlitherPro !")
                except Exception as e:
                    ctx.logger.error("Erreur lors de l'envoie au Reasoner")
                    await ctx.send(sender, ChatMessage(content=[TextContent(text=f"Erreur lors de l’envoi à l’agent : {e}")]))

            

    else:
        ctx.logger.info("📦 Non-text message received or empty.")
    
@chat_protocol.on_message(model=ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    ctx.logger.info(f"✅ Ack reçu du chat : {msg.status}")

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

@chat_protocol.on_message(model=ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    ctx.logger.info(f"✅ Ack reçu du chat : {msg.status}")

audit_agent.include(chat_protocol)

if __name__ == "__main__":
    audit_agent.run()
    

