
from uagents import Agent, Context, Model

class AuditReport(Model):
    slither: str
    solidity: str
    user : str=""

class ReasonedAnalysis(Model):
    vulnerabilities: list
    reasoning: str
    suggestions: list

client = Agent(name="vscode_client", mailbox="https://agentverse.ai", port=8000)

@client.on_event("startup")
async def main(ctx: Context):
    ctx.logger.info("🚀 VSCode Client started, sending audit request to Vigil3Audit agent...")

    reply, status = await ctx.send_and_receive(
        "agent1qtz4tzy6n783m4ap79neh4war4jmyjny0rqvx4w3pdnve6scyexpcp94yuq",  # adresse de ton agent sur Agentverse
        AuditReport(solidity="contract HelloWorld { ... }", slither="{...}", user=""),
        response_type=ReasonedAnalysis
    )
    print("Réponse :", reply.report)

if __name__ == "__main__":
    client.run()