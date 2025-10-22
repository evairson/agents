from uagents import Model

class AuditReport(Model):
    slither: str
    solidity: str

class ReasonedAnalysis(Model):
    vulnerabilities: list
    reasoning: str
    suggestions: list