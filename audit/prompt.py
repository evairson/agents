
def ON_MESSAGE(text : str) :
    return [
        {"role": "system", "content": "You are an audit agent. \
            The user will send you a message that may contain both a Solidity code block and a JSON object. \
            Your task is to extract both parts and return them with a summary of the user question in a single JSON response in the following format: \
            { \
            'question' : <summary_user_question>, \
            'solidity': '<solidity_code_or_null>', \
            'json': '<json_content_or_null>' \
            } \
            If the message contains Solidity code, include it as plain text under 'solidity'. \
            If the message contains JSON data, include the JSON string under 'json'. \
            Summarize the user’s question in simple English under 'question' \
            If either part is missing, return null for that field. \
            Do not include any explanations, only output the JSON result."},
        {"role": "user", "content": text}
    ]

def NO_SLITHER_AND_SOLIDITY(text : str) :
    return [
            {"role": "system", "content": 
            "You are Vigil3 Audit, an AI specialized in smart contract auditing. "
            "You require both the user's Solidity code and a Slither report to perform a full analysis. "
            "Introduce yourself and explain how you work. "
            "If the user needs help generating a Slither report, guide them through the process."
            },
            {"role": "user", "content": text}
        ]

def NO_SLITHER_REPORT() :
    return [
            {"role": "system", "content": "You are a smart contract auditor AI. The user has provided Solidity code but no Slither report. "
            },
            {"role": "user", "content": "Politely explain that you need a Slither report to proceed, and provide clear steps on how to generate one using Slither"}
        ]


def NO_SOLIDITY() :
    return [
        {"role": "system", "content": "You are a smart contract auditor AI. The user has provided a Slither report but no Solidity source code. "},
        {"role": "user", "content":  "Explain that you need the actual Solidity code to cross-check the findings in the report and perform a proper analysis."}
    ]

def LAUNCH_OTHER_AGENT() :
        return [
        {"role": "system", "content": "You are Vigil3 Audit. You are about to delegate part of the analysis to another specialized agent (for example, a reasoning or classification agent). "},
        {"role": "user", "content": "Inform the user that you are collaborating with another agent to provide a deeper analysis of their smart contract."}
    ]

def failed_launch(json, text) :
    if json["solidity"] != None :
        return NO_SLITHER_REPORT()
    if json["json"] != None :
        return NO_SOLIDITY()
    return NO_SLITHER_AND_SOLIDITY(text)