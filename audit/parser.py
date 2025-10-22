
import re, json
from dataclasses import dataclass
from typing import List, Optional
from uagents import Model

class AuditReport(Model):
    slither: str
    solidity: str
    user: str = ""

@dataclass
class SourceMapping:
    start: int
    length: int
    filename_relative: str
    filename_absolute: str
    filename_short: str
    is_dependency: bool
    lines: List[int]
    starting_column: int
    ending_column: int

@dataclass
class Parent:
    type: str
    name: str
    source_mapping: SourceMapping

@dataclass
class TypeSpecificFields:
    parent: Parent
    signature: str

@dataclass
class Element:
    type: str
    name: str
    source_mapping: SourceMapping
    type_specific_fields: Optional[TypeSpecificFields] = None

@dataclass
class Vulnerability:
    elements: List[Element]
    description: str
    markdown: str
    first_markdown_element: str
    id: str
    check: str
    impact: str
    confidence: str

class SlitherReport(Model):
    contract: str
    vulnerability: Vulnerability

def extract_json_block(text: str):
    """Seaching for json block"""
    matches = re.findall(r'\{.*\}', text, re.DOTALL)
    for match in matches:
        try:
            data = json.loads(match)
            return data
        except Exception:
            continue
    return None

def extract_solidity_code(text: str):
    """Searching for solidity text"""
    matches = re.findall(r"```solidity(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if matches:
        return matches[0].strip()

    if "pragma solidity" in text or "contract" in text:
        m = re.search(r'(pragma solidity[\s\S]+?})', text)
        if m:
            return m.group(1).strip()

    return None

def get_json_from_message(raw_message: str):
    parsed = extract_json_block(raw_message)
    if "solidity" not in parsed or "question" not in parsed or "json" not in parsed :
        return None
    return parsed