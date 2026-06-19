import ast
import pytest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent / "agent"
FORBIDDEN_IMPORTS = {"sklearn", "pandas", "xgboost", "torch", "numpy", "scipy"}
FORBIDDEN_TERMS = {"risk_score", "is_anomaly", "alert", "malicious", "detectors", "anomaly"}

class ScoringContractEnforcer(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.import_violations = []
        self.scoring_violations = []

    def visit_Import(self, node):
        for alias in node.names:
            base_module = alias.name.split('.')[0]
            if base_module in FORBIDDEN_IMPORTS:
                self.import_violations.append(f"Forbidden ML import '{alias.name}' in {self.filename}:{node.lineno}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_module = node.module.split('.')[0]
            if base_module in FORBIDDEN_IMPORTS:
                self.import_violations.append(f"Forbidden ML import '{node.module}' in {self.filename}:{node.lineno}")
        self.generic_visit(node)

    def visit_Name(self, node):
        for term in FORBIDDEN_TERMS:
            if term in node.id.lower():
                self.scoring_violations.append(f"Forbidden scoring terminology '{term}' used as variable '{node.id}' in {self.filename}:{node.lineno}")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        for term in FORBIDDEN_TERMS:
            if term in node.attr.lower():
                self.scoring_violations.append(f"Forbidden scoring terminology '{term}' used as attribute '{node.attr}' in {self.filename}:{node.lineno}")
        self.generic_visit(node)
        
    def visit_Dict(self, node):
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                for term in FORBIDDEN_TERMS:
                    if term in key.value.lower():
                        self.scoring_violations.append(f"Forbidden scoring terminology '{term}' used as dictionary key '{key.value}' in {self.filename}:{node.lineno}")
        self.generic_visit(node)

def test_no_ml_scoring_imports():
    """
    Parse the AST of all agent-side files and explicitly assert that they do not 
    import machine learning or data science libraries (e.g., sklearn, pandas).
    """
    assert AGENT_DIR.exists(), f"Agent directory not found at {AGENT_DIR}"

    all_violations = []
    for py_file in AGENT_DIR.rglob("*.py"):
        if py_file.name.startswith("test_"):
            continue
        with py_file.open("r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))
            
        visitor = ScoringContractEnforcer(py_file.name)
        visitor.visit(tree)
        all_violations.extend(visitor.import_violations)
        
    assert not all_violations, "Architectural boundary violations found (ML Imports):\\n" + "\\n".join(all_violations)

def test_no_scoring_variables():
    """
    Parse the AST to inspect variable names, function calls, and dictionary keys. 
    Assert that they do not contain forbidden decision terminology such as 
    risk_score, is_anomaly, alert, malicious, or detectors.
    """
    assert AGENT_DIR.exists(), f"Agent directory not found at {AGENT_DIR}"

    all_violations = []
    for py_file in AGENT_DIR.rglob("*.py"):
        if py_file.name.startswith("test_"):
            continue
        with py_file.open("r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))
            
        visitor = ScoringContractEnforcer(py_file.name)
        visitor.visit(tree)
        all_violations.extend(visitor.scoring_violations)
        
    assert not all_violations, "Architectural boundary violations found (Scoring Terminology):\\n" + "\\n".join(all_violations)
