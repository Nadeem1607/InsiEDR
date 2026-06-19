import ast
import os
import pytest
from pathlib import Path

# The base path of the InsiEDR agent package
AGENT_DIR = Path(__file__).resolve().parent.parent / "agent"

FORBIDDEN_IMPORTS = {"sklearn", "pandas", "xgboost", "torch", "psycopg2"}
FORBIDDEN_TERMS = {"risk_score", "anomaly", "alert", "prediction", "psycopg2"}
FORBIDDEN_CALLS = {"commit", "insert"}

class ArchitectureEnforcer(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.violations = []

    def visit_Import(self, node):
        for alias in node.names:
            base_module = alias.name.split('.')[0]
            if base_module in FORBIDDEN_IMPORTS:
                self.violations.append(f"Forbidden import '{alias.name}' in {self.filename}:{node.lineno}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_module = node.module.split('.')[0]
            if base_module in FORBIDDEN_IMPORTS:
                self.violations.append(f"Forbidden import '{node.module}' in {self.filename}:{node.lineno}")
        self.generic_visit(node)

    def visit_Name(self, node):
        for term in FORBIDDEN_TERMS:
            if term in node.id.lower():
                self.violations.append(f"Forbidden term '{term}' in identifier '{node.id}' in {self.filename}:{node.lineno}")
        self.generic_visit(node)
        
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            for term in FORBIDDEN_TERMS:
                if term in node.func.id.lower():
                    self.violations.append(f"Forbidden term '{term}' in function call '{node.func.id}' in {self.filename}:{node.lineno}")
        elif isinstance(node.func, ast.Attribute):
            for term in FORBIDDEN_TERMS:
                if term in node.func.attr.lower():
                    self.violations.append(f"Forbidden term '{term}' in function call '{node.func.attr}' in {self.filename}:{node.lineno}")
            for term in FORBIDDEN_CALLS:
                if term == node.func.attr.lower():
                    self.violations.append(f"Forbidden DB insertion function '{term}' called in {self.filename}:{node.lineno}")
        self.generic_visit(node)

def test_no_ml_or_scoring_logic_in_agent():
    """
    Asserts that no agent-side files import machine learning libraries
    or contain variables/functions related to anomaly detection.
    """
    assert AGENT_DIR.exists(), f"Agent directory not found at {AGENT_DIR}"
    
    all_violations = []
    
    for py_file in AGENT_DIR.rglob("*.py"):
        with py_file.open("r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))
            
        visitor = ArchitectureEnforcer(py_file.name)
        visitor.visit(tree)
        all_violations.extend(visitor.violations)
        
    assert not all_violations, "Architectural boundary violations found:\\n" + "\\n".join(all_violations)

def test_no_database_coupling_in_collectors():
    """
    Inspects collector entry points to ensure no direct database insertion logic exists.
    DB insertion is strictly a server-side responsibility.
    """
    collectors_dir = AGENT_DIR / "collectors"
    assert collectors_dir.exists(), f"Collectors directory not found at {collectors_dir}"
    
    for py_file in collectors_dir.rglob("*.py"):
        with py_file.open("r", encoding="utf-8") as f:
            code = f.read()
            tree = ast.parse(code, filename=str(py_file))
            
        visitor = ArchitectureEnforcer(py_file.name)
        visitor.visit(tree)
        
        # Check specifically for psycopg2 calls in these files
        assert not any("psycopg2" in v for v in visitor.violations), f"psycopg2 found in collector {py_file.name}"
        assert not any("insert" in v or "commit" in v for v in visitor.violations), f"DB insertion/commit found in collector {py_file.name}"
