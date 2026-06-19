import ast
import pytest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent / "agent"
FORBIDDEN_DB_DRIVERS = {"psycopg2"}
FORBIDDEN_DB_CALLS = {"commit"}

class DatabaseCouplingEnforcer(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.violations = []

    def visit_Import(self, node):
        for alias in node.names:
            base_module = alias.name.split('.')[0]
            if base_module in FORBIDDEN_DB_DRIVERS:
                self.violations.append(f"Forbidden DB driver '{alias.name}' imported in {self.filename}:{node.lineno}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_module = node.module.split('.')[0]
            if base_module in FORBIDDEN_DB_DRIVERS:
                self.violations.append(f"Forbidden DB driver '{node.module}' imported in {self.filename}:{node.lineno}")
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr.lower() in FORBIDDEN_DB_CALLS:
                self.violations.append(f"Forbidden DB insertion function '{node.func.attr}' called in {self.filename}:{node.lineno}")
        self.generic_visit(node)

def test_no_db_coupling_in_runtime():
    """
    Inspect the AST of the collector entry points (e.g., collect_features or collect). 
    Assert that they do not contain calls to database drivers like psycopg2 
    or execute any database insertion functions.
    """
    collectors_dir = AGENT_DIR / "collectors"
    assert collectors_dir.exists(), f"Collectors directory not found at {collectors_dir}"

    all_violations = []
    
    # Check all files in collectors and payload builder
    paths_to_check = list(collectors_dir.rglob("*.py"))
    
    payload_builder = AGENT_DIR / "payload.py"
    if payload_builder.exists():
        paths_to_check.append(payload_builder)

    for py_file in paths_to_check:
        with py_file.open("r", encoding="utf-8") as f:
            code = f.read()
            tree = ast.parse(code, filename=str(py_file))
            
        visitor = DatabaseCouplingEnforcer(py_file.name)
        visitor.visit(tree)
        all_violations.extend(visitor.violations)
        
    assert not all_violations, "Architectural boundary violations found (DB Coupling):\\n" + "\\n".join(all_violations)
