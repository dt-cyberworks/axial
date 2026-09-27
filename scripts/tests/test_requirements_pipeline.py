from pathlib import Path
import importlib.util
import sys


MODULE_PATH = Path(__file__).parents[1] / "requirements_pipeline.py"
SPEC = importlib.util.spec_from_file_location("requirements_pipeline", MODULE_PATH)
PIPELINE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = PIPELINE
SPEC.loader.exec_module(PIPELINE)


def test_repository_requirements_are_valid_and_covered():
    requirements, cases, errors = PIPELINE.validate()
    assert not errors
    assert requirements
    assert cases
    assert all(
        req.test_cases for req in requirements.values()
        if req.status not in PIPELINE.NON_IMPLEMENTING_STATUS
    )


def test_generated_traceability_is_deterministic():
    requirements, cases, errors = PIPELINE.validate()
    assert not errors
    first = PIPELINE.render(requirements, cases)
    second = PIPELINE.render(requirements, cases)
    assert first == second
    assert "REQ-TOOL-003" in first
    assert "TC-TOOL-001" in first



def test_backlog_contract_requires_decision_log_and_no_implementation_authority():
    template = (PIPELINE.REQ_DIR / "_template-backlog.md").read_text(encoding="utf-8")
    assert PIPELINE.BACKLOG_IMPL_AUTH_RE.search(template)
    assert PIPELINE.BACKLOG_IMPL_AUTH_NONE_RE.search(
        PIPELINE.BACKLOG_IMPL_AUTH_RE.search(template).group(1)
    )
    decision = PIPELINE.BACKLOG_DECISION_RE.search(template)
    assert decision and "proposed by" in decision.group(1)
