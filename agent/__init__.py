"""조사 에이전트(Investigation Agent) 패키지.

역할 분담 문서의 5개 항목을 각각 아래 모듈이 담당한다.

- Agent Loop 총괄            -> loop.py (InvestigationAgent)
- State / Evidence 관리      -> models.py (AgentState, Evidence, Hypothesis)
- Tool 연결·실행 계층         -> tools/ (ToolRegistry, ToolSpec, build_default_registry)
- Agent 판단·Prompt          -> prompts.py, claude_client.py (Claude), gemini_client.py (Gemini)
- Agent 제어 + 최종 산출물    -> loop.py 내 종료/중복/실패 처리 + report.py
- 보고서 출력                -> report.py (build_investigation_result)

Triage가 파이프라인에서 빠지면서 추가된 전(前) 단계:
- raw log 수집         -> raw_log_ingestion.py (fetch_recent_raw_logs)
- seed 생성(경량 triage) -> seed_prompts.py, seed_generation.py (SeedGenerator)
- 전체 파이프라인 연결   -> pipeline.py (run_investigation_pipeline)

*** 2026-09-22: primary-detection/ 을 sys.path에 추가 ***
1차 탐지팀 벤더 코드(primary-detection/normalizer/)는 agent/ 밖, 레포 루트에 있다
(agent/tools/normalizer_adapter.py 상단 설명 참고). primary-detection은 하이픈 때문에
파이썬 패키지로 import할 수 없어서, 여기서 그 폴더 자체를 sys.path에 추가해 그 밑의
normalizer 패키지를 최상위 패키지처럼(`from normalizer.tools... import ...`) 쓸 수 있게
한다. agent 패키지가 import될 때 제일 먼저 실행되는 곳이라 여기 둬야, 아래
raw_log_ingestion을 포함해 normalizer를 쓰는 모든 하위 모듈이 문제없이 import된다.
"""

import os as _os
import sys as _sys

_REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_PRIMARY_DETECTION_DIR = _os.path.join(_REPO_ROOT, "primary-detection")
if _PRIMARY_DETECTION_DIR not in _sys.path:
    _sys.path.insert(0, _PRIMARY_DETECTION_DIR)

from .models import (
    AgentState,
    Evidence,
    Hypothesis,
    ToolCallRecord,
    TerminationReason,
    VerdictType,
)
from .tools import ToolRegistry, ToolSpec, ToolValidationError, build_default_registry
from .claude_client import ClaudeClient, ClaudeDecisionError
from .gemini_client import GeminiClient, GeminiDecisionError
from .loop import InvestigationAgent
from .report import build_investigation_result, format_text_report
from .raw_log_ingestion import fetch_recent_raw_logs
from .seed_generation import SeedGenerator
from .pipeline import run_investigation_pipeline

__all__ = [
    "AgentState",
    "Evidence",
    "Hypothesis",
    "ToolCallRecord",
    "TerminationReason",
    "VerdictType",
    "ToolRegistry",
    "ToolSpec",
    "ToolValidationError",
    "build_default_registry",
    "ClaudeClient",
    "ClaudeDecisionError",
    "GeminiClient",
    "GeminiDecisionError",
    "InvestigationAgent",
    "build_investigation_result",
    "format_text_report",
    "fetch_recent_raw_logs",
    "SeedGenerator",
    "run_investigation_pipeline",
]