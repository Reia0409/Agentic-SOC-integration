# agent/tools/

Tool 연결·실행 계층입니다. `registry.py`가 LLM이 고른 도구 이름을 실제 함수로 연결하고,
인자를 검증하고, 실행 결과를 Agent에 돌려줍니다.

## 폴더 구성

- **`registry.py`** — `ToolRegistry`/`ToolSpec`/`build_default_registry()`. 도구 우선순위는
  ① 명시적으로 넘긴 handler → ② `real/<도구이름>.py` 안의 동일 이름 함수(자동 탐색) →
  ③ `mock_tools.py`의 목업(폴백). 팀원은 `real/` 밑에 파일만 넣으면 되고 이 파일을
  직접 고칠 필요가 없습니다.
- **`real/`** — 실제 조사 도구 구현 5개(파일명 = 도구 이름, 자동 탐색 대상).
  자세한 규칙은 [real/README.md](real/README.md).
- **`normalizer_adapter.py`** — 우리(에이전트팀)가 짠 얇은 어댑터. "S3에서 읽을지 로컬
  파일에서 읽을지"만 결정해서, `primary_detection/normalizer/`(1차 탐지팀 벤더 코드,
  레포 루트에 있음)의 정규화 함수에 그대로 넘깁니다. `real/*.py`와
  `raw_log_ingestion.py`(audit/auth 부분)가 여기를 거쳐서 로그를 정규화합니다.
- **`time_utils.py`** — 시간 문자열 파싱 등 공용 유틸.
- **`mock_tools.py`** — `real/`에 아직 구현이 없는 도구용 목업. 개발 초기 단계에서
  전체 파이프라인을 끊김 없이 돌리기 위한 폴백입니다.
- **`_s3_common.py`**(`real/` 안) — S3/로컬 소스 공통 로직(`daterange`, `list_and_read_text`).

## 2026-09-23 업데이트: `parsers/` 폴더 삭제됨

자체 파싱 로직 모음이던 `parsers/`는 완전히 없어졌습니다. 원래 남아있던 마지막 파일
`process_tree.py`(pid/ppid로 조상 체인을 엮는 헬퍼)까지 쓰는 곳이
`agent/tools/real/get_process_tree.py` 하나뿐이라, 별도 폴더로 분리해둘 이유가
없어져서 그 파일 안으로 합쳤습니다. 이제 "로그를 직접 파싱하는 코드"는 이 레포
어디에도 없고, 전부 `normalizer_adapter.py` → `primary_detection/normalizer/`를
거칩니다.

## 알아두면 좋은 것

- `agent/tools/fetch_audit_log.py`(이 폴더 바로 밑, `real/`이 아님)는 **쓰이지 않는
  레거시 파일**입니다. `registry.py`의 자동 탐색은 `real/<이름>.py`만 보기 때문에 이
  파일은 아예 로드되지 않고, 다른 어떤 코드도 `agent.tools.fetch_audit_log`를 import하지
  않습니다(직접 grep으로 확인). 실제로 쓰는 건 `real/fetch_audit_log.py`입니다 —
  이름이 같아서 헷갈리기 쉬우니 나중에 삭제할지 팀 확인이 필요합니다.
