"""
==========================================================================
EctoLedger REST API — Black-Box QA Test Suite
==========================================================================

127 test cases covering every REST API endpoint across 9 test modules.

Modules
-------
  test_api_auth.py            AUTH-01…10   Authentication & RBAC
  test_api_sessions.py        SESS-01…17   Session lifecycle
  test_api_events.py          EVT-01…10    Events & hash-chain verification
  test_api_sse.py             SSE-01…11    Server-Sent Events streaming
  test_api_policies.py        POL-01…11    Policies & approval gates
  test_api_tokens_webhooks.py TOK-01…08    RBAC tokens & webhook SSRF
                              WH-01…09
  test_api_config_metrics.py  CFG-01…06    Config, metrics, chat, certs, VCs
                              MET-01…04
                              CHAT-01…04
                              CERT-01…02
                              RPT-01,03
                              VC-01…05
  test_api_boundary.py        BND-01…13    Body limits, Unicode, pagination
                              ERR-01…05    Route & method edge cases
  test_api_concurrency.py     CON-01…09    Parallel ops & rate limiting

Prerequisites
-------------
    cd sdk/python
    pip install -e '.[dev]'

Running — auto-start ephemeral server
--------------------------------------
    # Build the server binary first:
    cargo build                             # or cargo build --release

    # Then run:
    pytest tests/test_api_*.py -v --tb=short

    # The conftest_adversarial.py fixture auto-starts an ephemeral server
    # with sqlite::memory: and LLM_BACKEND=mock.

Running — against an existing server
--------------------------------------
    export ECTOLEDGER_API_TOKEN="<your admin token>"
    export ECTOLEDGER_BASE_URL="http://localhost:3000"   # optional
    pytest tests/test_api_*.py -v --tb=short

Extra RBAC tokens (optional)
-----------------------------
    # For full AUTH-06/07/08/09/10 coverage, provision role-specific tokens:
    export ECTOLEDGER_AUDITOR_TOKEN="<auditor token>"
    export ECTOLEDGER_AGENT_TOKEN="<agent token>"

Selective runs
--------------
    pytest tests/test_api_auth.py -v                     # auth only
    pytest tests/test_api_concurrency.py -v              # concurrency only
    pytest tests/test_api_boundary.py -v -k "BND"        # boundary only
    pytest tests/test_api_*.py -v -k "not rate_limit"    # skip flaky rate-limit tests
"""
