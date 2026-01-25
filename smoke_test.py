"""Simple smoke test that mocks the Anthropic client and verifies
`generate_threat_assessment` returns a string without making network calls.

Run this from the project root inside the `venv311` environment:

    python smoke_test.py

Exit code 0 = success, non-zero = failure.
"""

import types
import sys

# Provide a minimal fake `streamlit` module so we can import `app` during tests
fake_st = types.SimpleNamespace()
fake_st.set_page_config = lambda *a, **k: None
fake_st.markdown = lambda *a, **k: None
fake_st.file_uploader = lambda *a, **k: None
fake_st.text_input = lambda *a, **k: None
fake_st.success = lambda *a, **k: None
fake_st.warning = lambda *a, **k: None
fake_st.info = lambda *a, **k: None
fake_st.error = lambda *a, **k: None
fake_st.empty = lambda *a, **k: types.SimpleNamespace(text=lambda *a, **k: None)
fake_st.progress = lambda *a, **k: types.SimpleNamespace(progress=lambda *a, **k: None)
fake_st.columns = lambda n: [types.SimpleNamespace(__enter__=lambda *a, **k: None, __exit__=lambda *a, **k: None) for _ in range(n)]
class _DummySessionState:
    def __init__(self):
        self._d = {}
    def __contains__(self, key):
        return key in self._d
    def __getattr__(self, name):
        return self._d.get(name, None)
    def __setattr__(self, name, value):
        if name == '_d':
            super().__setattr__(name, value)
        else:
            self._d[name] = value

fake_st.session_state = _DummySessionState()

sys.modules['streamlit'] = fake_st

# Provide a minimal fake `anthropic` module so we can import `app` during tests
fake_anthropic = types.SimpleNamespace()
class _AnthropicStub:
    def __init__(self, *a, **k):
        pass

fake_anthropic.Anthropic = _AnthropicStub
sys.modules['anthropic'] = fake_anthropic

from app import generate_threat_assessment
import anthropic


class FakeCompletion:
    def __init__(self, text: str):
        self.completion = text


class FakeCompletions:
    def create(self, *args, **kwargs):
        # Verify the prompt is formatted for Claude (starts with "\n\nHuman:")
        prompt = kwargs.get('prompt', '') if 'prompt' in kwargs else (args[1] if len(args) > 1 else '')
        if not isinstance(prompt, str) or not prompt.startswith("\n\nHuman:"):
            raise AssertionError("Prompt not prefixed with '\\n\\nHuman:'")
        # Return a fake generated report containing the required sections
        return FakeCompletion(
            "TABLE OF CONTENTS\n- [EXECUTIVE SUMMARY](#executive-summary)\n- [THREAT MODELING ANALYSIS](#threat-modeling-analysis)\n- [REFERENCES](#references)\n\n## EXECUTIVE SUMMARY\nOverall Risk Rating: LOW\nTop 5 Findings:\n- Test finding 1\n- Test finding 2\n\n## THREAT MODELING ANALYSIS\n...\n\n## REFERENCES\n- [NIST SP 800-53] https://csrc.nist.gov/"
        )


class FakeMessages:
    def create(self, *args, **kwargs):
        # Expect 'messages' kwarg with messages[0]['content'] containing the prompt text
        messages = kwargs.get('messages') if 'messages' in kwargs else (args[1] if len(args) > 1 else None)
        if not messages or not isinstance(messages, list):
            raise AssertionError("Messages API called without messages list")
        content = messages[0].get('content', '') if isinstance(messages[0], dict) else ''
        if 'You are an expert' not in content:
            raise AssertionError("Messages content missing expected payload")
        return FakeCompletion(
            "TABLE OF CONTENTS\n- [EXECUTIVE SUMMARY](#executive-summary)\n- [THREAT MODELING ANALYSIS](#threat-modeling-analysis)\n- [REFERENCES](#references)\n\n## EXECUTIVE SUMMARY\nOverall Risk Rating: LOW\nTop 5 Findings:\n- Test finding 1\n- Test finding 2\n\n## THREAT MODELING ANALYSIS\n...\n\n## REFERENCES\n- [NIST SP 800-53] https://csrc.nist.gov/"
        )



class FakeAnthropic:
    def __init__(self, *args, **kwargs):
        self._completions = FakeCompletions()
        # Provide beta.messages API used for Claude models
        self.beta = types.SimpleNamespace(messages=FakeMessages())

    @property
    def completions(self):
        return self._completions


def run_smoke_test():
    orig = anthropic.Anthropic
    anthropic.Anthropic = FakeAnthropic

    try:
        project_info = {
            'name': 'SmokeTest',
            'app_type': 'Web Application',
            'deployment': 'Cloud (AWS)',
            'criticality': 'Low',
            'compliance': ['None'],
            'environment': 'Development'
        }
        documents_content = "# Test Document\nThis is a test."
        framework = 'MITRE ATT&CK'
        risk_areas = ['Agentic AI Risk']

        result = generate_threat_assessment(
            project_info,
            documents_content,
            framework,
            risk_areas,
            api_key='fake'
        )

        if not result or not isinstance(result, str):
            print("SMOKE_TEST: Failed — result is not a string or is empty")
            return 2

        # Verify the report contains required structure
        required = ["TABLE OF CONTENTS", "EXECUTIVE SUMMARY", "REFERENCES"]
        for r in required:
            if r not in result:
                print(f"SMOKE_TEST: Failed — missing required section: {r}")
                return 4

        print("SMOKE_TEST: Success — output snippet:\n", result[:500])
        return 0

    except Exception as e:
        print("SMOKE_TEST: Exception:", e)
        return 3

    finally:
        anthropic.Anthropic = orig


if __name__ == '__main__':
    sys.exit(run_smoke_test())
