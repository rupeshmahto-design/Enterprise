import sys
import types

# Provide minimal stubs for streamlit and anthropic so importing app works in test env
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

# Minimal anthropic stub
fake_anthropic = types.SimpleNamespace()
class _AnthropicStub:
    def __init__(self, *a, **k):
        pass
fake_anthropic.Anthropic = _AnthropicStub
sys.modules['anthropic'] = fake_anthropic

from app import create_pdf_download


def test_create_pdf_with_weasyprint(monkeypatch):
    # Provide a minimal markdown.Markdown with toc
    class DummyMd:
        def __init__(self, extensions=None):
            self.toc = "<ul></ul>"

        def convert(self, text):
            return f"<p>{text}</p>"

    monkeypatch.setitem(sys.modules, 'markdown', types.SimpleNamespace(Markdown=DummyMd))

    # Provide a fake weasyprint.HTML that returns PDF bytes
    class FakeHTML:
        def __init__(self, string=None):
            self.string = string

        def write_pdf(self):
            return b"%PDF-FAKE-BYTES"

    monkeypatch.setitem(sys.modules, 'weasyprint', types.SimpleNamespace(HTML=FakeHTML))

    filename, content, mime = create_pdf_download('# EXECUTIVE SUMMARY\nTest', 'TestProject')

    assert mime == 'application/pdf'
    assert filename.endswith('.pdf')
    assert isinstance(content, (bytes, bytearray))
    assert content.startswith(b'%PDF')


def test_create_pdf_fallback_when_weasyprint_missing(monkeypatch):
    # Provide markdown module
    class DummyMd:
        def __init__(self, extensions=None):
            self.toc = "<ul></ul>"

        def convert(self, text):
            return f"<p>{text}</p>"

    monkeypatch.setitem(sys.modules, 'markdown', types.SimpleNamespace(Markdown=DummyMd))

    # Ensure weasyprint import will fail by removing any existing entry
    if 'weasyprint' in sys.modules:
        del sys.modules['weasyprint']

    filename, content, mime = create_pdf_download('# EXECUTIVE SUMMARY\nTest', 'TestProject')

    assert mime == 'text/markdown'
    assert filename.endswith('.md')
    assert isinstance(content, str)
