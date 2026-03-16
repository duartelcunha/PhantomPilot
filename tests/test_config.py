from pathlib import Path
import pytest, yaml
from phantompilot.config import ConfigError, ScanConfig, AdapterConfig, ModuleConfig, ReportConfig, load_config, validate_config
from phantompilot.models import ASICode, AdapterType, ReportFormat

class TestValidate:
    def test_valid(self, sample_config): assert validate_config(sample_config) == []
    def test_rest_missing(self): assert any("base_url" in e for e in validate_config(ScanConfig(adapter=AdapterConfig(adapter_type=AdapterType.REST), modules=[ModuleConfig(asi_code=ASICode.ASI01)])))
    def test_bad_auth(self): assert any("auth_type" in e for e in validate_config(ScanConfig(adapter=AdapterConfig(adapter_type=AdapterType.REST, base_url="http://x", auth_type="oauth"))))
    def test_lc_missing(self): assert any("module_path" in e for e in validate_config(ScanConfig(adapter=AdapterConfig(adapter_type=AdapterType.LANGCHAIN))))
    def test_dup(self): assert any("Duplicate" in e for e in validate_config(ScanConfig(adapter=AdapterConfig(adapter_type=AdapterType.LANGCHAIN, module_path="a", class_name="B"), modules=[ModuleConfig(asi_code=ASICode.ASI01), ModuleConfig(asi_code=ASICode.ASI01)])))
    def test_neg_timeout(self): assert any("timeout" in e.lower() for e in validate_config(ScanConfig(adapter=AdapterConfig(adapter_type=AdapterType.LANGCHAIN, module_path="a", class_name="B", timeout_seconds=-1))))
    def test_no_formats(self): assert any("format" in e.lower() for e in validate_config(ScanConfig(adapter=AdapterConfig(adapter_type=AdapterType.LANGCHAIN, module_path="a", class_name="B"), report=ReportConfig(formats=[]))))

class TestLoad:
    def test_valid(self, tmp_path):
        p = tmp_path/"c.yaml"; p.write_text(yaml.dump({"adapter": {"type": "langchain", "module_path": "m", "class_name": "C"}, "modules": [{"asi_code": "ASI01"}], "report": {"formats": ["json"]}}))
        assert load_config(p).adapter.adapter_type == AdapterType.LANGCHAIN
    def test_missing(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"): load_config(tmp_path/"x.yaml")
    def test_malformed(self, tmp_path):
        p = tmp_path/"b.yaml"; p.write_text(": : bad [[[")
        with pytest.raises(ConfigError, match="parse"): load_config(p)
    def test_bad_adapter(self, tmp_path):
        p = tmp_path/"c.yaml"; p.write_text(yaml.dump({"adapter": {"type": "pytorch"}}))
        with pytest.raises(ConfigError, match="Unknown adapter"): load_config(p)
    def test_non_mapping(self, tmp_path):
        p = tmp_path/"c.yaml"; p.write_text("- a\n- b\n")
        with pytest.raises(ConfigError, match="mapping"): load_config(p)
