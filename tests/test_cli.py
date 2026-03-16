from pathlib import Path
import yaml, pytest
from click.testing import CliRunner
from phantompilot.cli import main

@pytest.fixture
def runner(): return CliRunner()
@pytest.fixture
def valid_cfg(tmp_path):
    p = tmp_path/"c.yaml"; p.write_text(yaml.dump({"adapter": {"type": "langchain", "module_path": "m", "class_name": "C"}, "modules": [{"asi_code": "ASI01"}], "report": {"formats": ["json"]}})); return p
@pytest.fixture
def bad_cfg(tmp_path):
    p = tmp_path/"b.yaml"; p.write_text(yaml.dump({"adapter": {"type": "bad"}})); return p

class TestList:
    def test_ok(self, runner): assert runner.invoke(main, ["list-modules"]).exit_code == 0
    def test_all(self, runner):
        out = runner.invoke(main, ["list-modules"]).output
        for i in range(1, 11): assert f"ASI{i:02d}" in out

class TestValidate:
    def test_valid(self, runner, valid_cfg): assert runner.invoke(main, ["validate-config", "-c", str(valid_cfg)]).exit_code == 0
    def test_invalid(self, runner, bad_cfg): assert runner.invoke(main, ["validate-config", "-c", str(bad_cfg)]).exit_code != 0
    def test_missing(self, runner, tmp_path): assert runner.invoke(main, ["validate-config", "-c", str(tmp_path/"x.yaml")]).exit_code != 0

class TestScan:
    def test_dry(self, runner, valid_cfg): r = runner.invoke(main, ["scan", "-c", str(valid_cfg), "--dry-run"]); assert r.exit_code == 0 and "dry run" in r.output.lower()
    def test_bad_module(self, runner, valid_cfg): r = runner.invoke(main, ["scan", "-c", str(valid_cfg), "-m", "ASI99", "--dry-run"]); assert r.exit_code != 0

class TestVersion:
    def test_ver(self, runner): assert runner.invoke(main, ["--version"]).exit_code == 0
