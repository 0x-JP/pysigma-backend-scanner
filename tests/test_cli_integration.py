from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).parents[1]
EXPECTED = yaml.safe_load((ROOT / "tests" / "fixtures" / "expected-queries.yml").read_text())


@pytest.mark.parametrize("filename", sorted(EXPECTED))
def test_cli_conversion_from_installed_package(tmp_path, filename):
    executable = Path(sys.executable).parent / "sigma"
    result = subprocess.run([
        str(executable), "convert", "-t", "scanner",
        "-p", str(ROOT / "tests" / "fixtures" / "cloudtrail-pipeline.yml"),
        str(ROOT / "tests" / "fixtures" / "sigma" / filename),
    ], cwd=tmp_path, capture_output=True, text=True, check=True)
    prefix = "@index=cloudtrail and " if filename.startswith("aws_") else ""
    assert result.stdout.strip() == prefix + EXPECTED[filename]
