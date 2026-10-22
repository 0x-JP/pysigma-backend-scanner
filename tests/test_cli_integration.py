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


def test_cli_discovers_ecs_cloudtrail_pipeline(tmp_path):
    result = subprocess.run([
        str(Path(sys.executable).parent / "sigma"), "convert", "-t", "scanner",
        "-p", "scanner_cloudtrail",
        "-p", str(ROOT / "tests" / "fixtures" / "cloudtrail-pipeline.yml"),
        str(ROOT / "tests" / "fixtures" / "sigma" / "aws_cloudtrail_disable_logging.yml"),
    ], cwd=tmp_path, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == (
        "@index=cloudtrail and @ecs.cloud.service.name = 'cloudtrail.amazonaws.com'"
        " and (@ecs.event.action = 'StopLogging' or @ecs.event.action = 'UpdateTrail'"
        " or @ecs.event.action = 'DeleteTrail')"
    )
