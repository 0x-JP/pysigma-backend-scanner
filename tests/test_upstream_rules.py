from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

from sigma.backends.scanner import ScannerBackend


# SigmaHQ/sigma snapshot: b7920ed31356fb7f6a9275b34737d8604c65bac3 (DRL-1.1).
FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED = yaml.safe_load((FIXTURES / "expected-queries.yml").read_text())


@pytest.mark.parametrize("filename", sorted(EXPECTED))
def test_upstream_rule_query(filename):
    collection = SigmaCollection.from_yaml((FIXTURES / "sigma" / filename).read_text())
    assert ScannerBackend().convert(collection) == [EXPECTED[filename]]


def test_cloudtrail_pipeline_does_not_scope_windows():
    pipeline = ProcessingPipeline.from_yaml(
        (FIXTURES / "cloudtrail-pipeline.yml").read_text()
    )
    filename = "proc_creation_win_finger_execution.yml"
    collection = SigmaCollection.from_yaml((FIXTURES / "sigma" / filename).read_text())
    assert ScannerBackend(pipeline).convert(collection) == [EXPECTED[filename]]
