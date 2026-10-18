import pytest
import yaml
from sigma.collection import SigmaCollection

from sigma.backends.scanner import ScannerBackend


@pytest.fixture
def convert_rule():
    def convert(detection, pipeline=None):
        rules = SigmaCollection.from_yaml(yaml.safe_dump({
            "title": "Conversion test",
            "logsource": {"product": "test"},
            "detection": detection,
        }))
        return ScannerBackend(pipeline).convert(rules)

    return convert
