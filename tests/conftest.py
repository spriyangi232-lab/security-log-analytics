import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from sla.parser import build_frame, parse_lines

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "raw" / "OpenSSH_2k.log"


def events_from(lines, year=2015):
    return build_frame(list(parse_lines(lines, year=year)))


@pytest.fixture(scope="session")
def sample_log():
    return SAMPLE
