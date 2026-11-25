"""techscan - identify the technologies a website is built with, with proof."""
from pathlib import Path

__version__ = "0.1.0"

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
VENDOR_DIR = ROOT / "vendor" / "webappanalyzer" / "src"
RUNS_DIR = ROOT / "runs"
