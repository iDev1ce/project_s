from pathlib import Path
import os

def get_stix_output_dir():
    value = os.getenv("STIX_OUTPUT_DIR", "/tmp/stix")

    path = Path(value).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)

    return path