"""Kali-only image preflight; optionally pull versions and record local digests."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from run_static_scans import TOOLS


ROOT = Path(__file__).resolve().parents[1]


def image_references():
    images = json.loads((ROOT / 'scanners/images.json').read_text())
    if not isinstance(images, dict) or set(images) != {
        'semgrep', 'trivy', 'checkov', 'dockle', 'depcheck', 'grype', 'syft', 'gitleaks', 'osv',
    }:
        raise ValueError('Shared scanner image manifest is incomplete')
    images.update({tool: image for tool, (image, _) in TOOLS.items()})
    for image in images.values():
        if (not isinstance(image, str) or not re.fullmatch(
                r'[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9][A-Za-z0-9_.-]*(@sha256:[a-f0-9]{64})?', image)
                or image.endswith(':latest')):
            raise ValueError('Scanner image references require explicit version tags/digests')
    return images


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pull', action='store_true', help='Download manifest versions on Kali before recording')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    os.umask(0o077)
    records = []
    for tool, image in image_references().items():
        if options.pull:
            subprocess.run(['docker', 'pull', image], check=True, timeout=1200)
        result = subprocess.run(['docker', 'image', 'inspect', image], check=True,
                                capture_output=True, text=True, timeout=30)
        info = json.loads(result.stdout)[0]
        if not info.get('RepoDigests'):
            raise ValueError('Image lacks a recorded registry digest; pull the declared version first')
        records.append({'tool': tool, 'reference': image, 'image_id': info['Id'],
                        'registry_digests': info['RepoDigests'], 'architecture': info['Architecture']})
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps({'scope': 'Image availability and digests, not scanner compatibility',
                                        'images': records}, indent=2) + '\n')
    options.output.chmod(0o600)
    print(f'Recorded {len(records)} versioned scanner images; run real report-contract checks next')


if __name__ == '__main__':
    main()
