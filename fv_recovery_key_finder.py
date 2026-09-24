"""Find Apple FileVault recovery keys in files and images.

Dependencies
------------
Install the Python packages with::

    python3 -m pip install requests Pillow pytesseract

OCR also requires the Tesseract executable to be installed and available on
PATH. On macOS, install it with Homebrew::

    brew install tesseract

Text extraction requires an Apache Tika server. It assumes a latest-full
tika-docker (https://github.com/apache/tika-docker) is running.
The default URL is ``http://127.0.0.1:9998``. One way to start the
recommended full Tika image is:

    docker pull apache/tika:latest-full
    docker run -d --name tika -p 9998:9998 apache/tika:latest-full

Usage
-----
Search a folder and write matches to ``fv_recovery_key.txt``::

    python3 fv_recovery_key_finder.py /path/to/folder

Show directories, files, and OCR progress while scanning::

    python3 fv_recovery_key_finder.py -v /path/to/folder

Use a different Tika server or output file::

    python3 fv_recovery_key_finder.py \
        --tika-server http://tika-host:9998 \
        --output /path/to/results.txt \
        /path/to/folder

License
-------
This project is licensed under the MIT License. See ``LICENSE`` for the full
license text.

Acknowledgements
----------------
Author: Giuseppe Totaro (https://github.com/giuseppetotaro)

Thanks to Francesco Cappotto for his invaluable contribution.

This solution is inspired by Northloop Forensics for Bitlocker_Key_Finder:

https://github.com/northloopforensics/Bitlocker_Key_Finder

It uses Apache Tika for document text extraction and Tesseract through
Pytesseract for OCR of supported images.
"""

import os
import sys
import requests
import re
import argparse
import unicodedata
import json
import logging
from dataclasses import dataclass
from PIL import Image, ImageOps
import pytesseract

# Default Tika server URL.
TIKA_SERVER = "http://127.0.0.1:9998"
logger = logging.getLogger(__name__)

# The pattern matches six groups of four characters, separated by dash (or other separator), and checks the surrounding characters:
#
# | Part               | Meaning                                                                                                   |
# |--------------------|-----------------------------------------------------------------------------------------------------------|
# | `(?<![A-Z0-9])`    | The preceding character, if any, must not be an ASCII letter or digit.                                    |
# | `[A-Z0-9]{4}`      | Match the first group of exactly four letters or digits.                                                  |
# | `(?: ... ){5}`     | Repeat the enclosed separator-and-group pattern five times. `?:` avoids creating a capturing group.       |
# | `[ \t\r\n-]{1,12}` | Match 1–12 separator characters: spaces, tabs, carriage returns, newlines, or dashes, in any combination. |
# | `[A-Z0-9]{4}`      | Match the next four-character group.                                                                      |
# | `(?![A-Z0-9])`     | The following character, if any, must not be an ASCII letter or digit.                                    |
#
# The flags mean:
# - re.IGNORECASE: accept lowercase letters too.
# - re.ASCII: keep case-insensitive letter matching restricted to ASCII.
KEY_PATTERN = re.compile(
    r"(?<![A-Z0-9])"
    r"[A-Z0-9]{4}(?:[ \t\r\n-]{1,12}[A-Z0-9]{4}){5}"
    r"(?![A-Z0-9])",
    re.IGNORECASE | re.ASCII,
)

################################################################################
# Helper functions                                                             #
################################################################################

@dataclass(frozen=True)
class ScanConfig:
    walk_dir: str
    tika_server: str
    output: str
    verbose: bool


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
    description="Search for any Apple recovery key")
    parser.add_argument(dest="walk_dir", metavar="/path/to/root/folder")
    parser.add_argument("-t", "--tika-server", metavar="tika", default=TIKA_SERVER,
            help="network address of tika server")
    parser.add_argument("-o", "--output", metavar="/path/to/output",
            default="fv_recovery_key.txt", help="output file")
    parser.add_argument("-v", dest="verbose", action="store_true",
            help="verbose mode")
    args = parser.parse_args(argv)
    return ScanConfig(args.walk_dir, args.tika_server, args.output, args.verbose)

def image_variants(image):
    yield "original", image

    gray = ImageOps.grayscale(image)
    enlarged = gray.resize(
        (gray.width * 2, gray.height * 2),
        Image.Resampling.LANCZOS,
    )
    enhanced = ImageOps.autocontrast(enlarged)

    yield "enlarged-contrast", enhanced
    yield "enlarged-contrast-inverted", ImageOps.invert(enhanced)


def find_rk_with_ocr(path, *, crop=None, single_line=False):
    # Load the image fully before closing the input file.
    with Image.open(path) as source:
        oriented = ImageOps.exif_transpose(source)
        rgba = oriented.convert("RGBA")

        # Flatten transparency onto white.
        background = Image.new("RGBA", rgba.size, "white")
        image = Image.alpha_composite(background, rgba).convert("RGB")

    if single_line and crop is None:
        raise ValueError("single_line requires a key-region crop")

    if crop is not None:
        # Coordinates: (left, top, right, bottom), after EXIF rotation.
        image = image.crop(crop)

    psm = 7 if single_line else 6 if crop is not None else 11
    config = f"--psm {psm}"

    if crop is not None:
        config += " -c load_system_dawg=0 -c load_freq_dawg=0"

    candidates = {}

    for variant_name, variant in image_variants(image):
        if crop is not None:
            variant = ImageOps.expand(variant, border=10, fill="white")

        try:
            text = pytesseract.image_to_string(
                variant,
                lang="eng",
                config=config,
                timeout=30,
            )
        except RuntimeError as exc:
            # Includes OCR execution errors and timeouts.
            print(
                f"OCR failed for {path} ({variant_name}): {exc}",
                file=sys.stderr,
            )
            continue

        for key in find_rk(text):
            candidates.setdefault(key, []).append(variant_name)

    return candidates

def tika_version(tika_server):
    with requests.get(tika_server + "/version") as response:
        response.raise_for_status()
        version = None
        if response.text:
            version = response.text[len("Apache Tika "):] or None
        return version

def tika_extract(path, tika_server):
    # Separate connection and read-inactivity timeouts, in seconds.
    with open(path, 'rb') as source:
        with requests.put(tika_server + "/tika/json", data=source, timeout=(10, 300)) as response:
            response.raise_for_status()  # Rejects unsuccessful HTTP responses before scanning their contents.
            return response.text

def find_rk(text):
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(str.maketrans({
        "\u2010": "-",  # Hyphen
        "\u2011": "-",  # Non-breaking hyphen
        "\u2012": "-",  # Figure dash
        "\u2013": "-",  # En dash
        "\u2014": "-",  # Em dash
        "\u2212": "-",  # Minus sign
    }))

    results = []
    for match in KEY_PATTERN.finditer(text):
        compact = re.sub(r"[ \t\r\n-]", "", match.group()).upper()
        results.append("-".join(
            compact[i:i + 4] for i in range(0, 24, 4)
        ))
    return list(dict.fromkeys(results))  # Removes duplicate matches while preserving their first-seen order.


def is_supported_image(content_type):
    if not content_type:
        return False
    return content_type.split("/")[0] == "image"


def is_output_file(file_path, output_path):
    try:
        return os.path.samefile(file_path, output_path)
    except OSError:
        return os.path.abspath(file_path) == os.path.abspath(output_path)


def find_results(file_path, tika_server):
    text = tika_extract(file_path, tika_server)
    content = json.loads(text)
    content_text = content.get("tk:content")
    content_type = content.get("Content-Type")

    if not content_text:
        return []

    results = find_rk(content_text)
    if not results and is_supported_image(content_type):
        logger.debug(
            "Attempting OCR for %s as it is an image but no recovery key was found in text.",
            file_path,
        )
        results = list(find_rk_with_ocr(file_path))
    return results


def scan_files(config):
    for root, subdirs, files in os.walk(config.walk_dir):
        logger.debug("Scanning directory: %s", root)
        if config.verbose:
            for subdir in subdirs:
                logger.debug("  subdirectory: %s", subdir)

        for filename in files:
            file_path = os.path.join(root, filename)
            # This prevents scanning the results file when it sits inside the
            # directory being searched. Otherwise, the script could rediscover
            # keys it already wrote to that file.
            if is_output_file(file_path, config.output):
                continue

            logger.debug("  file: %s", file_path)
            try:
                results = find_results(file_path, config.tika_server)
            except (requests.exceptions.RequestException, OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to extract %s: %s", file_path, exc)
                continue

            if results:
                yield file_path, results

################################################################################
# Main function and execution.                                                 #
################################################################################

def main(argv=None):
    config = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if config.verbose else logging.INFO,
        format="%(message)s",
    )
    version = tika_version(config.tika_server) or sys.exit("Failed to get Tika version. Please ensure the Tika server is running and accessible.")
    logger.info("Tika version = %s", version)
    try:
        logger.info("Tesseract version = %s", pytesseract.get_tesseract_version())
    except (OSError, pytesseract.TesseractNotFoundError):
        logger.warning("Failed to get Tesseract version. Tesseract may not be installed or accessible for OCR.")

    logger.info("walk_dir = %s", config.walk_dir)
    logger.info("walk_dir (absolute) = %s", os.path.abspath(config.walk_dir))

    num_results = 0

    with open(config.output, "w", encoding="utf-8") as output_file:
        for file_path, results in scan_files(config):
            num_results += len(results)
            print(f"{file_path} {len(results)} {results}", file=output_file)

    logger.info("Total results found: %s", num_results)

if __name__ == "__main__":
    main()