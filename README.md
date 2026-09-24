# FileVault Recovery Key Finder

The **FileVault Recovery Key Finder** searches files for Apple FileVault
recovery keys. It uses Apache Tika for document text extraction and Tesseract
OCR for supported images.

## Requirements

- Python 3
- Docker, for the Apache Tika server
- Tesseract OCR, for image scanning

Install the Python dependencies:

```bash
python3 -m pip install requests Pillow pytesseract
```

On macOS, install Tesseract with Homebrew:

```bash
brew install tesseract
```

Start the Apache Tika server:

```bash
docker pull apache/tika:latest-full
docker run -d --name tika -p 9998:9998 apache/tika:latest-full
```

The default Tika server URL is `http://127.0.0.1:9998`.

## Usage

Search a folder and write matches to `fv_recovery_key.txt`:

```bash
python3 fv_recovery_key_finder.py /path/to/folder
```

Enable verbose logging to show directories, subdirectories, files, and OCR
progress:

```bash
python3 fv_recovery_key_finder.py -v /path/to/folder
```

Use a different Tika server or output file:

```bash
python3 fv_recovery_key_finder.py \
	--tika-server http://tika-host:9998 \
	--output /path/to/results.txt \
	/path/to/folder
```

Run `python3 fv_recovery_key_finder.py --help` for all available options.

## Acknowledgements

**Author:** [Giuseppe Totaro](https://github.com/giuseppetotaro)

Thanks to **Francesco Cappotto** for his invaluable contribution.

This project was inspired by [Bitlocker_Key_Finder](https://github.com/northloopforensics/Bitlocker_Key_Finder)
by Northloop Forensics.

## License

This project is released under the [MIT License](LICENSE).

Apache Tika, Tesseract, and the Python dependencies are third-party software
and remain subject to their respective licenses.