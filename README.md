# fv_recovery_key_finder
The **FileVault Recovery Key Finder** is a Python-based solution which automates the search of FileVault recovery keys within textual contents extracted from files.

This solution is inspired by [Bitlocker_Key_Finder](https://github.com/northloopforensics/Bitlocker_Key_Finder).

## Getting started
```
python3 fv_recovery_finder.py /path/to/folder
```

## Installation

### Tika
```
docker pull apache/tika:latest-full
Run tika server by using the following command:
docker run -d -p 9998:9998 apache/tika:latest-full
Extract text API
curl -T test.png http://localhost:9998/tika
```

### Python
```
pip3 install requests
```

## Usage
```
python3 fv_recovery_key_finder.py [-h] [-t tika] [-o /path/to/output] [-v] /path/to/folder
```