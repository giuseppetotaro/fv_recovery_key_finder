import os
import sys
import requests
import re
import argparse


TIKA_SERVER = "http://localhost:9998/tika"

parser = argparse.ArgumentParser(
        description="Search for any Apple recovery key")
parser.add_argument(dest="walk_dir", metavar="/path/to/root/folder")
parser.add_argument("-t", "--tika-server", metavar="tika", dest="tika_server",
        action="store", required=False, default=TIKA_SERVER,
        help="network address of tika server")
parser.add_argument("-o", "--output", metavar="/path/to/output", dest="output",
        action="store", required=False, default="rk.out", help="output file")
parser.add_argument("-v", dest="verbose", action="store_true",
        help="verbose mode")
args = parser.parse_args()

walk_dir = args.walk_dir
tika_server = args.tika_server
output = args.output
verbose = args.verbose

def tika_extract(path):
    url = "http://localhost:9998/tika"
    headers = {'Accept': 'text/plain'}
    r = requests.put(url, data=open(path, 'rb'), headers=headers)

    return r.text


def find_rk(text, pattern=None):
    if not pattern:
        pattern = re.compile(r'[0-9A-Z]{4}(?:\-[0-9A-Z]{4}){5}')
    res = pattern.findall(text)
    return res


pattern = re.compile(r'[0-9A-Z]{4}(?:\-[0-9A-Z]{4}){5}')
#TODO: option to support lowercase letters and/or other separators

print('walk_dir = ' + walk_dir)

# If your current working directory may change during script execution, it's recommended to
# immediately convert program arguments to an absolute path. Then the variable root below will
# be an absolute path as well. Example:
# walk_dir = os.path.abspath(walk_dir)
print('walk_dir (absolute) = ' + os.path.abspath(walk_dir))

f = open(output, 'w')

num_results = 0

for root, subdirs, files in os.walk(walk_dir):
    print(f"--\nroot =  {root}")

    for subdir in subdirs:
        print('\t- subdirectory ' + subdir)

    for filename in files:
        file_path = os.path.join(root, filename)

        print('\t- file %s (full path: %s)' % (filename, file_path))

        text = tika_extract(file_path)

        #print("##########")
        #print(text)
        #print("##########")

        res = find_rk(text, pattern)
        if len(res) > num_results:
            num_results += 1
            print(f"One more result found. Number of results: {num_results}")
            print(f"{file_path} {len(res)} {res}", file=f)

f.close()