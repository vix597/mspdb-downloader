"""
Main MS PDB downloader module.

Download or generate a list of URLs/curl commands to download
PDB files from the Microsoft symbol server.
"""
import os
import re
import sys
import struct
import argparse
import binascii

import pefile
import requests

# Example URL:
# http://msdl.microsoft.com/download/symbols/notepad.pdb/A976171302F1449EA6B676E127B7434D2/notepad.pdb


def to_pdb(filename: str) -> str:
    """Switch the extension to .pdb."""
    ret = re.sub(r'.[^.]+$', '.pdb', os.path.basename(filename))
    return ret


def is_pe(path: str) -> bool:
    """Check if the file is a PE file."""
    _, ext = os.path.splitext(path)
    if ext in (".exe", ".dll"):
        return True
    try:
        pefile.PE(path, fast_load=True)
    except:
        return False
    return True


def download_file(url: str, dest: str) -> None:
    """Download a file with requests."""
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(dest, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)


def build_url(filename):
    """Build the URL to download the PDB"""
    pdb_ident = None
    pdb = to_pdb(filename)
    pe = pefile.PE(filename, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])

    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return None

    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
        # IMAGE_DEBUG_TYPE_CODEVIEW
        if dbg.struct.Type == 2:
            pdb_ident = "%08X%04X%04X%s%X" % (
                 dbg.entry.Signature_Data1,
                 dbg.entry.Signature_Data2,
                 dbg.entry.Signature_Data3,
                binascii.hexlify(dbg.entry.Signature_Data4).decode("utf-8").upper(),
                dbg.entry.Age
            )
            break

    if not pdb_ident:
        return None

    return f"http://msdl.microsoft.com/download/symbols/{pdb}/{pdb_ident}/{pdb}"


def main():
    parser = argparse.ArgumentParser(description="Download Microsoft PDB files")
    parser.add_argument("--path", action="append", help="Directory or file to get PDBs for", required=True)
    parser.add_argument("--recursive", action="store_true", help="If path is a directory, walk it recurssively")
    parser.add_argument("--dest", help="Destination directory to store downloaded PDBs (optional).")

    args = parser.parse_args()

    if args.dest and not os.path.exists(args.dest):
        os.mkdir(args.dest)
    elif args.dest and os.path.exists(args.dest) and not os.path.isdir(args.dest):
        print("--dest must be a new or existing directory.", file=sys.stderr)
        sys.exit(1)

    print("Generating list of paths to process...", file=sys.stderr)
    process_paths = []
    for path in args.path:
        if not os.path.exists(path):
            continue

        if not os.path.isdir(path):
            if is_pe(path):
                process_paths.append(path)
            continue

        if os.path.isdir(path) and args.recursive:
            count = 0
            for root, _, files in os.walk(path):
                for fname in files:
                    count += 1
                    if count % 10000 == 0:
                        print(f"Still processing (processed: {count}. pe-files found: {len(process_paths)})...", file=sys.stderr)
                    fpath = os.path.join(root, fname)
                    if not is_pe(fpath):
                        continue
                    process_paths.append(fpath)
            continue

        for fname in os.listdir(path):
            fpath = os.path.join(path, fname)
            if not is_pe(fpath):
                continue
            process_paths.append(fpath)

    if not process_paths:
        print("No files to process", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {len(process_paths)} paths.", file=sys.stderr)

    for path in process_paths:
        url = build_url(path)
        if not url:
            continue

        filename = os.path.basename(path)
        dest = None
        if args.dest:
            dest = os.path.join(args.dest, to_pdb(filename))

        if dest:
            print(f"Saving {url} to {dest}")
            try:
                download_file(url, dest)
            except requests.exceptions.HTTPError as exc:
                print(f"Failed to get {url}. {exc}", file=sys.stderr)
        else:
            curl_cmd = f"curl -L {url}"
            print(curl_cmd)


if __name__ == '__main__':
    main()