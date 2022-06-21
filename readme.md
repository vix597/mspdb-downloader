# mspdb-downloader

Download PDB files from microsoft symbol servers or generate a list a curl commands
to perform the symbol download.

# Usage

```shell
$ python -m mspdb-downloader -h
usage: __main__.py [-h] --path PATH [--recursive] [--dest DEST]

Download Microsoft PDB files

optional arguments:
  -h, --help   show this help message and exit
  --path PATH  Directory or file to get PDBs for
  --recursive  If path is a directory, walk it recurssively
  --dest DEST  Destination directory to store downloaded PDBs (optional).
```
