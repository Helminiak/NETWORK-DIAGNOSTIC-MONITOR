"""Verify complete checksum coverage, file selection and deterministic output."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('archive',type=Path)
parser.add_argument('--compare',type=Path)
args=parser.parse_args()
root=Path(__file__).resolve().parent.parent
allow=set(json.loads((root/'release-files.json').read_text()))
with zipfile.ZipFile(args.archive) as z:
    assert z.testzip() is None, 'ZIP CRC check'
    names=z.namelist()
    assert len(names)==len(set(names)), 'No duplicate ZIP entries'
    prefixes={PurePosixPath(n).parts[0] for n in names}
    assert len(prefixes)==1, 'One package root'
    prefix=prefixes.pop()+'/'
    relative={n[len(prefix):] for n in names}
    assert relative==allow|{'BUILD_SOURCE.json','SHA256SUMS.txt'}, 'Exact positive allowlist'
    for name in names:
        p=PurePosixPath(name)
        assert not p.is_absolute() and '..' not in p.parts and '\\' not in name, 'Safe ZIP paths'
        assert z.getinfo(name).date_time==(1980,1,1,0,0,0), 'Fixed entry timestamp'
    covered={}
    for line in z.read(prefix+'SHA256SUMS.txt').decode().splitlines():
        digest,name=line.split('  ',1)
        assert name not in covered, 'Unique manifest paths'
        covered[name]=digest
        assert hashlib.sha256(z.read(prefix+name)).hexdigest()==digest, 'Checksum: '+name
    assert set(covered)==relative-{'SHA256SUMS.txt'}, 'Full manifest coverage'
    meta=json.loads(z.read(prefix+'BUILD_SOURCE.json'))
    assert len(meta['gitCommit'])==40 and meta['sourceDirty'] is False, 'Committed candidate provenance'
    assert z.read(prefix+'VERSION').decode().strip()==meta['candidate'], 'Candidate version'
    for rel in allow:
        assert z.read(prefix+rel)==(root/rel).read_bytes(), 'Source-to-package byte match: '+rel
if args.compare:
    assert args.archive.read_bytes()==args.compare.read_bytes(), 'Independent builds have identical bytes'
digest=hashlib.sha256(args.archive.read_bytes()).hexdigest()
sidecar=args.archive.with_name(args.archive.name+'.sha256')
assert sidecar.read_text().split('  ',1)[0]==digest, 'Archive SHA-256 sidecar'
print('PACKAGE PASS: exact allowlist, source bytes, manifest coverage, safe paths, provenance and'+(' identical independent builds;' if args.compare else ' archive;')+' SHA256='+digest)
