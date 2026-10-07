"""Build a candidate from an explicit allowlist and a committed Git checkout.

Uses stored ZIP entries and fixed metadata so output does not depend on the
platform's compression library. Python is a build dependency, not a runtime.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT/'dist')
    parser.add_argument('--allow-dirty', action='store_true')
    args = parser.parse_args()
    version = (ROOT/'VERSION').read_text(encoding='utf-8').strip()
    match = re.fullmatch(r'V([0-9]+)\.([0-9]+)-RC([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?', version)
    if not match:
        raise SystemExit('VERSION is not an accepted candidate version.')
    major, minor, rc, *patch = [v for v in match.groups() if v is not None]
    package_name = 'Network_Diagnostic_Monitor_V'+major+'_'+minor+'_RC'+rc+(''.join('_'+v for v in patch))
    commit = git('rev-parse', 'HEAD')
    dirty = bool(git('status', '--porcelain'))
    if dirty and not args.allow_dirty:
        raise SystemExit('Commit or restore source changes before building a candidate. Use --allow-dirty only for an explicitly labelled development build.')
    tracked = set(subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z']).decode('utf-8').split('\0'))
    paths = json.loads((ROOT/'release-files.json').read_text(encoding='utf-8'))
    if not isinstance(paths,list) or not all(isinstance(p,str) for p in paths) or len(set(p.casefold() for p in paths)) != len(paths):
        raise SystemExit('Release allowlist must have unique case-insensitive file paths.')
    files = {}
    for rel in sorted(paths):
        path = ROOT/rel
        if rel not in tracked or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise SystemExit('Release input must be a tracked regular file within this checkout: '+rel)
        files[rel] = path.read_bytes()
    if any(v in files for v in ['BUILD_SOURCE.json','SHA256SUMS.txt']):
        raise SystemExit('Generated metadata must not be a release input.')
    metadata = {'candidate':version,'gitCommit':commit,'sourceDirty':dirty,'repository':'https://github.com/Helminiak/NETWORK-DIAGNOSTIC-MONITOR','packaging':'Explicit allowlist; stored ZIP entries; fixed timestamp and permissions'}
    files['BUILD_SOURCE.json'] = (json.dumps(metadata,indent=2)+'\n').encode('utf-8')
    manifest = ''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in sorted(files.items()))
    files['SHA256SUMS.txt'] = manifest.encode('utf-8')
    output_dir = args.output_dir.resolve();output_dir.mkdir(parents=True,exist_ok=True)
    archive = output_dir/(package_name+'.zip')
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as z:
        for name,data in sorted(files.items()):
            entry=zipfile.ZipInfo(package_name+'/'+name,date_time=(1980,1,1,0,0,0))
            entry.create_system=3;entry.compress_type=zipfile.ZIP_STORED
            entry.external_attr=((0o100755 if name.endswith('.sh') else 0o100644) << 16)
            z.writestr(entry,data)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (output_dir/(archive.name+'.sha256')).write_text(digest+'  '+archive.name+'\n',encoding='utf-8')
    (output_dir/'build-source.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    print('BUILD PASS:',archive.name,';',len(files)-1,'manifest-covered files;',archive.stat().st_size,'bytes; SHA256='+digest+'; commit='+commit+'; dirty='+str(dirty))

if __name__=='__main__':
    main()
