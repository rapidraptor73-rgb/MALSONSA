#!/usr/bin/env python3
"""Build a release from an explicit source allowlist, never from runtime data."""
import argparse
import hashlib
import io
from pathlib import Path
import tarfile

ROOT=Path(__file__).resolve().parents[1]
FILES=['VERSION','install.sh','README.md','docs/INSTALL.md','docs/RULES.md','installer/install.py',
       'scripts/verify_install.py','scripts/build_release.py',
       'backend/app.py','backend/detection_rules.py','backend/hosts_api.py','backend/soc_event_enricher.py','backend/verify_src.py',
       'backend/requirements.txt','backend/requirements.lock.txt']
FILES += ['backend/'+name for name in ('central_store.py','central_schema.sql','central_ingest.py','collection_control.py','central_worker.py','central_exporter.py','central_archive.py')]
FILES += ['deploy/central/'+name for name in ('central-rsyslog-forward.sh','install_primary.py','install_was.py','agent_batch.py','install_agent_batch.py')]
FILES += ['deploy/systemd/'+name for name in ('soc-central-worker.service','soc-central-exporter.service','soc-central-archive.service','malsonsa-agent-flush.service','malsonsa-agent-flush.timer')]
FILES += ['docs/CENTRAL_STORAGE.md']
FILES += ['docs/RELEASE_1.1.md']
FILES += ['scripts/verify_central.py']
FILES += ['dashboard/frontend/'+name for name in ['index.html','hosts.html','rsyslog.html','rules.html','rules.js','theme.css','risk-details.js','site-config.js']]


def build(output):
    version=(ROOT/'VERSION').read_text().strip()
    prefix='malsonsa-v'+version
    output=Path(output); output.mkdir(parents=True,exist_ok=True)
    archive=output/(prefix+'.tar.gz'); manifest=[]
    with tarfile.open(archive,'w:gz') as tar:
        for name in FILES:
            path=ROOT/name
            if path.is_symlink(): raise ValueError('symlinks are not release inputs: '+name)
            data=path.read_bytes().replace(b'\r\n',b'\n')
            manifest.append(hashlib.sha256(data).hexdigest()+'  '+name)
            info=tarfile.TarInfo(prefix+'/'+name); info.size=len(data); info.mode=0o755 if name.endswith('.sh') else 0o644
            info.mtime=0; tar.addfile(info,io.BytesIO(data))
        data=('\n'.join(manifest)+'\n').encode()
        info=tarfile.TarInfo(prefix+'/SHA256SUMS'); info.size=len(data); info.mode=0o644; info.mtime=0
        tar.addfile(info,io.BytesIO(data))
    sums=output/'SHA256SUMS'
    with sums.open('w',encoding='utf-8',newline='\n') as f:
        f.write(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
    print(archive); return archive


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',default='release')
    build(parser.parse_args().output)
