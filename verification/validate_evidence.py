"""Validate a declared synthetic status fixture independently of PowerShell."""
import json
from pathlib import Path
import jsonschema

root=Path(__file__).resolve().parent.parent
status=json.loads((root/'verification/historical-status.json').read_text(encoding='utf-8-sig'))
schema=json.loads((root/'schema/status.v1.schema.json').read_text())
jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).validate(status)
assert status['sensor']['name']=='SYNTHETIC_TEST_SENSOR'
assert status['sensor']['deployment']=='SYNTHETIC_HISTORICAL_FIXTURE'
assert status['lifecycle']=='HISTORICAL'
assert status['network']['unresolvedAtStop'] and not status['network']['recovered']
node_ids={n['id'] for n in status['topology']['nodes']}
assert all(e['from'] in node_ids and e['to'] in node_ids for e in status['topology']['edges'])
assert status['topology']['lanClientCount'] is None and not status['topology']['inventoryComplete']
assert status['traffic']['routerWanRxMbps'] is None and status['traffic']['routerWanTxMbps'] is None
assert len(status['traffic']['history'])<=120
assert any(r['wireStatus']=='OK' and r['answerPolicy']=='PUBLIC_NAME_NONPUBLIC_ANSWER' for r in status['probes'])
print('PASS synthetic identity and provenance; Draft 2020-12 status schema; unresolved incident; unknown router metrics; bounded history; private-answer integrity semantics.')
