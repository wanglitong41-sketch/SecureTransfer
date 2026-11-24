import { resolve } from 'node:path';

export function stageSevenEvidence(name = '') {
  return resolve(process.env['ST_EVIDENCE_DIR'] ?? 'docs/evidence/stage-7', name);
}
