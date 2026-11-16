// Synthetic mock data only. Domains are example.test, IPs are documentation/private ranges.

export const TOOL = { name: 'maasspec', version: '0.4.0' }

const S1_SHA = 'a3f19c0e7b2d4815c6e0f9a7d3b21c4e8f5a6b7c9d0e1f2a3b4c5d6e7f809a1b'
const S2_SHA = '5e0c7a91d24b3f680a1e9c47b85d2f306c7e1a94f3b0d852e19a4c072d6f8b3e'
const S3_SHA = 'c71b0e4a93f2d68e15a7c3b90e4d8f217a6c95b3d0e2f4178b3a6c5d91e0f7a2'
const S4_SHA = '0d4e8a17f6b25c93a8e1d07f3c95b624e07a1d8c52f9b3e6a41c0d78e6b29f35'
const S5_SHA = '9b27e4c01f8a6d53c3e90b7a64d1f28eb5a03c967e2d4f810c6b9a3ed58f1247'
const S6_SHA = '4f8c2e6ab1d73095e2a64c8f07b5d9e3a6c1f4803d9e2b57c4a8016fe7b35d29'
const S6_LAYER = 'e8a05d3c7f2b961e4c0d8a73b9e16f25d3a7c0481e5b9f62a0c4d87e35f61b9c'

export const spectra: Spectrum[] = [
  {
    id: 's1',
    analysisId: 'an_01JH8Q3K7V2M9X4T6R5Y0B1C2D',
    inputType: 'sample',
    name: 'invoice_q3.exe',
    sha256: S1_SHA,
    size: 14893056,
    source: 'local file',
    generated: '2025-01-14 09:42:17Z',
    review: 'Reviewed',
    family: { name: 'Example RAT', method: 'yara: ExampleRAT_config_v2', confidence: 0.7 },
    capabilities: ['keylogging', 'screen capture', 'persistence'],
    riskSignals: ['packed section', 'anti-debug'],
    c2Count: 2,
    configExtracted: true,
    encryptionObserved: true,
    truncated: true,
    artifacts: [
      { id: 'art-1', type: 'input', name: 'invoice_q3.exe', sha256: S1_SHA, size: 14893056, producedBy: 'loader.file 0.4.0' },
    ],
    issues: [
      { level: 'info', module: 'scan.window', message: 'Scan window truncated at 8 MiB. sha256 computed over the full file.', recoverable: true },
    ],
    findings: [
      {
        id: 'f-001', type: 'c2', subtype: 'http_url', value: 'https://update.example.test/gate.php', confidence: 0.72,
        grade: { r: 'C', c: 2, rationale: 'Static config decode; URL sits in the decrypted config block next to the campaign id. Not observed live.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: ['http', 'post'],
        extractedBy: { module: 'config.example_rat', version: '1.3.0', technique: 'RC4 config decrypt' },
        confidenceMethod: 'decoder match + structural check', location: '.rsrc +0x1a40',
        selectors: [
          { kind: 'url', value: 'https://update.example.test/gate.php', normalized: 'https://update.example.test/gate.php' },
          { kind: 'domain', value: 'update.example.test', normalized: 'update.example.test' },
        ],
        context: { config_key: 'c2_primary', method: 'POST', interval_s: '300' },
        familyData: { family: 'Example RAT', build: '2.4.1' },
      },
      {
        id: 'f-002', type: 'c2', subtype: 'ipv4', value: '10.0.0.5', confidence: 0.35, private: true,
        grade: { r: 'C', c: 4, rationale: 'Private address in the fallback slot. Likely a test value left in the build.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: ['fallback'],
        extractedBy: { module: 'config.example_rat', version: '1.3.0', technique: 'RC4 config decrypt' },
        confidenceMethod: 'decoder match; private range penalty', location: '.rsrc +0x1a88',
        selectors: [{ kind: 'ipv4', value: '10.0.0.5', normalized: '10.0.0.5' }],
        context: { config_key: 'c2_fallback' },
      },
      {
        id: 'f-003', type: 'credential_pattern', subtype: 'email', value: 'ops@example.test', confidence: 0.35,
        grade: { r: 'C', c: 4, rationale: 'Address found as a plain string near SMTP routines; no config relationship established.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: ['smtp'],
        extractedBy: { module: 'strings.patterns', version: '0.9.2', technique: 'regex over ASCII/UTF-16 strings' },
        confidenceMethod: 'pattern match only', location: '.data +0x0420',
        selectors: [{ kind: 'email', value: 'ops@example.test', normalized: 'ops@example.test' }],
        context: { encoding: 'utf-16le' },
      },
      {
        id: 'f-004', type: 'family_indicator', subtype: 'yara', value: 'Example RAT', confidence: 0.7,
        grade: { r: 'C', c: 3, rationale: 'Single YARA rule hit on config layout. Rule is maintained locally, not peer reviewed.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: ['yara'],
        extractedBy: { module: 'family.yara', version: '0.6.0', technique: 'ExampleRAT_config_v2' },
        confidenceMethod: 'rule weight', location: '.rsrc',
        selectors: [{ kind: 'sha256', value: S1_SHA, normalized: S1_SHA }],
        context: { rule: 'ExampleRAT_config_v2', rule_author: 'local' },
        familyData: { family: 'Example RAT', variant: 'v2 config' },
      },
      {
        id: 'f-005', type: 'config', subtype: 'mutex', value: 'Global\\ExRAT_7c2a', confidence: 0.6,
        grade: { r: 'C', c: 3, rationale: 'Mutex name decoded from config; not observed at runtime.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: [],
        extractedBy: { module: 'config.example_rat', version: '1.3.0', technique: 'RC4 config decrypt' },
        confidenceMethod: 'decoder match', location: '.rsrc +0x1ac0',
        selectors: [],
        context: { config_key: 'mutex' },
      },
      {
        id: 'f-006', type: 'crypto_material', subtype: 'rc4_key', value: '6b3f91a0d2c4e857', confidence: 0.55,
        grade: { r: 'C', c: 3, rationale: 'Key decrypts the config block successfully; key reuse across builds unknown.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: ['config-key'],
        extractedBy: { module: 'config.example_rat', version: '1.3.0', technique: 'key scan + trial decrypt' },
        confidenceMethod: 'successful decrypt', location: '.text +0x3f10',
        selectors: [],
        context: { key_length: '8' },
      },
    ],
  },
  {
    id: 's2',
    analysisId: 'an_01JH8R0P2N5Q8W1E4T7Y3U6I9O',
    inputType: 'cape_report',
    name: 'cape_report_48213.json',
    sha256: S2_SHA,
    size: 2384117,
    source: 'local file',
    generated: '2025-01-14 10:05:51Z',
    review: 'Unreviewed',
    family: { name: 'Example RAT', method: 'cape signature', confidence: 0.45 },
    capabilities: ['persistence', 'process injection'],
    riskSignals: ['network beacon'],
    c2Count: 2,
    configExtracted: false,
    encryptionObserved: false,
    artifacts: [
      { id: 'art-1', type: 'input', name: 'cape_report_48213.json', sha256: S2_SHA, size: 2384117, producedBy: 'loader.cape 0.4.0' },
      { id: 'art-2', type: 'sample_reference', parent: 'art-1', name: 'target.file', sha256: S1_SHA, size: 14893056, producedBy: 'CAPE task 48213' },
    ],
    issues: [],
    findings: [
      {
        id: 'f-001', type: 'c2', subtype: 'dns_query', value: 'beacon.example.test', confidence: 0.45,
        grade: { r: 'C', c: 3, rationale: 'Sandbox observation, capped at 0.45. Resolution seen once in a single run.' },
        provenance: { kind: 'sandbox' }, source: 'art-2', tags: ['dns'],
        extractedBy: { module: 'cape.network', version: '0.4.0', technique: 'report.network.dns' },
        confidenceMethod: 'sandbox cap 0.45', location: 'network.dns[0]',
        selectors: [{ kind: 'domain', value: 'beacon.example.test', normalized: 'beacon.example.test' }],
        context: { answers: '93.184.216.34' },
      },
      {
        id: 'f-002', type: 'c2', subtype: 'tcp_connect', value: '93.184.216.34:443', confidence: 0.45,
        grade: { r: 'C', c: 3, rationale: 'Sandbox observation, capped at 0.45. TLS handshake completed; payload not decoded.' },
        provenance: { kind: 'sandbox' }, source: 'art-2', tags: ['tls'],
        extractedBy: { module: 'cape.network', version: '0.4.0', technique: 'report.network.tcp' },
        confidenceMethod: 'sandbox cap 0.45', location: 'network.tcp[2]',
        selectors: [
          { kind: 'ipv4_port', value: '93.184.216.34:443', normalized: '93.184.216.34:443' },
          { kind: 'ipv4', value: '93.184.216.34', normalized: '93.184.216.34' },
        ],
        context: { sni: 'beacon.example.test', bytes_out: '1842' },
      },
      {
        id: 'f-003', type: 'behavior', subtype: 'registry_run_key', value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater', confidence: 0.45,
        grade: { r: 'C', c: 3, rationale: 'Sandbox observation, capped at 0.45.' },
        provenance: { kind: 'sandbox' }, source: 'art-2', tags: ['persistence'],
        extractedBy: { module: 'cape.behavior', version: '0.4.0', technique: 'report.behavior.summary.write_keys' },
        confidenceMethod: 'sandbox cap 0.45', location: 'behavior.summary.write_keys[4]',
        selectors: [],
        context: { process: 'invoice_q3.exe', pid: '2412' },
      },
      {
        id: 'f-004', type: 'behavior', subtype: 'process_injection', value: 'CreateRemoteThread → explorer.exe', confidence: 0.45,
        grade: { r: 'C', c: 3, rationale: 'Sandbox observation, capped at 0.45.' },
        provenance: { kind: 'sandbox' }, source: 'art-2', tags: ['injection'],
        extractedBy: { module: 'cape.behavior', version: '0.4.0', technique: 'report.signatures' },
        confidenceMethod: 'sandbox cap 0.45', location: 'signatures[7]',
        selectors: [],
        context: { signature: 'injection_createremotethread' },
      },
      {
        id: 'f-005', type: 'family_indicator', subtype: 'cape_detection', value: 'Example RAT', confidence: 0.45,
        grade: { r: 'C', c: 3, rationale: 'CAPE detection label, capped at 0.45. Agrees with static YARA on the same sha256.' },
        provenance: { kind: 'sandbox' }, source: 'art-2', tags: [],
        extractedBy: { module: 'cape.detections', version: '0.4.0', technique: 'report.detections' },
        confidenceMethod: 'sandbox cap 0.45', location: 'detections[0]',
        selectors: [{ kind: 'sha256', value: S1_SHA, normalized: S1_SHA }],
        context: { cape_task: '48213' },
        familyData: { family: 'Example RAT' },
      },
    ],
  },
  {
    id: 's3',
    analysisId: 'an_01JH8S4D6F8G0H2J4K6L8Z0X2C',
    inputType: 'archive',
    name: 'shipment_docs.zip',
    sha256: S3_SHA,
    size: 418304,
    source: 'local file',
    generated: '2025-01-14 10:31:02Z',
    review: 'Skip',
    family: null,
    capabilities: [],
    riskSignals: ['double extension', 'encrypted member'],
    c2Count: 0,
    configExtracted: false,
    encryptionObserved: true,
    artifacts: [
      { id: 'art-1', type: 'input', name: 'shipment_docs.zip', sha256: S3_SHA, size: 418304, producedBy: 'loader.file 0.4.0' },
    ],
    issues: [
      { level: 'warning', module: 'archive.zip', message: 'Member readme.lnk is encrypted (ZipCrypto). Name listed; contents not inspected.', recoverable: true },
    ],
    findings: [
      {
        id: 'f-001', type: 'embedded_artifact', subtype: 'zip_member', value: 'Shipment_Details.pdf.exe', confidence: 0.9,
        grade: { r: 'B', c: 2, rationale: 'Read directly from the central directory.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: ['double-extension'],
        extractedBy: { module: 'archive.zip', version: '0.3.1', technique: 'central directory listing' },
        confidenceMethod: 'structural read', location: 'cd entry 0',
        selectors: [], context: { compressed: '201 KB', method: 'deflate' },
      },
      {
        id: 'f-002', type: 'embedded_artifact', subtype: 'zip_member', value: 'readme.lnk', confidence: 0.9,
        grade: { r: 'B', c: 2, rationale: 'Read directly from the central directory. Member is encrypted.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: ['encrypted'],
        extractedBy: { module: 'archive.zip', version: '0.3.1', technique: 'central directory listing' },
        confidenceMethod: 'structural read', location: 'cd entry 1',
        selectors: [], context: { compressed: '2 KB', method: 'zipcrypto' },
      },
      {
        id: 'f-003', type: 'embedded_artifact', subtype: 'zip_member', value: 'invoice.js', confidence: 0.9,
        grade: { r: 'B', c: 2, rationale: 'Read directly from the central directory.' },
        provenance: { kind: 'static' }, source: 'art-1', tags: ['script'],
        extractedBy: { module: 'archive.zip', version: '0.3.1', technique: 'central directory listing' },
        confidenceMethod: 'structural read', location: 'cd entry 2',
        selectors: [], context: { compressed: '14 KB', method: 'deflate' },
      },
    ],
  },
  {
    id: 's4',
    analysisId: 'an_01JH8T7B9N1M3Q5W7E9R1T3Y5U',
    inputType: 'feed_record',
    name: 'threatfox : 1287345',
    sha256: S4_SHA,
    size: 1206,
    source: 'threatfox',
    generated: '2025-01-14 11:12:40Z',
    review: 'Unreviewed',
    family: { name: 'Example RAT', method: 'feed label', confidence: 0.5 },
    capabilities: [],
    riskSignals: [],
    c2Count: 1,
    configExtracted: false,
    encryptionObserved: false,
    artifacts: [
      { id: 'art-1', type: 'feed_record', name: 'threatfox ioc 1287345', sha256: S4_SHA, size: 1206, producedBy: 'feed.threatfox 0.4.0' },
    ],
    issues: [],
    findings: [
      {
        id: 'f-001', type: 'c2', subtype: 'ip_port', value: '93.184.216.34:8443', confidence: 0.7,
        grade: { r: 'C', c: 3, rationale: 'ThreatFox record with reporter confidence 75. Feed claim; MaaSSpec did not observe it.' },
        provenance: { kind: 'feed', feed: 'ThreatFox' }, source: 'art-1', tags: ['botnet_cc'],
        extractedBy: { module: 'feed.threatfox', version: '0.4.0', technique: 'ioc field mapping' },
        confidenceMethod: 'feed confidence_level 75 → 0.70', location: 'data[0].ioc',
        selectors: [
          { kind: 'ipv4_port', value: '93.184.216.34:8443', normalized: '93.184.216.34:8443' },
          { kind: 'ipv4', value: '93.184.216.34', normalized: '93.184.216.34' },
        ],
        context: { threat_type: 'botnet_cc', reporter: 'example_reporter', first_seen: '2025-01-13 22:04 UTC' },
      },
      {
        id: 'f-002', type: 'family_indicator', subtype: 'feed_label', value: 'Example RAT', confidence: 0.5,
        grade: { r: 'C', c: 4, rationale: 'malware_printable label from the record. Labels are reporter-assigned.' },
        provenance: { kind: 'feed', feed: 'ThreatFox' }, source: 'art-1', tags: [],
        extractedBy: { module: 'feed.threatfox', version: '0.4.0', technique: 'malware_printable' },
        confidenceMethod: 'feed label default 0.50', location: 'data[0].malware_printable',
        selectors: [], context: { malware: 'win.example_rat' },
        familyData: { family: 'Example RAT', malpedia: 'win.example_rat' },
      },
    ],
  },
  {
    id: 's5',
    analysisId: 'an_01JH8T8C0P2A4S6D8F0G2H4J6K',
    inputType: 'feed_record',
    name: 'threatfox : 1287351',
    sha256: S5_SHA,
    size: 1144,
    source: 'threatfox',
    generated: '2025-01-14 11:12:41Z',
    review: 'Unreviewed',
    family: { name: 'Example.Loader', method: 'feed label', confidence: 0.35 },
    capabilities: [],
    riskSignals: [],
    c2Count: 0,
    configExtracted: false,
    encryptionObserved: false,
    artifacts: [
      { id: 'art-1', type: 'feed_record', name: 'threatfox ioc 1287351', sha256: S5_SHA, size: 1144, producedBy: 'feed.threatfox 0.4.0' },
      { id: 'art-2', type: 'sample_reference', parent: 'art-1', name: 'payload hash', sha256: S6_SHA, size: null, producedBy: 'feed.threatfox 0.4.0' },
    ],
    issues: [],
    findings: [
      {
        id: 'f-001', type: 'other', subtype: 'payload_delivery_url', value: 'http://cdn.example.test/load.bin', confidence: 0.35,
        grade: { r: 'D', c: 3, rationale: 'ThreatFox record with reporter confidence 50 and no linked sandbox run. Feed claim.' },
        provenance: { kind: 'feed', feed: 'ThreatFox' }, source: 'art-1', tags: ['payload_delivery'],
        extractedBy: { module: 'feed.threatfox', version: '0.4.0', technique: 'ioc field mapping' },
        confidenceMethod: 'feed confidence_level 50 → 0.35', location: 'data[0].ioc',
        selectors: [
          { kind: 'url', value: 'http://cdn.example.test/load.bin', normalized: 'http://cdn.example.test/load.bin' },
          { kind: 'domain', value: 'cdn.example.test', normalized: 'cdn.example.test' },
          { kind: 'sha256', value: S6_SHA, normalized: S6_SHA },
        ],
        context: { threat_type: 'payload_delivery', reporter: 'example_reporter' },
      },
    ],
  },
  {
    id: 's6',
    analysisId: 'an_01JH8V2X4C6V8B0N2M4Q6W8E0R',
    inputType: 'sample',
    name: 'load.bin',
    sha256: S6_SHA,
    size: 286720,
    source: 'unpacme',
    generated: '2025-01-14 11:40:09Z',
    review: 'Unreviewed',
    family: { name: 'Example.Loader', method: 'unpacme malware_id', confidence: 0.7 },
    capabilities: ['download and execute'],
    riskSignals: ['packed', 'unpacked layer'],
    c2Count: 1,
    configExtracted: false,
    encryptionObserved: false,
    artifacts: [
      { id: 'art-1', type: 'input', name: 'unpacme results 9f3c2a71', sha256: '7a0e3c5b9d1f2e4a6c8b0d2f4e6a8c0b1d3f5e7a9c1b3d5f7e9a0c2b4d6f8e1a', size: 9311, producedBy: 'feed.unpacme 0.4.0' },
      { id: 'art-2', type: 'submitted_sample', parent: 'art-1', name: 'load.bin', sha256: S6_SHA, size: 286720, producedBy: 'UnpacMe' },
      { id: 'art-3', type: 'unpacked_layer', parent: 'art-2', name: 'layer 1', sha256: S6_LAYER, size: 143360, producedBy: 'UnpacMe' },
    ],
    issues: [
      { level: 'info', module: 'feed.unpacme', message: 'Layer strings scanned from the results document. Layer bytes were not retrieved.', recoverable: true },
    ],
    findings: [
      {
        id: 'f-001', type: 'family_indicator', subtype: 'malware_id', value: 'Example.Loader', confidence: 0.7,
        grade: { r: 'B', c: 3, rationale: 'UnpacMe malware_id on the unpacked layer. Service claim; not reproduced locally.' },
        provenance: { kind: 'feed', feed: 'UnpacMe' }, source: 'art-3', tags: [],
        extractedBy: { module: 'feed.unpacme', version: '0.4.0', technique: 'results.malware_id' },
        confidenceMethod: 'service label default 0.70', location: 'results[1].malware_id[0]',
        selectors: [{ kind: 'sha256', value: S6_LAYER, normalized: S6_LAYER }],
        context: { unpack_id: '9f3c2a71' },
        familyData: { family: 'Example.Loader' },
      },
      {
        id: 'f-002', type: 'c2', subtype: 'http_url', value: 'https://update.example.test/gate.php', confidence: 0.5,
        grade: { r: 'C', c: 3, rationale: 'URL in unpacked layer strings. Matches a decoded C2 in another loaded spectrum.' },
        provenance: { kind: 'static' }, source: 'art-3', tags: ['layer-strings'],
        extractedBy: { module: 'strings.patterns', version: '0.9.2', technique: 'regex over layer strings' },
        confidenceMethod: 'pattern match + layer context', location: 'layer 1 strings[211]',
        selectors: [
          { kind: 'url', value: 'https://update.example.test/gate.php', normalized: 'https://update.example.test/gate.php' },
          { kind: 'domain', value: 'update.example.test', normalized: 'update.example.test' },
        ],
        context: { layer: '1' },
      },
      {
        id: 'f-003', type: 'credential_pattern', subtype: 'email', value: 'drop@example.test', confidence: 0.4,
        grade: { r: 'C', c: 4, rationale: 'Pattern match in layer strings only.' },
        provenance: { kind: 'static' }, source: 'art-3', tags: ['layer-strings'],
        extractedBy: { module: 'strings.patterns', version: '0.9.2', technique: 'regex over layer strings' },
        confidenceMethod: 'pattern match only', location: 'layer 1 strings[340]',
        selectors: [{ kind: 'email', value: 'drop@example.test', normalized: 'drop@example.test' }],
        context: { layer: '1' },
      },
      {
        id: 'f-004', type: 'wallet', subtype: 'bitcoin', value: 'bc1qexampletestwallet0q8z7m2k4r9x5n3', confidence: 0.4,
        grade: { r: 'C', c: 4, rationale: 'Bech32-shaped string in layer strings; checksum not validated.' },
        provenance: { kind: 'static' }, source: 'art-3', tags: ['layer-strings'],
        extractedBy: { module: 'strings.patterns', version: '0.9.2', technique: 'regex over layer strings' },
        confidenceMethod: 'pattern match only', location: 'layer 1 strings[512]',
        selectors: [{ kind: 'bitcoin', value: 'bc1qexampletestwallet0q8z7m2k4r9x5n3', normalized: 'bc1qexampletestwallet0q8z7m2k4r9x5n3' }],
        context: { layer: '1' },
      },
    ],
  },
]

export const FINDING_TYPES: FindingType[] = [
  'c2', 'config', 'credential_pattern', 'crypto_material', 'embedded_artifact',
  'family_indicator', 'behavior', 'wallet', 'panel', 'other',
]

export const SELECTOR_KINDS = [
  'sha256', 'sha1', 'md5', 'imphash', 'tlsh', 'ssdeep', 'domain', 'url',
  'ipv4', 'ipv4_port', 'email', 'bitcoin', 'cert_serial',
] as const

export function getSpectrum(id: string) {
  return spectra.find((s) => s.id === id) ?? spectra[0]
}

export function warnCount(s: Spectrum) {
  return s.issues.filter((i) => i.level === 'warning' || i.level === 'error').length
}

export function shortHash(h: string, n = 12) {
  return h.slice(0, n)
}

export function formatBytes(n: number | null) {
  if (n == null) return 'unknown'
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MiB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${n} B`
}

/** Defang URLs and domains for display. Never used for copy. */
export function defang(value: string) {
  const m = value.match(/^(https?)(:\/\/)([^/:]+)(.*)$/i)
  if (m) return `${m[1].replace(/t/gi, 'x')}${m[2]}${m[3].replace(/\./g, '[.]')}${m[4]}`
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(value) && !/^\d+(\.\d+){3}$/.test(value)) return value.replace(/\./g, '[.]')
  return value
}

export function isDefangable(value: string) {
  return defang(value) !== value
}

export type SelectorRow = {
  kind: string
  value: string
  spectra: string[]
  best: number
}

/** Pivot every selector across loaded spectra, including each spectrum's own sha256. */
export function pivotSelectors(list: Spectrum[] = spectra): SelectorRow[] {
  const map = new Map<string, SelectorRow>()
  const add = (kind: string, value: string, sid: string, conf: number) => {
    const key = `${kind}|${value}`
    const row = map.get(key) ?? { kind, value, spectra: [], best: 0 }
    if (!row.spectra.includes(sid)) row.spectra.push(sid)
    row.best = Math.max(row.best, conf)
    map.set(key, row)
  }
  for (const s of list) {
    if (s.inputType !== 'feed_record') add('sha256', s.sha256, s.id, 1)
    for (const f of s.findings) for (const sel of f.selectors) add(sel.kind, sel.normalized, s.id, f.confidence)
  }
  return [...map.values()]
}

export type InputType = 'sample' | 'archive' | 'cape_report' | 'feed_record'
export type Source = 'local file' | 'malwarebazaar' | 'threatfox' | 'unpacme'
export type Review = 'Unreviewed' | 'Reviewed' | 'Skip'
export type FindingType =
  | 'c2' | 'config' | 'credential_pattern' | 'crypto_material' | 'embedded_artifact'
  | 'family_indicator' | 'behavior' | 'wallet' | 'panel' | 'other'

export type Provenance = { kind: 'static' } | { kind: 'sandbox' } | { kind: 'feed'; feed: string }

export type Finding = {
  id: string
  type: FindingType
  subtype: string
  value: string
  confidence: number
  private?: boolean
  grade: { r: string; c: number; rationale: string }
  provenance: Provenance
  source: string
  tags: string[]
  extractedBy: { module: string; version: string; technique: string }
  confidenceMethod: string
  location: string
  selectors: { kind: string; value: string; normalized: string }[]
  context: Record<string, string>
  familyData?: Record<string, string>
}

export type Artifact = {
  id: string
  type: 'input' | 'feed_record' | 'sample_reference' | 'submitted_sample' | 'unpacked_layer'
  parent?: string
  name: string
  sha256: string
  size: number | null
  producedBy: string
}

export type Issue = {
  level: 'info' | 'warning' | 'error'
  module: string
  message: string
  recoverable: boolean
}

export type Spectrum = {
  id: string
  analysisId: string
  inputType: InputType
  name: string
  sha256: string
  size: number
  source: Source
  generated: string
  review: Review
  family: { name: string; method: string; confidence: number } | null
  capabilities: string[]
  riskSignals: string[]
  c2Count: number
  configExtracted: boolean
  encryptionObserved: boolean
  truncated?: boolean
  artifacts: Artifact[]
  issues: Issue[]
  findings: Finding[]
}
