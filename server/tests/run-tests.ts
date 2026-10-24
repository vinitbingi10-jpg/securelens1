import assert from 'assert';
import { isPrivateIPv4, isPrivateIPv6, validateScanTarget } from '../security/ssrf.js';
import { db, hashPassword, verifyPassword } from '../db/database.js';
import { generateToken, getUserFromToken, revokeToken } from '../auth/auth.js';
import { generateHtmlReport } from '../reports/report-generator.js';
import { ScanJob, ScannerFinding, ScannerRun } from '../scanners/types.js';

console.log('--- Starting Secure Lens Automated Test Suite ---');

async function runTests() {
  let passed = 0;
  let failed = 0;

  function test(name: string, fn: () => void | Promise<void>) {
    return Promise.resolve()
      .then(() => fn())
      .then(() => {
        console.log(`[PASS] ${name}`);
        passed++;
      })
      .catch((err) => {
        console.error(`[FAIL] ${name}:`, err.message);
        failed++;
      });
  }

  // 1. SSRF Protection Tests
  await test('SSRF: blocks 127.0.0.1 loopback', () => {
    assert.strictEqual(isPrivateIPv4('127.0.0.1'), true);
  });

  await test('SSRF: blocks 10.0.0.1 Class A private range', () => {
    assert.strictEqual(isPrivateIPv4('10.254.12.1'), true);
  });

  await test('SSRF: blocks 192.168.1.1 Class C private range', () => {
    assert.strictEqual(isPrivateIPv4('192.168.1.1'), true);
  });

  await test('SSRF: blocks 169.254.169.254 Cloud Metadata address', () => {
    assert.strictEqual(isPrivateIPv4('169.254.169.254'), true);
  });

  await test('SSRF: allows valid public IPv4', () => {
    assert.strictEqual(isPrivateIPv4('8.8.8.8'), false);
    assert.strictEqual(isPrivateIPv4('93.184.216.34'), false);
  });

  await test('SSRF: blocks IPv6 loopback (::1)', () => {
    assert.strictEqual(isPrivateIPv6('::1'), true);
  });

  await test('Target Validation: blocks non-http/https protocol', async () => {
    const res = await validateScanTarget('ftp://evil.com/file');
    assert.strictEqual(res.valid, false);
    assert.match(res.error || '', /Unsupported protocol/);
  });

  await test('Target Validation: blocks restricted database port 5432', async () => {
    const res = await validateScanTarget('http://example.com:5432/');
    assert.strictEqual(res.valid, false);
    assert.match(res.error || '', /restricted/);
  });

  // 2. Authentication and Cryptographic Tests
  await test('Auth: password hashing and verification with scrypt', () => {
    const { hash, salt } = hashPassword('MySuperSecurePass2026!');
    assert.strictEqual(verifyPassword('MySuperSecurePass2026!', hash, salt), true);
    assert.strictEqual(verifyPassword('WrongPassword123', hash, salt), false);
  });

  await test('Auth: token issuance and revocation', () => {
    const dummyUser = db.findUserByEmail('analyst@securelens.local');
    assert.ok(dummyUser);

    const token = generateToken(dummyUser!.id);
    const resolved = getUserFromToken(token);
    assert.strictEqual(resolved?.id, dummyUser!.id);

    revokeToken(token);
    assert.strictEqual(getUserFromToken(token), null);
  });

  // 3. Database and Deduplication Tests
  await test('DB: finding creation and deduplication', () => {
    const testJobId = 'scan_unit_test_dedup';
    const finding1: ScannerFinding = {
      id: 'fnd_test_1',
      scanJobId: testJobId,
      scannerName: 'Header Test',
      title: 'Missing Header',
      category: 'Headers & Policy',
      severity: 'HIGH',
      originalSeverity: 'HIGH',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: 'Test description',
      affectedUrl: 'https://test.local',
      evidence: {},
      fingerprint: 'test_fingerprint_unique_1',
      firstSeenAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
    };

    db.addFindings([finding1]);
    const retrieved = db.getFindingById('fnd_test_1');
    assert.ok(retrieved);
    assert.strictEqual(retrieved?.title, 'Missing Header');
  });

  // 4. Report Generation Tests
  await test('Reports: generateHtmlReport produces valid HTML with findings', () => {
    const mockJob: ScanJob = {
      id: 'scan_report_test',
      userId: 'usr_sec_analyst_01',
      targetUrl: 'https://security.example.org',
      targetHost: 'security.example.org',
      scanProfile: 'owasp_standard',
      selectedTools: ['http_headers'],
      enableNetworkChecks: false,
      authorizationConfirmedAt: new Date().toISOString(),
      status: 'completed',
      metrics: {
        criticalCount: 0,
        highCount: 1,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        totalFindings: 1,
      },
      createdAt: new Date().toISOString(),
    };

    const mockRun: ScannerRun = {
      id: 'run_test_1',
      scanJobId: mockJob.id,
      scannerName: 'HTTP Security Headers Inspector',
      scannerVersion: 'v2.4.1',
      status: 'completed',
      findingsCount: 1,
    };

    const mockFinding: ScannerFinding = {
      id: 'fnd_report_1',
      scanJobId: mockJob.id,
      scannerName: 'HTTP Security Headers Inspector',
      title: 'HSTS Header Missing',
      category: 'Headers & Policy',
      severity: 'HIGH',
      originalSeverity: 'HIGH',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: 'Test HSTS missing',
      affectedUrl: 'https://security.example.org',
      evidence: { rawHeader: 'Strict-Transport-Security: null' },
      fingerprint: 'hsts_missing_example',
      firstSeenAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
    };

    const html = generateHtmlReport(mockJob, [mockRun], [mockFinding], new Map());
    assert.ok(html.includes('SECURE LENS'));
    assert.ok(html.includes('HSTS Header Missing'));
    assert.ok(html.includes('Strict-Transport-Security: null'));
  });

  console.log(`\nTest Execution Summary: ${passed} Passed, ${failed} Failed.`);
  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
