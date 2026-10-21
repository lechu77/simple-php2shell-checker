import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractPhpVersion,
  evaluatePhpVulnerability,
  detectWafs,
  detectPhpCookies,
  determineStatus,
  normalizeUrl,
  asyncPool,
  auditSingleUrl,
  auditBulkUrls
} from '../functions/api/checker.js';

test('extractPhpVersion correctly parses version patterns', () => {
  assert.deepEqual(extractPhpVersion('PHP/8.3.20'), {
    versionString: '8.3.20',
    major: 8,
    minor: 3,
    patch: 20
  });

  assert.deepEqual(extractPhpVersion('Apache/2.4.52 (Ubuntu) PHP/8.4.27-1+deb OpenSSL/3.0.2'), {
    versionString: '8.4.27',
    major: 8,
    minor: 4,
    patch: 27
  });

  assert.deepEqual(extractPhpVersion('PHP/8.2'), {
    versionString: '8.2.0',
    major: 8,
    minor: 2,
    patch: 0
  });

  assert.equal(extractPhpVersion('nginx/1.24.0'), null);
  assert.equal(extractPhpVersion('PHP'), null);
  assert.equal(extractPhpVersion(null), null);
});

test('evaluatePhpVulnerability evaluates fixed branches accurately', () => {
  // Branch 8.5 (fixed at 8.5.12)
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 5, patch: 12, versionString: '8.5.12' }).isPatched, true);
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 5, patch: 11, versionString: '8.5.11' }).isPatched, false);

  // Branch 8.4 (fixed at 8.4.27)
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 4, patch: 27, versionString: '8.4.27' }).isPatched, true);
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 4, patch: 26, versionString: '8.4.26' }).isPatched, false);

  // Branch 8.3 (fixed at 8.3.36)
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 3, patch: 36, versionString: '8.3.36' }).isPatched, true);
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 3, patch: 35, versionString: '8.3.35' }).isPatched, false);
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 3, patch: 20, versionString: '8.3.20' }).isPatched, false);

  // Branch 8.2 (fixed at 8.2.35)
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 2, patch: 35, versionString: '8.2.35' }).isPatched, true);
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 2, patch: 34, versionString: '8.2.34' }).isPatched, false);

  // EOL Branches (< 8.2)
  const eol81 = evaluatePhpVulnerability({ major: 8, minor: 1, patch: 29, versionString: '8.1.29' });
  assert.equal(eol81.isPatched, false);
  assert.equal(eol81.isEol, true);

  const eol74 = evaluatePhpVulnerability({ major: 7, minor: 4, patch: 33, versionString: '7.4.33' });
  assert.equal(eol74.isPatched, false);
  assert.equal(eol74.isEol, true);

  // Future major / minor branches
  assert.equal(evaluatePhpVulnerability({ major: 8, minor: 6, patch: 0, versionString: '8.6.0' }).isPatched, true);
  assert.equal(evaluatePhpVulnerability({ major: 9, minor: 0, patch: 0, versionString: '9.0.0' }).isPatched, true);
});

test('detectWafs identifies perimeter headers', () => {
  const cfHeaders = new Headers({
    'cf-ray': '8f123456789abcde-MAD',
    'server': 'cloudflare'
  });
  assert.deepEqual(detectWafs(cfHeaders), ['Cloudflare']);

  const cloudFrontHeaders = new Headers({
    'x-amz-cf-id': 'k8x09-xyz123==',
    'server': 'AmazonS3'
  });
  assert.deepEqual(detectWafs(cloudFrontHeaders), ['AWS CloudFront']);

  const sucuriHeaders = new Headers({
    'x-sucuri-id': '19023'
  });
  assert.deepEqual(detectWafs(sucuriHeaders), ['Sucuri']);

  const impervaHeaders = new Headers({
    'x-iinfo': '123-4567-89'
  });
  assert.deepEqual(detectWafs(impervaHeaders), ['Imperva Incapsula']);

  const emptyHeaders = new Headers({
    'server': 'nginx/1.22'
  });
  assert.deepEqual(detectWafs(emptyHeaders), []);
});

test('detectPhpCookies detects session cookies and framework tokens', () => {
  const cookies1 = ['PHPSESSID=abf182c9e701; Path=/; HttpOnly'];
  assert.deepEqual(detectPhpCookies(cookies1), ['PHPSESSID']);

  const cookies2 = [
    'laravel_session=eyJpdiI6In...; Path=/',
    'XSRF-TOKEN=eyJp...; Path=/'
  ];
  assert.deepEqual(detectPhpCookies(cookies2), ['Laravel Session']);

  const cookiesNone = ['session_id=1234; theme=dark'];
  assert.deepEqual(detectPhpCookies(cookiesNone), []);
});

test('determineStatus classifies results according to status rules', () => {
  // Vulnerable without WAF
  const vulnNoWaf = determineStatus({
    versionAssessment: { isPatched: false, reason: 'PHP 8.3.20 is vulnerable' },
    hasGenericPhpHeader: false,
    detectedCookies: [],
    wafs: []
  });
  assert.equal(vulnNoWaf.status, 'Vulnerable');

  // Vulnerable WITH WAF
  const vulnWithWaf = determineStatus({
    versionAssessment: { isPatched: false, reason: 'PHP 8.3.20 is vulnerable' },
    hasGenericPhpHeader: false,
    detectedCookies: [],
    wafs: ['Cloudflare']
  });
  assert.equal(vulnWithWaf.status, 'Mitigated by WAF');

  // Patched version
  const patched = determineStatus({
    versionAssessment: { isPatched: true, reason: 'PHP 8.3.36 is patched' },
    hasGenericPhpHeader: false,
    detectedCookies: [],
    wafs: ['AWS CloudFront']
  });
  assert.equal(patched.status, 'Patched');

  // Opaque (no version exposed, but PHPSESSID cookie present)
  const opaqueCookie = determineStatus({
    versionAssessment: null,
    hasGenericPhpHeader: false,
    detectedCookies: ['PHPSESSID'],
    wafs: []
  });
  assert.equal(opaqueCookie.status, 'Opaque');

  // Opaque (generic X-Powered-By: PHP header)
  const opaqueHeader = determineStatus({
    versionAssessment: null,
    hasGenericPhpHeader: true,
    detectedCookies: [],
    wafs: ['Cloudflare']
  });
  assert.equal(opaqueHeader.status, 'Opaque');

  // Not PHP
  const notPhp = determineStatus({
    versionAssessment: null,
    hasGenericPhpHeader: false,
    detectedCookies: [],
    wafs: ['Cloudflare']
  });
  assert.equal(notPhp.status, 'Not PHP');
});

test('normalizeUrl handles protocol auto-prepend and validates', () => {
  assert.equal(normalizeUrl('example.com'), 'https://example.com/');
  assert.equal(normalizeUrl('http://test.org/path'), 'http://test.org/path');
  assert.equal(normalizeUrl('https://api.domain.io/endpoint'), 'https://api.domain.io/endpoint');
  assert.equal(normalizeUrl('not a url %%%'), null);
  assert.equal(normalizeUrl(''), null);
});

test('asyncPool respects concurrency limit', async () => {
  let active = 0;
  let maxActive = 0;
  const items = [1, 2, 3, 4, 5, 6, 7];

  const results = await asyncPool(3, items, async (num) => {
    active++;
    if (active > maxActive) maxActive = active;
    await new Promise((r) => setTimeout(r, 10));
    active--;
    return num * 2;
  });

  assert.equal(maxActive <= 3, true);
  assert.deepEqual(results, [2, 4, 6, 8, 10, 12, 14]);
});

test('auditBulkUrls rejects requests over 10 URLs', async () => {
  const overLimit = Array.from({ length: 11 }, (_, i) => `https://example${i}.com`);
  await assert.rejects(async () => {
    await auditBulkUrls(overLimit, 4);
  }, /Maximum of 10 URLs allowed/);
});

test('auditSingleUrl performs mock HEAD with fallback and header parsing', async () => {
  // Mock fetch simulating vulnerable PHP 8.3.20 without WAF
  const mockFetch = async (url, options) => {
    return {
      status: 200,
      headers: new Headers({
        'x-powered-by': 'PHP/8.3.20',
        'server': 'Apache/2.4.52'
      }),
      body: {
        cancel: async () => {}
      }
    };
  };

  const res = await auditSingleUrl('https://vuln-site.internal', mockFetch);
  assert.equal(res.status, 'Vulnerable');
  assert.equal(res.phpVersion, '8.3.20');
  assert.deepEqual(res.wafDetected, []);
  assert.equal(res.httpStatus, 200);
});

test('auditSingleUrl detects Cloudflare mitigation for vulnerable version', async () => {
  // Mock fetch simulating vulnerable PHP 8.2.20 behind Cloudflare
  const mockFetch = async () => {
    return {
      status: 200,
      headers: new Headers({
        'x-powered-by': 'PHP/8.2.20',
        'cf-ray': '8f123456789abcde-MAD',
        'server': 'cloudflare'
      }),
      body: { cancel: async () => {} }
    };
  };

  const res = await auditSingleUrl('https://mitigated-site.internal', mockFetch);
  assert.equal(res.status, 'Mitigated by WAF');
  assert.equal(res.phpVersion, '8.2.20');
  assert.deepEqual(res.wafDetected, ['Cloudflare']);
});

test('auditSingleUrl falls back from 405 HEAD to GET', async () => {
  let callCount = 0;
  const methods = [];

  const mockFetch = async (url, options) => {
    callCount++;
    methods.push(options.method);
    if (options.method === 'HEAD') {
      return {
        status: 405,
        headers: new Headers({ 'allow': 'GET, POST' })
      };
    }
    return {
      status: 200,
      headers: new Headers({
        'x-powered-by': 'PHP/8.4.27',
        'set-cookie': 'PHPSESSID=test1234; path=/'
      }),
      body: { cancel: async () => {} }
    };
  };

  const res = await auditSingleUrl('https://head-blocked.internal', mockFetch);
  assert.deepEqual(methods, ['HEAD', 'GET']);
  assert.equal(res.status, 'Patched');
  assert.equal(res.phpVersion, '8.4.27');
  assert.equal(res.httpStatus, 200);
});

test('auditSingleUrl identifies Opaque target via session cookie when expose_php is disabled', async () => {
  const mockFetch = async () => {
    return {
      status: 200,
      headers: new Headers({
        'server': 'nginx/1.24.0',
        'set-cookie': 'PHPSESSID=opaque-session-token; path=/'
      }),
      body: { cancel: async () => {} }
    };
  };

  const res = await auditSingleUrl('https://opaque-site.internal', mockFetch);
  assert.equal(res.status, 'Opaque');
  assert.equal(res.phpVersion, null);
  assert.deepEqual(res.cookiesDetected, ['PHPSESSID']);
});
