/**
 * PHP2Shell (CVE-2026-109618 & CVE-2026-109619) Passive Fingerprinter
 * Fixed versions:
 *  - PHP 8.5: >= 8.5.12
 *  - PHP 8.4: >= 8.4.27
 *  - PHP 8.3: >= 8.3.36
 *  - PHP 8.2: >= 8.2.35
 *  - EOL branches (< 8.2): End-of-Life, unpatched / vulnerable
 *  - >= 8.6: Patched
 */

export const FIXED_BRANCHES = {
  '8.5': 12,
  '8.4': 27,
  '8.3': 36,
  '8.2': 35
};

export const WAF_SIGNATURES = [
  { name: 'Cloudflare', header: 'cf-ray' },
  { name: 'Cloudflare', header: 'server', regex: /cloudflare/i },
  { name: 'AWS CloudFront', header: 'x-amz-cf-id' },
  { name: 'AWS CloudFront', header: 'x-amz-cf-pop' },
  { name: 'Sucuri', header: 'x-sucuri-id' },
  { name: 'Sucuri', header: 'x-sucuri-cache' },
  { name: 'Imperva Incapsula', header: 'x-iinfo' },
  { name: 'Imperva Incapsula', header: 'x-cdn', regex: /imperva|incapsula/i },
  { name: 'Akamai', header: 'x-akamai-transformed' },
  { name: 'Akamai', header: 'akamai-grn' },
  { name: 'Akamai', header: 'server', regex: /akamai/i },
  { name: 'Fastly', header: 'fastly-debug-digest' },
  { name: 'Fastly', header: 'x-served-by', regex: /cache-/i },
  { name: 'Varnish', header: 'x-varnish' },
  { name: 'F5 BIG-IP', header: 'server', regex: /big-?ip/i },
  { name: 'F5 BIG-IP', header: 'x-f5-' },
  { name: 'Wordfence', header: 'server', regex: /wordfence/i }
];

export const PHP_SESSION_COOKIE_PATTERNS = [
  { name: 'PHPSESSID', regex: /PHPSESSID=/i },
  { name: 'Laravel Session', regex: /laravel_session=/i },
  { name: 'CakePHP Session', regex: /CAKEPHP=/i },
  { name: 'CodeIgniter Session', regex: /ci_session=/i },
  { name: 'Symfony Session', regex: /symfony=/i },
  { name: 'Craft CMS Session', regex: /craftsessionid=/i },
  { name: 'ExpressionEngine Session', regex: /exp_sessionid=/i },
  { name: 'WordPress Cookie', regex: /(?:wordpress_sec_|wp-settings-)/i },
  { name: 'Joomla Session', regex: /joomla_[a-z0-9_]+=/i },
  { name: 'Drupal Session', regex: /SESS[a-z0-9]{32}=/i },
  { name: 'PrestaShop Cookie', regex: /PrestaShop-[a-z0-9]+=/i }
];

/**
 * Parses and extracts PHP version from header strings.
 * Returns { versionString, major, minor, patch } or null if no version found.
 */
export function extractPhpVersion(headerValue) {
  if (!headerValue || typeof headerValue !== 'string') return null;

  // Match patterns like "PHP/8.3.20", "PHP 8.4.27-1+ubuntu", "php/8.2.35"
  const match = headerValue.match(/(?:PHP\/?\s*|\bphp\/)([0-9]+)\.([0-9]+)(?:\.([0-9]+))?/i);
  if (!match) return null;

  const major = parseInt(match[1], 10);
  const minor = parseInt(match[2], 10);
  const patch = match[3] !== undefined ? parseInt(match[3], 10) : 0;
  const versionString = `${major}.${minor}.${patch}`;

  return {
    versionString,
    major,
    minor,
    patch
  };
}

/**
 * Assesses whether a parsed PHP version is patched or vulnerable against PHP2Shell.
 */
export function evaluatePhpVulnerability(parsedVersion) {
  if (!parsedVersion) return null;

  const { major, minor, patch, versionString } = parsedVersion;
  const branchKey = `${major}.${minor}`;

  if (major > 8) {
    return {
      version: versionString,
      isPatched: true,
      isEol: false,
      reason: `PHP ${versionString} is ahead of the vulnerable 8.x branch.`
    };
  }

  if (major === 8) {
    if (minor > 5) {
      return {
        version: versionString,
        isPatched: true,
        isEol: false,
        reason: `PHP ${versionString} is a later branch (>= 8.6) not affected.`
      };
    }

    if (branchKey in FIXED_BRANCHES) {
      const minFixedPatch = FIXED_BRANCHES[branchKey];
      const isPatched = patch >= minFixedPatch;
      return {
        version: versionString,
        isPatched,
        isEol: false,
        minFixedPatch,
        reason: isPatched
          ? `PHP ${versionString} is patched (fixed in >= ${branchKey}.${minFixedPatch}).`
          : `PHP ${versionString} is vulnerable to PHP2Shell (fixed in >= ${branchKey}.${minFixedPatch}).`
      };
    }

    // Branch 8.1 or 8.0: EOL
    return {
      version: versionString,
      isPatched: false,
      isEol: true,
      reason: `PHP ${versionString} is End-of-Life (EOL) with no official upstream backport.`
    };
  }

  // Major < 8 (e.g. PHP 7.x, 5.x): EOL
  return {
    version: versionString,
    isPatched: false,
    isEol: true,
    reason: `PHP ${versionString} is End-of-Life (EOL) with no official upstream backport.`
  };
}

/**
 * Detects presence of WAF / Reverse Proxy perimeters based on response headers.
 */
export function detectWafs(headers) {
  const detected = new Set();

  for (const sig of WAF_SIGNATURES) {
    const headerVal = headers.get(sig.header);
    if (!headerVal) continue;

    if (!sig.regex) {
      detected.add(sig.name);
    } else if (sig.regex.test(headerVal)) {
      detected.add(sig.name);
    }
  }

  return Array.from(detected);
}

/**
 * Detects PHP session cookies or framework markers.
 */
export function detectPhpCookies(cookieStrings) {
  if (!cookieStrings || cookieStrings.length === 0) return [];
  const detected = new Set();
  const rawJoined = cookieStrings.join('; ');

  for (const pattern of PHP_SESSION_COOKIE_PATTERNS) {
    if (pattern.regex.test(rawJoined)) {
      detected.add(pattern.name);
    }
  }

  return Array.from(detected);
}

/**
 * Determines overall audit status according to requirements:
 * Statuses: 'Vulnerable', 'Mitigated by WAF', 'Patched', 'Not PHP', or 'Opaque'.
 */
export function determineStatus({
  versionAssessment,
  hasGenericPhpHeader,
  detectedCookies,
  wafs
}) {
  const hasWaf = wafs && wafs.length > 0;

  if (versionAssessment) {
    if (versionAssessment.isPatched) {
      return {
        status: 'Patched',
        details: versionAssessment.reason
      };
    }

    // Vulnerable or EOL version
    if (hasWaf) {
      return {
        status: 'Mitigated by WAF',
        details: `${versionAssessment.reason} Mitigated at edge by: ${wafs.join(', ')}.`
      };
    }

    return {
      status: 'Vulnerable',
      details: `${versionAssessment.reason} No WAF perimeter detected.`
    };
  }

  // No specific PHP version exposed. Check if PHP execution is confirmed.
  const hasPhpCookie = detectedCookies && detectedCookies.length > 0;
  if (hasGenericPhpHeader || hasPhpCookie) {
    const indicators = [];
    if (hasGenericPhpHeader) indicators.push('generic PHP header');
    if (hasPhpCookie) indicators.push(`cookie: ${detectedCookies.join(', ')}`);

    return {
      status: 'Opaque',
      details: `PHP execution confirmed via ${indicators.join(' & ')}, but version is masked (expose_php = Off).`
    };
  }

  return {
    status: 'Not PHP',
    details: 'No PHP version headers, framework tokens, or session cookies detected.'
  };
}

/**
 * Normalizes input URL. Prepends https:// if missing.
 */
export function normalizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  let trimmed = rawUrl.trim();
  if (!trimmed) return null;

  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = `https://${trimmed}`;
  }

  try {
    const parsed = new URL(trimmed);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}

/**
 * Concurrency pool runner to process items with concurrency limit (3-5).
 */
export async function asyncPool(limit, items, iteratorFn) {
  const results = [];
  const executing = new Set();

  for (const item of items) {
    const promise = Promise.resolve().then(() => iteratorFn(item));
    results.push(promise);
    executing.add(promise);

    const clean = () => executing.delete(promise);
    promise.then(clean, clean);

    if (executing.size >= limit) {
      await Promise.race(executing);
    }
  }

  return Promise.all(results);
}

/**
 * Audits a single URL with low-overhead HEAD request, fallback to GET, manual redirect handling,
 * and strict 4-second timeout.
 */
export async function auditSingleUrl(targetUrl, fetchFn = fetch) {
  const normalized = normalizeUrl(targetUrl);
  if (!normalized) {
    return {
      url: targetUrl,
      status: 'Opaque',
      phpVersion: null,
      wafDetected: [],
      httpStatus: 'Invalid URL',
      details: 'Invalid or unsupported URL syntax.',
      responseTimeMs: 0
    };
  }

  const startTime = Date.now();
  let currentUrl = normalized;
  let redirectsCount = 0;
  const maxRedirects = 3;

  let finalStatus = 0;
  const aggregatedHeaders = new Map();
  const rawSetCookies = [];

  const addHeadersToMap = (headers) => {
    if (!headers) return;
    for (const [k, v] of headers.entries()) {
      const lower = k.toLowerCase();
      if (!aggregatedHeaders.has(lower)) {
        aggregatedHeaders.set(lower, v);
      }
    }
    if (typeof headers.getSetCookie === 'function') {
      const cookies = headers.getSetCookie();
      if (Array.isArray(cookies)) {
        rawSetCookies.push(...cookies);
      }
    } else {
      const cookie = headers.get('set-cookie');
      if (cookie) rawSetCookies.push(cookie);
    }
  };

  try {
    while (redirectsCount <= maxRedirects) {
      let res = null;
      let usedMethod = 'HEAD';

      // 4-second strict timeout
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);

      try {
        res = await fetchFn(currentUrl, {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PHP2ShellAuditor/1.0; +https://github.com/lechu77/simple-php2shell-checker)',
            'Accept': '*/*'
          }
        });

        // Fallback to GET if HEAD is rejected by server
        if ([405, 403, 501].includes(res.status)) {
          clearTimeout(timer);
          const getController = new AbortController();
          const getTimer = setTimeout(() => getController.abort(), 4000);
          try {
            res = await fetchFn(currentUrl, {
              method: 'GET',
              redirect: 'manual',
              signal: getController.signal,
              headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; PHP2ShellAuditor/1.0; +https://github.com/lechu77/simple-php2shell-checker)',
                'Accept': '*/*',
                'Range': 'bytes=0-1024'
              }
            });
            usedMethod = 'GET';
          } finally {
            clearTimeout(getTimer);
          }
        }
      } catch (fetchErr) {
        // Fallback to GET if HEAD failed with network/protocol error
        if (usedMethod === 'HEAD') {
          const getController = new AbortController();
          const getTimer = setTimeout(() => getController.abort(), 4000);
          try {
            res = await fetchFn(currentUrl, {
              method: 'GET',
              redirect: 'manual',
              signal: getController.signal,
              headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; PHP2ShellAuditor/1.0; +https://github.com/lechu77/simple-php2shell-checker)',
                'Accept': '*/*',
                'Range': 'bytes=0-1024'
              }
            });
            usedMethod = 'GET';
          } finally {
            clearTimeout(getTimer);
          }
        } else {
          throw fetchErr;
        }
      } finally {
        clearTimeout(timer);
      }

      if (!res) {
        throw new Error('No response received from target.');
      }

      finalStatus = res.status;
      addHeadersToMap(res.headers);

      // Cancel GET body stream immediately to avoid overhead
      if (res.body && typeof res.body.cancel === 'function') {
        try {
          await res.body.cancel();
        } catch {
          // ignore stream cancel errors
        }
      }

      // Check manual redirects
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const location = res.headers.get('location');
        if (location && redirectsCount < maxRedirects) {
          try {
            currentUrl = new URL(location, currentUrl).href;
            redirectsCount++;
            continue;
          } catch {
            // malformed location, stop redirect chain
            break;
          }
        }
      }

      break;
    }
  } catch (err) {
    const responseTimeMs = Date.now() - startTime;
    const isTimeout = err.name === 'AbortError' || err.message?.includes('aborted');

    return {
      url: normalized,
      status: 'Opaque',
      phpVersion: null,
      wafDetected: [],
      httpStatus: isTimeout ? 'Timeout (4s)' : 'Connection Failed',
      details: isTimeout
        ? 'Target failed to respond within 4.0s timeout limit.'
        : `Network request error: ${err.message || 'Host unreachable'}`,
      responseTimeMs
    };
  }

  const responseTimeMs = Date.now() - startTime;

  // Extract PHP Version from X-Powered-By or Server
  const xPoweredBy = aggregatedHeaders.get('x-powered-by') || '';
  const serverHeader = aggregatedHeaders.get('server') || '';

  const parsedFromPoweredBy = extractPhpVersion(xPoweredBy);
  const parsedFromServer = extractPhpVersion(serverHeader);
  const parsedVersion = parsedFromPoweredBy || parsedFromServer;

  const versionAssessment = evaluatePhpVulnerability(parsedVersion);

  const hasGenericPhpHeader =
    /\bphp\b/i.test(xPoweredBy) ||
    /\bphp\b/i.test(serverHeader);

  // WAF and cookie detection
  const wafs = detectWafs(aggregatedHeaders);
  const detectedCookies = detectPhpCookies(rawSetCookies);

  // Determine final status
  const { status, details } = determineStatus({
    versionAssessment,
    hasGenericPhpHeader,
    detectedCookies,
    wafs
  });

  return {
    url: normalized,
    status,
    phpVersion: parsedVersion ? parsedVersion.versionString : null,
    isEol: versionAssessment ? versionAssessment.isEol : false,
    wafDetected: wafs,
    httpStatus: finalStatus,
    phpDetected: !!(parsedVersion || hasGenericPhpHeader || detectedCookies.length > 0),
    cookiesDetected: detectedCookies,
    responseTimeMs,
    details
  };
}

/**
 * Audits up to 10 URLs in bulk using concurrency limit of 4.
 */
export async function auditBulkUrls(urls, concurrency = 4, fetchFn = fetch) {
  if (!Array.isArray(urls)) {
    throw new TypeError('URLs parameter must be an array.');
  }

  if (urls.length > 10) {
    throw new Error('Maximum of 10 URLs allowed per audit batch.');
  }

  const results = await asyncPool(concurrency, urls, (url) => auditSingleUrl(url, fetchFn));

  const summary = {
    total: results.length,
    vulnerable: results.filter(r => r.status === 'Vulnerable').length,
    mitigated: results.filter(r => r.status === 'Mitigated by WAF').length,
    patched: results.filter(r => r.status === 'Patched').length,
    opaque: results.filter(r => r.status === 'Opaque').length,
    notPhp: results.filter(r => r.status === 'Not PHP').length
  };

  return {
    results,
    summary,
    timestamp: new Date().toISOString()
  };
}
