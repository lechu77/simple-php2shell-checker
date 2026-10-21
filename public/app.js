/**
 * PHP2Shell Auditor - Frontend Vanilla JavaScript
 * High-Density Dark Gothic Neon Cybersecurity Telemetry Client.
 */

// Application State
let currentResults = [];
let isAuditing = false;

// DOM Elements
const urlInput = document.getElementById('url-input');
const urlCountBadge = document.getElementById('url-count-badge');
const auditBtn = document.getElementById('audit-btn');
const btnSpinner = document.getElementById('btn-spinner');
const btnIcon = document.getElementById('btn-icon');
const btnText = document.getElementById('btn-text');
const loadSamplesBtn = document.getElementById('load-samples-btn');
const clearBtn = document.getElementById('clear-btn');
const exportCsvBtn = document.getElementById('export-csv-btn');
const filterStatus = document.getElementById('filter-status');
const searchInput = document.getElementById('search-input');
const statusAlert = document.getElementById('status-alert');
const alertMessage = document.getElementById('alert-message');

// Metrics Cards
const metricsDeck = document.getElementById('metrics-deck');
const metricTotal = document.getElementById('metric-total');
const metricVuln = document.getElementById('metric-vuln');
const metricMitigated = document.getElementById('metric-mitigated');
const metricPatched = document.getElementById('metric-patched');
const metricOpaque = document.getElementById('metric-opaque');

// Table Elements
const resultsSection = document.getElementById('results-section');
const resultsTbody = document.getElementById('results-tbody');
const resultsCountBadge = document.getElementById('results-count-badge');
const emptyState = document.getElementById('empty-state');

// Sample Target URLs for testing
const SAMPLE_URLS = [
  'https://httpbin.org/status/200',
  'https://www.php.net',
  'https://wordpress.org',
  'https://cloudflare.com',
  'https://laravel.com'
];

/**
 * Extracts clean list of URLs from textarea.
 */
function getParsedUrls() {
  if (!urlInput) return [];
  return urlInput.value
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0);
}

/**
 * Updates textarea line counter badge.
 */
function updateUrlCounter() {
  const urls = getParsedUrls();
  const count = urls.length;
  urlCountBadge.textContent = `${count} / 10 URLS LOADED`;

  if (count > 10) {
    urlCountBadge.className = 'px-2.5 py-0.5 text-xs font-mono font-bold rounded bg-blood-950 text-blood-500 border border-blood-600 shadow-md shadow-blood-950 animate-pulse';
    auditBtn.disabled = true;
    showAlert('Maximum of 10 URLs allowed per batch.', 'error');
  } else {
    urlCountBadge.className = count === 0
      ? 'px-2.5 py-0.5 text-xs font-mono font-medium rounded bg-crypt-900 text-slate-500 border border-crypt-800'
      : 'px-2.5 py-0.5 text-xs font-mono font-bold rounded bg-blood-950 text-blood-500 border border-blood-900';
    auditBtn.disabled = count === 0 || isAuditing;
    if (count <= 10 && statusAlert && !isAuditing) {
      hideAlert();
    }
  }
}

/**
 * Displays error or informational alert message.
 */
function showAlert(message, type = 'error') {
  if (!statusAlert || !alertMessage) return;
  alertMessage.textContent = message;
  statusAlert.classList.remove('hidden');

  if (type === 'error') {
    statusAlert.className = 'mb-4 p-3.5 rounded border text-xs font-mono flex items-start gap-2 bg-blood-950 border-blood-600 text-red-200 shadow-lg shadow-blood-950 box-neon-blood';
  } else if (type === 'warning') {
    statusAlert.className = 'mb-4 p-3.5 rounded border text-xs font-mono flex items-start gap-2 bg-hellfire-950 border-hellfire-400 text-amber-200 shadow-lg shadow-hellfire-950 box-neon-amber';
  } else {
    statusAlert.className = 'mb-4 p-3.5 rounded border text-xs font-mono flex items-start gap-2 bg-crypt-900 border-crypt-700 text-slate-300 shadow-lg shadow-black';
  }
}

function hideAlert() {
  if (statusAlert) statusAlert.classList.add('hidden');
}

/**
 * Sets button loading spinner state.
 */
function setLoading(loading) {
  isAuditing = loading;
  if (loading) {
    auditBtn.disabled = true;
    urlInput.disabled = true;
    btnSpinner.classList.remove('hidden');
    btnIcon.classList.add('hidden');
    btnText.textContent = 'AUDITING TARGETS...';
  } else {
    urlInput.disabled = false;
    btnSpinner.classList.add('hidden');
    btnIcon.classList.remove('hidden');
    btnText.textContent = 'START AUDIT';
    updateUrlCounter();
  }
}

/**
 * Returns HTML badge styling for detected statuses.
 */
function getStatusBadge(status) {
  switch (status) {
    case 'Vulnerable':
      return `
        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-black bg-blood-950 text-blood-500 border border-blood-600 shadow-lg shadow-blood-950 neon-blood">
          <span class="w-1.5 h-1.5 rounded-full bg-blood-500 animate-occult-pulse"></span>
          VULNERABLE
        </span>`;
    case 'Mitigated by WAF':
      return `
        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-black bg-hellfire-950 text-hellfire-400 border border-hellfire-400/80 shadow-lg shadow-hellfire-950 neon-amber">
          <svg class="w-3.5 h-3.5 text-hellfire-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
          MITIGATED BY WAF
        </span>`;
    case 'Patched':
      return `
        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-black bg-toxic-950 text-toxic-400 border border-toxic-400/80 shadow-lg shadow-toxic-950 neon-toxic">
          <svg class="w-3.5 h-3.5 text-toxic-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
          PATCHED
        </span>`;
    case 'Opaque':
      return `
        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-black bg-eldritch-950 text-purple-400 border border-eldritch-400/80 shadow-lg shadow-eldritch-950 neon-purple">
          <svg class="w-3.5 h-3.5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"/></svg>
          OPAQUE (PHP)
        </span>`;
    case 'Not PHP':
    default:
      return `
        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-medium bg-crypt-900 text-slate-400 border border-crypt-700">
          NOT PHP
        </span>`;
  }
}

/**
 * Updates summary telemetry cards.
 */
function updateMetricsDeck(summary) {
  if (!metricsDeck || !summary) return;
  metricTotal.textContent = summary.total || 0;
  metricVuln.textContent = summary.vulnerable || 0;
  metricMitigated.textContent = summary.mitigated || 0;
  metricPatched.textContent = summary.patched || 0;
  metricOpaque.textContent = (summary.opaque || 0) + (summary.notPhp || 0);
  metricsDeck.classList.remove('hidden');
}

/**
 * Renders the results table with filtering.
 */
function renderResultsTable() {
  if (!resultsTbody) return;

  const statusFilterVal = filterStatus ? filterStatus.value : 'ALL';
  const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : '';

  const filtered = currentResults.filter(item => {
    const matchesStatus = statusFilterVal === 'ALL' || item.status === statusFilterVal;
    const matchesSearch = !searchTerm ||
      item.url.toLowerCase().includes(searchTerm) ||
      (item.phpVersion && item.phpVersion.toLowerCase().includes(searchTerm)) ||
      (item.wafDetected && item.wafDetected.some(w => w.toLowerCase().includes(searchTerm)));
    return matchesStatus && matchesSearch;
  });

  resultsCountBadge.textContent = `${filtered.length} of ${currentResults.length} targets`;
  resultsTbody.innerHTML = '';

  if (filtered.length === 0) {
    resultsTbody.innerHTML = `
      <tr>
        <td colspan="6" class="px-4 py-8 text-center text-xs font-mono text-slate-600 bg-black/50">
          No targets match current filter criteria.
        </td>
      </tr>`;
    return;
  }

  filtered.forEach((row, index) => {
    const tr = document.createElement('tr');
    tr.className = 'border-b border-crypt-800/80 hover:bg-crypt-850/60 transition-colors text-xs font-mono';

    const wafDisplay = row.wafDetected && row.wafDetected.length > 0
      ? row.wafDetected.map(w => `<span class="inline-block px-1.5 py-0.5 rounded bg-crypt-900 text-hellfire-400 border border-hellfire-950 mr-1 mb-1 shadow-sm font-semibold">${escapeHtml(w)}</span>`).join('')
      : '<span class="text-slate-600">None detected</span>';

    const versionDisplay = row.phpVersion
      ? `<span class="px-2 py-0.5 rounded font-bold ${row.isEol ? 'bg-blood-950 text-blood-500 border border-blood-800 neon-blood' : 'bg-crypt-900 text-slate-200 border border-crypt-700'}">${escapeHtml(row.phpVersion)}${row.isEol ? ' (EOL)' : ''}</span>`
      : '<span class="text-slate-600 italic">Hidden / Not exposed</span>';

    const httpBadgeClass = typeof row.httpStatus === 'number' && row.httpStatus >= 200 && row.httpStatus < 300
      ? 'text-toxic-400'
      : (typeof row.httpStatus === 'number' && row.httpStatus >= 300 && row.httpStatus < 400
        ? 'text-cyan-400'
        : 'text-blood-500');

    tr.innerHTML = `
      <td class="px-4 py-3 text-slate-600 select-none">${index + 1}</td>
      <td class="px-4 py-3 font-medium text-slate-200 max-w-xs md:max-w-md truncate" title="${escapeHtml(row.url)}">
        <div class="flex items-center gap-2">
          <a href="${escapeHtml(row.url)}" target="_blank" rel="noopener noreferrer" class="hover:text-blood-500 underline decoration-slate-800 hover:decoration-blood-500 transition-colors truncate">
            ${escapeHtml(row.url)}
          </a>
          <button onclick="navigator.clipboard.writeText('${escapeHtml(row.url)}')" title="Copy URL" class="text-slate-600 hover:text-blood-500 p-0.5 transition-colors">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
          </button>
        </div>
      </td>
      <td class="px-4 py-3 whitespace-nowrap">
        ${getStatusBadge(row.status)}
      </td>
      <td class="px-4 py-3 whitespace-nowrap">
        ${versionDisplay}
      </td>
      <td class="px-4 py-3">
        ${wafDisplay}
      </td>
      <td class="px-4 py-3 whitespace-nowrap font-bold ${httpBadgeClass}">
        ${escapeHtml(String(row.httpStatus))}
        <span class="text-[10px] font-normal text-slate-600 ml-1">(${row.responseTimeMs || 0}ms)</span>
      </td>
    `;

    resultsTbody.appendChild(tr);
  });
}

/**
 * Escapes HTML strings to prevent XSS.
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return String(str || '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Exports current results as CSV.
 */
function exportResultsToCsv() {
  if (!currentResults || currentResults.length === 0) {
    showAlert('No audit results available to export.', 'warning');
    return;
  }

  const headers = [
    'Target_URL',
    'Detected_Status',
    'PHP_Version',
    'Is_EOL',
    'WAF_Perimeter',
    'HTTP_Status',
    'Response_Time_ms',
    'Cookies_Detected',
    'Diagnostic_Details'
  ];

  const rows = currentResults.map(item => {
    return [
      `"${(item.url || '').replace(/"/g, '""')}"`,
      `"${(item.status || '').replace(/"/g, '""')}"`,
      `"${(item.phpVersion || '').replace(/"/g, '""')}"`,
      item.isEol ? 'TRUE' : 'FALSE',
      `"${(item.wafDetected || []).join('; ').replace(/"/g, '""')}"`,
      `"${item.httpStatus}"`,
      item.responseTimeMs || 0,
      `"${(item.cookiesDetected || []).join('; ').replace(/"/g, '""')}"`,
      `"${(item.details || '').replace(/"/g, '""')}"`
    ].join(',');
  });

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const a = document.createElement('a');
  a.href = url;
  a.download = `php2shell-audit-${timestamp}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Primary Audit Function
 */
async function runAudit() {
  const urls = getParsedUrls();

  if (urls.length === 0) {
    showAlert('Please provide at least one target URL to audit.', 'warning');
    return;
  }

  if (urls.length > 10) {
    showAlert('Maximum of 10 URLs allowed per batch.', 'error');
    return;
  }

  hideAlert();
  setLoading(true);

  try {
    const response = await fetch('/api/check', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ urls })
    });

    if (!response.ok) {
      let errText = `HTTP Error ${response.status}`;
      try {
        const errJson = await response.json();
        if (errJson.error) errText = errJson.error;
      } catch {
        // fallback to status code
      }
      throw new Error(errText);
    }

    const data = await response.json();
    currentResults = data.results || [];

    if (emptyState) emptyState.classList.add('hidden');
    if (resultsSection) resultsSection.classList.remove('hidden');
    if (exportCsvBtn) exportCsvBtn.disabled = false;

    updateMetricsDeck(data.summary);
    renderResultsTable();
  } catch (err) {
    showAlert(`Audit execution error: ${err.message}`, 'error');
  } finally {
    setLoading(false);
  }
}

// Event Listeners
if (urlInput) {
  urlInput.addEventListener('input', updateUrlCounter);
  urlInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      if (!auditBtn.disabled) {
        runAudit();
      }
    }
  });
}

if (auditBtn) {
  auditBtn.addEventListener('click', runAudit);
}

if (loadSamplesBtn) {
  loadSamplesBtn.addEventListener('click', () => {
    urlInput.value = SAMPLE_URLS.join('\n');
    updateUrlCounter();
    hideAlert();
  });
}

if (clearBtn) {
  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    currentResults = [];
    updateUrlCounter();
    hideAlert();
    if (metricsDeck) metricsDeck.classList.add('hidden');
    if (resultsSection) resultsSection.classList.add('hidden');
    if (emptyState) emptyState.classList.remove('hidden');
    if (exportCsvBtn) exportCsvBtn.disabled = true;
  });
}

if (exportCsvBtn) {
  exportCsvBtn.addEventListener('click', exportResultsToCsv);
}

if (filterStatus) {
  filterStatus.addEventListener('change', renderResultsTable);
}

if (searchInput) {
  searchInput.addEventListener('input', renderResultsTable);
}

// Initial state initialization
updateUrlCounter();
