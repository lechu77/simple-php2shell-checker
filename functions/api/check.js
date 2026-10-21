import { auditBulkUrls } from './checker.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

/**
 * Cloudflare Pages Function entrypoint for POST /api/check
 */
export async function onRequestPost(context) {
  try {
    const { request } = context;

    let payload;
    try {
      payload = await request.json();
    } catch {
      return new Response(
        JSON.stringify({
          error: 'Malformed JSON payload. Expected { urls: string[] }.'
        }),
        { status: 400, headers: CORS_HEADERS }
      );
    }

    if (!payload || !Array.isArray(payload.urls)) {
      return new Response(
        JSON.stringify({
          error: 'Invalid request body. Field "urls" must be an array of URL strings.'
        }),
        { status: 400, headers: CORS_HEADERS }
      );
    }

    const { urls } = payload;

    if (urls.length === 0) {
      return new Response(
        JSON.stringify({
          error: 'Empty URL list provided. Please supply between 1 and 10 URLs.'
        }),
        { status: 400, headers: CORS_HEADERS }
      );
    }

    if (urls.length > 10) {
      return new Response(
        JSON.stringify({
          error: `Audit quota exceeded. Maximum 10 URLs per batch allowed (received ${urls.length}).`
        }),
        { status: 400, headers: CORS_HEADERS }
      );
    }

    // Run audit with concurrency pool limit 4
    const responseData = await auditBulkUrls(urls, 4, fetch);

    return new Response(JSON.stringify(responseData), {
      status: 200,
      headers: CORS_HEADERS
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: 'Internal edge execution error during audit.',
        message: err.message || 'Unknown error'
      }),
      { status: 500, headers: CORS_HEADERS }
    );
  }
}

/**
 * Handle CORS preflight requests
 */
export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400'
    }
  });
}
