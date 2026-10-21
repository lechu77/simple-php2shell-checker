import test from 'node:test';
import assert from 'node:assert/strict';
import { onRequestPost, onRequestOptions } from '../functions/api/check.js';

test('onRequestOptions returns 204 with CORS headers', async () => {
  const res = await onRequestOptions();
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), '*');
  assert.equal(res.headers.get('Access-Control-Allow-Methods'), 'POST, OPTIONS');
});

test('onRequestPost rejects malformed body', async () => {
  const mockContext = {
    request: {
      json: async () => { throw new Error('SyntaxError'); }
    }
  };
  const res = await onRequestPost(mockContext);
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.match(data.error, /Malformed JSON payload/);
});

test('onRequestPost rejects missing urls array', async () => {
  const mockContext = {
    request: {
      json: async () => ({ notUrls: [] })
    }
  };
  const res = await onRequestPost(mockContext);
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.match(data.error, /Field "urls" must be an array/);
});

test('onRequestPost rejects empty urls array', async () => {
  const mockContext = {
    request: {
      json: async () => ({ urls: [] })
    }
  };
  const res = await onRequestPost(mockContext);
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.match(data.error, /Empty URL list/);
});

test('onRequestPost rejects more than 10 URLs', async () => {
  const mockContext = {
    request: {
      json: async () => ({
        urls: Array.from({ length: 11 }, (_, i) => `https://test${i}.internal`)
      })
    }
  };
  const res = await onRequestPost(mockContext);
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.match(data.error, /Maximum 10 URLs per batch allowed/);
});
