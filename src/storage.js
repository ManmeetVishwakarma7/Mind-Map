const path = require('node:path');
const crypto = require('node:crypto');

const maxBytes = Math.max(1, Number(process.env.MAX_UPLOAD_MB || 20)) * 1024 * 1024;
const bucket = process.env.SUPABASE_STORAGE_BUCKET || 'mindmap-resources';
const rules = {
  '.pdf': { mime: ['application/pdf'], kind: 'pdf' },
  '.png': { mime: ['image/png'], kind: 'image' },
  '.jpg': { mime: ['image/jpeg'], kind: 'image' },
  '.jpeg': { mime: ['image/jpeg'], kind: 'image' },
  '.webp': { mime: ['image/webp'], kind: 'image' },
  '.mp4': { mime: ['video/mp4'], kind: 'video_file' },
  '.webm': { mime: ['video/webm'], kind: 'video_file' },
  '.txt': { mime: ['text/plain'], kind: 'notes_file' }
};

function storageConfig() {
  const base = process.env.SUPABASE_URL?.replace(/\/$/, '');
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!base || !key) throw new Error('Supabase Storage is not configured.');
  return { base, key };
}
function objectUrl(key) {
  const safe = resolveKey(key);
  return `${storageConfig().base}/storage/v1/object/${encodeURIComponent(bucket)}/${encodeURIComponent(path.basename(safe))}`;
}
function safeKey(originalName, mimeType, size) {
  if (!originalName || typeof originalName !== 'string' || originalName.length > 255) throw new Error('Invalid file name.');
  if (size > maxBytes) throw new Error(`Files must be smaller than ${Math.floor(maxBytes / 1024 / 1024)} MB.`);
  const ext = path.extname(originalName).toLowerCase();
  const rule = rules[ext];
  if (!rule || !rule.mime.includes(mimeType)) throw new Error('File type is not supported or its MIME type does not match the extension.');
  return { key: `${crypto.randomUUID()}${ext}`, type: rule.kind, ext };
}
function validateSignature(type, buffer) {
  const starts=(bytes)=>buffer.length>=bytes.length&&buffer.subarray(0,bytes.length).equals(Buffer.from(bytes));
  const valid=type==='pdf'?starts('%PDF-'):
    type==='image'?(starts([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])||starts([0xff,0xd8,0xff])||(buffer.length>=12&&buffer.subarray(0,4).toString()==='RIFF'&&buffer.subarray(8,12).toString()==='WEBP')):
    type==='video_file'?(buffer.length>=12&&buffer.subarray(4,8).toString()==='ftyp'||starts([0x1a,0x45,0xdf,0xa3])):
    type==='notes_file'?!buffer.includes(0):false;
  if(!valid)throw new Error('File content does not match its declared type.');
  return true;
}
function resolveKey(key) {
  if (typeof key !== 'string' || !/^[a-f0-9-]{36}\.(pdf|png|jpe?g|webp|mp4|webm|txt)$/.test(key)) throw new Error('Invalid storage key.');
  return path.resolve('/', key);
}
async function storageRequest(url, options = {}) {
  const { base, key } = storageConfig();
  const response = await fetch(url.startsWith('http') ? url : `${base}${url}`, {
    ...options,
    headers: { apikey: key, Authorization: `Bearer ${key}`, ...(options.headers || {}) }
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Supabase Storage request failed (${response.status})${detail ? `: ${detail.slice(0, 250)}` : ''}`);
  }
  return response;
}
async function ensureBucket() {
  const bucketPath = `/storage/v1/bucket/${encodeURIComponent(bucket)}`;
  try {
    await storageRequest(bucketPath);
    return;
  } catch (error) {
    if (!String(error.message).includes('(404)')) throw error;
  }
  const allowedMimeTypes = [...new Set(Object.values(rules).flatMap(rule => rule.mime))];
  try {
    await storageRequest('/storage/v1/bucket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: bucket,
        name: bucket,
        public: false,
        file_size_limit: maxBytes,
        allowed_mime_types: allowedMimeTypes
      })
    });
  } catch (error) {
    // Another upload may have created it after our lookup.
    if (!String(error.message).includes('(409)')) throw error;
  }
  await storageRequest(bucketPath);
}
async function saveBuffer(key, buffer, mimeType = 'application/octet-stream') {
  const safe = resolveKey(key);
  await ensureBucket();
  await storageRequest(`/storage/v1/object/${encodeURIComponent(bucket)}/${encodeURIComponent(path.basename(safe))}`, {
    method: 'POST', body: buffer, headers: { 'Content-Type': mimeType, 'x-upsert': 'false' }
  });
}
async function deleteKey(key) {
  if (!key) return;
  const safe = resolveKey(key);
  await storageRequest(`/storage/v1/object/${encodeURIComponent(bucket)}`, {
    method: 'DELETE', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prefixes: [path.basename(safe)] })
  });
}
async function getBuffer(key) {
  const safe = resolveKey(key);
  const response = await storageRequest(`/storage/v1/object/${encodeURIComponent(bucket)}/${encodeURIComponent(path.basename(safe))}`);
  return Buffer.from(await response.arrayBuffer());
}
function getMaxBytes() { return maxBytes; }

module.exports = { safeKey, validateSignature, saveBuffer, deleteKey, getBuffer, getMaxBytes };
