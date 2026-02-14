/**
 * Next.js API Route: POST /api/orders
 *
 * 1. Saves the order on the server (appends to data/store-data.json in GitHub).
 * 2. Sends an immediate email notification to the admin (optional, via Resend).
 * 3. Works on all devices (PC + mobile); CORS and same-origin handled.
 * 4. Customers use your site URL only — no IP or special settings required.
 *
 * Required env: GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO
 * Optional: GITHUB_BRANCH (default main), ADMIN_EMAIL, RESEND_API_KEY (for email notifications)
 */

const GITHUB_API = 'https://api.github.com';
const RESEND_API = 'https://api.resend.com';
const STORE_DATA_PATH = 'data/store-data.json';

function corsHeaders(origin) {
  const o = origin || '*';
  return {
    'Access-Control-Allow-Origin': o,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
    'Access-Control-Max-Age': '86400',
  };
}

function setCors(res, origin) {
  Object.entries(corsHeaders(origin)).forEach(([k, v]) => res.setHeader(k, v));
}

async function getFile(owner, repo, path, branch, token) {
  const url = `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(branch)}`;
  const res = await fetch(url, {
    headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub GET failed: ${res.status} ${err}`);
  }
  return res.json();
}

async function putFile(owner, repo, path, content, sha, branch, token, message) {
  const url = `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodeURIComponent(path)}`;
  const body = {
    message: message || 'Add order via Orders API',
    content: Buffer.from(content, 'utf8').toString('base64'),
    branch,
  };
  if (sha) body.sha = sha;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub PUT failed: ${res.status} ${err}`);
  }
  return res.json();
}

/**
 * Send order notification email to admin via Resend API (no extra dependency).
 * Uses env: RESEND_API_KEY, ADMIN_EMAIL. If either is missing, skips email and returns.
 */
async function notifyAdminByEmail(order) {
  const apiKey = process.env.RESEND_API_KEY;
  const toEmail = (process.env.ADMIN_EMAIL || '').trim();
  if (!apiKey || !toEmail) {
    console.log('[api/orders] Email skip: RESEND_API_KEY or ADMIN_EMAIL not set');
    return;
  }
  const items = (order.items || [])
    .map((i) => `• ${i.name || 'Item'} — ${i.size || '-'} / ${i.color || '-'} × ${i.quantity || 1} = ${((i.price || 0) * (i.quantity || 1))} MAD`)
    .join('\n');
  const html = `
    <h2>New order: ${order.id}</h2>
    <p><strong>Customer:</strong> ${escapeHtml(order.fullName || '-')}</p>
    <p><strong>Phone:</strong> ${escapeHtml(order.phone || '-')}</p>
    <p><strong>City:</strong> ${escapeHtml(order.city || '-')}</p>
    ${order.notes ? `<p><strong>Notes:</strong> ${escapeHtml(order.notes)}</p>` : ''}
    <p><strong>Total:</strong> ${order.total != null ? order.total : '-'} MAD</p>
    <h3>Items</h3>
    <pre>${items || '—'}</pre>
    <p><small>Date: ${order.date || new Date().toISOString()}</small></p>
  `;
  const res = await fetch(`${RESEND_API}/emails`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'Black T-Shirt Orders <onboarding@resend.dev>',
      to: [toEmail],
      subject: `New order ${order.id} — ${order.fullName || 'Customer'}`,
      html,
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    console.error('[api/orders] Resend error', res.status, err);
    return;
  }
  console.log('[api/orders] Admin notified by email', order.id);
}

function escapeHtml(s) {
  if (s == null) return '';
  const str = String(s);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Parse request body: Next.js may provide req.body as object (when bodyParser parses JSON) or we read raw. */
function parseBody(req) {
  const raw = req.body;
  if (raw === undefined || raw === null) {
    return null;
  }
  if (typeof raw === 'object' && raw !== null && !Array.isArray(raw)) {
    return raw;
  }
  if (typeof raw === 'string') {
    if (raw.trim() === '') return {};
    try {
      return JSON.parse(raw);
    } catch (e) {
      throw new Error('Invalid JSON body');
    }
  }
  throw new Error('Unsupported body type');
}

export default async function handler(req, res) {
  const origin = req.headers.origin || (req.headers.referer ? new URL(req.headers.referer || 'https://example.com').origin : '*');
  const userAgent = req.headers['user-agent'] || '(none)';
  const device = /mobile|android|iphone|ipad|webos|blackberry/i.test(userAgent) ? 'mobile' : 'desktop';

  if (req.method === 'OPTIONS') {
    setCors(res, origin);
    res.status(204);
    return res.end();
  }

  if (req.method !== 'POST') {
    setCors(res, origin);
    res.status(405).json({ error: 'Method not allowed', success: false });
    return;
  }

  console.log('[api/orders] POST', { origin, device, contentType: req.headers['content-type'], userAgent: userAgent.slice(0, 80) });

  const token = process.env.GITHUB_TOKEN;
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = (process.env.GITHUB_BRANCH || 'main').trim() || 'main';

  if (!token || !owner || !repo) {
    console.error('[api/orders] Missing env: GITHUB_TOKEN, GITHUB_OWNER, or GITHUB_REPO');
    setCors(res, origin);
    res.status(500).json({ error: 'Orders API not configured (missing env)', success: false });
    return;
  }

  let order;
  try {
    order = parseBody(req);
  } catch (e) {
    console.error('[api/orders] Body parse error', e.message);
    setCors(res, origin);
    res.status(400).json({ error: 'Invalid JSON body', success: false });
    return;
  }

  if (!order || typeof order !== 'object') {
    console.error('[api/orders] Empty or non-object body');
    setCors(res, origin);
    res.status(400).json({ error: 'Request body must be a JSON object', success: false });
    return;
  }

  if (!order.fullName && !order.phone) {
    console.error('[api/orders] Validation failed: missing fullName and phone');
    setCors(res, origin);
    res.status(400).json({ error: 'Order must include fullName and phone', success: false });
    return;
  }

  order.id = order.id || 'ord-' + Date.now();
  order.status = order.status || 'pending';
  console.log('[api/orders] Order accepted', { id: order.id, fullName: order.fullName, phone: order.phone, device });

  try {
    const file = await getFile(owner, repo, STORE_DATA_PATH, branch, token);
    const content = Buffer.from(file.content, 'base64').toString('utf8');
    const data = JSON.parse(content);
    if (!Array.isArray(data.orders)) data.orders = [];
    data.orders.unshift(order);
    const newContent = JSON.stringify(data, null, 2);
    await putFile(owner, repo, STORE_DATA_PATH, newContent, file.sha, branch, token, 'Add order ' + order.id);
    console.log('[api/orders] Order saved', order.id, device);

    // Notify admin by email (optional; does not block or fail the response)
    try {
      await notifyAdminByEmail(order);
    } catch (emailErr) {
      console.error('[api/orders] Admin email failed (order already saved)', emailErr.message);
    }

    setCors(res, origin);
    res.status(200).json({ success: true, ok: true, id: order.id });
  } catch (err) {
    console.error('[api/orders] Error saving order', err.message, err.stack);
    setCors(res, origin);
    res.status(500).json({ error: 'Failed to save order', detail: err.message, success: false });
  }
}
