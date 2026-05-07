// =============================================================================
// Hogar Financiero — Backend multi-hogar con autenticación
// Catch-all para todas las rutas /api/*
// =============================================================================

const SESSION_DAYS = 30;
const PBKDF2_ITER = 100000;

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-App-Key',
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors },
  });

// -----------------------------------------------------------------------------
// Crypto helpers (Web Crypto API)
// -----------------------------------------------------------------------------
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: PBKDF2_ITER, hash: 'SHA-256' },
    key, 256
  );
  return Array.from(new Uint8Array(bits))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomToken(length = 32) {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomId(prefix = 'h') {
  return `${prefix}_${randomToken(8)}`;
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// -----------------------------------------------------------------------------
// Session management
// -----------------------------------------------------------------------------
async function createSession(env, email, hogarId) {
  const token = randomToken(32);
  const session = {
    email,
    hogarId,
    expiresAt: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000,
    createdAt: Date.now(),
  };
  await env.FINANZAS_KV.put(`session:${token}`, JSON.stringify(session), {
    expirationTtl: SESSION_DAYS * 24 * 60 * 60,
  });
  return token;
}

async function getSession(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1];
  const raw = await env.FINANZAS_KV.get(`session:${token}`);
  if (!raw) return null;
  const session = JSON.parse(raw);
  if (session.expiresAt < Date.now()) {
    await env.FINANZAS_KV.delete(`session:${token}`);
    return null;
  }
  return { ...session, token };
}

// -----------------------------------------------------------------------------
// Migración: si existe el state legacy y es el primer registro,
// lo movemos al hogar del primer usuario.
// -----------------------------------------------------------------------------
async function migrateLegacyIfFirst(env, hogarId) {
  const legacy = await env.FINANZAS_KV.get('state');
  if (!legacy) return false;
  const list = await env.FINANZAS_KV.list({ prefix: 'hogar:' });
  if (list.keys.length > 1) return false;
  await env.FINANZAS_KV.put(`hogar:${hogarId}`, legacy);
  await env.FINANZAS_KV.delete('state');
  return true;
}

// -----------------------------------------------------------------------------
// MAIN HANDLER (catch-all)
// -----------------------------------------------------------------------------
export async function onRequest(context) {
  const { request, env, params } = context;

  // Preflight CORS
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  // params.path es el array con las partes de la URL después de /api/
  // Ej: /api/auth/register → params.path = ['auth', 'register']
  // Ej: /api/state → params.path = ['state']
  const segments = Array.isArray(params.path) ? params.path : [params.path];
  const path = segments.join('/');

  if (!env.FINANZAS_KV) {
    return json({ error: 'KV no configurado en el servidor' }, 500);
  }

  try {
    if (path === 'auth/register' && request.method === 'POST') return await handleRegister(request, env);
    if (path === 'auth/login' && request.method === 'POST') return await handleLogin(request, env);
    if (path === 'auth/logout' && request.method === 'POST') return await handleLogout(request, env);
    if (path === 'auth/me' && request.method === 'GET') return await handleMe(request, env);
    if (path === 'state' && request.method === 'GET') return await handleGetState(request, env);
    if (path === 'state' && request.method === 'POST') return await handleSaveState(request, env);

    return json({ error: 'Ruta no encontrada', path }, 404);
  } catch (err) {
    return json({ error: 'Error interno', message: err.message }, 500);
  }
}

// -----------------------------------------------------------------------------
// HANDLERS
// -----------------------------------------------------------------------------

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }

  const email = normalizeEmail(body.email);
  const password = String(body.password || '');

  if (!isValidEmail(email)) return json({ error: 'Email inválido' }, 400);
  if (password.length < 6) return json({ error: 'La contraseña debe tener al menos 6 caracteres' }, 400);

  const existing = await env.FINANZAS_KV.get(`user:${email}`);
  if (existing) return json({ error: 'Ya existe una cuenta con este email' }, 409);

  const hogarId = randomId('h');
  const salt = randomToken(16);
  const passwordHash = await hashPassword(password, salt);

  const user = {
    email,
    passwordHash,
    salt,
    hogarId,
    role: 'admin',
    createdAt: new Date().toISOString(),
  };

  await env.FINANZAS_KV.put(`user:${email}`, JSON.stringify(user));

  const emptyState = {
    config: null,
    transactions: [],
    subscriptions: [],
    goals: [],
    version: 0,
    updatedAt: null,
    updatedBy: null,
  };
  await env.FINANZAS_KV.put(`hogar:${hogarId}`, JSON.stringify(emptyState));

  // Migrar legacy si es el primer hogar
  const migrated = await migrateLegacyIfFirst(env, hogarId);

  const token = await createSession(env, email, hogarId);

  return json({
    ok: true,
    token,
    email,
    hogarId,
    migrated,
  });
}

async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }

  const email = normalizeEmail(body.email);
  const password = String(body.password || '');

  if (!isValidEmail(email)) return json({ error: 'Email inválido' }, 400);

  const raw = await env.FINANZAS_KV.get(`user:${email}`);
  if (!raw) return json({ error: 'Email o contraseña incorrectos' }, 401);

  const user = JSON.parse(raw);
  const hash = await hashPassword(password, user.salt);
  if (hash !== user.passwordHash) {
    return json({ error: 'Email o contraseña incorrectos' }, 401);
  }

  const token = await createSession(env, email, user.hogarId);

  return json({
    ok: true,
    token,
    email,
    hogarId: user.hogarId,
  });
}

async function handleLogout(request, env) {
  const session = await getSession(env, request);
  if (session) {
    await env.FINANZAS_KV.delete(`session:${session.token}`);
  }
  return json({ ok: true });
}

async function handleMe(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ error: 'No autenticado' }, 401);
  return json({
    ok: true,
    email: session.email,
    hogarId: session.hogarId,
  });
}

async function handleGetState(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ error: 'No autenticado' }, 401);

  const raw = await env.FINANZAS_KV.get(`hogar:${session.hogarId}`);
  if (!raw) {
    return json({
      config: null,
      transactions: [],
      subscriptions: [],
      goals: [],
      version: 0,
      updatedAt: null,
    });
  }

  const data = JSON.parse(raw);
  return json({
    config: data.config || null,
    transactions: data.transactions || [],
    subscriptions: data.subscriptions || [],
    goals: data.goals || [],
    version: data.version || 0,
    updatedAt: data.updatedAt || null,
    updatedBy: data.updatedBy || null,
  });
}

async function handleSaveState(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ error: 'No autenticado' }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }

  const payload = {
    config: body.config || null,
    transactions: Array.isArray(body.transactions) ? body.transactions : [],
    subscriptions: Array.isArray(body.subscriptions) ? body.subscriptions : [],
    goals: Array.isArray(body.goals) ? body.goals : [],
    version: (body.version || 0) + 1,
    updatedAt: new Date().toISOString(),
    updatedBy: body.updatedBy || session.email,
  };

  await env.FINANZAS_KV.put(`hogar:${session.hogarId}`, JSON.stringify(payload));

  return json({
    ok: true,
    version: payload.version,
    updatedAt: payload.updatedAt,
  });
}
