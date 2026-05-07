// =============================================================================
// Hogar Financiero — Backend multi-hogar con invitaciones
// Catch-all para todas las rutas /api/*
// =============================================================================

const SESSION_DAYS = 30;
const PBKDF2_ITER = 100000;
const MAX_MEMBERS_PER_HOGAR = 4;
const INVITE_TTL_DAYS = 7;

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors },
  });

// -----------------------------------------------------------------------------
// Crypto helpers
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

// Genera código tipo "INV-AB12-CD34" (legible, sin caracteres confusos)
function generateInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sin 0, O, 1, I
  const segment = (n) => Array.from({ length: n }, () =>
    chars[Math.floor(Math.random() * chars.length)]).join('');
  return `INV-${segment(4)}-${segment(4)}`;
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeInviteCode(code) {
  return String(code || '').trim().toUpperCase();
}

// -----------------------------------------------------------------------------
// Hogar / Members helpers
// -----------------------------------------------------------------------------
async function getHogarMeta(env, hogarId) {
  const raw = await env.FINANZAS_KV.get(`hogar_meta:${hogarId}`);
  if (!raw) return null;
  return JSON.parse(raw);
}

// Si el hogar no tiene meta (cuenta creada antes del sistema de miembros),
// lo creamos automáticamente con el usuario actual como admin.
async function ensureHogarMeta(env, hogarId, currentUserEmail) {
  let meta = await getHogarMeta(env, hogarId);
  if (meta) return meta;

  // Verificar que el hogar realmente existe
  const hogarRaw = await env.FINANZAS_KV.get(`hogar:${hogarId}`);
  if (!hogarRaw) return null;

  // Crear meta retroactivamente con el usuario actual como admin
  meta = {
    hogarId,
    members: [{ email: currentUserEmail, role: 'admin', joinedAt: new Date().toISOString() }],
    createdAt: new Date().toISOString(),
    autoCreated: true,
  };
  await saveHogarMeta(env, hogarId, meta);
  return meta;
}

async function saveHogarMeta(env, hogarId, meta) {
  await env.FINANZAS_KV.put(`hogar_meta:${hogarId}`, JSON.stringify(meta));
}

async function createHogarMeta(env, hogarId, ownerEmail) {
  const meta = {
    hogarId,
    members: [{ email: ownerEmail, role: 'admin', joinedAt: new Date().toISOString() }],
    createdAt: new Date().toISOString(),
  };
  await saveHogarMeta(env, hogarId, meta);
  return meta;
}

// -----------------------------------------------------------------------------
// Sessions
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
// Migración legacy (datos previos a sistema multi-hogar)
// -----------------------------------------------------------------------------
async function migrateLegacyIfFirst(env, hogarId, ownerEmail) {
  const legacyKeys = ['state', 'app_state_v1'];
  for (const lk of legacyKeys) {
    const legacy = await env.FINANZAS_KV.get(lk);
    if (!legacy) continue;
    const list = await env.FINANZAS_KV.list({ prefix: 'hogar:' });
    if (list.keys.length > 1) return false; // ya hay otros hogares, no migrar
    await env.FINANZAS_KV.put(`hogar:${hogarId}`, legacy);
    await env.FINANZAS_KV.delete(lk);
    return true;
  }
  return false;
}

// -----------------------------------------------------------------------------
// MAIN HANDLER
// -----------------------------------------------------------------------------
export async function onRequest(context) {
  const { request, env, params } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  const segments = Array.isArray(params.path) ? params.path : [params.path];
  const path = segments.join('/');

  if (!env.FINANZAS_KV) {
    return json({ error: 'KV no configurado en el servidor' }, 500);
  }

  try {
    // Auth
    if (path === 'auth/register' && request.method === 'POST') return await handleRegister(request, env);
    if (path === 'auth/login' && request.method === 'POST') return await handleLogin(request, env);
    if (path === 'auth/logout' && request.method === 'POST') return await handleLogout(request, env);
    if (path === 'auth/me' && request.method === 'GET') return await handleMe(request, env);

    // State
    if (path === 'state' && request.method === 'GET') return await handleGetState(request, env);
    if (path === 'state' && request.method === 'POST') return await handleSaveState(request, env);

    // Members & Invitations
    if (path === 'members' && request.method === 'GET') return await handleGetMembers(request, env);
    if (path === 'members' && request.method === 'DELETE') return await handleRemoveMember(request, env);
    if (path === 'invite/create' && request.method === 'POST') return await handleCreateInvite(request, env);
    if (path === 'invite/list' && request.method === 'GET') return await handleListInvites(request, env);
    if (path === 'invite/revoke' && request.method === 'POST') return await handleRevokeInvite(request, env);
    if (path === 'invite/preview' && request.method === 'POST') return await handlePreviewInvite(request, env);

    return json({ error: 'Ruta no encontrada', path }, 404);
  } catch (err) {
    return json({ error: 'Error interno', message: err.message }, 500);
  }
}

// =============================================================================
// AUTH HANDLERS
// =============================================================================

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }

  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  const inviteCode = normalizeInviteCode(body.inviteCode || '');

  if (!isValidEmail(email)) return json({ error: 'Email inválido' }, 400);
  if (password.length < 6) return json({ error: 'La contraseña debe tener al menos 6 caracteres' }, 400);

  const existing = await env.FINANZAS_KV.get(`user:${email}`);
  if (existing) return json({ error: 'Ya existe una cuenta con este email' }, 409);

  let hogarId;
  let migrated = false;
  let joinedHogar = false;

  if (inviteCode) {
    // Unirse a hogar existente
    const inviteRaw = await env.FINANZAS_KV.get(`invite:${inviteCode}`);
    if (!inviteRaw) return json({ error: 'Código de invitación inválido o expirado' }, 404);
    const invite = JSON.parse(inviteRaw);
    if (invite.usedAt) return json({ error: 'Este código ya fue usado' }, 410);
    if (invite.expiresAt && invite.expiresAt < Date.now()) {
      return json({ error: 'Código de invitación expirado' }, 410);
    }

    // Verificar capacidad del hogar
    const meta = await getHogarMeta(env, invite.hogarId);
    if (!meta) return json({ error: 'Hogar no encontrado' }, 404);
    if (meta.members.length >= MAX_MEMBERS_PER_HOGAR) {
      return json({ error: `El hogar ya tiene el máximo de ${MAX_MEMBERS_PER_HOGAR} miembros` }, 403);
    }
    if (meta.members.find(m => m.email === email)) {
      return json({ error: 'Este email ya es miembro del hogar' }, 409);
    }

    hogarId = invite.hogarId;
    joinedHogar = true;

    // Agregar como miembro
    meta.members.push({
      email,
      role: 'member',
      joinedAt: new Date().toISOString(),
      invitedBy: invite.createdBy,
    });
    await saveHogarMeta(env, hogarId, meta);

    // Marcar invite como usada
    invite.usedAt = new Date().toISOString();
    invite.usedBy = email;
    await env.FINANZAS_KV.put(`invite:${inviteCode}`, JSON.stringify(invite));
  } else {
    // Crear hogar nuevo
    hogarId = randomId('h');
    await createHogarMeta(env, hogarId, email);

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
    migrated = await migrateLegacyIfFirst(env, hogarId, email);
  }

  // Crear usuario
  const salt = randomToken(16);
  const passwordHash = await hashPassword(password, salt);
  const user = {
    email,
    passwordHash,
    salt,
    hogarId,
    createdAt: new Date().toISOString(),
  };
  await env.FINANZAS_KV.put(`user:${email}`, JSON.stringify(user));

  const token = await createSession(env, email, hogarId);

  return json({
    ok: true,
    token,
    email,
    hogarId,
    migrated,
    joinedHogar,
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

  const meta = await ensureHogarMeta(env, session.hogarId, session.email);
  const myMember = meta?.members?.find(m => m.email === session.email);

  return json({
    ok: true,
    email: session.email,
    hogarId: session.hogarId,
    role: myMember?.role || 'member',
    membersCount: meta?.members?.length || 1,
  });
}

// =============================================================================
// STATE HANDLERS
// =============================================================================

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
    updatedByEmail: data.updatedByEmail || null,
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
    updatedBy: body.updatedBy || null,
    updatedByEmail: session.email,
  };

  await env.FINANZAS_KV.put(`hogar:${session.hogarId}`, JSON.stringify(payload));

  return json({
    ok: true,
    version: payload.version,
    updatedAt: payload.updatedAt,
  });
}

// =============================================================================
// MEMBERS HANDLERS
// =============================================================================

async function handleGetMembers(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ error: 'No autenticado' }, 401);

  const meta = await ensureHogarMeta(env, session.hogarId, session.email);
  if (!meta) return json({ members: [], maxMembers: MAX_MEMBERS_PER_HOGAR });

  return json({
    members: meta.members,
    maxMembers: MAX_MEMBERS_PER_HOGAR,
    yourEmail: session.email,
  });
}

async function handleRemoveMember(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ error: 'No autenticado' }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }
  const targetEmail = normalizeEmail(body.email);

  const meta = await ensureHogarMeta(env, session.hogarId, session.email);
  if (!meta) return json({ error: 'Hogar no encontrado' }, 404);

  const me = meta.members.find(m => m.email === session.email);
  if (!me || me.role !== 'admin') {
    return json({ error: 'Solo el administrador puede quitar miembros' }, 403);
  }

  const target = meta.members.find(m => m.email === targetEmail);
  if (!target) return json({ error: 'Miembro no encontrado' }, 404);
  if (target.role === 'admin') {
    return json({ error: 'No puedes quitar al administrador' }, 403);
  }

  // Quitar miembro del hogar y eliminar su cuenta de usuario
  meta.members = meta.members.filter(m => m.email !== targetEmail);
  await saveHogarMeta(env, session.hogarId, meta);

  // Eliminar la cuenta del usuario removido (su sesión queda inválida automáticamente)
  await env.FINANZAS_KV.delete(`user:${targetEmail}`);

  return json({ ok: true });
}

// =============================================================================
// INVITATIONS HANDLERS
// =============================================================================

async function handleCreateInvite(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ error: 'No autenticado' }, 401);

  const meta = await ensureHogarMeta(env, session.hogarId, session.email);
  if (!meta) return json({ error: 'Hogar no encontrado' }, 404);

  // Verificar que tenga capacidad
  if (meta.members.length >= MAX_MEMBERS_PER_HOGAR) {
    return json({ error: `El hogar ya tiene el máximo de ${MAX_MEMBERS_PER_HOGAR} miembros` }, 403);
  }

  // Generar código único
  let code;
  for (let i = 0; i < 5; i++) {
    code = generateInviteCode();
    const exists = await env.FINANZAS_KV.get(`invite:${code}`);
    if (!exists) break;
  }

  const expiresAt = Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000;
  const invite = {
    code,
    hogarId: session.hogarId,
    createdBy: session.email,
    createdAt: new Date().toISOString(),
    expiresAt,
    usedAt: null,
    usedBy: null,
  };

  await env.FINANZAS_KV.put(`invite:${code}`, JSON.stringify(invite), {
    expirationTtl: INVITE_TTL_DAYS * 24 * 60 * 60 + 60,
  });

  return json({
    ok: true,
    code,
    expiresAt,
    expiresInDays: INVITE_TTL_DAYS,
  });
}

async function handleListInvites(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ error: 'No autenticado' }, 401);

  // Listar invites de este hogar
  const list = await env.FINANZAS_KV.list({ prefix: 'invite:' });
  const invites = [];
  for (const k of list.keys) {
    const raw = await env.FINANZAS_KV.get(k.name);
    if (!raw) continue;
    const inv = JSON.parse(raw);
    if (inv.hogarId === session.hogarId) {
      invites.push(inv);
    }
  }

  return json({ invites });
}

async function handleRevokeInvite(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ error: 'No autenticado' }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }
  const code = normalizeInviteCode(body.code);

  const raw = await env.FINANZAS_KV.get(`invite:${code}`);
  if (!raw) return json({ error: 'Invitación no encontrada' }, 404);
  const invite = JSON.parse(raw);
  if (invite.hogarId !== session.hogarId) {
    return json({ error: 'No autorizado' }, 403);
  }

  await env.FINANZAS_KV.delete(`invite:${code}`);
  return json({ ok: true });
}

async function handlePreviewInvite(request, env) {
  // No requiere auth - permite ver info del invite antes de registrarse
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }
  const code = normalizeInviteCode(body.code);

  const raw = await env.FINANZAS_KV.get(`invite:${code}`);
  if (!raw) return json({ error: 'Código inválido' }, 404);
  const invite = JSON.parse(raw);

  if (invite.usedAt) return json({ error: 'Este código ya fue usado' }, 410);
  if (invite.expiresAt && invite.expiresAt < Date.now()) {
    return json({ error: 'Código expirado' }, 410);
  }

  return json({
    ok: true,
    invitedBy: invite.createdBy,
    hogarId: invite.hogarId,
  });
}
