// =============================================================================
// Cloudflare Pages Function: /api/state
// =============================================================================
// Maneja GET (leer estado) y POST (guardar estado) con auth por clave compartida
// Bindings necesarios:
//   - KV namespace: FINANZAS_KV
//   - Variable secret: APP_KEY
// =============================================================================

const KEY_NAME = 'app_state_v1';
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-App-Key',
  'Access-Control-Max-Age': '86400'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...CORS_HEADERS
    }
  });
}

function checkAuth(request, env) {
  const provided = request.headers.get('X-App-Key');
  if (!provided || !env.APP_KEY) return false;
  // Comparación segura contra timing attacks (longitud + char por char)
  if (provided.length !== env.APP_KEY.length) return false;
  let result = 0;
  for (let i = 0; i < provided.length; i++) {
    result |= provided.charCodeAt(i) ^ env.APP_KEY.charCodeAt(i);
  }
  return result === 0;
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function onRequestGet({ request, env }) {
  if (!checkAuth(request, env)) {
    return json({ error: 'Clave inválida' }, 401);
  }
  if (!env.FINANZAS_KV) {
    return json({ error: 'KV no configurado' }, 500);
  }

  try {
    const raw = await env.FINANZAS_KV.get(KEY_NAME);
    if (!raw) {
      return json({
        config: null,
        transactions: [],
        subscriptions: [],
        version: 0,
        updatedAt: null
      });
    }
    const data = JSON.parse(raw);
    return json(data);
  } catch (err) {
    return json({ error: 'Error leyendo datos: ' + err.message }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  if (!checkAuth(request, env)) {
    return json({ error: 'Clave inválida' }, 401);
  }
  if (!env.FINANZAS_KV) {
    return json({ error: 'KV no configurado' }, 500);
  }

  try {
    const body = await request.json();

    // Validación básica
    if (!body || typeof body !== 'object') {
      return json({ error: 'Datos inválidos' }, 400);
    }

    const payload = {
      config: body.config || null,
      transactions: Array.isArray(body.transactions) ? body.transactions : [],
      subscriptions: Array.isArray(body.subscriptions) ? body.subscriptions : [],
      version: (body.version || 0) + 1,
      updatedAt: new Date().toISOString(),
      updatedBy: body.updatedBy || 'unknown'
    };

    await env.FINANZAS_KV.put(KEY_NAME, JSON.stringify(payload));
    return json({ ok: true, version: payload.version, updatedAt: payload.updatedAt });
  } catch (err) {
    return json({ error: 'Error guardando: ' + err.message }, 500);
  }
}
