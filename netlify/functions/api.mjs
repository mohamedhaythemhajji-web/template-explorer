import { getStore } from '@netlify/blobs';
import { timingSafeEqual } from 'node:crypto';

export const config = { path: '/api/*' };

const { API_TOKEN = '' } = process.env;
const MAX_IMAGE = 5.5 * 1024 * 1024; // Netlify caps request bodies at ~6 MB

const boardsStore = () => getStore({ name: 'boards', consistency: 'strong' });
const imagesStore = () => getStore({ name: 'images', consistency: 'strong' });

const J = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
  });

/* ---- input sanitising (allow-list) ---- */
const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
const num = (v, d = 0) => (Number.isFinite(+v) ? +v : d);
const tm = v => (v === '' || v == null || !Number.isFinite(+v) ? '' : Math.max(0, +v));

function sanitizeRegion(r) {
  return {
    id: str(r.id, 40),
    x: num(r.x), y: num(r.y), w: num(r.w), h: num(r.h),
    num: str(String(r.num ?? ''), 20),
    label: str(r.label, 300),
    feed: str(r.feed, 1000),
    type: str(r.type, 80),
    concept: str(r.concept, 200),
    notes: str(r.notes, 5000),
    color: /^#[0-9a-f]{6}$/i.test(r.color) ? r.color : '',
    t0: tm(r.t0),
    t1: tm(r.t1),
    pts: (Array.isArray(r.pts) ? r.pts : []).slice(0, 400)
      .filter(p => Array.isArray(p) && p.length >= 2)
      .map(p => [Math.min(100, Math.max(0, num(p[0]))), Math.min(100, Math.max(0, num(p[1])))]),
    fields: (Array.isArray(r.fields) ? r.fields : []).slice(0, 50)
      .map(f => ({ k: str(f && f.k, 100), v: str(f && f.v, 1000), req: !!(f && f.req) }))
  };
}
const pct = v => Math.min(100, Math.max(0, num(v)));
function sanitizeBoard(b) {
  if (!b || typeof b !== 'object') return null;
  const c = b.canvas || {};
  const types = (Array.isArray(b.types) ? b.types : []).slice(0, 30).map(t => str(t, 80)).filter(Boolean);
  return {
    name: str(b.name, 200) || 'Untitled template',
    thumb: typeof b.thumb === 'string' && b.thumb.startsWith('data:image/') && b.thumb.length < 500000 ? b.thumb : null,
    imgW: num(b.imgW), imgH: num(b.imgH), origW: num(b.origW), origH: num(b.origH),
    canvas: { w: Math.max(1, num(c.w, 1080)), h: Math.max(1, num(c.h, 1080)) },
    canvasAuto: b.canvasAuto !== false,
    types: types.length ? types : ['Element', 'Controller'],
    fieldNames: (Array.isArray(b.fieldNames) ? b.fieldNames : []).slice(0, 50).map(t => str(t, 100)).filter(Boolean),
    /* video scenes: boards that share the same vid belong to one video */
    vid: /^[A-Za-z0-9_-]{3,64}$/.test(b.vid || '') ? b.vid : '',
    vname: str(b.vname, 200),
    vurl: /^https?:\/\//i.test(b.vurl || '') ? str(b.vurl, 1000) : '',
    t: Math.max(0, num(b.t)),
    regions: (Array.isArray(b.regions) ? b.regions : []).slice(0, 1000)
      .filter(r => r && typeof r === 'object').map(sanitizeRegion),
arrows: (Array.isArray(b.arrows) ? b.arrows : []).slice(0, 200)
      .filter(a => a && typeof a === 'object')
      .map(a => ({
        id: str(a.id, 40), from: str(a.from, 40), to: str(a.to, 40),
        x1: pct(a.x1), y1: pct(a.y1), x2: pct(a.x2), y2: pct(a.y2),
        color: /^#[0-9a-f]{6}$/i.test(a.color) ? a.color : '',
        label: str(a.label, 120),
        curve: Math.max(-1, Math.min(1, num(a.curve))),
        dash: !!a.dash
      })),
    updated: Date.now()  };
}

/* store the doc, and mirror the small fields into blob metadata so the
   list endpoint doesn't have to download every thumbnail */
async function saveDoc(store, id, doc) {
  await store.setJSON(id, doc, {
    metadata: { rev: doc.rev, imageRev: doc.imageRev || 0, hasImage: !!doc.hasImage, updated: doc.updated || 0 }
  });
}

function conflictOrMissing(existing) {
  if (!existing) return J({ error: 'deleted' }, 404);
  return J({ error: 'conflict', rev: existing.rev, updated: existing.updated }, 409);
}

export default async (req) => {
  try {
    /* ---- optional shared access code ---- */
    if (API_TOKEN) {
      const given = Buffer.from(req.headers.get('x-team-token') || '');
      const want = Buffer.from(API_TOKEN);
      if (given.length !== want.length || !timingSafeEqual(given, want)) {
        return J({ error: 'unauthorized' }, 401);
      }
    }

    const url = new URL(req.url);
    const parts = url.pathname.split('/').filter(Boolean).slice(1); // drop "api"
    if (parts[0] !== 'boards') return J({ error: 'not found' }, 404);
    const id = parts[1], sub = parts[2], m = req.method;
    if (id && !/^[A-Za-z0-9_-]{3,64}$/.test(id)) return J({ error: 'bad id' }, 400);

    const boards = boardsStore();
    const images = imagesStore();

    /* GET /api/boards  -> light list (metadata only) */
    if (!id) {
      if (m !== 'GET') return J({ error: 'method not allowed' }, 405);
      const { blobs } = await boards.list();
      const out = await Promise.all(blobs.map(async b => {
        const meta = await boards.getMetadata(b.key);
        const md = meta && meta.metadata;
        if (!md) return null;
        return { id: b.key, rev: md.rev, imageRev: md.imageRev || 0, hasImage: !!md.hasImage, updated: md.updated || 0 };
      }));
      return J(out.filter(Boolean));
    }

    /* /api/boards/:id */
    if (!sub) {
      if (m === 'GET') {
        const d = await boards.get(id, { type: 'json' });
        if (!d) return J({ error: 'not found' }, 404);
        return J({ id, ...d });
      }
      if (m === 'PUT') {
        let body;
        try { body = await req.json(); } catch (e) { return J({ error: 'bad json' }, 400); }
        const baseRev = Number(body && body.baseRev) || 0;
        const clean = sanitizeBoard(body);
        if (!clean) return J({ error: 'bad body' }, 400);
        const existing = await boards.get(id, { type: 'json' });

        if (baseRev === 0) {
          if (existing) return conflictOrMissing(existing);
          const doc = { ...clean, rev: 1, imageRev: 0, hasImage: false };
          await saveDoc(boards, id, doc);
          return J({ rev: 1, updated: doc.updated });
        }
        if (!existing) return J({ error: 'deleted' }, 404);
        if (existing.rev !== baseRev) return conflictOrMissing(existing);
        const doc = { ...clean, rev: baseRev + 1, imageRev: existing.imageRev || 0, hasImage: !!existing.hasImage };
        await saveDoc(boards, id, doc);
        return J({ rev: doc.rev, updated: doc.updated });
      }
      if (m === 'DELETE') {
        await boards.delete(id);
        await images.delete(id);
        return J({ ok: true });
      }
      return J({ error: 'method not allowed' }, 405);
    }

    /* /api/boards/:id/image */
    if (sub === 'image') {
      if (m === 'GET') {
        const res = await images.getWithMetadata(id, { type: 'arrayBuffer' });
        if (!res) return J({ error: 'no image' }, 404);
        return new Response(res.data, {
          status: 200,
          headers: {
            'content-type': (res.metadata && res.metadata.contentType) || 'image/jpeg',
            'cache-control': 'private, max-age=31536000, immutable'
          }
        });
      }
      if (m === 'PUT') {
        const baseRev = Number(url.searchParams.get('baseRev')) || 0;
        const buf = await req.arrayBuffer();
        if (!buf.byteLength) return J({ error: 'expected an image body' }, 400);
        if (buf.byteLength > MAX_IMAGE) return J({ error: 'image too large' }, 413);
        const existing = await boards.get(id, { type: 'json' });
        if (!existing) return J({ error: 'deleted' }, 404);
        if (existing.rev !== baseRev) return conflictOrMissing(existing);

        const imageRev = Date.now();
        await images.set(id, buf, {
          metadata: { contentType: req.headers.get('content-type') || 'image/jpeg', imageRev }
        });
        const doc = { ...existing, hasImage: true, imageRev, updated: imageRev, rev: baseRev + 1 };
        await saveDoc(boards, id, doc);
        return J({ rev: doc.rev, imageRev });
      }
      return J({ error: 'method not allowed' }, 405);
    }

    return J({ error: 'not found' }, 404);
  } catch (err) {
    console.error(err);
    return J({ error: 'server error' }, 500);
  }
};