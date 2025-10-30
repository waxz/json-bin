import { Hono } from 'hono';
import { handleRequest } from './jsonbin.js';

const app = new Hono();

// Global error handler
app.onError((err, c) => {
  console.error('Unhandled error in Hono app', err);
  return c.text('Internal Server Error', 500);
});

// Delegate all requests to the existing handler in jsonbin.js
app.all('*', async (c) => {
  // handleRequest expects (request, env)
  try {
    const resp = await handleRequest(c.req, c.env);
    return resp;
  } catch (e) {
    console.error('Error delegating to handleRequest', e);
    return c.text(e.message || String(e), 500);
  }
});

// Export the fetch binding for Cloudflare/wrangler
// Use handleRequest directly here to ensure bindings (env) are passed unchanged.
export default {
  async fetch(request, env) {
    // Prefer direct delegation to keep behavior identical to previous handler.
    try {
      return await handleRequest(request, env);
    } catch (e) {
      console.error('Error in handleRequest:', e);
      return new Response(JSON.stringify({ ok: false, error: e.message || String(e) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  },
};
