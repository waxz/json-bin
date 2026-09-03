import { handleRequest } from './jsonbin.js';
// Standard CORS headers to allow browser access
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request, env, ctx) {
    // 1. Handle Preflight (OPTIONS) requests immediately
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // 2. Pass request, env, and ctx (for waitUntil)

      const url =  new URL(request.url);
      
      if (url.pathname === "/") {
        // Create a new URL object to avoid mutating the original request URL
        // const homeUrl = new URL("/home.html", url.origin);
        
        // console.log(`Redirecting to static resource: ${homeUrl.pathname}`);

        // // env.ASSETS.fetch accepts a URL object, a string, or a Request object
        // return await env.ASSETS.fetch(homeUrl.toString());
        return await env.ASSETS.fetch(request);

      }
      
      if(url.pathname.startsWith("/static")){
        console.log(`fetch local resource:`,request)
        return await env.ASSETS.fetch(request)
      }

      const response = await handleRequest(request, env, ctx);

      // 3. Attach CORS headers to the response so the UI works
      const newHeaders = new Headers(response.headers);
      Object.keys(corsHeaders).forEach(key => newHeaders.set(key, corsHeaders[key]));

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });

    } catch (e) {
      console.error('CRITICAL WORKER ERROR:', e);
      // Return a clean JSON error. Never expose the stack trace to clients -
      // it can leak internal file paths and implementation details.
      return new Response(JSON.stringify({
        success: false,
        error: e.message || 'Internal Server Error'
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  },
};