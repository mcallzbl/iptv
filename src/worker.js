import playlist from "../IPTV.m3u";

const PLAYLIST_PATHS = new Set(["/", "/IPTV.m3u"]);

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,OPTIONS",
};

const PLAYLIST_HEADERS = {
  ...CORS_HEADERS,
  "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8",
  "Cache-Control": "public, max-age=300",
  "Content-Disposition": 'inline; filename="IPTV.m3u"',
};

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: CORS_HEADERS,
      });
    }

    if (PLAYLIST_PATHS.has(url.pathname)) {
      return request.method === "HEAD"
        ? new Response(null, { status: 200, headers: PLAYLIST_HEADERS })
        : new Response(playlist, { status: 200, headers: PLAYLIST_HEADERS });
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
  },
};
