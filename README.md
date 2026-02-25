# iptv

Cloudflare Worker that serves a static `IPTV.m3u`.

## What it does

- `GET /IPTV.m3u` returns the playlist in this repo.
- `GET /` also returns the same playlist (for convenience).
- CORS is enabled (`Access-Control-Allow-Origin: *`).

## Deploy

1. Install Wrangler (pick one):
   - `pnpm dlx wrangler@latest login`
   - or `pnpm add -D wrangler`
2. Deploy:
   - `pnpm dlx wrangler@latest deploy`
3. Open:
   - `https://<your-worker-subdomain>/IPTV.m3u`

## Bind your own domain

In Cloudflare dashboard:

1. Go to `Workers & Pages` -> your worker -> `Settings` -> `Domains & Routes`.
2. Add a custom domain (for example `tv.example.com`).
3. Then access:
   - `https://tv.example.com/IPTV.m3u`
