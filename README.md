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

## Check invalid sources

Use the Python checker to validate URLs in `IPTV.m3u` and generate a markdown report.
It checks playability, not only whether `GET` returns HTTP `200`.

- Run:
  - `python3 scripts/check_sources.py --input IPTV.m3u`
- Custom report path:
  - `python3 scripts/check_sources.py --input IPTV.m3u --output reports/latest_invalid_report.md`
- CI-style failure when any source is invalid:
  - `python3 scripts/check_sources.py --input IPTV.m3u --fail-on-invalid`
- Check a single URL directly:
  - `python3 scripts/check_sources.py --check-url "http://example.com/live/index.m3u8"`
- Exclude stuttering sources (speed-based):
  - `python3 scripts/check_sources.py --input IPTV.m3u --probe-segments 4 --min-realtime-ratio 1.2 --min-single-realtime-ratio 0.9 --min-segment-kbps 800`

Report includes channel name, source URL, line numbers in the source file, and whether the channel has alternative sources.
