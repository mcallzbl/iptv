# Repository Guidelines

## Project Structure & Module Organization
This repository is a minimal Cloudflare Worker that serves a static playlist.

- `src/worker.js`: request handling, CORS behavior, allowed methods, and route matching.
- `IPTV.m3u`: playlist source content returned by `/` and `/IPTV.m3u`.
- `wrangler.toml`: Worker entrypoint, compatibility date, and `.m3u` text rule.
- `README.md`: deployment and domain-binding quick start.

Keep runtime logic in `src/` and treat `IPTV.m3u` as content, not code.

## Build, Test, and Development Commands
Use Wrangler via `pnpm dlx` (no package scripts are defined yet).

- `pnpm dlx wrangler@latest login`: authenticate Wrangler with Cloudflare.
- `pnpm dlx wrangler@latest dev`: run the Worker locally.
- `pnpm dlx wrangler@latest deploy`: deploy the Worker.

Quick manual checks while developing:

- `curl -i http://127.0.0.1:8787/IPTV.m3u`
- `curl -I http://127.0.0.1:8787/`
- `curl -i http://127.0.0.1:8787/unknown`

## Coding Style & Naming Conventions
- Language: JavaScript ES modules.
- Formatting pattern in current code: 2-space indentation, semicolons, double quotes.
- Use `UPPER_SNAKE_CASE` for shared constants (for example `CORS_HEADERS`).
- Keep route sets explicit and small (`PLAYLIST_PATHS`).
- Return explicit status codes and headers for each branch.

If you add linting/formatting tools later, document the exact commands in `README.md` and this file.

## Testing Guidelines
There is currently no automated test suite in this repository. Validate behavior with local `wrangler dev` plus HTTP checks for:

- `GET` and `HEAD` on `/` and `/IPTV.m3u`
- `OPTIONS` preflight response
- `404` for unknown paths
- `405` for unsupported methods

When adding tests, place them under `tests/` and prefer clear names like `worker.routes.test.js`.

## Commit & Pull Request Guidelines
Existing history uses short, one-line messages (English and Chinese), e.g., `增加cf worker`, `first commit`.

- Keep commit subjects concise and action-oriented.
- One logical change per commit.
- PRs should include: purpose, behavior changes, validation steps (commands run), and sample response headers/body when endpoint behavior changes.
