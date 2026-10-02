# Plan: static archive of discourse.igelsociety.org

**Goal.** Replace a live Discourse 2.8.0.beta11 instance (DigitalOcean) with a static, read-only mirror hosted free on Cloudflare Pages, at the same domain and the same URLs, with working full-text search and all uploads preserved. Then decommission the droplet.

**Why.** The forum is effectively dormant (~234 topics, ~215 of them conference material for IGEL 2022–2025), is not needed writable, and is running a Discourse version roughly four years behind on security patches. Static removes the attack surface and the hosting cost.

**Working language: R** (httr2, jsonlite, xml2, purrr, fs, glue, whisker). Node is used only to run Pagefind at build time.

---

## Ground rules for the agent

- Do **not** touch the live site beyond read-only HTTP GETs.
- Do **not** run destructive commands (droplet deletion, DNS changes). Those are manual steps for the human, marked **HUMAN** below.
- Everything must be regenerable from `raw/` without re-crawling. If a build step needs a network call other than during Phase 1, that is a design bug.
- Delegate implementation to a subagent with a model override (`sonnet` for the scraper and generator, `haiku` for mechanical edits). Keep design review, link-audit interpretation, and the go/no-go decision in the main loop.
- Pause for approval at the end of each phase. Do not chain phases unattended.

---

## Phase 0 — Preservation master (HUMAN, do first)

1. Log in as admin → **Admin → Backups** → tick *include uploads* → **Backup** → download the `.tar.gz`.
2. Store two copies in different places (e.g. institutional drive + society archive). Record the SHA-256.
3. Only after this file is verified downloadable does anything else start.

This backup, not the static site, is the real preservation artifact. The static site is the access copy.

---

## Phase 1 — Harvest (`R/01_harvest.R`)

Pull everything to `raw/` as unmodified JSON plus binary uploads. Ship this phase before writing any HTML.

**Endpoints** (all public, no auth; verify anonymous JSON access is not blocked before building anything else):

| What | Endpoint | Notes |
|---|---|---|
| Site metadata | `/site.json` | categories, groups, site settings exposed to anon |
| Category list | `/categories.json?include_subcategories=true` | |
| Topics per category | `/c/{slug}/{id}.json?page=N` | `page` starts at 0; stop when `topic_list.topics` is empty |
| Topic + first posts | `/t/{id}.json` | `post_stream.posts` holds ~20; `post_stream.stream` holds **all** post ids |
| Remaining posts | `/t/{id}/posts.json?post_ids[]=...` | chunk the leftover ids from `stream` in batches of 20 |

**Requirements:**

- Write each response verbatim to `raw/` (`raw/site.json`, `raw/categories.json`, `raw/category/{id}-p{N}.json`, `raw/topic/{id}.json`, `raw/topic/{id}-posts-{k}.json`). No transformation at this stage.
- Sleep ~0.7 s between requests. On HTTP 429, back off exponentially and retry (Discourse rate-limits anonymous IPs). On repeated failure, abort loudly rather than writing a partial file.
- Resumable: skip any `raw/` file that already exists unless `--force`.
- Set a descriptive `User-Agent` identifying this as an archival crawl.
- A topic is only complete when `length(post_stream.stream)` equals the number of posts collected. Assert this per topic and fail the run on mismatch.
- Write `raw/manifest.json`: harvest timestamp (UTC), Discourse version string, topic count, post count, per-file SHA-256.

**Assets:** parse every post's `cooked` HTML for references to `/uploads/`, `/user_avatar/`, `/letter_avatar_proxy/`, including `srcset` variants, plus category/site logo URLs from `site.json`. Download each to `raw/assets/` preserving the original path. Deduplicate by URL.

---

## Phase 2 — Generate (`R/02_build.R`)

Read only from `raw/`. Emit to `dist/`.

**URL layout — must match the live site exactly:**

```
/                              → home (category index)
/c/{slug}/{id}/index.html      → category page, all topics, newest first
/t/{slug}/{id}/index.html      → topic page, ALL posts on one page
/uploads/...                   → byte-identical to original paths
/search/index.html             → Pagefind UI
/404.html
/robots.txt, /sitemap.xml
```

Post-level deep links (`/t/{slug}/{id}/7`) become anchors `#post-7` on the topic page. Emit `id="post-N"` on every post.

**Post bodies:** Discourse already returns rendered HTML in `cooked`. Do not re-render from markdown. Parse `cooked` with `xml2` and rewrite in place:

- absolute `https://discourse.igelsociety.org/...` → root-relative
- internal `/t/...` and `/c/...` links → the generated static paths
- `/uploads/` and avatar paths → unchanged (assets sit at the same paths)
- strip `<script>`, lazy-load attributes, and any `data-*` the SPA needed
- leave external links untouched

**Per post, render:** author display name + username, post number, absolute timestamp, body. **Do not** emit email addresses, user bio fields, IP data, or trust levels. Link author names to plain text, not to `/u/{username}` pages — user pages are out of scope (see Decisions).

**Archive banner** on every page: "This forum is archived and read-only. Snapshot taken {date}." Include the snapshot date in the footer and in `sitemap.xml` lastmod.

**Templating:** `whisker`, templates in `templates/`. One base layout, three page templates (home, category, topic). Keep CSS in a single hand-written stylesheet — do not try to reproduce the Discourse theme; aim for legible and plain. Mark the post container `data-pagefind-body` and the topic title `data-pagefind-meta="title"`.

---

## Phase 3 — Search

```
npx -y pagefind --site dist
```

Run after generation, writes `dist/pagefind/`. Wire the Pagefind UI into `/search/index.html`. 234 topics is far below any scale concern. Verify the index reports a page count equal to topics + categories + 1.

---

## Phase 4 — Redirects (`dist/_redirects`)

Cloudflare Pages honours `_redirects`; GitHub Pages does not. This is the reason for the host choice, since preserving URLs is a hard requirement.

Generate from `raw/`, one static rule per topic and category:

```
/t/:slug/12345/*   /t/real-slug/12345/   301
/t/12345           /t/real-slug/12345/   301
/c/:slug/33        /c/real-slug/33/      301
/latest            /                     301
/categories        /                     301
/top               /                     301
/search            /search/              301
/u/*               /                     301
```

~234 topic rules plus a handful of category rules sits well inside Cloudflare's static-rule limit. Order matters: specific before wildcard.

---

## Phase 5 — Audit (`R/03_audit.R`)

The build is not done until all of these pass. Report as a table, do not silently continue.

1. Every topic id in `raw/` has a corresponding file in `dist/`.
2. Post count in `dist/` equals post count in `raw/`.
3. Zero remaining absolute links to `discourse.igelsociety.org` in generated HTML.
4. Every internal `href` and `src` in `dist/` resolves to a file that exists.
5. Every asset referenced in any `cooked` body exists under `dist/uploads/` (list misses explicitly — a missing conference slide deck matters more than a missing avatar).
6. No email addresses in output: grep `dist/` for `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` and review every hit by hand. Addresses typed into post bodies by members are the realistic case; decide per hit whether to keep or redact.
7. Spot-check three topics against the live site side by side before the live site goes away.

---

## Phase 6 — Deploy and decommission (HUMAN)

1. Push repo; connect Cloudflare Pages; build output directory `dist`.
2. Verify on the `*.pages.dev` URL first — search, a conference topic with slides, an uploaded image, a `/t/{id}` redirect.
3. Announce to members that the forum is going read-only, **before** the cutover, with a date.
4. Repoint the `discourse.igelsociety.org` DNS record at Cloudflare Pages.
5. Let it run in parallel for a week with the droplet powered off but not destroyed.
6. Destroy the droplet. Confirm the Phase 0 backup still verifies first.
7. Update the society's privacy page: the forum is archived, posts are frozen, and erasure requests are handled manually via the repo.

---

## Repository layout

```
.
├── R/            01_harvest.R  02_build.R  03_audit.R
├── templates/
├── raw/          committed — JSON + assets, the regeneration source
├── dist/         gitignored — build output
├── renv.lock
├── Makefile      harvest / build / search / audit / all
└── README.md     snapshot date, Discourse version, how to rebuild
```

Use `renv` so the build is reproducible. Commit `raw/` — it is small, and it is what makes the archive regenerable and auditable rather than a one-off scrape.

---

## Decisions to confirm before Phase 2

- **User pages (`/u/{username}`).** Plan says omit and redirect to home. Generating them would publish a permanent per-person post index, which is a bigger GDPR surface than the thread pages themselves. Confirm.
- **Avatars.** Keeping them is harmless but they are personal images. Default: keep uploaded avatars, drop letter-avatar proxies (regenerate as CSS initials).
- **Deleted/hidden posts.** The anon API already excludes them. Do not attempt to recover them from the backup.
- **Zenodo deposit.** Attractive for an open-science archive with a DOI, but it would freeze member names and post text into a citable record under a different consent assumption than a society forum. Treat as a separate decision after the site is live, not part of this work.

---

## Known weak points in this plan

- The site is on 2.8.0.beta11; JSON field names are stable across that range, but the agent should validate the shape of the first topic response against expectations rather than assume current-docs structure.
- `cooked` HTML from an old Discourse may contain lightbox wrappers and `srcset` sets that need unwrapping to produce clean static images. Expect to iterate on the rewrite rules after inspecting a few real posts.
- Oneboxed external links (YouTube embeds, DOI previews) were rendered server-side at post time and will be preserved as-is — meaning they rot independently. Nothing to do about this, but the audit should count them so the extent is known.
