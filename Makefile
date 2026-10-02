SHELL := /bin/bash
.PHONY: harvest redact build search redirects audit all

# Phase 1: copy the public forum into raw_verbatim/ (unredacted, never committed).
# Resumable; progress is also saved to harvest.log.
harvest:
	set -o pipefail; Rscript R/01_harvest.R 2>&1 | tee harvest.log

# Phase 1b: raw_verbatim/ -> raw/ with emails and Zoom passcodes redacted (the committed copy).
redact:
	Rscript R/01b_redact.R

# Phase 2: raw/ -> dist/, the static site (built from the redacted copy only; build-report.json next to dist/).
build:
	Rscript R/02_build.R

# Phase 3: full-text search index in dist/pagefind/. Run it after every build, because a build replaces
# dist/ entirely. The version is pinned so the index format and the UI files stay reproducible; npx
# downloads it from the npm registry on first use.
search:
	npx -y pagefind@1.5.2 --site dist

# Phase 4: dist/_redirects (Cloudflare Pages), from raw/ and the built pages in dist/. Run it after every build,
# because a build replaces dist/ entirely.
redirects:
	Rscript R/02b_redirects.R

# Phase 5: the final gate before deployment. Reads raw/, dist/ and (if present) raw_verbatim/, changes none of
# them, writes audit-report.json next to dist/ and exits 1 if a check fails. Run it after the build, the search
# index and the redirects.
audit:
	Rscript R/03_audit.R

# Everything that works offline, from the committed raw/ to a deployable dist/, ending with the audit.
all: build search redirects audit
