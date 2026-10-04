#!/usr/bin/env Rscript
# Phase 2 (Generate): build the static, read-only forum archive from the redacted raw/ copy.
#
#   Rscript R/02_build.R [--raw DIR] [--out DIR]
#
# Reads ONLY --raw (default "raw", made by R/01b_redact.R) and templates/; there is no network access.
# Writes --out (default "dist"), with the same URLs as the live forum:
#   index.html                      home: search box and category index (IGEL conferences first, newest first)
#   c/{slug}/{id}/index.html        top-level category (subcategories: c/{parent}/{slug}/{id}/index.html)
#   t/{slug}/{id}/index.html        topic, all posts on one page
#   search/index.html               Pagefind UI page (the index itself is built in Phase 3)
#   404.html  robots.txt  sitemap.xml  archive.css
#   <every file of raw/assets/>     byte-identical, without the leading "assets/"
# and NEXT TO --out (not inside it) build-report.json: what was rendered, skipped and rewritten.
#
# A post body is the "cooked" HTML Discourse already rendered. It is parsed with xml2 and walked once;
# the walker emits sanitised HTML, so nothing is re-rendered from markdown and nothing the Discourse
# front end needed (data-* attributes, scripts, avatars ...) survives. What it does, by rule number
# (the comments on the render_* functions use the same numbers):
#   1  every URL attribute loses the forum host (href, src, srcset candidates, poster, cite)
#   2  /t/{slug}/{id}[/{n}] and /c/... links are resolved by id to the static URLs (#post-n for n > 1);
#      a link into the forum that cannot be followed is unwrapped to its text and reported
#   3  mentions and /u/ /groups/ links become <span class="mention"> (user pages are out of scope)
#   4  script, style, iframe, object, embed, form (with content), event handlers, javascript: URLs, every
#      data-*, loading and style attribute go; only allow-listed attributes survive
#   5  div.lightbox-wrapper is unwrapped to <a href="full image"><img></a>, its filename line dropped
#   6  avatars and the empty quote controls are removed
#   7  YouTube thumbnails keep their link and gain the video title as alt text and visible caption
#   8  discourse-local-date spans become <time> with the UTC time (title: the author's own time and zone)
#   9  attachments get download="file name"
#   10 oneboxes and the poll keep structure and classes (without data-*)
#   11 nothing may point at the forum host any more: enforced for every page by check_page()
#   12 unknown elements are unwrapped and unknown classes are listed in the report
#
# Safety: --raw must be a redacted copy (manifest.json with derived_from == "raw_verbatim" and a
# redaction block, plus redaction-report.json). An existing --out must be empty or hold sitemap.xml
# (this script's own earlier output). The site is built in <out>.build-tmp, checked, and swapped into
# place, so a failure or interruption leaves an existing --out as it was. Output is deterministic: no
# clocks, no random ids, stable ordering, "\n" line endings; the only date shown is the snapshot date.

BASE_URL         <- "https://discourse.igelsociety.org"
FORUM_HOST       <- "discourse.igelsociety.org"
RAW_DEFAULT      <- "raw"
OUT_DEFAULT      <- "dist"
TEMPLATE_DIR     <- "templates"
MANIFEST_FILE    <- "manifest.json"
REDACTION_REPORT <- "redaction-report.json"
SITEMAP_FILE     <- "sitemap.xml"
REPORT_FILE      <- "build-report.json"
STYLESHEET       <- "archive.css"
TMP_SUFFIX       <- ".build-tmp"       # sibling directory the site is built in
OLD_SUFFIX       <- ".build-old"       # where the previous --out waits while the new one is swapped in
TMP_MARKER       <- ".build-in-progress"
TEMPLATE_FILES   <- c(base = "base.html", home = "home.html", category = "category.html",
                      topic = "topic.html", search = "search.html", not_found = "404.html")

RENDERED_POST_TYPES <- c(1L, 2L)       # regular post, moderator action
SYSTEM_POST_TYPE    <- 3L              # "small action" (pinned, closed ...): always empty, skipped

# Home page: the categories of the IGEL conferences (slugs igel2025, igel2024 ...) come first, newest year first;
# the other categories follow in the forum's own order.
CONFERENCE_SLUG     <- "^igel([0-9]{4})$"
# Only the pages that carry the Pagefind search widget may contain a <script>.
SEARCH_WIDGET_KINDS <- c("search", "home")

# ---- what the cooked-HTML walker keeps -----------------------------------------------------------

ASSET_DIRS  <- c("uploads", "user_avatar", "letter_avatar_proxy", "images", "plugins", "assets",
                 "secure-uploads")
AVATAR_DIRS <- c("user_avatar", "letter_avatar_proxy")

ALLOWED_ELEMENTS <- c(
  "a", "abbr", "address", "article", "aside", "b", "bdi", "bdo", "big", "blockquote", "br", "caption",
  "cite", "code", "col", "colgroup", "dd", "del", "details", "dfn", "div", "dl", "dt", "em", "figcaption",
  "figure", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "i", "img", "ins", "kbd", "li", "mark",
  "ol", "p", "pre", "q", "s", "samp", "section", "small", "span", "strike", "strong", "sub", "summary",
  "sup", "table", "tbody", "td", "tfoot", "th", "thead", "time", "tr", "u", "ul", "var", "wbr")
VOID_ELEMENTS <- c("area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
                   "source", "track", "wbr")
# removed together with their content (rule 4; svg because its <use> sprites only exist on the live site)
DROP_ELEMENTS <- c("script", "style", "iframe", "object", "embed", "form", "noscript", "template", "applet",
                   "frame", "frameset", "link", "meta", "base", "title", "svg", "input", "button",
                   "textarea", "select")
ALLOWED_ATTRS <- c("class", "href", "src", "srcset", "poster", "cite", "alt", "title", "width", "height",
                   "colspan", "rowspan", "start", "name", "rel", "target", "download", "lang", "dir", "role",
                   "scope", "headers", "abbr", "aria-hidden", "aria-label")
URL_ATTRS <- c("href", "src", "srcset", "poster", "cite")
# Classes the stylesheet knows or the rules below handle; any other class is listed in the report.
KNOWN_CLASSES <- c(
  "emoji", "only-emoji", "mention", "mention-group", "hashtag", "anchor", "attachment", "lightbox",
  "lightbox-wrapper", "md-table", "onebox", "allowlistedgeneric", "lazyYT", "lazyYT-container",
  "ytp-thumbnail-image", "inline-onebox", "onebox-body", "onebox-metadata", "onebox-avatar", "source",
  "site-icon", "thumbnail", "aspect-image", "quote", "no-group", "title", "poll", "poll-container",
  "poll-info", "info-label", "info-number", "email-redacted", "video-title", "clear-both")

COUNTER_KEYS <- c(
  "urls_made_root_relative", "protocol_relative_urls_made_root_relative", "srcset_candidates_rewritten",
  "external_links_untouched",
  "topic_links_resolved", "topic_post_anchors_added", "topic_post_anchors_dropped",
  "category_links_resolved", "home_links_resolved", "asset_links_kept",
  "links_unwrapped_unresolvable", "autolink_texts_replaced", "mentions_unlinked", "profile_links_unlinked",
  "lightboxes_unwrapped", "lightbox_meta_removed", "avatars_removed", "quote_controls_removed",
  "youtube_captions", "youtube_without_thumbnail", "local_dates_reformatted", "local_dates_left_as_text",
  "attachments_with_download", "anchor_names_renamed", "img_alt_added", "javascript_urls_removed",
  "data_attributes_stripped", "style_attributes_stripped", "clear_both_styles_to_class",
  "loading_attributes_stripped", "event_handler_attributes_stripped")

USAGE <- "Usage: Rscript R/02_build.R [--raw DIR] [--out DIR]
  --raw DIR  redacted copy of the harvest to read (default: raw)
  --out DIR  directory to build the site in (default: dist); it must be empty or hold an earlier build
             (sitemap.xml). build-report.json is written next to it."

# ---- helpers -----------------------------------------------------------------------------------
# Parsed JSON is always read with [[ ]]: `$` partial-matches.

`%||%` <- function(x, y) if (is.null(x)) y else x

say <- function(fmt, ...) message("[build] ", if (...length() > 0) sprintf(fmt, ...) else fmt)

abort <- function(...) {
  stop(structure(class = c("build_abort", "error", "condition"),
                 list(message = paste0(...), call = NULL)))
}

parse_args <- function(argv) {
  opts <- list(raw = RAW_DEFAULT, out = OUT_DEFAULT, templates = TEMPLATE_DIR)
  flags <- c("--raw" = "raw", "--out" = "out")
  i <- 1L
  while (i <= length(argv)) {
    a <- argv[i]
    flag <- sub("=.*$", "", a)
    if (flag %in% names(flags)) {
      if (grepl("=", a, fixed = TRUE)) {
        v <- sub("^[^=]*=", "", a)
      } else {
        if (i >= length(argv)) abort(flag, " needs a value\n", USAGE)
        i <- i + 1L
        v <- argv[i]
      }
      opts[[flags[[flag]]]] <- v
    } else if (a %in% c("-h", "--help")) {
      cat(USAGE, "\n")
      quit(save = "no", status = 0L)
    } else {
      abort("Unknown argument: ", a, "\n", USAGE)
    }
    i <- i + 1L
  }
  if (!nzchar(opts$raw) || !nzchar(opts$out)) abort("--raw and --out must not be empty")
  opts
}

shown <- function(x, n = 5L) {
  paste0(paste(utils::head(x, n), collapse = ", "), if (length(x) > n) sprintf(", ... (%d in all)", length(x)) else "")
}

# ---- files and text ----------------------------------------------------------------------------
# Text always goes through raw bytes: in a non-UTF-8 session (LANG=C) writeLines() would turn
# non-ASCII characters into <U+XXXX> escapes.

read_bytes <- function(path) readBin(path, "raw", n = file.size(path))

bytes_to_text <- function(bytes, what) {
  txt <- tryCatch(rawToChar(bytes), error = function(e) abort(what, " contains a NUL byte"))
  Encoding(txt) <- "UTF-8"
  if (!validUTF8(txt)) abort(what, " is not valid UTF-8")
  txt
}

read_text <- function(path, what = path) gsub("\r\n?", "\n", bytes_to_text(read_bytes(path), what))

# Strings that arrive unmarked (literals in tests, a non-UTF-8 session) are marked UTF-8 if they are.
as_utf8 <- function(x) {
  if (length(x) != 1L || is.na(x)) return(x)
  if (Encoding(x) == "unknown" && validUTF8(x)) Encoding(x) <- "UTF-8"
  enc2utf8(x)
}

write_text <- function(text, path) {
  text <- gsub("\r\n?", "\n", as_utf8(text))
  if (!validUTF8(text)) abort("Refusing to write ", path, ": the text is not valid UTF-8")
  fs::dir_create(dirname(path))
  writeBin(charToRaw(text), path)
}

read_json_file <- function(path) {
  tryCatch(jsonlite::read_json(path, simplifyVector = FALSE),
           error = function(e) abort("Cannot parse JSON file ", path, ": ", conditionMessage(e)))
}

to_json <- function(x) {
  paste0(jsonlite::toJSON(x, auto_unbox = TRUE, pretty = TRUE, null = "null", na = "null", digits = NA), "\n")
}

list_tree <- function(dir) {
  entries <- fs::dir_ls(dir, recurse = TRUE, all = TRUE)
  if (length(entries) == 0L) return(list(files = character(), other = character()))
  type <- as.character(fs::file_info(entries)$type)
  rel <- as.character(fs::path_rel(entries, start = dir))
  list(files = rel[type == "file"], other = rel[!type %in% c("file", "directory")])
}

# ---- directories: resolving, guards, the swap --------------------------------------------------

# Absolute path with symlinks resolved as far as it exists (--out usually does not exist yet).
resolve_path <- function(p) {
  p <- as.character(fs::path_abs(p))
  rest <- character()
  while (!fs::file_exists(p)) {
    if (fs::is_link(p)) abort(p, " is a dangling symbolic link")
    rest <- c(basename(p), rest)
    p <- dirname(p)
  }
  as.character(fs::path_join(c(fs::path_real(p), rest)))
}

# device:inode of p and of every ancestor that exists.
ancestor_ids <- function(p) {
  ids <- character()
  repeat {
    if (fs::file_exists(p)) {
      fi <- fs::file_info(p)
      ids <- c(ids, paste(fi$device_id, fi$inode))
    }
    parent <- dirname(p)
    if (parent == p) break
    p <- parent
  }
  ids
}

# Compares directories by identity, so symlinks and differently spelled paths cannot fool it.
check_dirs <- function(raw, out) {
  raw_chain <- ancestor_ids(raw)
  if (fs::file_exists(out)) {
    out_chain <- ancestor_ids(out)
    if (identical(out_chain[1], raw_chain[1])) abort("--raw and --out are the same directory")
    if (out_chain[1] %in% raw_chain) abort("--out contains --raw")
  }
  if (raw_chain[1] %in% ancestor_ids(out)) abort("--out is inside --raw")
}

# Our own output: empty (apart from .DS_Store) or holding the sitemap.
dir_state <- function(dir) {
  entries <- basename(as.character(fs::dir_ls(dir, all = TRUE)))
  entries <- entries[entries != ".DS_Store"]
  if (length(entries) == 0L) "empty" else if (SITEMAP_FILE %in% entries) "built" else "foreign"
}

# What may happen to --out: "absent", "empty" or "built". Anything else must not be touched.
out_state <- function(out) {
  if (!fs::file_exists(out)) return("absent")
  if (!fs::is_dir(out)) abort(out, " exists and is not a directory")
  state <- dir_state(out)
  if (state == "foreign") {
    abort(out, " exists, is not empty and holds no ", SITEMAP_FILE, " (so it is not this script's own output); ",
          "refusing to touch it. Move it away or choose another --out.")
  }
  state
}

# Leftovers of an interrupted run: a half-built tree is removed (only if it carries our marker); a
# previous output that was moved aside but never replaced is put back. Anything else is left alone.
clear_stale <- function(out, tmp, aside) {
  for (p in c(tmp, aside)) if (fs::is_link(p)) abort(p, " is a symbolic link; refusing to touch it")
  if (fs::file_exists(aside)) {
    if (!fs::is_dir(aside) || dir_state(aside) == "foreign") {
      abort(aside, " exists but is not an earlier output of this script; refusing to touch it")
    }
    if (fs::file_exists(out)) {
      say("removing stale %s", aside)
      unlink(aside, recursive = TRUE)
    } else {
      say("restoring %s: an earlier run was interrupted while swapping", out)
      if (!file.rename(aside, out)) abort("Cannot move ", aside, " back to ", out)
    }
  }
  if (fs::file_exists(tmp)) {
    if (!file.exists(file.path(tmp, TMP_MARKER)) && !(fs::is_dir(tmp) && dir_state(tmp) == "empty")) {
      abort(tmp, " exists but was not left by this script (no ", TMP_MARKER, " inside); refusing to delete it")
    }
    say("removing stale %s", tmp)
    unlink(tmp, recursive = TRUE)
  }
}

# Moves the old --out aside, renames the new tree in, deletes the old one; undone if the rename fails.
swap_in <- function(tmp, out, aside) {
  had_old <- fs::file_exists(out)
  if (had_old && !file.rename(out, aside)) abort("Cannot move ", out, " aside")
  if (!file.rename(tmp, out)) {
    if (had_old) file.rename(aside, out)
    abort("Cannot move ", tmp, " to ", out, if (had_old) " (the previous output was put back)")
  }
  if (had_old) {
    unlink(aside, recursive = TRUE)
    if (fs::file_exists(aside)) say("WARNING: could not delete the previous output, now at %s; remove it by hand", aside)
  }
}

# ---- the input: guard, site, categories, topics ------------------------------------------------

# Only a redacted copy may be published: manifest.json says what it was derived from and how it was
# redacted, and the redaction report must exist.
verify_redacted <- function(raw) {
  mpath <- file.path(raw, MANIFEST_FILE)
  if (!file.exists(mpath)) abort(raw, " has no ", MANIFEST_FILE, ": not a harvest or a redacted copy of one")
  manifest <- read_json_file(mpath)
  if (!identical(manifest[["derived_from"]], "raw_verbatim") ||
      !is.list(manifest[["redaction"]]) || length(manifest[["redaction"]]) == 0L) {
    abort(raw, " is not a redacted copy (its ", MANIFEST_FILE, " lacks derived_from == \"raw_verbatim\" and a redaction block); ",
          "run R/01b_redact.R and build from its output. Refusing to build from unredacted data.")
  }
  if (!file.exists(file.path(raw, REDACTION_REPORT))) {
    abort(raw, " is not a redacted copy (no ", REDACTION_REPORT, "). Refusing to build from unredacted data.")
  }
  manifest
}

# ---- dates (all UTC) ---------------------------------------------------------------------------

UTC_RE <- paste0("^(\\d{4})-(\\d{2})-(\\d{2})",
                 "(?:[T ](\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.\\d+)?)?)?",
                 "\\s*(Z|[+-]\\d{2}(?::?\\d{2})?)?(?:\\s+UTC)?$")

# "2022-07-14T12:00:00Z", "2022-07-14T12:00:00.306Z", "2022-07-14 12:00 UTC", "2022-07-14" -> parts, or NULL.
parse_utc <- function(x) {
  if (!is.character(x) || length(x) != 1L || is.na(x)) return(NULL)
  m <- regmatches(trimws(x), regexec(UTC_RE, trimws(x), perl = TRUE))[[1]]
  if (length(m) == 0L) return(NULL)
  num <- function(s) if (nzchar(s)) as.integer(s) else 0L
  t <- ISOdatetime(num(m[2]), num(m[3]), num(m[4]), num(m[5]), num(m[6]), num(m[7]), tz = "UTC")
  if (is.na(t)) return(NULL)
  zone <- m[8]
  if (nzchar(zone) && zone != "Z") {
    digits <- gsub("[^0-9]", "", zone)
    hh <- as.integer(substr(digits, 1L, 2L))
    mm <- if (nchar(digits) >= 4L) as.integer(substr(digits, 3L, 4L)) else 0L
    t <- t - (if (startsWith(zone, "-")) -1 else 1) * (hh * 3600 + mm * 60)
  }
  list(epoch = as.numeric(t), date = format(t, "%Y-%m-%d", tz = "UTC"), hm = format(t, "%H:%M", tz = "UTC"),
       iso = format(t, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"), has_time = nzchar(m[5]))
}

# ---- site, categories, topics ------------------------------------------------------------------

load_site <- function(raw, manifest) {
  basic <- read_json_file(file.path(raw, "site-basic-info.json"))
  stamp <- parse_utc(manifest[["harvested_at_utc"]])
  if (is.null(stamp)) abort(MANIFEST_FILE, " has no usable harvested_at_utc")
  version <- manifest[["discourse_version"]]
  if (!is.character(version) || length(version) != 1L || !nzchar(version)) abort(MANIFEST_FILE, " has no discourse_version")
  str <- function(x, default = "") if (is.character(x) && length(x) == 1L && !is.na(x)) x else default
  list(title = str(basic[["title"]], str(manifest[["site_title"]], "Forum archive")),
       description = trimws(str(basic[["description"]])),
       logo_raw = str(basic[["logo_small_url"]], str(basic[["logo_url"]])),
       favicon_raw = str(basic[["favicon_url"]]),
       apple_touch_icon_raw = str(basic[["apple_touch_icon_url"]]),
       harvested_at = manifest[["harvested_at_utc"]], snapshot_date = stamp$date, discourse_version = version)
}

# Header images from site-basic-info.json: root-relative, and only if the file is among the assets.
site_asset_url <- function(u, asset_paths, what, warnings) {
  if (!nzchar(u)) return(list(url = "", warnings = warnings))
  info <- classify_url(u)
  if (info$kind != "internal") {
    return(list(url = "", warnings = c(warnings, sprintf("%s is not a forum URL, so it is left out of the header", what))))
  }
  path <- url_decode(info$path)
  if (is.na(path) || !path %in% asset_paths) {
    return(list(url = "", warnings = c(warnings, sprintf("%s is not among the harvested assets, so it is left out of the header", what))))
  }
  list(url = info$path, warnings = warnings)
}

# Flattens categories.json into one record per category, parents first, siblings by position.
load_categories <- function(raw) {
  json <- read_json_file(file.path(raw, "categories.json"))
  top <- json[["category_list"]][["categories"]]
  if (!is.list(top) || length(top) == 0L) abort("categories.json has no category_list$categories")
  rows <- list()
  by_position <- function(nodes) {
    pos <- vapply(nodes, function(n) as.integer(n[["position"]] %||% 0L), 1L)
    ids <- vapply(nodes, function(n) as.integer(n[["id"]]), 1L)
    nodes[order(pos, ids, method = "radix")]
  }
  visit <- function(node, parent_id, parent_slugs) {
    slugs <- c(parent_slugs, node[["slug"]])
    id <- as.integer(node[["id"]])
    check_slug(node[["slug"]], paste("category", id))
    about <- if (is.character(node[["topic_url"]])) regmatches(node[["topic_url"]], regexec("^/t/[^/]+/([0-9]+)", node[["topic_url"]]))[[1]] else character()
    rows[[length(rows) + 1L]] <<- list(
      id = id, slug = node[["slug"]], name = node[["name"]] %||% node[["slug"]],
      description = trimws(node[["description_text"]] %||% ""),
      parent_id = parent_id, depth = length(parent_slugs),
      path = sprintf("/c/%s/%d/", paste(slugs, collapse = "/"), id),
      about_topic_id = if (length(about) == 2L) as.integer(about[2]) else NA_integer_,
      reported_topic_count = as.integer(node[["topic_count"]] %||% NA_integer_))
    kids <- node[["subcategory_list"]]
    if (is.list(kids) && length(kids) > 0L) {
      if (length(parent_slugs) >= 1L) abort("Category ", id, " has subcategories of its own; this build supports one level of subcategories")
      for (kid in by_position(kids)) visit(kid, id, slugs)
    }
  }
  for (node in by_position(top)) visit(node, NA_integer_, character())
  ids <- vapply(rows, function(r) r$id, 1L)
  if (anyDuplicated(ids)) abort("categories.json lists category ", shown(ids[duplicated(ids)]), " twice")
  stats::setNames(rows, ids)
}

check_slug <- function(slug, what) {
  if (!is.character(slug) || length(slug) != 1L || !grepl("^[A-Za-z0-9._~%-]+$", slug)) {
    abort(what, " has a slug this build cannot put in a URL path: '", slug, "'")
  }
}

post_record <- function(p) {
  list(id = as.integer(p[["id"]]), number = as.integer(p[["post_number"]]),
       type = as.integer(p[["post_type"]] %||% 1L),
       created_at = if (is.character(p[["created_at"]])) p[["created_at"]] else NA_character_,
       username = as.character(p[["username"]] %||% ""), name = as.character(p[["name"]] %||% ""),
       reply_to = as.integer(p[["reply_to_post_number"]] %||% NA_integer_),
       cooked = as.character(p[["cooked"]] %||% ""),
       hidden = isTRUE(p[["hidden"]]) || isTRUE(p[["user_deleted"]]) || !is.null(p[["deleted_at"]]))
}

check_topic_shape <- function(t, id) {
  problems <- character()
  if (!identical(as.integer(t[["id"]] %||% NA), as.integer(id))) problems <- c(problems, "id does not match the file name")
  if (!is.character(t[["slug"]]) || !nzchar(t[["slug"]])) problems <- c(problems, "no slug")
  if (!is.character(t[["title"]])) problems <- c(problems, "no title")
  if (!is.numeric(t[["category_id"]])) problems <- c(problems, "no category_id")
  posts <- t[["post_stream"]][["posts"]]
  if (!is.list(posts)) {
    problems <- c(problems, "no post_stream$posts")
  } else if (!all(vapply(posts, function(p) is.numeric(p[["id"]]) && is.numeric(p[["post_number"]]) && is.character(p[["cooked"]]), NA))) {
    problems <- c(problems, "a post lacks id, post_number or cooked")
  }
  if (length(problems) > 0L) abort("raw/topic/", id, ".json does not have the expected shape (", paste(problems, collapse = "; "), ")")
}

# One record per topic file, posts of topic/{id}.json plus topic/{id}-posts-{k}.json sorted by post_number.
# Posts that are not rendered (system events, hidden, deleted) are counted here and dropped.
load_topics <- function(raw) {
  dir <- file.path(raw, "topic")
  if (!dir.exists(dir)) abort(raw, " has no topic/ directory")
  files <- list.files(dir, pattern = "\\.json$")
  main <- files[grepl("^[0-9]+\\.json$", files)]
  chunks <- files[grepl("^[0-9]+-posts-[0-9]+\\.json$", files)]
  stray <- setdiff(files, c(main, chunks))
  if (length(stray) > 0L) abort("Unexpected files in ", dir, ": ", shown(stray))
  ids <- sort(as.integer(sub("\\.json$", "", main)))
  chunk_topic <- as.integer(sub("-posts-.*$", "", chunks))
  chunk_k <- as.integer(sub("^.*-posts-([0-9]+)\\.json$", "\\1", chunks))
  if (length(setdiff(chunk_topic, ids)) > 0L) abort("Chunk files without a topic file: topic ", shown(setdiff(chunk_topic, ids)))
  lapply(ids, function(id) {
    t <- read_json_file(file.path(dir, sprintf("%d.json", id)))
    check_topic_shape(t, id)
    check_slug(t[["slug"]], paste("topic", id))
    posts <- t[["post_stream"]][["posts"]]
    mine <- which(chunk_topic == id)
    for (j in mine[order(chunk_k[mine])]) {
      extra <- read_json_file(file.path(dir, chunks[j]))[["post_stream"]][["posts"]]
      if (!is.list(extra)) abort(chunks[j], " has no post_stream$posts")
      posts <- c(posts, extra)
    }
    posts <- lapply(posts, post_record)
    numbers <- vapply(posts, function(p) p$number, 1L)
    if (anyDuplicated(vapply(posts, function(p) p$id, 1L))) abort("Topic ", id, " has the same post twice")
    posts <- posts[order(numbers, method = "radix")]
    system <- vapply(posts, function(p) p$type == SYSTEM_POST_TYPE, NA)
    hidden <- vapply(posts, function(p) p$hidden, NA)
    shown_ok <- vapply(posts, function(p) p$type %in% RENDERED_POST_TYPES, NA)
    render <- shown_ok & !hidden
    tags <- vapply(t[["tags"]] %||% list(), function(x) as.character(if (is.list(x)) x[["name"]] %||% "" else x), "")
    list(id = id, slug = t[["slug"]], title = t[["title"]], category_id = as.integer(t[["category_id"]]),
         created_at = if (is.character(t[["created_at"]])) t[["created_at"]] else NA_character_,
         last_posted_at = if (is.character(t[["last_posted_at"]])) t[["last_posted_at"]] else NA_character_,
         pinned = isTRUE(t[["pinned"]]), closed = isTRUE(t[["closed"]]), archived = isTRUE(t[["archived"]]),
         tags = tags[nzchar(tags)], posts = posts[render],
         n_input = length(posts), n_system = sum(system), n_hidden = sum(hidden & !system),
         n_other = sum(!shown_ok & !system & !hidden),
         stream_length = length(t[["post_stream"]][["stream"]]))
  })
}

# ---- URLs: classification, routing --------------------------------------------------------------

URL_RE <- "(?s)^(?:([A-Za-z][A-Za-z0-9+.-]*):)?(?://([^/?#]*))?([^?#]*)(?:\\?([^#]*))?(?:#(.*))?$"

# kind: unsafe (javascript: data: vbscript:), mailto, fragment (#x), internal (this forum, absolute or
# root-relative), external, relative (no leading slash), other. For "internal" the host may be set.
classify_url <- function(u) {
  u <- gsub("[\t\n\r]", "", trimws(as_utf8(u)))
  m <- regmatches(u, regexec(URL_RE, u, perl = TRUE))[[1]]
  scheme <- if (length(m) == 6L) tolower(m[2]) else ""
  host <- if (length(m) == 6L) tolower(m[3]) else ""
  path <- if (length(m) == 6L) m[4] else u
  info <- list(raw = u, scheme = scheme, host = host, path = path,
               query = if (length(m) == 6L) m[5] else "", fragment = if (length(m) == 6L) m[6] else "",
               has_query = grepl("^[^#]*\\?", u), has_fragment = grepl("#", u, fixed = TRUE))
  info$kind <-
    if (length(m) == 0L) "other"
    else if (scheme %in% c("javascript", "vbscript", "data")) "unsafe"
    else if (scheme == "mailto") "mailto"
    else if (scheme %in% c("http", "https") || (scheme == "" && nzchar(host))) {
      if (host == FORUM_HOST) "internal" else "external"
    }
    else if (nzchar(scheme)) "external"
    else if (startsWith(path, "/")) "internal"
    else if (path == "" && !info$has_query && info$has_fragment) "fragment"
    else if (path == "" && !info$has_query) "other"
    else "relative"
  if (info$kind == "internal" && !nzchar(info$path)) info$path <- "/"
  info
}

as_root_relative <- function(info) {
  paste0(info$path, if (info$has_query) paste0("?", info$query), if (info$has_fragment) paste0("#", info$fragment))
}

url_decode <- function(x) {
  x <- gsub("%(?![0-9A-Fa-f]{2})", "%25", x, perl = TRUE)
  if (grepl("%00", x, fixed = TRUE)) return(NA_character_)
  out <- utils::URLdecode(x)
  Encoding(out) <- "UTF-8"
  if (validUTF8(out)) out else NA_character_
}

first_segment <- function(path) {
  segs <- strsplit(path, "/", fixed = TRUE)[[1]]
  segs <- segs[nzchar(segs)]
  if (length(segs) == 0L) "" else segs[1]
}

# "url1, url2 1.5x, url3 2x" -> list of (url, descriptor). A comma right after a URL ends the candidate.
srcset_candidates <- function(x) {
  toks <- regmatches(x, gregexpr("[^\\s,]\\S*(?:\\s+[0-9]*\\.?[0-9]+[wx])?", x, perl = TRUE))[[1]]
  lapply(toks, function(tok) {
    pieces <- strsplit(tok, "\\s+", perl = TRUE)[[1]]
    list(url = sub(",+$", "", pieces[1]), desc = if (length(pieces) > 1L) pieces[2] else "")
  })
}

route_topic <- function(segs, ctx) {
  n <- length(segs)
  num <- grepl("^[0-9]+$", segs)
  id <- NA_character_
  post <- NA_character_
  if (n == 1L && num[1]) {
    id <- segs[1]
  } else if (n == 2L && num[2] && !num[1]) {
    id <- segs[2]
  } else if (n == 2L && num[1] && num[2]) {
    # "/t/{a slug that is all digits}/{id}" or "/t/{id}/{post}": the topic's own slug decides
    hit <- ctx$topics[[segs[2]]]
    if (!is.null(hit) && identical(hit$slug, segs[1])) {
      id <- segs[2]
    } else {
      id <- segs[1]
      post <- segs[2]
    }
  } else if (n == 3L && num[2] && num[3]) {
    id <- segs[2]
    post <- segs[3]
  }
  list(type = "topic", id = id, post = post)
}

route_category <- function(segs, ctx) {
  num <- grepl("^[0-9]+$", segs)
  list(type = "category", id = if (any(num)) segs[which(num)[1]] else NA_character_,
       slug = if (length(segs) > 0L) segs[length(segs)] else NA_character_)
}

# What a forum path points at: home, topic, category, profile (/u/ /groups/), asset, or other.
route_internal <- function(path, ctx) {
  segs <- strsplit(path, "/", fixed = TRUE)[[1]]
  segs <- segs[nzchar(segs)]
  if (length(segs) == 0L) return(list(type = "home"))
  rest <- segs[-1]
  switch(segs[1],
    t = route_topic(rest, ctx),
    c = route_category(rest, ctx),
    u = , users = , groups = , g = list(type = "profile", name = if (length(rest) > 0L) rest[1] else ""),
    if (segs[1] %in% ASSET_DIRS) list(type = "asset") else list(type = "other"))
}

# The static URL of a topic ("/t/real-slug/id/", plus "#post-n" when n > 1 and that post is rendered).
resolve_topic <- function(route, ctx) {
  if (is.na(route$id)) return(NULL)
  t <- ctx$topics[[route$id]]
  if (is.null(t)) return(NULL)
  href <- paste0("/t/", t$slug, "/", route$id, "/")
  anchored <- FALSE
  dropped <- FALSE
  n <- if (is.na(route$post)) NA_integer_ else suppressWarnings(as.integer(route$post))
  if (!is.na(n) && n > 1L) {
    if (n %in% t$posts) {
      href <- paste0(href, "#post-", n)
      anchored <- TRUE
    } else {
      dropped <- TRUE
    }
  }
  list(href = href, text = t$title, anchored = anchored, anchor_dropped = dropped)
}

resolve_category <- function(route, ctx) {
  cat <- if (!is.na(route$id)) ctx$categories[[route$id]] else NULL
  if (is.null(cat) && !is.na(route$slug)) {
    hits <- Filter(function(k) identical(k$slug, route$slug), ctx$categories)
    if (length(hits) == 1L) cat <- hits[[1]]
  }
  if (is.null(cat)) NULL else list(href = cat$path, text = cat$name)
}

# ---- the rewriter: state and bookkeeping --------------------------------------------------------
# ctx$topics: named by topic id, list(slug, title, posts = rendered post numbers); ctx$categories: named
# by category id, list(slug, name, path); ctx$asset_paths: root-relative paths of the copied assets
# (NULL: do not check). Everything the report needs is collected on ctx as the walker goes.

new_rewriter <- function(topics = list(), categories = list(), asset_paths = NULL) {
  ctx <- new.env(parent = emptyenv())
  ctx$topics <- topics
  ctx$categories <- categories
  ctx$asset_paths <- asset_paths
  ctx$counts <- stats::setNames(as.list(integer(length(COUNTER_KEYS))), COUNTER_KEYS)
  ctx$groups <- list(elements_dropped = list(), attributes_dropped = list())
  ctx$unknown_elements <- list()
  ctx$unknown_classes <- list()
  ctx$missing_assets <- list()
  ctx$unresolved <- list()
  ctx$external_images <- list()
  ctx$where <- ""
  ctx$in_lightbox <- FALSE
  ctx$name_map <- list()
  ctx$seen_names <- character()
  ctx
}

bump <- function(ctx, key, by_name = NULL, by = 1L) {
  if (is.null(by_name)) {
    ctx$counts[[key]] <- (ctx$counts[[key]] %||% 0L) + by
  } else {
    if (!nzchar(by_name)) by_name <- "(empty)"
    group <- ctx$groups[[key]] %||% list()
    group[[by_name]] <- (group[[by_name]] %||% 0L) + by
    ctx$groups[[key]] <- group
  }
  invisible(NULL)
}

# Counts occurrences per key and remembers where the first one was.
note_once <- function(ctx, store, key) {
  cur <- ctx[[store]]
  entry <- cur[[key]] %||% list(count = 0L, first_seen = ctx$where)
  entry$count <- entry$count + 1L
  cur[[key]] <- entry
  ctx[[store]] <- cur
  invisible(NULL)
}

note_unresolved <- function(ctx, target, action) {
  ctx$unresolved[[length(ctx$unresolved) + 1L]] <- list(source = ctx$where, target = target, action = action)
  invisible(NULL)
}

note_external_image <- function(ctx, info) {
  ctx$external_images[[length(ctx$external_images) + 1L]] <- list(source = ctx$where, host = info$host, url = info$raw)
  invisible(NULL)
}

note_classes <- function(ctx, name, cls) {
  for (k in setdiff(cls, KNOWN_CLASSES)) note_once(ctx, "unknown_classes", paste0(name, ".", k))
  invisible(NULL)
}

check_asset <- function(ctx, path) {
  if (is.null(ctx$asset_paths)) return(invisible(NULL))
  decoded <- url_decode(path)
  if (is.na(decoded) || !decoded %in% ctx$asset_paths) note_once(ctx, "missing_assets", path)
  invisible(NULL)
}

begin_page <- function(ctx) {
  ctx$seen_names <- character()
  invisible(NULL)
}

# ---- the rewriter: URLs (rule 1) ----------------------------------------------------------------

# An absolute (or protocol-relative) forum URL is about to become root-relative.
count_root_relative <- function(ctx, info) {
  if (nzchar(info$host)) {
    bump(ctx, "urls_made_root_relative")
    if (info$scheme == "") bump(ctx, "protocol_relative_urls_made_root_relative")
  }
  invisible(NULL)
}

# Rewrites one URL attribute value: the forum host disappears, assets stay at their paths. NULL drops
# the attribute (javascript: and friends).
rewrite_url <- function(u, ctx, attr = "src", el = "") {
  info <- classify_url(u)
  switch(info$kind,
    unsafe = , mailto = {
      bump(ctx, "javascript_urls_removed")
      NULL
    },
    internal = {
      count_root_relative(ctx, info)
      if (first_segment(info$path) %in% ASSET_DIRS) check_asset(ctx, info$path)
      as_root_relative(info)
    },
    external = {
      if (el == "img") note_external_image(ctx, info)
      if (el == "a") bump(ctx, "external_links_untouched")
      u
    },
    u)
}

rewrite_srcset <- function(x, ctx, el = "img") {
  parts <- character()
  for (cand in srcset_candidates(x)) {
    new <- rewrite_url(cand$url, ctx, "srcset", el)
    if (is.null(new)) next
    if (!identical(new, cand$url)) bump(ctx, "srcset_candidates_rewritten")
    parts <- c(parts, trimws(paste(new, cand$desc)))
  }
  if (length(parts) == 0L) NULL else paste(parts, collapse = ", ")
}

# ---- the rewriter: serialising ------------------------------------------------------------------

NBSP    <- intToUtf8(0xA0)
CTRL_RE <- "[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]"

escape_text <- function(x) {
  x <- gsub(CTRL_RE, "", x, perl = TRUE)
  x <- gsub("&", "&amp;", x, fixed = TRUE)
  x <- gsub("<", "&lt;", x, fixed = TRUE)
  x <- gsub(">", "&gt;", x, fixed = TRUE)
  gsub(NBSP, "&nbsp;", x, fixed = TRUE)
}

escape_attr <- function(x) gsub("\"", "&quot;", escape_text(x), fixed = TRUE)

emit_element <- function(name, attrs = character(), inner = "") {
  open <- paste0("<", name, if (length(attrs) > 0L) paste0(" ", names(attrs), "=\"", vapply(unname(attrs), escape_attr, ""), "\"", collapse = ""), ">")
  if (name %in% VOID_ELEMENTS) open else paste0(open, inner, "</", name, ">")
}

attr_get <- function(attrs, name) {
  if (length(attrs) > 0L && name %in% names(attrs)) attrs[[name]] else NA_character_
}

class_tokens <- function(attrs) {
  cl <- attr_get(attrs, "class")
  if (is.na(cl)) character() else strsplit(trimws(cl), "\\s+")[[1]]
}

FRAGMENT_OPEN  <- "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body><div id=\"cooked-root\">"
FRAGMENT_CLOSE <- "</div></body></html>"

# The fragment is wrapped in a root element (so libxml2 adds no implied <p>), parsed as UTF-8, and
# whitespace is kept (xml2's default NOBLANKS drops the space in `<img> <strong>`).
parse_fragment <- function(html) {
  doc <- xml2::read_html(charToRaw(paste0(FRAGMENT_OPEN, as_utf8(html), FRAGMENT_CLOSE)),
                         encoding = "UTF-8", options = c("RECOVER", "NOERROR", "NONET"))
  root <- xml2::xml_find_first(doc, "//div[@id='cooked-root']")
  if (inherits(root, "xml_missing")) abort("Internal error: the fragment root was lost while parsing")
  root
}

render_nodes <- function(nodes, ctx) {
  n <- length(nodes)
  if (n == 0L) return("")
  types <- xml2::xml_type(nodes)
  out <- character(n)
  for (i in seq_len(n)) {
    out[i] <- switch(types[i],
      text = , cdata = escape_text(xml2::xml_text(nodes[[i]])),
      element = render_element(nodes[[i]], ctx),
      "")
  }
  paste0(out, collapse = "")
}

is_clear_both <- function(style) grepl("^\\s*clear\\s*:\\s*both\\s*;?\\s*$", style, ignore.case = TRUE)

# Attributes to keep, in their original order (rule 4: allow-list; data-*, on*, style, loading never
# pass). `overrides` replaces a value (NULL removes the attribute) or adds one at the end.
clean_attrs <- function(name, attrs, ctx, overrides = list()) {
  kept <- character()
  done <- character()
  clear_both <- FALSE
  nms <- names(attrs) %||% character()
  for (i in seq_along(attrs)) {
    nm <- tolower(nms[i])
    v <- attrs[[i]]
    if (nm %in% names(overrides)) {
      done <- c(done, nm)
      if (!is.null(overrides[[nm]])) kept[[nm]] <- overrides[[nm]]
      next
    }
    if (startsWith(nm, "data-")) { bump(ctx, "data_attributes_stripped"); next }
    if (grepl("^on[a-z]+$", nm)) { bump(ctx, "event_handler_attributes_stripped"); next }
    if (nm == "style") {
      if (is_clear_both(v)) clear_both <- TRUE else bump(ctx, "style_attributes_stripped")
      next
    }
    if (nm == "loading") { bump(ctx, "loading_attributes_stripped"); next }
    if (!nm %in% ALLOWED_ATTRS) { bump(ctx, "attributes_dropped", nm); next }
    if (nm %in% URL_ATTRS) {
      v <- if (nm == "srcset") rewrite_srcset(v, ctx, name) else rewrite_url(v, ctx, nm, name)
      if (is.null(v)) next
    }
    kept[[nm]] <- v
  }
  for (nm in setdiff(names(overrides), done)) {
    if (!is.null(overrides[[nm]])) kept[[nm]] <- overrides[[nm]]
  }
  if (clear_both) {
    bump(ctx, "clear_both_styles_to_class")
    kept[["class"]] <- paste(c(if ("class" %in% names(kept)) kept[["class"]], "clear-both"), collapse = " ")
  }
  kept
}

# ---- the rewriter: elements ---------------------------------------------------------------------

render_element <- function(node, ctx) {
  name <- xml2::xml_name(node)
  attrs <- xml2::xml_attrs(node)
  cls <- class_tokens(attrs)
  if (name %in% DROP_ELEMENTS) {
    bump(ctx, "elements_dropped", name)
    # libxml2 knows only HTML 4: after <embed>, say, it nests the following siblings inside it
    return(if (name %in% VOID_ELEMENTS) render_nodes(xml2::xml_contents(node), ctx) else "")
  }
  if (name == "div") {
    if ("lightbox-wrapper" %in% cls) return(render_lightbox(node, ctx))
    if ("lazyYT" %in% cls) return(render_youtube(node, attrs, cls, ctx))
    if ("quote-controls" %in% cls) {                                  # rule 6
      bump(ctx, "quote_controls_removed")
      return("")
    }
    if ("meta" %in% cls && isTRUE(ctx$in_lightbox)) {                 # rule 5
      bump(ctx, "lightbox_meta_removed")
      return("")
    }
  }
  if (name == "span" && "discourse-local-date" %in% cls) return(render_local_date(node, attrs, ctx))
  if (name == "img") return(render_img(attrs, cls, ctx))
  if (name == "a") return(render_anchor(node, attrs, cls, ctx))
  render_generic(node, name, attrs, cls, ctx)
}

# Any other element: kept if it is on the allow-list (rule 12: unknown classes are reported), else
# unwrapped to its content and reported.
render_generic <- function(node, name, attrs, cls, ctx, overrides = list(), inner = NULL) {
  if (!name %in% ALLOWED_ELEMENTS) {
    note_once(ctx, "unknown_elements", name)
    return(render_nodes(xml2::xml_contents(node), ctx))
  }
  note_classes(ctx, name, cls)
  kept <- clean_attrs(name, attrs, ctx, overrides)
  if (name %in% VOID_ELEMENTS) return(paste0(emit_element(name, kept), render_nodes(xml2::xml_contents(node), ctx)))
  emit_element(name, kept, inner %||% render_nodes(xml2::xml_contents(node), ctx))
}

# Rule 6: avatars are removed (also any image that points into the avatar directories, which were not
# harvested). Rule 1: src and srcset lose the forum host. External images stay and are reported.
render_img <- function(attrs, cls, ctx, alt = NULL) {
  src <- attr_get(attrs, "src")
  if ("avatar" %in% cls || (!is.na(src) && first_segment(classify_url(src)$path) %in% AVATAR_DIRS)) {
    bump(ctx, "avatars_removed")
    return("")
  }
  note_classes(ctx, "img", cls)
  kept <- clean_attrs("img", attrs, ctx, if (is.null(alt)) list() else list(alt = alt))
  if (!"alt" %in% names(kept)) {
    kept[["alt"]] <- ""
    bump(ctx, "img_alt_added")
  }
  emit_element("img", kept)
}

# Rule 5: div.lightbox-wrapper disappears; what remains is <a href="FULL"><img ...></a> (the filename
# and size line, div.meta with its icons, is dropped by render_element while in_lightbox is set).
render_lightbox <- function(node, ctx) {
  bump(ctx, "lightboxes_unwrapped")
  was <- ctx$in_lightbox
  ctx$in_lightbox <- TRUE
  on.exit(ctx$in_lightbox <- was)
  render_nodes(xml2::xml_contents(node), ctx)
}

# Rule 7: the existing static anchor + thumbnail stays; data-youtube-title is captured before
# data-* is stripped and becomes the img alt and a visible caption inside the link. A video whose
# anchor holds no thumbnail (nothing to click) gets the caption as its only content.
render_youtube <- function(node, attrs, cls, ctx) {
  title <- attr_get(attrs, "data-youtube-title")
  vid <- attr_get(attrs, "data-youtube-id")
  a_node <- xml2::xml_find_first(node, ".//a")
  img_node <- xml2::xml_find_first(node, ".//img")
  has_a <- !inherits(a_node, "xml_missing")
  has_img <- !inherits(img_node, "xml_missing")
  a_attrs <- if (has_a) xml2::xml_attrs(a_node) else character()
  href <- attr_get(a_attrs, "href")
  if (is.na(href) && is.na(vid)) return(render_generic(node, "div", attrs, cls, ctx))
  caption <- if (!is.na(title) && nzchar(trimws(title))) trimws(title) else "YouTube video"
  img_html <- ""
  if (has_img) {
    img_html <- render_img(xml2::xml_attrs(img_node), class_tokens(xml2::xml_attrs(img_node)), ctx, alt = caption)
  } else {
    bump(ctx, "youtube_without_thumbnail")
  }
  overrides <- if (is.na(href)) list(href = paste0("https://www.youtube.com/watch?v=", vid), target = "_blank", rel = "noopener") else list()
  a_kept <- clean_attrs("a", a_attrs, ctx, overrides)
  bump(ctx, "youtube_captions")
  link <- emit_element("a", a_kept, paste0(img_html, "<span class=\"video-title\">", escape_text(caption), "</span>"))
  note_classes(ctx, "div", cls)
  emit_element("div", clean_attrs("div", attrs, ctx), link)
}

# Rule 8: a Discourse local date shows the UTC time; the author's own time and zone go into title.
render_local_date <- function(node, attrs, ctx) {
  preview <- attr_get(attrs, "data-email-preview")
  txt <- xml2::xml_text(node)
  n_data <- sum(startsWith(tolower(names(attrs) %||% character()), "data-"))
  if (n_data > 0L) bump(ctx, "data_attributes_stripped", by = n_data)
  parts <- parse_utc(if (!is.na(preview)) preview else txt)
  if (is.null(parts)) parts <- parse_utc(txt)
  if (is.null(parts)) {
    bump(ctx, "local_dates_left_as_text")
    return(escape_text(txt))
  }
  bump(ctx, "local_dates_reformatted")
  tm <- attr_get(attrs, "data-time")
  tz <- attr_get(attrs, "data-timezone")
  if (!parts$has_time) {
    return(emit_element("time", c(datetime = parts$date), escape_text(parts$date)))
  }
  local <- if (!is.na(tm) && nzchar(tm)) paste0(substr(tm, 1L, 5L), if (!is.na(tz) && nzchar(tz)) paste0(" ", tz)) else NULL
  attrs_out <- c(datetime = parts$iso, if (!is.null(local)) c(title = local))
  emit_element("time", attrs_out, escape_text(paste0(parts$date, " ", parts$hm, " UTC")))
}

# ---- the rewriter: links (rules 2, 3, 9) --------------------------------------------------------

FORUM_URL_TEXT_RE <- "^\\s*(?:https?:)?//discourse\\.igelsociety\\.org(?:[/?#]|\\s*$)"

# An autolink: the anchor's visible text is itself the absolute forum URL.
anchor_is_autolink <- function(node) {
  length(xml2::xml_children(node)) == 0L &&
    grepl(FORUM_URL_TEXT_RE, xml2::xml_text(node), perl = TRUE, ignore.case = TRUE)
}

download_name <- function(node, info) {
  txt <- trimws(gsub("[\r\n\t]+", " ", xml2::xml_text(node)))
  if (nzchar(txt)) txt else basename(info$path)
}

anchor_name_override <- function(attrs, ctx) {
  nm <- attr_get(attrs, "name")
  if (is.na(nm) || !nzchar(nm)) return(list())
  new <- ctx$name_map[[nm]]
  if (is.null(new) || identical(new, nm)) list() else list(name = new)
}

# Rule 3: users' pages are out of scope, so a mention or any /u/ /groups/ link keeps its text only.
mention_span <- function(node, ctx, by_class, username = "") {
  bump(ctx, if (by_class) "mentions_unlinked" else "profile_links_unlinked")
  inner <- if (anchor_is_autolink(node) && nzchar(username)) {
    bump(ctx, "autolink_texts_replaced")
    escape_text(paste0("@", username))
  } else {
    render_nodes(xml2::xml_contents(node), ctx)
  }
  paste0("<span class=\"mention\">", inner, "</span>")
}

# A link into the forum that cannot be followed in the archive: the anchor goes, its text stays (an
# autolink's text becomes the root-relative path).
unwrap_unresolved <- function(node, info, ctx, why) {
  bump(ctx, "links_unwrapped_unresolvable")
  note_unresolved(ctx, info$path, paste0("link removed, text kept (", why, ")"))
  if (anchor_is_autolink(node)) {
    bump(ctx, "autolink_texts_replaced")
    return(escape_text(as_root_relative(info)))
  }
  render_nodes(xml2::xml_contents(node), ctx)
}

render_internal_link <- function(node, attrs, cls, info, ctx) {
  route <- route_internal(info$path, ctx)
  if (route$type == "profile") return(mention_span(node, ctx, FALSE, route$name))
  keep <- function(href, inner = NULL, extra = list()) {
    count_root_relative(ctx, info)
    render_generic(node, "a", attrs, cls, ctx, overrides = c(list(href = href), extra), inner = inner)
  }
  if (route$type == "home") {
    bump(ctx, "home_links_resolved")
    return(keep("/"))
  }
  if (route$type == "asset") {
    check_asset(ctx, info$path)
    bump(ctx, "asset_links_kept")
    extra <- list()
    if ("attachment" %in% cls) {                                      # rule 9
      bump(ctx, "attachments_with_download")
      extra <- list(download = download_name(node, info))
    }
    return(keep(as_root_relative(info), extra = extra))
  }
  if (route$type == "topic") {
    res <- resolve_topic(route, ctx)
    if (is.null(res)) return(unwrap_unresolved(node, info, ctx, "topic is not in the archive"))
    bump(ctx, "topic_links_resolved")
    if (res$anchored) bump(ctx, "topic_post_anchors_added")
    if (res$anchor_dropped) {
      bump(ctx, "topic_post_anchors_dropped")
      note_unresolved(ctx, info$path, "link kept, #post anchor dropped (that post is not in the archive)")
    }
    inner <- NULL
    if (anchor_is_autolink(node)) {
      bump(ctx, "autolink_texts_replaced")
      inner <- escape_text(res$text)
    }
    return(keep(res$href, inner))
  }
  if (route$type == "category") {
    res <- resolve_category(route, ctx)
    if (is.null(res)) return(unwrap_unresolved(node, info, ctx, "category is not in the archive"))
    bump(ctx, "category_links_resolved")
    inner <- NULL
    if (anchor_is_autolink(node)) {
      bump(ctx, "autolink_texts_replaced")
      inner <- escape_text(res$text)
    }
    return(keep(res$href, inner))
  }
  unwrap_unresolved(node, info, ctx, "page does not exist in the archive")
}

render_anchor <- function(node, attrs, cls, ctx) {
  href <- attr_get(attrs, "href")
  name_ov <- anchor_name_override(attrs, ctx)
  by_class <- any(c("mention", "mention-group") %in% cls)
  if (is.na(href)) {
    if (by_class) return(mention_span(node, ctx, TRUE))
    return(render_generic(node, "a", attrs, cls, ctx, overrides = name_ov))
  }
  info <- classify_url(href)
  if (by_class) {
    route <- if (info$kind == "internal") route_internal(info$path, ctx) else list()
    return(mention_span(node, ctx, TRUE, if (identical(route$type, "profile")) route$name else ""))
  }
  switch(info$kind,
    unsafe = {
      bump(ctx, "javascript_urls_removed")
      render_nodes(xml2::xml_contents(node), ctx)
    },
    mailto = {
      note_unresolved(ctx, "(mailto link)", "link removed, text kept (mailto links are never published)")
      bump(ctx, "links_unwrapped_unresolvable")
      render_nodes(xml2::xml_contents(node), ctx)
    },
    fragment = {
      frag <- info$fragment
      new <- if (nzchar(frag)) ctx$name_map[[frag]] else NULL
      render_generic(node, "a", attrs, cls, ctx, overrides = c(name_ov, list(href = paste0("#", new %||% frag))))
    },
    internal = render_internal_link(node, attrs, cls, info, ctx),
    render_generic(node, "a", attrs, cls, ctx, overrides = name_ov))
}

# One post's anchor names (<a name="x">) must be unique on the topic page, where all posts share one
# document: a name already used by an earlier post gets a "-p{post}" suffix, and the same-post
# #fragment links follow (ctx$name_map).
plan_anchor_names <- function(root, ctx, post_number) {
  ctx$name_map <- list()
  nodes <- xml2::xml_find_all(root, ".//a[@name]")
  if (length(nodes) == 0L) return(invisible(NULL))
  used <- ctx$seen_names
  for (nm in xml2::xml_attr(nodes, "name")) {
    if (is.na(nm) || !nzchar(nm) || !is.null(ctx$name_map[[nm]])) next
    new <- nm
    if (nm %in% used) {
      new <- sprintf("%s-p%s", nm, if (is.na(post_number)) "x" else post_number)
      k <- 2L
      while (new %in% used) {
        new <- sprintf("%s-p%s-%d", nm, if (is.na(post_number)) "x" else post_number, k)
        k <- k + 1L
      }
      bump(ctx, "anchor_names_renamed")
    }
    ctx$name_map[[nm]] <- new
    used <- c(used, new)
  }
  ctx$seen_names <- used
  invisible(NULL)
}

# Entry point: the sanitised HTML of one post body. `where` names the post in the report.
rewrite_cooked <- function(html, ctx, where = "", post_number = NA_integer_) {
  ctx$where <- where
  ctx$in_lightbox <- FALSE
  root <- parse_fragment(html)
  plan_anchor_names(root, ctx, post_number)
  trimws(render_nodes(xml2::xml_contents(root), ctx))
}

# ---- page data ----------------------------------------------------------------------------------

count_label <- function(n) sprintf("%d %s", n, if (n == 1L) "topic" else "topics")

page_file <- function(url) paste0(sub("^/", "", url), if (endsWith(url, "/")) "index.html")

# Categories with the number of their own topics, not counting the pinned About topic.
category_counts <- function(cats, topics) {
  cat_of <- vapply(topics, function(t) t$category_id, 1L)
  ids <- vapply(topics, function(t) t$id, 1L)
  vapply(cats, function(k) {
    own <- ids[cat_of == k$id]
    sum(cat_of == k$id) - (!is.na(k$about_topic_id) && k$about_topic_id %in% own)
  }, 1L)
}

category_entry <- function(k, count) {
  list(name = k$name, path = k$path, topic_count_label = count_label(count),
       has_description = nzchar(k$description), description = k$description)
}

crumbs_of <- function(k, cats) {
  chain <- list(k)
  while (!is.na(chain[[1]]$parent_id)) chain <- c(list(cats[[as.character(chain[[1]]$parent_id)]]), chain)
  lapply(chain, function(x) list(name = x$name, path = x$path, has_link = TRUE))
}

# The top-level categories in home-page order. `tops` arrives in forum order and the sort is stable, so the
# categories that are not conferences keep that order.
conferences_first <- function(tops) {
  is_conf <- vapply(tops, function(k) grepl(CONFERENCE_SLUG, k$slug), NA)
  year <- vapply(tops[is_conf], function(k) as.integer(sub(CONFERENCE_SLUG, "\\1", k$slug)), 1L)
  c(tops[is_conf][order(-year, method = "radix")], tops[!is_conf])
}

home_data <- function(site, cats, counts) {
  tops <- conferences_first(Filter(function(k) is.na(k$parent_id), cats))
  entries <- lapply(tops, function(k) {
    kids <- Filter(function(x) identical(x$parent_id, k$id), cats)
    c(category_entry(k, counts[[as.character(k$id)]]),
      list(has_children = length(kids) > 0L,
           children = unname(lapply(kids, function(x) category_entry(x, counts[[as.character(x$id)]])))))
  })
  list(site_title = site$title, snapshot_date = site$snapshot_date,
       has_site_description = nzchar(site$description), site_description = site$description,
       categories = unname(entries))
}

# One row per topic of the category (its own only), pinned first, then newest activity, then highest id.
category_rows <- function(topics_of) {
  if (length(topics_of) == 0L) return(list())
  pinned <- vapply(topics_of, function(t) t$pinned, NA)
  epoch <- vapply(topics_of, function(t) t$activity_epoch, 1)
  id <- vapply(topics_of, function(t) t$id, 1L)
  ord <- order(!pinned, -epoch, -id, method = "radix")
  unname(lapply(topics_of[ord], function(t) list(
    path = t$url, title = t$title, pinned = t$pinned, tags = paste(t$tags, collapse = ", "),
    replies = as.character(t$replies), created = t$created_date, activity = t$activity_date)))
}

category_data <- function(k, cats, counts, topics_of) {
  kids <- Filter(function(x) identical(x$parent_id, k$id), cats)
  crumbs <- crumbs_of(k, cats)
  crumbs[[length(crumbs)]]$has_link <- FALSE
  rows <- category_rows(topics_of)
  list(name = k$name, crumbs = crumbs, has_description = nzchar(k$description), description = k$description,
       has_subcategories = length(kids) > 0L,
       subcategories = unname(lapply(kids, function(x) category_entry(x, counts[[as.character(x$id)]]))),
       has_topics = length(rows) > 0L, topics = rows)
}

# The author line is plain text: the display name (when there is one that differs from the username)
# and @username. Never a link to a profile page.
post_view <- function(p, bodies, numbers) {
  user <- p$username
  name <- if (nzchar(p$name) && tolower(p$name) != tolower(user)) p$name else if (nzchar(user)) "" else "(unknown author)"
  when <- parse_utc(p$created_at)
  list(number = as.character(p$number),
       has_name = nzchar(name), display_name = name, has_handle = nzchar(user), handle = paste0("@", user),
       both = nzchar(name) && nzchar(user),
       iso = if (is.null(when)) "" else when$iso,
       when = if (is.null(when)) (if (is.na(p$created_at)) "" else p$created_at) else paste0(when$date, " ", when$hm, " UTC"),
       has_reply_to = !is.na(p$reply_to) && p$reply_to != p$number && p$reply_to %in% numbers,
       reply_to = if (is.na(p$reply_to)) "" else as.character(p$reply_to),
       body = bodies)
}

topic_status <- function(t) {
  parts <- c(if (t$closed) "closed", if (t$archived) "archived")
  if (length(parts) == 0L) return("")
  sprintf("This topic was %s on the original forum.", paste(parts, collapse = " and "))
}

topic_data <- function(t, cats, views) {
  status <- topic_status(t)
  list(title = t$title, crumbs = crumbs_of(cats[[as.character(t$category_id)]], cats),
       has_tags = length(t$tags) > 0L,
       tags = lapply(seq_along(t$tags), function(i) list(name = t$tags[i], comma = i < length(t$tags))),
       has_status = nzchar(status), status = status, posts = unname(views))
}

# ---- templates and pages ------------------------------------------------------------------------

load_templates <- function(dir) {
  need <- c(TEMPLATE_FILES, STYLESHEET)
  missing <- need[!file.exists(file.path(dir, need))]
  if (length(missing) > 0L) abort("Missing template files in ", dir, ": ", paste(missing, collapse = ", "))
  lapply(TEMPLATE_FILES, function(f) read_text(file.path(dir, f)))
}

layout_fields <- function(site, kind, title, canonical = NULL, description = NULL, noindex = FALSE) {
  list(page_title = title, page_kind = kind,
       has_description = !is.null(description) && nzchar(description), description = description %||% "",
       noindex = noindex, has_canonical = !is.null(canonical), canonical_url = canonical %||% "",
       has_favicon = nzchar(site$favicon), favicon_url = site$favicon,
       has_apple_touch_icon = nzchar(site$apple_touch_icon), apple_touch_icon_url = site$apple_touch_icon,
       has_logo = nzchar(site$logo), logo_url = site$logo,
       site_title = site$title, snapshot_date = site$snapshot_date, discourse_version = site$discourse_version)
}

# The page template is rendered first, then inserted into the base layout as {{{content}}}.
render_page <- function(templates, kind, data, layout) {
  content <- whisker::whisker.render(templates[[kind]], data)
  whisker::whisker.render(templates[["base"]], c(layout, list(content = content)))
}

# ---- checks on every page before it is written --------------------------------------------------

LOCAL_PART <- "[A-Za-z0-9._%+-]+"
PAT_EMAIL <- paste0("(?:\\G|(?<![A-Za-z0-9._%+-]))", LOCAL_PART, "@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.",
                    "(?!(?i:png|jpg|jpeg|gif|webp|svg|bmp|ico)(?![A-Za-z]))[A-Za-z]{2,}")
PAGE_RULES <- c(
  "a data-* attribute other than the Pagefind ones" = "<[^>]*\\sdata-(?!pagefind-(?:body|meta|filter)\\b)[A-Za-z0-9_.:-]+",
  "a link or image that still points at the forum host" =
    "(?i)<(?!link rel=\"canonical\")[^>]*\\s(?:href|src|srcset|poster|cite|action)\\s*=\\s*\"[^\"]*discourse\\.igelsociety\\.org",
  "a link to a user or group page" = "(?i)<a\\b[^>]*\\shref\\s*=\\s*\"/(?:u|users|groups|g)/",
  "a mailto: URL" = "(?i)<[^>]*\\s(?:href|src)\\s*=\\s*\"\\s*mailto:",
  "an avatar image" = "(?i)<img\\b[^>]*\\sclass\\s*=\\s*\"(?:[^\"]*\\s)?avatar(?:\\s[^\"]*)?\"",
  "an e-mail address" = PAT_EMAIL)

# Addresses the redaction left in place on purpose (general addresses of organisations): the redacted tree's
# own report lists them (redaction-report.json, allowlist$addresses; no key means none). check_page() ignores
# exactly these, as whole addresses in any letter case; every other address still aborts the build.
ALLOWED_ADDRESSES <- character()

allowlist_of <- function(raw) {
  entries <- read_json_file(file.path(raw, REDACTION_REPORT))[["allowlist"]][["addresses"]]
  if (is.null(entries)) return(character())
  if (!is.list(entries)) abort(REDACTION_REPORT, ": allowlist$addresses is not a list")
  addr <- vapply(entries, function(e) {
    a <- if (is.list(e)) e[["address"]]
    if (!is.character(a) || length(a) != 1L ||
        !grepl("^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$", a, perl = TRUE)) {
      abort(REDACTION_REPORT, ": an allowlist entry has no valid address")
    }
    tolower(a)
  }, "")
  if (anyDuplicated(addr)) abort(REDACTION_REPORT, ": an allowlisted address is listed twice")
  unname(addr)
}

without_allowed <- function(html) {
  for (a in ALLOWED_ADDRESSES) {
    html <- gsub(paste0("(?<![A-Za-z0-9._%+-])(?i:\\Q", a, "\\E)(?![A-Za-z0-9-]|\\.[A-Za-z0-9])"), "", html, perl = TRUE)
  }
  html
}

check_page <- function(html, where, kind) {
  for (what in names(PAGE_RULES)) {
    subject <- if (what == "an e-mail address") without_allowed(html) else html
    if (grepl(PAGE_RULES[[what]], subject, perl = TRUE)) abort("Self-check failed: ", where, " contains ", what)
  }
  if (!kind %in% SEARCH_WIDGET_KINDS && grepl("(?i)<script\\b", html, perl = TRUE)) abort("Self-check failed: ", where, " contains a <script>")
  if (grepl("(?i)<iframe\\b|<object\\b|<embed\\b|<form\\b|\\son[a-z]+\\s*=\\s*\"", html, perl = TRUE)) {
    abort("Self-check failed: ", where, " contains an iframe, object, embed, form or event handler")
  }
  invisible(TRUE)
}

# ---- site files ---------------------------------------------------------------------------------

sitemap_xml <- function(urls, date) {
  loc <- vapply(paste0(BASE_URL, urls), function(u) gsub("&", "&amp;", utils::URLencode(u), fixed = TRUE), "")
  paste0("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
         "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
         paste0("<url><loc>", loc, "</loc><lastmod>", date, "</lastmod></url>\n", collapse = ""),
         "</urlset>\n")
}

robots_txt <- function() paste0("User-agent: *\nAllow: /\n\nSitemap: ", BASE_URL, "/", SITEMAP_FILE, "\n")

# Every file of raw/assets/ (but never a .DS_Store) at the same path below the site root.
list_assets <- function(raw) {
  dir <- file.path(raw, "assets")
  if (!dir.exists(dir)) return(character())
  tree <- list_tree(dir)
  if (length(tree$other) > 0L) abort(dir, " holds entries that are not plain files: ", shown(tree$other))
  rel <- tree$files[basename(tree$files) != ".DS_Store"]
  rel[order(rel, method = "radix")]
}

copy_assets <- function(raw, tmp, rel) {
  if (length(rel) == 0L) return(invisible(0L))
  from <- file.path(raw, "assets", rel)
  to <- file.path(tmp, rel)
  fs::dir_create(unique(dirname(to)))
  if (!all(file.copy(from, to, overwrite = FALSE, copy.date = FALSE))) abort("Could not copy some assets")
  if (!identical(unname(file.size(from)), unname(file.size(to))) ||
      !identical(unname(tools::md5sum(from)), unname(tools::md5sum(to)))) {
    abort("An asset copy differs from its source")
  }
  invisible(length(rel))
}

# ---- the build report ---------------------------------------------------------------------------

no_entries <- function() stats::setNames(list(), character())   # a JSON {} rather than []

sorted_counts <- function(x) if (length(x) == 0L) no_entries() else x[order(names(x), method = "radix")]

notes_to_list <- function(store, key_name) {
  if (length(store) == 0L) return(list())
  keys <- names(store)[order(names(store), method = "radix")]
  unname(lapply(keys, function(k) stats::setNames(list(k, store[[k]]$count, store[[k]]$first_seen), c(key_name, "count", "first_seen"))))
}

# ---- run ----------------------------------------------------------------------------------------

run_build <- function(opts) {
  started <- Sys.time()
  raw <- resolve_path(opts$raw)
  out <- resolve_path(opts$out)
  say("raw=%s out=%s", raw, out)
  if (!dir.exists(raw)) abort("--raw ", opts$raw, " is not a directory")
  check_dirs(raw, out)
  manifest <- verify_redacted(raw)
  ALLOWED_ADDRESSES <<- allowlist_of(raw)
  say("%s is a redacted copy (%d redactions in %d files)", raw,
      as.integer(manifest[["redaction"]][["total_redactions"]] %||% 0L), as.integer(manifest[["redaction"]][["files_modified"]] %||% 0L))
  templates <- load_templates(opts$templates)
  if (!dir.exists(dirname(out))) abort("The parent directory of --out does not exist: ", dirname(out))
  out_state(out)

  site <- load_site(raw, manifest)
  cats <- load_categories(raw)
  topics <- load_topics(raw)
  asset_rel <- list_assets(raw)
  asset_paths <- paste0("/", asset_rel)
  warnings <- character()
  say("site '%s', Discourse %s, snapshot %s", site$title, site$discourse_version, site$snapshot_date)
  say("categories: %d (%d top-level, %d sub); topics: %d; assets: %d", length(cats),
      sum(vapply(cats, function(k) is.na(k$parent_id), NA)), sum(vapply(cats, function(k) !is.na(k$parent_id), NA)),
      length(topics), length(asset_rel))

  for (field in c("logo", "favicon", "apple_touch_icon")) {
    res <- site_asset_url(site[[paste0(field, "_raw")]], asset_paths, paste0("site-basic-info.json ", field, "_url"), warnings)
    site[[field]] <- res$url
    warnings <- res$warnings
  }

  # topic metadata the category pages and the link resolver need
  topic_ids <- vapply(topics, function(t) t$id, 1L)
  unknown_cat <- setdiff(vapply(topics, function(t) t$category_id, 1L), as.integer(names(cats)))
  if (length(unknown_cat) > 0L) abort("Topics belong to categories that are not in categories.json: ", shown(unknown_cat))
  topics <- lapply(topics, function(t) {
    t$url <- sprintf("/t/%s/%d/", t$slug, t$id)
    created <- parse_utc(t$created_at)
    active <- parse_utc(if (is.na(t$last_posted_at)) t$created_at else t$last_posted_at) %||% created
    t$created_date <- if (is.null(created)) "" else created$date
    t$activity_date <- if (is.null(active)) "" else active$date
    t$activity_epoch <- if (is.null(active)) 0 else active$epoch
    t$replies <- max(length(t$posts) - 1L, 0L)
    t
  })
  names(topics) <- as.character(topic_ids)
  counts <- category_counts(cats, topics)
  mismatch <- Filter(Negate(is.null), lapply(cats, function(k) {
    if (!is.na(k$reported_topic_count) && k$reported_topic_count != counts[[as.character(k$id)]]) {
      list(category = k$id, reported_by_categories_json = k$reported_topic_count, archived_own_topics = counts[[as.character(k$id)]])
    }
  }))
  stream_mismatch <- vapply(topics, function(t) t$stream_length != t$n_input, NA)

  ctx <- new_rewriter(
    topics = lapply(topics, function(t) list(slug = t$slug, title = t$title, posts = vapply(t$posts, function(p) p$number, 1L))),
    categories = lapply(cats, function(k) list(slug = k$slug, name = k$name, path = k$path)),
    asset_paths = asset_paths)

  tmp <- paste0(out, TMP_SUFFIX)
  aside <- paste0(out, OLD_SUFFIX)
  report_final <- file.path(dirname(out), REPORT_FILE)
  report_part <- paste0(report_final, ".part")
  clear_stale(out, tmp, aside)
  state <- out_state(out)
  fs::dir_create(tmp)
  write_text("", file.path(tmp, TMP_MARKER))
  done <- FALSE
  on.exit({ if (!done) unlink(tmp, recursive = TRUE); unlink(report_part) }, add = TRUE)

  pages <- list()
  emit <- function(url, kind, data, layout, label) {
    html <- render_page(templates, kind, data, layout)
    check_page(html, label, kind)
    write_text(html, file.path(tmp, page_file(url)))
    pages[[length(pages) + 1L]] <<- list(kind = kind, url = url)
    invisible(html)
  }
  title_of <- function(x) sprintf("%s - %s (archive)", x, site$title)

  emit("/", "home", home_data(site, cats, counts),
       layout_fields(site, "home", sprintf("%s (archive)", site$title), canonical = paste0(BASE_URL, "/"), description = site$description), "home page")

  tags_used <- list()
  posts_rendered <- 0L
  for (i in seq_along(topics)) {
    t <- topics[[i]]
    begin_page(ctx)
    numbers <- vapply(t$posts, function(p) p$number, 1L)
    views <- vector("list", length(t$posts))
    for (j in seq_along(t$posts)) {
      p <- t$posts[[j]]
      body <- rewrite_cooked(p$cooked, ctx, where = sprintf("topic %d, post %d", t$id, p$number), post_number = p$number)
      views[[j]] <- post_view(p, body, numbers)
    }
    posts_rendered <- posts_rendered + length(views)
    for (tag in t$tags) tags_used[[tag]] <- (tags_used[[tag]] %||% 0L) + 1L
    emit(t$url, "topic", topic_data(t, cats, views),
         layout_fields(site, "topic", title_of(t$title), canonical = paste0(BASE_URL, t$url)), sprintf("topic %d", t$id))
    if (i %% 50L == 0L || i == length(topics)) say("topics rendered: %d/%d", i, length(topics))
  }

  for (k in cats) {
    topics_of <- Filter(function(t) t$category_id == k$id, topics)
    emit(k$path, "category", category_data(k, cats, counts, unname(topics_of)),
         layout_fields(site, "category", title_of(k$name), canonical = paste0(BASE_URL, k$path), description = k$description),
         sprintf("category %d", k$id))
  }
  emit("/search/", "search", list(site_title = site$title), layout_fields(site, "search", title_of("Search")), "search page")
  emit("/404.html", "not_found", list(), layout_fields(site, "not-found", title_of("Page not found"), noindex = TRUE), "404 page")

  urls <- vapply(pages, function(p) p$url, "")
  kinds <- vapply(pages, function(p) p$kind, "")
  write_text(sitemap_xml(c("/", "/search/", urls[kinds == "category"], urls[kinds == "topic"]), site$snapshot_date),
             file.path(tmp, SITEMAP_FILE))
  write_text(robots_txt(), file.path(tmp, "robots.txt"))
  if (!file.copy(file.path(opts$templates, STYLESHEET), file.path(tmp, STYLESHEET), overwrite = FALSE, copy.date = FALSE)) abort("Cannot copy ", STYLESHEET)

  generated <- c(vapply(pages, function(p) page_file(p$url), ""), SITEMAP_FILE, "robots.txt", STYLESHEET)
  clash <- intersect(generated, asset_rel)
  if (length(clash) > 0L) abort("Assets would overwrite generated files: ", shown(clash))
  copy_assets(raw, tmp, asset_rel)
  say("pages: %d HTML (1 home, %d category, %d topic, search, 404); %d posts rendered; %d assets copied",
      length(pages), sum(kinds == "category"), sum(kinds == "topic"), posts_rendered, length(asset_rel))

  # the finished tree holds exactly what was generated and copied
  actual <- list_tree(tmp)
  expected <- sort(c(generated, asset_rel), method = "radix")
  if (length(actual$other) > 0L || !identical(sort(setdiff(actual$files, TMP_MARKER), method = "radix"), expected)) {
    abort("Self-check failed: the new tree does not hold exactly the generated pages and the copied assets")
  }
  n_articles <- 0L
  for (p in pages[kinds == "topic"]) {
    html <- read_text(file.path(tmp, page_file(p$url)))
    n_articles <- n_articles + sum(gregexpr("<article class=\"post\" id=\"post-", html, fixed = TRUE)[[1]] > 0L)
  }
  if (n_articles != posts_rendered) abort("Self-check failed: ", n_articles, " post articles written for ", posts_rendered, " posts")
  say("self-checks passed")

  # ---- the report
  n_in <- sum(vapply(topics, function(t) t$n_input, 1L))
  skipped <- c(system_events = sum(vapply(topics, function(t) t$n_system, 1L)),
               hidden_or_deleted = sum(vapply(topics, function(t) t$n_hidden, 1L)),
               other_post_types = sum(vapply(topics, function(t) t$n_other, 1L)))
  ext <- ctx$external_images
  ext <- ext[!duplicated(vapply(ext, function(e) paste(e$source, e$url, sep = "\r"), ""))]
  host_counts <- table(vapply(ext, function(e) e$host, ""))
  report <- list(
    snapshot = list(harvested_at_utc = site$harvested_at, snapshot_date = site$snapshot_date,
                    discourse_version = site$discourse_version, site_title = site$title),
    pages = list(home = 1L, category = sum(kinds == "category"), topic = sum(kinds == "topic"), search = 1L,
                 not_found = 1L, html_total = length(pages), other_files = as.list(c(SITEMAP_FILE, "robots.txt", STYLESHEET)),
                 assets_copied = length(asset_rel)),
    posts = list(in_input = n_in, rendered = posts_rendered, skipped_system_events = skipped[["system_events"]],
                 skipped_hidden_or_deleted = skipped[["hidden_or_deleted"]], skipped_other_post_types = skipped[["other_post_types"]]),
    topics = list(total = length(topics), with_tags = sum(vapply(topics, function(t) length(t$tags) > 0L, NA)),
                  pinned = sum(vapply(topics, function(t) t$pinned, NA)), closed = sum(vapply(topics, function(t) t$closed, NA)),
                  archived = sum(vapply(topics, function(t) t$archived, NA)),
                  without_last_posted_at = sum(vapply(topics, function(t) is.na(t$last_posted_at), NA)),
                  stream_length_differs_from_posts = sum(stream_mismatch)),
    categories = list(total = length(cats), top_level = sum(vapply(cats, function(k) is.na(k$parent_id), NA)),
                      sub = sum(vapply(cats, function(k) !is.na(k$parent_id), NA)),
                      topic_count_differs_from_categories_json = unname(mismatch)),
    tags = list(distinct = length(tags_used), assignments = sum(unlist(tags_used)), usage = sorted_counts(tags_used)),
    rewrites = c(ctx$counts, list(elements_dropped = sorted_counts(ctx$groups$elements_dropped),
                                  attributes_dropped_not_on_allow_list = sorted_counts(ctx$groups$attributes_dropped))),
    unresolved_internal_links = unname(ctx$unresolved),
    external_images = list(count = length(ext), hosts = sorted_counts(as.list(stats::setNames(as.integer(host_counts), names(host_counts)))),
                           list = unname(ext)),
    missing_assets = notes_to_list(ctx$missing_assets, "path"),
    unknown_elements = notes_to_list(ctx$unknown_elements, "element"),
    unknown_classes = notes_to_list(ctx$unknown_classes, "element_class"),
    warnings = as.list(warnings))
  if (posts_rendered + sum(skipped) != n_in) {
    abort("Self-check failed: ", posts_rendered, " rendered + ", sum(skipped), " skipped posts are not the ", n_in, " posts in the input")
  }
  write_text(to_json(report), report_part)

  if (out_state(out) != state) abort("--out changed while the site was being built; nothing was replaced")
  file.remove(file.path(tmp, TMP_MARKER))
  swap_in(tmp, out, aside)
  done <- TRUE
  if (!file.rename(report_part, report_final)) abort("The site is in place, but ", report_part, " could not be renamed to ", report_final)
  say("wrote %s and %s", out, report_final)
  say("report: %d posts rendered, %d skipped; %d internal links to review, %d external images, %d unknown elements, %d unknown classes",
      posts_rendered, sum(skipped), length(ctx$unresolved), length(ext), length(ctx$unknown_elements), length(ctx$unknown_classes))
  for (w in warnings) say("WARNING: %s", w)
  if (length(ctx$missing_assets) > 0L) {
    say("WARNING: %d files that posts link to are not among the harvested assets and will be broken on the site (see missing_assets in %s): %s",
        length(ctx$missing_assets), REPORT_FILE, shown(names(ctx$missing_assets), 3L))
  }
  say("DONE in %.0f s", as.numeric(difftime(Sys.time(), started, units = "secs")))
  invisible(report)
}

main <- function(argv = commandArgs(trailingOnly = TRUE)) {
  ok <- tryCatch({
    run_build(parse_args(argv))
    TRUE
  }, build_abort = function(e) {
    message("\nBUILD ABORTED: ", conditionMessage(e))
    FALSE
  }, error = function(e) {
    message("\nBUILD FAILED (unexpected error): ", conditionMessage(e))
    FALSE
  })
  if (!ok) quit(save = "no", status = 1L)
}

if (sys.nframe() == 0L) main()
