#!/usr/bin/env Rscript
# Phase 1 (Harvest): copy the public content of https://discourse.igelsociety.org into raw_verbatim/
# (byte-exact and unredacted, never committed; R/01b_redact.R derives the committed raw/ from it).
#
#   Rscript R/01_harvest.R [--force] [--out DIR] [--limit-topics N]
#
# Stored under --out (default "raw_verbatim"):
#   site.json, about.json, site-basic-info.json, categories.json   verbatim API responses
#   category/{id}-p{N}.json     paginated topic listing of every category (last page is empty)
#   topic/{id}.json             /t/{id}.json
#   topic/{id}-posts-{k}.json   /t/{id}/posts.json chunks for the posts beyond the first ~20
#   assets/<url path>           every same-host file referenced from post bodies, plus logos
#   assets-report.json          downloaded / missing / unclassified, and where each asset is used
#   manifest.json               written last, only if all checks passed; SHA-256 of every file
#
# Ground rules: read-only GET requests, anonymous (no credentials of any kind), ~0.7 s between
# requests, no half-written files (<file>.part is validated, then renamed), and a file that
# already exists is skipped (but still read) unless --force.

BASE_URL   <- "https://discourse.igelsociety.org"
USER_AGENT <- "IGEL-discourse-archive/1.0 (read-only archival crawl of discourse.igelsociety.org)"

PAUSE_SECS    <- 0.7    # between EVERY request, JSON and assets alike
CHUNK_SIZE    <- 20L    # post ids per /t/{id}/posts.json call
MAX_PAGES     <- 200L   # runaway guard for category listings
MAX_REDIRECTS <- 5L
BACKOFF_START <- 10     # seconds; doubles after every failed attempt ...
BACKOFF_CAP   <- 120    # ... up to this
HINT_CAP      <- 600    # longest server-requested wait (Retry-After, wait_seconds) we will honour
MAX_TRIES     <- c(rate_limit = 6L, server = 4L)

ASSET_DIRS <- c("uploads", "user_avatar", "letter_avatar_proxy", "images", "plugins", "assets",
                "secure-uploads")
PAGE_DIRS  <- c("t", "u", "c", "tag", "g", "latest", "categories", "top", "search", "about")
BINARY_EXT <- c("png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tif", "tiff", "svg", "pdf",
                "zip", "gz", "tgz", "tar", "7z", "rar", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
                "odt", "ods", "odp", "key", "pages", "numbers", "mp3", "m4a", "wav", "ogg", "mp4",
                "m4v", "mov", "avi", "webm", "epub", "mobi")

# Same-host references in raw HTML: absolute URLs, protocol-relative "//host/..." URLs (some posts
# link their uploads that way; the lookbehind keeps "https://other.org//host/..." from matching), or
# root-relative paths that start right after a delimiter (so the "/uploads/x" inside
# "https://other.org/uploads/x" is not picked up). They end at whitespace, a quote, < > or ")".
SAME_HOST_RE <- paste0(
  "(?i:(?:https?://|(?<![A-Za-z0-9:/.-])//)discourse\\.igelsociety\\.org)/[^\\s\"'<>)]*",
  "|(?:^|(?<=[\\s\"'(>,]))/(?![/\\s\"'<>)])[^\\s\"'<>)]*"
)

USAGE <- "Usage: Rscript R/01_harvest.R [--force] [--out DIR] [--limit-topics N]
  --force           re-download files that already exist
  --out DIR         output directory (default: raw_verbatim)
  --limit-topics N  enumerate everything, but fetch only the first N topic ids (ascending)"

# ---- helpers -----------------------------------------------------------------------------------
# Parsed JSON is always read with [[ ]]: `$` partial-matches, so x$subcategory_list would silently
# return x$subcategory_list_style on categories without children.

`%||%` <- function(x, y) if (is.null(x)) y else x

say <- function(fmt, ...) message("[harvest] ", if (...length() > 0) sprintf(fmt, ...) else fmt)

abort <- function(...) {
  stop(structure(class = c("harvest_abort", "error", "condition"),
                 list(message = paste0(...), call = NULL)))
}

parse_args <- function(argv) {
  opts <- list(force = FALSE, out = "raw_verbatim", limit = NA_integer_)
  i <- 1L
  value_of <- function(flag) {
    if (i >= length(argv)) abort(flag, " needs a value\n", USAGE)
    argv[i + 1L]
  }
  while (i <= length(argv)) {
    a <- argv[i]
    if (a == "--force") {
      opts$force <- TRUE
    } else if (a == "--out") {
      opts$out <- value_of(a)
      i <- i + 1L
    } else if (startsWith(a, "--out=")) {
      opts$out <- sub("^--out=", "", a)
    } else if (a == "--limit-topics" || startsWith(a, "--limit-topics=")) {
      v <- if (a == "--limit-topics") { i <- i + 1L; argv[i] } else sub("^--limit-topics=", "", a)
      n <- suppressWarnings(as.integer(v))
      if (is.na(n) || n < 1L) abort("--limit-topics needs a positive integer, got '", v, "'")
      opts$limit <- n
    } else if (a %in% c("-h", "--help")) {
      cat(USAGE, "\n")
      quit(save = "no", status = 0L)
    } else {
      abort("Unknown argument: ", a, "\n", USAGE)
    }
    i <- i + 1L
  }
  if (!nzchar(opts$out)) abort("--out must not be empty")
  opts
}

# ---- HTTP: throttle, redirects (same host only), retry/backoff ---------------------------------

# ctx holds the run state. http and sleep are injectable so the logic can be tested offline.
new_ctx <- function(out, force = FALSE, http = http_once, sleep = Sys.sleep, now = Sys.time) {
  ctx <- new.env(parent = emptyenv())
  ctx$out <- out
  ctx$force <- force
  ctx$http <- http                # function(url, dest) -> list(status, content_type, ...)
  ctx$sleep <- sleep
  ctx$now <- now
  ctx$n_requests <- 0L
  ctx$last_request_end <- NULL
  ctx$used <- character()         # files (relative to out) read or written by this run
  ctx
}

# One HTTP exchange, no redirects, body streamed to dest. Never throws for HTTP errors; transport
# failures come back as status NA. Only the User-Agent header is set: no credentials, no cookies.
http_once <- function(url, dest) {
  req <- httr2::request(url) |>
    httr2::req_user_agent(USER_AGENT) |>
    httr2::req_timeout(300) |>
    httr2::req_options(followlocation = FALSE, connecttimeout = 30) |>
    httr2::req_error(is_error = function(resp) FALSE)
  resp <- tryCatch(httr2::req_perform(req, path = dest), error = function(e) e)
  if (inherits(resp, "error")) {
    return(list(status = NA_integer_, error = conditionMessage(resp)))
  }
  list(
    status = httr2::resp_status(resp),
    content_type = httr2::resp_header(resp, "content-type"),
    content_disposition = httr2::resp_header(resp, "content-disposition"),
    location = httr2::resp_header(resp, "location"),
    retry_after = tryCatch(httr2::resp_retry_after(resp), error = function(e) NA_real_)
  )
}

# The only place a request is counted and paced.
do_request <- function(ctx, url, dest) {
  if (!is.null(ctx$last_request_end)) {
    idle <- as.numeric(difftime(ctx$now(), ctx$last_request_end, units = "secs"))
    if (idle < PAUSE_SECS) ctx$sleep(PAUSE_SECS - idle)
  }
  ctx$n_requests <- ctx$n_requests + 1L
  res <- ctx$http(url, dest)
  ctx$last_request_end <- ctx$now()
  res
}

same_host_redirect <- function(location) {
  if (is.null(location) || is.na(location)) return(NULL)
  if (grepl("^/($|[^/])", location)) return(paste0(BASE_URL, location))
  if (grepl("^https://discourse\\.igelsociety\\.org(/|$)", location, ignore.case = TRUE)) return(location)
  NULL
}

# Follows redirects only within BASE_URL; a redirect elsewhere is returned as the (non-200) result.
send <- function(ctx, url, dest) {
  for (hop in seq_len(MAX_REDIRECTS + 1L)) {
    res <- do_request(ctx, url, dest)
    status <- res[["status"]]
    if (is.na(status) || !status %in% c(301L, 302L, 303L, 307L, 308L)) return(res)
    target <- same_host_redirect(res[["location"]])
    if (is.null(target)) {
      res[["error"]] <- paste("refusing redirect to", res[["location"]] %||% "(no Location header)")
      return(res)
    }
    url <- target
  }
  res[["error"]] <- "too many redirects"
  res
}

# Seconds the server asked us to wait: Retry-After header or Discourse's extras.wait_seconds.
wait_hint <- function(res, body_path) {
  hint <- res[["retry_after"]] %||% NA_real_
  hint <- if (is.finite(hint)) hint else 0
  if (file.exists(body_path) && file.size(body_path) < 1e5) {
    body <- tryCatch(jsonlite::read_json(body_path), error = function(e) NULL)
    w <- body[["extras"]][["wait_seconds"]]
    if (is.numeric(w) && length(w) == 1L && is.finite(w)) hint <- max(hint, w)
  }
  max(hint, 0)
}

# GET url into dest via dest.part. 429 / 5xx / network errors are retried with exponential backoff
# (10 s, 20 s, ... capped at 120 s, or the server's own hint if larger) and then abort the run.
# Any other status is returned to the caller (nothing is written); on 200 the validated file is
# renamed into place.
fetch_file <- function(ctx, url, dest, validate = NULL) {
  part <- paste0(dest, ".part")
  dir.create(dirname(dest), recursive = TRUE, showWarnings = FALSE)
  attempt <- 0L
  repeat {
    attempt <- attempt + 1L
    res <- send(ctx, url, part)
    status <- res[["status"]]
    if (!(is.na(status) || status == 429L || status >= 500L)) break
    hint <- wait_hint(res, part)
    unlink(part)
    max_tries <- if (!is.na(status) && status == 429L) MAX_TRIES[["rate_limit"]] else MAX_TRIES[["server"]]
    what <- if (is.na(status)) paste("network error:", res[["error"]]) else paste("HTTP", status)
    if (attempt >= max_tries) {
      abort("GET ", url, " failed after ", attempt, " attempts (last: ", what,
            "). Stopping; nothing partial was written, re-run to resume.")
    }
    wait <- max(min(BACKOFF_START * 2^(attempt - 1L), BACKOFF_CAP), min(hint, HINT_CAP))
    say("%s for %s; attempt %d/%d, waiting %.0f s", what, url, attempt, max_tries, wait)
    ctx$sleep(wait)
  }
  if (status == 200L) {
    problem <- if (is.null(validate)) NULL else validate(part)
    if (!is.null(problem)) {
      unlink(part)
      abort("GET ", url, " returned 200 but the body is unusable: ", problem)
    }
    if (!file.rename(part, dest)) abort("Cannot move ", part, " to ", dest)
  } else {
    unlink(part)
  }
  res
}

# ---- JSON files --------------------------------------------------------------------------------

out_file <- function(ctx, rel) file.path(ctx$out, rel)
mark_used <- function(ctx, rel) ctx$used <- c(ctx$used, rel)

read_json_file <- function(path) {
  tryCatch(jsonlite::read_json(path, simplifyVector = FALSE),
           error = function(e) abort("Cannot parse JSON file ", path, ": ", conditionMessage(e)))
}

json_problem <- function(path) {
  tryCatch({ jsonlite::read_json(path); NULL }, error = function(e) conditionMessage(e))
}

# Stores the response bytes verbatim (never re-serialised). Existing files are read, not fetched.
get_json <- function(ctx, url_path, rel) {
  dest <- out_file(ctx, rel)
  mark_used(ctx, rel)
  if (file.exists(dest) && !ctx$force) return(read_json_file(dest))
  res <- fetch_file(ctx, paste0(BASE_URL, url_path), dest, validate = json_problem)
  if (res[["status"]] != 200L) {
    abort("GET ", url_path, " returned HTTP ", res[["status"]], " (expected 200)",
          if (!is.null(res[["error"]])) paste0(": ", res[["error"]]) else "", ". Not archiving it.")
  }
  read_json_file(dest)
}

# Our own outputs (report, manifest): same .part-then-rename discipline.
write_json_atomic <- function(x, dest) {
  part <- paste0(dest, ".part")
  jsonlite::write_json(x, part, auto_unbox = TRUE, pretty = TRUE, null = "null", na = "null",
                       digits = NA)
  if (!file.rename(part, dest)) abort("Cannot move ", part, " to ", dest)
}

file_info <- function(path) {
  list(sha256 = digest::digest(file = path, algo = "sha256"), bytes = file.size(path))
}

# ---- categories and topic enumeration ----------------------------------------------------------

# Flattens the nested categories.json into one record per category (parents and children).
# `path` is the slug path used in listing URLs: "announcements" or "announcements/events".
flatten_categories <- function(categories_json) {
  rows <- list()
  url_of <- function(upload) {
    if (is.list(upload)) upload[["url"]] else if (is.character(upload)) upload else NULL
  }
  # "/t/about-the-igel-2025-category/704" -> 704: the category's own "About" topic
  about_topic_of <- function(topic_url) {
    m <- regmatches(topic_url, regexec("^/t/[^/]+/([0-9]+)", topic_url))[[1]]
    if (length(m) == 2L) as.integer(m[2]) else NA_integer_
  }
  visit <- function(node, parent_id, parent_path) {
    path <- c(parent_path, node[["slug"]])
    rows[[length(rows) + 1L]] <<- list(
      id = as.integer(node[["id"]]),
      slug = node[["slug"]],
      parent_id = parent_id,
      path = paste(path, collapse = "/"),
      topic_count = as.integer(node[["topic_count"]] %||% NA_integer_),
      about_topic_id = if (is.character(node[["topic_url"]])) about_topic_of(node[["topic_url"]]) else NA_integer_,
      logo_url = url_of(node[["uploaded_logo"]]),
      background_url = url_of(node[["uploaded_background"]])
    )
    for (child in node[["subcategory_list"]]) visit(child, as.integer(node[["id"]]), path)
  }
  top <- categories_json[["category_list"]][["categories"]]
  if (!is.list(top) || length(top) == 0L) abort("categories.json has no category_list$categories")
  for (node in top) visit(node, NA_integer_, character())
  ids <- purrr::map_int(rows, function(r) r$id)
  if (anyDuplicated(ids)) {
    say("WARNING: categories.json lists some category ids twice; keeping the first of each")
    rows <- rows[!duplicated(ids)]
  }
  rows
}

# Pages every category listing (a parent's listing also contains its children's topics) until an
# empty page, which is stored too so a re-run can tell the enumeration ended without any request.
# Returns one row per unique topic id.
enumerate_topics <- function(ctx, cats) {
  rows <- list()
  n_pages <- 0L
  for (category in cats) {
    before <- length(rows)
    page <- 0L
    repeat {
      x <- get_json(ctx,
                    sprintf("/c/%s/%d.json?page=%d", category$path, category$id, page),
                    sprintf("category/%d-p%d.json", category$id, page))
      topics <- x[["topic_list"]][["topics"]]
      if (!is.list(topics)) abort("Listing of category ", category$id, " page ", page, " has no topic_list$topics")
      n_pages <- n_pages + 1L
      if (length(topics) == 0L) break
      rows <- c(rows, lapply(topics, function(t) list(
        topic_id = as.integer(t[["id"]]),
        category_id = as.integer(t[["category_id"]] %||% NA_integer_),
        posts_count = as.integer(t[["posts_count"]] %||% NA_integer_)
      )))
      page <- page + 1L
      if (page >= MAX_PAGES) abort("Category ", category$id, " listing did not end after ", MAX_PAGES, " pages")
    }
    say("category %s (id %d): %d listed topics", category$path, category$id, length(rows) - before)
  }
  listed <- data.frame(
    topic_id = purrr::map_int(rows, function(r) r$topic_id),
    category_id = purrr::map_int(rows, function(r) r$category_id),
    posts_count = purrr::map_int(rows, function(r) r$posts_count)
  )
  listed <- listed[!duplicated(listed$topic_id), ]
  say("listings: %d pages, %d unique topics", n_pages, nrow(listed))
  listed
}

# ---- topics and their posts --------------------------------------------------------------------

check_topic_shape <- function(topic, id) {
  ps <- topic[["post_stream"]]
  problems <- character()
  if (!identical(as.integer(topic[["id"]] %||% NA), as.integer(id))) problems <- c(problems, "id does not match")
  if (!is.character(topic[["slug"]])) problems <- c(problems, "no slug")
  if (!is.character(topic[["title"]])) problems <- c(problems, "no title")
  if (!is.numeric(topic[["category_id"]])) problems <- c(problems, "no category_id")
  if (!is.list(ps[["stream"]]) || length(ps[["stream"]]) == 0L) problems <- c(problems, "no post_stream$stream")
  if (!is.list(ps[["posts"]])) problems <- c(problems, "no post_stream$posts")
  if (length(problems) == 0L) {
    ok <- vapply(ps[["posts"]], function(p) {
      is.numeric(p[["id"]]) && is.numeric(p[["post_number"]]) && is.character(p[["cooked"]])
    }, logical(1))
    if (!all(ok)) problems <- c(problems, "a post lacks id, post_number or cooked")
  }
  if (length(problems) > 0L) {
    abort("Topic ", id, " does not have the expected JSON shape (", paste(problems, collapse = "; "),
          "). Discourse 2.8.0.beta11 was assumed; inspect raw/topic/", id, ".json.")
  }
}

# Stream ids that are not among the posts already present, in stream order, in chunks of `size`.
leftover_chunks <- function(stream, present, size = CHUNK_SIZE) {
  left <- stream[!stream %in% present]
  if (length(left) == 0L) return(list())
  unname(split(left, ceiling(seq_along(left) / size)))
}

assert_topic_complete <- function(id, stream, collected) {
  missing <- setdiff(stream, collected)
  extra <- setdiff(collected, stream)
  dupes <- unique(collected[duplicated(collected)])
  if (length(missing) > 0L || length(extra) > 0L || length(dupes) > 0L) {
    show <- function(x) if (length(x) == 0L) "none" else paste(utils::head(x, 10L), collapse = ", ")
    abort("Topic ", id, " is incomplete: stream lists ", length(stream), " post ids, collected ",
          length(collected), " (missing: ", show(missing), "; unexpected: ", show(extra),
          "; duplicated: ", show(dupes), "). If raw/topic files are stale, re-run with --force.")
  }
}

# fetch_chunk(k, ids) must return the list of post objects for those ids.
collect_topic_posts <- function(id, topic, fetch_chunk, size = CHUNK_SIZE) {
  stream <- purrr::map_int(topic[["post_stream"]][["stream"]], as.integer)
  posts <- topic[["post_stream"]][["posts"]]
  present <- purrr::map_int(posts, function(p) as.integer(p[["id"]]))
  chunks <- leftover_chunks(stream, present, size)
  for (k in seq_along(chunks)) posts <- c(posts, fetch_chunk(k, chunks[[k]]))
  assert_topic_complete(id, stream, purrr::map_int(posts, function(p) as.integer(p[["id"]])))
  posts
}

harvest_topic <- function(ctx, id) {
  topic <- get_json(ctx, sprintf("/t/%d.json", id), sprintf("topic/%d.json", id))
  check_topic_shape(topic, id)
  fetch_chunk <- function(k, ids) {
    query <- paste0("post_ids[]=", ids, collapse = "&")
    x <- get_json(ctx, sprintf("/t/%d/posts.json?%s", id, query), sprintf("topic/%d-posts-%d.json", id, k))
    posts <- x[["post_stream"]][["posts"]]
    if (!is.list(posts)) abort("Topic ", id, ": posts.json chunk ", k, " has no post_stream$posts")
    posts
  }
  posts <- collect_topic_posts(id, topic, fetch_chunk)
  wrong <- purrr::map_lgl(posts, function(p) !is.null(p[["topic_id"]]) && p[["topic_id"]] != id)
  if (any(wrong)) abort("Topic ", id, ": a collected post belongs to a different topic")
  posts_df <- data.frame(
    post_id = purrr::map_int(posts, function(p) as.integer(p[["id"]])),
    post_number = purrr::map_int(posts, function(p) as.integer(p[["post_number"]])),
    cooked = purrr::map_chr(posts, function(p) p[["cooked"]])
  )
  list(id = id, slug = topic[["slug"]], category_id = as.integer(topic[["category_id"]]),
       posts = posts_df[order(posts_df$post_number), ])
}

harvest_topics <- function(ctx, ids) {
  topics <- vector("list", length(ids))
  from_disk <- 0L
  for (i in seq_along(ids)) {
    before <- ctx$n_requests
    topics[[i]] <- harvest_topic(ctx, ids[i])
    if (ctx$n_requests > before) {
      say("topic %d (%d/%d): %d posts, %d requests", ids[i], i, length(ids),
          nrow(topics[[i]]$posts), ctx$n_requests - before)
    } else {
      from_disk <- from_disk + 1L
    }
  }
  say("topics: %d complete (%d read from disk)", length(ids), from_disk)
  topics
}

# ---- assets: discovery -------------------------------------------------------------------------

extract_same_host_urls <- function(html) {
  if (!is.character(html) || length(html) != 1L || is.na(html)) return(character())
  hits <- regmatches(html, gregexpr(SAME_HOST_RE, html, perl = TRUE))[[1]]
  hits <- sub(",+$", "", hits)                 # srcset lists: "url, url 1.5x, url 2x"
  gsub("&amp;", "&", hits, fixed = TRUE)
}

url_decode <- function(x) {
  x <- gsub("%(?![0-9A-Fa-f]{2})", "%25", x, perl = TRUE)   # a lone % is just a percent sign
  if (grepl("%00", x, fixed = TRUE)) return(NA_character_)
  out <- utils::URLdecode(x)
  Encoding(out) <- "UTF-8"
  if (validUTF8(out)) out else NA_character_
}

# Decoded asset path without leading slash, or NA if it could escape the assets directory.
safe_rel_path <- function(path) {
  if (is.na(path)) return(NA_character_)
  segs <- strsplit(path, "/", fixed = TRUE)[[1]]
  segs <- segs[!segs %in% c("", ".")]
  bad <- length(segs) == 0L ||
    any(segs == "..") ||
    any(nchar(segs, "bytes") > 255L) ||
    any(grepl("[\\x00-\\x1f\\x7f\\\\]", segs, perl = TRUE)) ||
    (!l10n_info()[["UTF-8"]] && any(grepl("[^\\x20-\\x7e]", segs, perl = TRUE)))
  if (bad) NA_character_ else paste(segs, collapse = "/")
}

# kind: "asset" (download), "page" (a forum page link, ignored) or "unclassified".
# url is what gets requested (query as written, fragment dropped); key is the dedupe key.
classify_url <- function(raw) {
  rel <- sub("^(?i:(?:https?:)?//discourse\\.igelsociety\\.org)", "", raw, perl = TRUE)
  rel <- sub("#.*$", "", rel)
  path_enc <- sub("\\?.*$", "", rel)
  first <- strsplit(path_enc, "/", fixed = TRUE)[[1]][2]
  path <- url_decode(path_enc)
  kind <- if (is.na(first) || first == "" || first %in% PAGE_DIRS) "page" else
    if (first %in% ASSET_DIRS && !endsWith(path_enc, "/")) "asset" else "unclassified"
  safe <- if (kind == "asset") safe_rel_path(path) else NA_character_
  list(kind = kind, url = paste0(BASE_URL, rel),
       key = if (!is.na(safe)) paste0("/", safe) else if (!is.na(path)) path else path_enc,
       rel = safe, refused = kind == "asset" && is.na(safe))
}

# URLs that must be fetched although no post mentions them: site logo/icons and category images.
site_refs <- function(meta, cats) {
  ref <- character()
  raw <- character()
  warns <- character()
  add <- function(label, url) {
    if (!is.character(url) || length(url) != 1L || is.na(url) || !nzchar(url)) return()
    hits <- extract_same_host_urls(url)
    if (length(hits) == 0L) {
      warns <<- c(warns, sprintf("%s points off-host and is not downloaded: %s", label, url))
    } else {
      ref <<- c(ref, label)
      raw <<- c(raw, hits[1])
    }
  }
  basic <- meta$basic
  for (field in grep("_url$", names(basic), value = TRUE)) add(paste0("site-basic-info/", field), basic[[field]])
  for (category in cats) {
    add(sprintf("category/%d/uploaded_logo", category$id), category$logo_url)
    add(sprintf("category/%d/uploaded_background", category$id), category$background_url)
  }
  list(refs = data.frame(ref = ref, raw = raw), warnings = warns)
}

post_refs <- function(topics) {
  parts <- lapply(topics, function(t) {
    urls <- lapply(t$posts$cooked, extract_same_host_urls)
    data.frame(ref = rep(paste0(t$id, "/", t$posts$post_number), lengths(urls)),
               raw = as.character(unlist(urls)))
  })
  do.call(rbind, parts)
}

# Groups every reference by path. Returns the assets to download plus what was set aside.
discover_assets <- function(topics, meta, cats) {
  site <- site_refs(meta, cats)
  refs <- rbind(site$refs, post_refs(topics))
  warns <- site$warnings
  uniq <- unique(refs$raw)
  info <- stats::setNames(lapply(uniq, classify_url), uniq)
  of_ref <- info[refs$raw]                       # one classification per reference, same order
  kind <- vapply(of_ref, function(i) i$kind, "")
  key <- vapply(of_ref, function(i) i$key, "")
  refused <- vapply(of_ref, function(i) i$refused, NA)

  summarise <- function(k) {
    idx <- which(key == k)
    all_refs <- unique(refs$ref[idx])
    list(path = k, url = of_ref[[idx[1]]]$url, rel = of_ref[[idx[1]]]$rel,
         n_refs = length(all_refs), example_refs = utils::head(all_refs, 5L))
  }
  paths <- function(selected) sort(unique(key[selected]), method = "radix")

  asset_paths <- paths(kind == "asset" & !refused)
  assets <- lapply(asset_paths, summarise)
  unclassified <- lapply(paths(kind == "unclassified"), summarise)
  for (k in paths(refused)) warns <- c(warns, paste("refused unsafe asset path:", k))

  # APFS/HFS+ are case-insensitive: two paths differing only by case would overwrite each other.
  lower <- tolower(asset_paths)
  for (k in asset_paths[lower %in% lower[duplicated(lower)]]) {
    warns <- c(warns, paste("path collides case-insensitively with another asset:", k))
  }
  say("references: %d asset paths (%d refs), %d unclassified paths, %d page links ignored",
      length(assets), sum(kind == "asset"), length(unclassified), sum(kind == "page"))
  list(assets = assets, unclassified = unclassified, warnings = warns)
}

# ---- assets: download and report ---------------------------------------------------------------

chr_or_na <- function(x) if (is.null(x) || length(x) == 0L || is.na(x)) NA_character_ else as.character(x)
clean_utf8 <- function(x) if (is.na(x)) x else iconv(x, "UTF-8", "UTF-8", sub = "byte")

asset_entry <- function(a, status, info = NULL, content_type = NULL, content_disposition = NULL, note = NA) {
  list(path = a$path, url = a$url, status = status,
       bytes = if (is.null(info)) NA else info$bytes,
       sha256 = if (is.null(info)) NA_character_ else info$sha256,
       content_type = clean_utf8(chr_or_na(content_type)),
       content_disposition = clean_utf8(chr_or_na(content_disposition)),
       note = note, n_refs = a$n_refs, example_refs = as.list(a$example_refs))
}

entry_warnings <- function(e) {
  w <- character()
  if (identical(e$status, 200L)) {
    ext <- tolower(tools::file_ext(e$path))
    if (grepl("^text/html", e$content_type %||% "", ignore.case = TRUE) && ext %in% BINARY_EXT) {
      w <- c(w, sprintf("served as text/html although the path ends in .%s: %s (likely an error page)", ext, e$path))
    }
    if (isTRUE(e$bytes == 0)) w <- c(w, paste("empty file:", e$path))
  }
  w
}

# Response headers are not stored next to the asset, so a resumed run takes them from the previous
# assets-report.json, trusting an entry only if its SHA-256 still matches the file on disk.
load_journal <- function(ctx) {
  path <- out_file(ctx, "assets-report.json")
  prev <- if (file.exists(path)) tryCatch(jsonlite::read_json(path), error = function(e) NULL)
  journal <- list()
  for (e in prev[["assets"]]) {
    if (identical(as.integer(e[["status"]]), 200L) && is.character(e[["path"]])) journal[[e[["path"]]]] <- e
  }
  journal
}

harvest_assets <- function(ctx, topics, meta, cats) {
  found <- discover_assets(topics, meta, cats)
  journal <- if (ctx$force) list() else load_journal(ctx)
  entries <- list()                              # named by asset path
  unknown_headers <- 0L

  write_report <- function(complete) {
    sorted <- unname(entries[order(names(entries), method = "radix")])
    gone <- Filter(function(e) !identical(e$status, 200L), sorted)
    warns <- c(found$warnings, unlist(lapply(sorted, entry_warnings)))
    if (unknown_headers > 0L) {
      warns <- c(warns, sprintf("%d assets were already on disk without recorded response headers (content_type and content_disposition unknown); re-run with --force to record them", unknown_headers))
    }
    unclassified <- lapply(found$unclassified, function(u) {
      u$example_refs <- as.list(u$example_refs)
      u[c("path", "url", "n_refs", "example_refs")]
    })
    write_json_atomic(list(
      complete = complete,
      counts = list(assets = length(sorted), ok = length(sorted) - length(gone),
                    missing = length(gone), unclassified = length(unclassified)),
      assets = sorted,
      missing = gone,
      unclassified = unclassified,
      warnings = as.list(warns)
    ), out_file(ctx, "assets-report.json"))
    mark_used(ctx, "assets-report.json")
    warns
  }
  complete <- FALSE
  on.exit(if (!complete) write_report(FALSE), add = TRUE)

  # Pass 1 reuses files already on disk (no network); pass 2 downloads the rest. Doing it in this
  # order means every interim flush of the report already carries all known response headers.
  todo <- list()
  for (a in found$assets) {
    rel <- file.path("assets", a$rel)
    mark_used(ctx, rel)
    dest <- out_file(ctx, rel)
    if (file.exists(dest) && !ctx$force) {
      info <- file_info(dest)
      prev <- journal[[a$path]]
      trusted <- !is.null(prev) && identical(prev[["sha256"]], info$sha256)
      if (!trusted) unknown_headers <- unknown_headers + 1L
      entries[[a$path]] <- asset_entry(a, 200L, info,
                                       if (trusted) prev[["content_type"]],
                                       if (trusted) prev[["content_disposition"]])
    } else {
      todo[[length(todo) + 1L]] <- a
    }
  }
  say("assets: %d already on disk, %d to download", length(entries), length(todo))

  for (j in seq_along(todo)) {
    a <- todo[[j]]
    dest <- out_file(ctx, file.path("assets", a$rel))
    res <- fetch_file(ctx, a$url, dest)
    if (res[["status"]] == 200L) {
      info <- file_info(dest)
      entries[[a$path]] <- asset_entry(a, 200L, info, res[["content_type"]], res[["content_disposition"]])
      say("asset %d/%d: 200, %s bytes, %s", j, length(todo), format(info$bytes, big.mark = ","), a$path)
    } else {
      note <- res[["error"]] %||% NA_character_
      if (file.exists(dest)) {
        note <- paste0(if (is.na(note)) "" else paste0(note, "; "), "an older copy from an earlier run is still on disk")
      }
      entries[[a$path]] <- asset_entry(a, as.integer(res[["status"]]), note = note)
      say("asset %d/%d: MISSING (HTTP %s) %s (used in: %s)", j, length(todo), res[["status"]], a$path,
          paste(a$example_refs, collapse = ", "))
    }
    if (j %% 25L == 0L) write_report(FALSE)
  }
  complete <- TRUE
  warns <- write_report(TRUE)
  ok <- sum(vapply(entries, function(e) identical(e$status, 200L), NA))
  say("assets: %d ok, %d missing, %d unclassified paths, %d report warnings",
      ok, length(entries) - ok, length(found$unclassified), length(warns))
  list(ok = ok, missing = length(entries) - ok, warnings = warns)
}

# ---- checks, reconciliation, manifest ----------------------------------------------------------

# Info only: private categories legitimately make the site-wide numbers differ, so nothing here fails.
reconcile <- function(listed, topics, cats, about_stats, limit) {
  warns <- character()
  note <- function(msg) warns <<- c(warns, msg)
  enumerated <- nrow(listed)
  posts <- sum(vapply(topics, function(t) nrow(t$posts), integer(1)))
  about_topics <- about_stats[["topic_count"]]
  about_posts <- about_stats[["post_count"]]
  if (!is.null(about_topics) && enumerated != about_topics) {
    note(sprintf("enumerated %d topics but about.json reports topic_count %d", enumerated, about_topics))
  }
  if (is.na(limit) && !is.null(about_posts) && posts != about_posts) {
    note(sprintf("collected %d posts but about.json reports post_count %d", posts, about_posts))
  }

  category_of <- stats::setNames(listed$category_id, listed$topic_id)   # listing first ...
  for (t in topics) {                                                    # ... topic JSON wins
    listed_as <- category_of[[as.character(t$id)]]
    if (!identical(listed_as, t$category_id)) {
      note(sprintf("topic %d: listing says category %s, topic JSON says %d", t$id, listed_as, t$category_id))
    }
    category_of[[as.character(t$id)]] <- t$category_id
  }
  per_category <- lapply(cats, function(category) {
    ids <- as.integer(names(category_of)[which(category_of == category$id)])
    has_about <- !is.na(category$about_topic_id) && category$about_topic_id %in% ids
    expected <- length(ids) - has_about    # a category's topic_count leaves out its own About topic
    reported <- category$topic_count
    agrees <- !is.na(reported) && reported == expected
    if (!agrees) {
      note(sprintf("category %s (id %d): categories.json reports %s topics, found %d (%d without its About topic)",
                   category$path, category$id, reported, length(ids), expected))
    }
    list(id = category$id, path = category$path, reported_topic_count = reported,
         topics_with_category_id = length(ids), about_topic_among_them = has_about, match = agrees)
  })
  list(
    topics = list(enumerated = enumerated, fetched = length(topics), about_topic_count = about_topics,
                  match = !is.null(about_topics) && enumerated == about_topics),
    posts = list(collected = posts, about_post_count = about_posts,
                 match = if (is.na(limit)) !is.null(about_posts) && posts == about_posts else NA),
    categories = per_category,
    warnings = as.list(warns)
  )
}

list_out_files <- function(out) {
  files <- fs::dir_ls(out, recurse = TRUE, type = "file", all = TRUE)
  rel <- as.character(fs::path_rel(files, start = out))
  rel <- rel[basename(rel) != ".DS_Store" & rel != "manifest.json"]
  rel[order(rel, method = "radix")]
}

final_checks <- function(ctx, topics, discourse_version) {
  leftovers <- list_out_files(ctx$out)
  leftovers <- leftovers[endsWith(leftovers, ".part")]
  if (length(leftovers) > 0L) abort("Partial files left under ", ctx$out, ": ", paste(leftovers, collapse = ", "))
  for (t in topics) {
    if (!file.exists(out_file(ctx, sprintf("topic/%d.json", t$id)))) abort("topic/", t$id, ".json is missing")
  }
  if (!is.character(discourse_version) || !nzchar(discourse_version)) abort("about.json has no about$version")
}

write_manifest <- function(ctx, meta, cats, topics, assets, reconciliation, limit, extra_warnings) {
  manifest_path <- out_file(ctx, "manifest.json")
  prev <- if (!is.null(ctx$previous_manifest)) ctx$previous_manifest
  rel <- list_out_files(ctx$out)
  files <- stats::setNames(lapply(rel, function(r) file_info(out_file(ctx, r))), rel)
  unexpected <- setdiff(rel, ctx$used)
  if (length(unexpected) > 0L) {
    extra_warnings <- c(extra_warnings, sprintf(
      "%d files under the output directory were not used by this run (stale or from another run), e.g. %s",
      length(unexpected), paste(utils::head(unexpected, 3L), collapse = ", ")))
  }
  digests <- function(f) vapply(f, function(e) e[["sha256"]], "")
  # A run that fetched nothing and finds identical files keeps the earlier timestamp, so
  # re-verifying an archive does not move its snapshot date.
  unchanged <- ctx$n_requests == 0L && !is.null(prev) && identical(digests(prev[["files"]]), digests(files))
  manifest <- list(
    harvested_at_utc = if (unchanged) prev[["harvested_at_utc"]] else format(ctx$now(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
    base_url = BASE_URL,
    user_agent = USER_AGENT,
    discourse_version = meta$about[["about"]][["version"]],
    site_title = meta$basic[["title"]] %||% meta$about[["about"]][["title"]],
    counts = list(categories = length(cats), topics = length(topics),
                  posts = sum(vapply(topics, function(t) nrow(t$posts), integer(1))),
                  assets_ok = assets$ok, assets_missing = assets$missing),
    limited = if (is.na(limit)) NULL else limit,
    about_stats = meta$about[["about"]][["stats"]],
    reconciliation = reconciliation,
    warnings = as.list(extra_warnings),
    files = files
  )
  write_json_atomic(manifest, manifest_path)
  manifest
}

# ---- run ---------------------------------------------------------------------------------------

run_harvest <- function(opts, ctx = new_ctx(opts$out, opts$force)) {
  started <- ctx$now()
  say("out=%s force=%s limit-topics=%s", ctx$out, ctx$force, if (is.na(opts$limit)) "none" else opts$limit)
  fs::dir_create(ctx$out)
  # raw/ is the redacted, committed copy (R/01b_redact.R); a harvest is verbatim, so never write one there.
  if (file.exists(out_file(ctx, "redaction-report.json"))) {
    abort(ctx$out, " is a redacted copy (it contains redaction-report.json). Harvest into raw_verbatim/ ",
          "(the default) and run R/01b_redact.R to refresh raw/.")
  }

  # An interrupted earlier run may have left .part files; the manifest must only ever describe a
  # finished run, so it is removed now and rewritten at the very end.
  fs::file_delete(fs::dir_ls(ctx$out, recurse = TRUE, glob = "*.part", type = "file", all = TRUE))
  manifest_path <- out_file(ctx, "manifest.json")
  ctx$previous_manifest <- if (file.exists(manifest_path)) tryCatch(jsonlite::read_json(manifest_path), error = function(e) NULL)
  unlink(manifest_path)

  meta <- list()
  get_json(ctx, "/site.json", "site.json")
  meta$about <- get_json(ctx, "/about.json", "about.json")
  meta$basic <- get_json(ctx, "/site/basic-info.json", "site-basic-info.json")
  meta$categories <- get_json(ctx, "/categories.json?include_subcategories=true", "categories.json")
  version <- meta$about[["about"]][["version"]]
  say("Discourse %s, site '%s'", version %||% "?", meta$basic[["title"]] %||% "?")

  cats <- flatten_categories(meta$categories)
  say("categories: %d (%d top-level, %d sub)", length(cats),
      sum(vapply(cats, function(k) is.na(k$parent_id), NA)), sum(vapply(cats, function(k) !is.na(k$parent_id), NA)))
  listed <- enumerate_topics(ctx, cats)
  if (nrow(listed) == 0L) abort("No topics found in any category listing")

  ids <- sort(listed$topic_id)
  if (!is.na(opts$limit)) ids <- utils::head(ids, opts$limit)
  topics <- harvest_topics(ctx, ids)
  assets <- harvest_assets(ctx, topics, meta, cats)

  final_checks(ctx, topics, version)
  recon <- reconcile(listed, topics, cats, meta$about[["about"]][["stats"]], opts$limit)
  for (w in recon$warnings) say("note (info only): %s", w)
  manifest <- write_manifest(ctx, meta, cats, topics, assets, recon, opts$limit,
                             if (length(assets$warnings) > 0L) sprintf("assets-report.json has %d warnings", length(assets$warnings)))
  say("manifest.json written: %d files", length(manifest$files))
  say("DONE: %d categories, %d topics, %d posts, %d assets ok, %d assets missing; %d HTTP requests in %.0f s",
      manifest$counts$categories, manifest$counts$topics, manifest$counts$posts,
      manifest$counts$assets_ok, manifest$counts$assets_missing, ctx$n_requests,
      as.numeric(difftime(ctx$now(), started, units = "secs")))
  invisible(manifest)
}

main <- function(argv = commandArgs(trailingOnly = TRUE)) {
  ok <- tryCatch({
    run_harvest(parse_args(argv))
    TRUE
  }, harvest_abort = function(e) {
    message("\nHARVEST ABORTED: ", conditionMessage(e))
    FALSE
  }, error = function(e) {
    message("\nHARVEST FAILED (unexpected error): ", conditionMessage(e))
    FALSE
  })
  if (!ok) quit(save = "no", status = 1L)
}

if (sys.nframe() == 0L) main()
