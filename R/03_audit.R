#!/usr/bin/env Rscript
# Phase 5 (Audit): the last gate before the static forum archive is deployed.
#
#   Rscript R/03_audit.R [--raw DIR] [--site DIR] [--verbatim DIR] [--spot-check ID,ID,ID]
#
# Reads the redacted harvest (--raw, default "raw"), the finished site (--site, default "dist": built by
# R/02_build.R, indexed by Pagefind, with _redirects from R/02b_redirects.R) and, if it exists, the unredacted
# harvest (--verbatim, default "raw_verbatim", local only). There is no network access, and nothing is taken
# from the build (no code, no build-report.json): everything is re-derived from raw/ and from the files of the
# site, so the audit does not have to trust the build. It reads and reports; it fixes nothing and modifies none
# of its inputs. Its only output is audit-report.json NEXT TO --site (not inside it), written to
# audit-report.json.part and renamed: deterministic (no clocks, stable order, complete lists) and tied to what
# was audited (sha256 of raw/manifest.json and of the sorted "sha256  path" lines of every file of the site). A
# run that stops before the verdict removes an older audit-report.json, so a report is never older than the run
# that left it. Exit status: 1 if a check FAILs or the audit cannot run, else 0. It prints counts and locations
# (file, topic id, post number, rule), never an e-mail address, a passcode or post text; everything printed or
# stored also goes through scrub().
#
# Intended, so not defects: user pages are omitted (mentions are plain spans); avatar images are omitted (their
# paths under /user_avatar/ and /letter_avatar_proxy/ are counted apart); the post_type 3 "small action" posts
# are not rendered; PDFs and attachments are published as uploaded; OSF view_only= and Dropbox rlkey= keys stay;
# the forum host appears legitimately in <link rel="canonical">, sitemap.xml and robots.txt only.
#
# Checks (one row each; PASS, FAIL or INFO):
#   1   pages         every topic, category and fixed page exists, no other HTML page
#   2   posts         the posts rendered per topic are exactly the renderable posts of raw/
#   2b  no word lost  every word of a raw post body occurs in the rendered post body
#   3   forum host    no attribute value names the forum host (except rel="canonical"); text mentions (INFO)
#   4   links         every internal URL, fragment, _redirects destination and sitemap URL resolves; external (INFO)
#   5   assets        every asset the posts use is in the site; raw/assets/ is in the site byte for byte
#   6a  personal data e-mail addresses, mailto:, passcodes in everything the site publishes
#   6b                inventory of zoom/OSF/Dropbox links, redaction markers and the redaction report (INFO)
#   6c                values of the unredacted harvest searched in the site (needs --verbatim)
#   6d                e-mail addresses inside PDF and Word attachments, best effort (INFO)
#   7   spot-check    what to compare by hand against the live forum (INFO)
#   8   onebox        oneboxes, YouTube blocks, polls, hot-linked images, external links (INFO)
#   9   minimisation  no avatar, user link, data-*, script, iframe, form, event handler ...
#   10  search        the Pagefind index covers exactly the pages of the site
#   11  redirects     _redirects fits Cloudflare Pages' limits and shadows nothing

FORUM_HOST       <- "discourse.igelsociety.org"
RAW_DEFAULT      <- "raw"
SITE_DEFAULT     <- "dist"
VERBATIM_DEFAULT <- "raw_verbatim"
SPOT_DEFAULT     <- "365,178,307"
MANIFEST_FILE    <- "manifest.json"
REDACTION_REPORT <- "redaction-report.json"
REPORT_FILE      <- "audit-report.json"
SCREEN_LIMIT     <- 10L                  # offenders listed per failing check on screen (the JSON has them all)

FIXED_PAGES  <- c("index.html", "search/index.html", "404.html")
FIXED_FILES  <- c("robots.txt", "sitemap.xml", "_redirects", "archive.css")
RENDERED_POST_TYPES <- c(1L, 2L)         # regular post, moderator action

# Paths in post bodies that point at an asset of the forum, and the avatar subset that is left out on purpose.
ASSET_DIRS  <- c("uploads", "images", "user_avatar", "letter_avatar_proxy", "plugins", "assets", "secure-uploads")
AVATAR_DIRS <- c("user_avatar", "letter_avatar_proxy")
DOCUMENT_EXTENSIONS <- c("pdf", "doc", "docx", "docm", "dot", "dotx", "rtf", "odt", "txt", "ppt", "pptx", "pps",
                         "ppsx", "odp", "key", "xls", "xlsx", "ods", "csv", "tsv", "zip", "gz", "tgz", "tar",
                         "7z", "rar", "epub", "tex", "ipynb", "json", "xml", "html", "htm")
IMAGE_EXTENSIONS   <- c("png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico", "avif", "tif", "tiff", "heic")

# What must not be in the output. The e-mail pattern is the plan's; the lookbehind only keeps matching fast on
# long runs of address characters (it finds the same matches). A match whose last label is an image extension
# is a retina image name (image@2x.png), not an address.
EMAIL_RE       <- "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
NOT_AN_ADDRESS <- c("png", "jpg", "jpeg", "gif", "webp", "svg")
PARAM_RE       <- "(?i)[?&;](?i:pwd|passcode|password)=(?!REDACTED(?:[\\s\"'<>&#]|\\z))[^\\s\"'<>&#]+"
PARAM_VALUE_RE <- "(?i)[?&;](?i:pwd|passcode|password)=([^\\s\"'<>&#]+)"
PASSCODE_LABEL <- "(?:kenncode|kennwort|passcode|passwort|password|zugangscode|wachtwoord|toegangscode)"
PASSCODE_RE    <- sprintf("(?i)\\b%s\\b[ \\t]*[:=][ \\t]*(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{4,12}\\b", PASSCODE_LABEL)
PASSCODE_VALUE <- sprintf("(?i)\\b%s\\b[ \\t]*[:=][ \\t]*((?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{4,12})\\b", PASSCODE_LABEL)

URL_ATTRS <- c("href", "src", "srcset", "imagesrcset", "poster", "cite", "action", "formaction", "longdesc", "background")
URL_RE    <- "(?s)^(?:([A-Za-z][A-Za-z0-9+.-]*):)?(?://([^/?#]*))?([^?#]*)(?:\\?([^#]*))?(?:#(.*))?$"
ALLOWED_DATA_ATTRS <- c("data-pagefind-body", "data-pagefind-meta", "data-pagefind-filter")
FORBIDDEN_STRINGS  <- c("trust_level", "avatar_template", "user_title", "last_seen", "ip_address", "primary_group")
FORBIDDEN_ELEMENTS <- c("iframe", "object", "embed", "form")
# The pages that carry the Pagefind search widget: a <script> is allowed there and nowhere else.
SEARCH_WIDGET_PAGES <- c("search/index.html", "index.html")
USER_PREFIXES      <- c("/u", "/users", "/groups", "/g")

# Elements that start a new line of text (inline ones, and unknown ones, are transparent: a word split by
# <b> stays one word, as in a browser). The audit reads the text of a post this way on both sides.
BLOCK_ELEMENTS <- c("address", "article", "aside", "blockquote", "body", "br", "caption", "center", "col",
                    "colgroup", "dd", "details", "dialog", "dir", "div", "dl", "dt", "fieldset", "figcaption",
                    "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr",
                    "html", "legend", "li", "main", "menu", "nav", "ol", "optgroup", "option", "p", "pre",
                    "section", "summary", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul")
BLOCK_TAG_RE <- sprintf("</?(?:%s)(?![A-Za-z0-9:-])[^>]*>", paste(BLOCK_ELEMENTS, collapse = "|"))

USAGE <- "Usage: Rscript R/03_audit.R [--raw DIR] [--site DIR] [--verbatim DIR] [--spot-check ID,ID,ID]
  --raw DIR          redacted copy of the harvest (default: raw)
  --site DIR         finished site to audit (default: dist); audit-report.json is written next to it
  --verbatim DIR     unredacted harvest, local only (default: raw_verbatim); check 6c is skipped if it is absent
  --spot-check IDS   topic ids to compare by hand against the live forum (default: 365,178,307)"

# ---- helpers -----------------------------------------------------------------------------------
# Parsed JSON is always read with [[ ]]: `$` partial-matches.

`%||%` <- function(x, y) if (is.null(x)) y else x

say <- function(fmt, ...) message("[audit] ", if (...length() > 0) sprintf(fmt, ...) else fmt)

abort <- function(...) {
  stop(structure(class = c("audit_abort", "error", "condition"),
                 list(message = paste0(...), call = NULL)))
}

parse_args <- function(argv) {
  opts <- list(raw = RAW_DEFAULT, site = SITE_DEFAULT, verbatim = VERBATIM_DEFAULT, spot = SPOT_DEFAULT)
  flags <- c("--raw" = "raw", "--site" = "site", "--verbatim" = "verbatim", "--spot-check" = "spot")
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
  if (!nzchar(opts$raw) || !nzchar(opts$site)) abort("--raw and --site must not be empty")
  ids <- trimws(strsplit(opts$spot, ",", fixed = TRUE)[[1]])
  ids <- ids[nzchar(ids)]
  if (!all(grepl("^[0-9]+$", ids))) abort("--spot-check takes topic ids separated by commas, e.g. 365,178,307")
  opts$spot <- unique(as.integer(ids))
  opts
}

# "123, 456" for short lists of numbers or names inside one line.
inline <- function(x, n = 5L) {
  paste0(utils::head(x, n) |> paste(collapse = ", "), if (length(x) > n) sprintf(", ... (%d in all)", length(x)))
}

sorted <- function(x) sort(x, method = "radix")

# Count of each distinct value, most frequent first, ties in byte order (no locale-dependent sorting anywhere).
count_by <- function(x) {
  if (length(x) == 0L) return(stats::setNames(integer(), character()))
  u <- unique(x) |> sorted()
  n <- tabulate(match(x, u), length(u))
  o <- order(-n, u, method = "radix")
  stats::setNames(n[o], u[o])
}

# Strings that are printed or stored must not carry personal data even by accident (a URL or a file name
# can contain anything): e-mail addresses and passcode parameter values are masked.
scrub <- function(x) {
  if (!is.character(x) || length(x) == 0L) return(x)
  x <- gsub(EMAIL_RE, "<address>", x, perl = TRUE)
  gsub("(?i)([?&;](?i:pwd|passcode|password)=)(?!REDACTED(?:[\\s\"'<>&#]|\\z))[^\\s\"'<>&#]+", "\\1<value>", x, perl = TRUE)
}

scrub_data <- function(x) if (length(x) == 0L) x else rapply(x, scrub, classes = "character", how = "replace")

# ---- files and text ----------------------------------------------------------------------------
# Text always goes through raw bytes: a non-UTF-8 session (LANG=C) must read the same as a UTF-8 one.

read_bytes <- function(path) readBin(path, "raw", n = file.size(path))

# Bytes of a text file as one UTF-8 string with "\n" line endings. NUL bytes and invalid UTF-8 are repaired
# (so that the scans can go on) and reported through $clean.
bytes_to_utf8 <- function(bytes) {
  nul <- any(bytes == as.raw(0L))
  if (nul) bytes <- bytes[bytes != as.raw(0L)]
  txt <- rawToChar(bytes)
  Encoding(txt) <- "UTF-8"
  valid <- validUTF8(txt)
  if (!valid) txt <- iconv(txt, "UTF-8", "UTF-8", sub = "byte")
  list(text = gsub("\r\n?", "\n", txt), clean = valid && !nul)
}

read_text <- function(path) bytes_to_utf8(read_bytes(path))$text

# (A parse error would quote the text around the fault, so the message only names the file.)
read_json_file <- function(path) {
  tryCatch(jsonlite::read_json(path, simplifyVector = FALSE), error = function(e) abort("Cannot parse JSON file ", path))
}

to_json <- function(x) {
  jsonlite::toJSON(x, auto_unbox = TRUE, pretty = TRUE, null = "null", na = "null", digits = NA) |> paste0("\n")
}

list_tree <- function(dir) {
  if (!dir.exists(dir)) return(list(files = character(), other = character()))
  entries <- fs::dir_ls(dir, recurse = TRUE, all = TRUE)
  if (length(entries) == 0L) return(list(files = character(), other = character()))
  type <- as.character(fs::file_info(entries)$type)
  rel <- as.character(fs::path_rel(entries, start = dir))
  list(files = rel[type == "file"] |> sorted(), other = rel[!type %in% c("file", "directory")] |> sorted())
}

sha256_of <- function(path) digest::digest(file = path, algo = "sha256")

# ---- URLs --------------------------------------------------------------------------------------

# %XX sequences decoded as UTF-8 bytes.
percent_decode <- function(s) {
  if (!grepl("%", s, fixed = TRUE)) return(s)
  b <- charToRaw(s)
  hex <- c(as.raw(0x30:0x39), as.raw(0x41:0x46), as.raw(0x61:0x66))
  out <- raw()
  i <- 1L
  n <- length(b)
  while (i <= n) {
    if (b[i] == as.raw(0x25) && i + 2L <= n && b[i + 1L] %in% hex && b[i + 2L] %in% hex) {
      out <- c(out, as.raw(strtoi(rawToChar(b[(i + 1L):(i + 2L)]), 16L)))
      i <- i + 3L
    } else {
      out <- c(out, b[i])
      i <- i + 1L
    }
  }
  r <- rawToChar(out[out != as.raw(0L)])
  Encoding(r) <- "UTF-8"
  if (validUTF8(r)) r else s
}

percent_decode_all <- function(x) vapply(x, percent_decode, "", USE.NAMES = FALSE)

# scheme, host (lower case, without user and port), path, query and fragment of every URL.
split_urls <- function(u) {
  u <- gsub("[\t\n\r]", "", trimws(u))
  m <- regmatches(u, regexec(URL_RE, u, perl = TRUE))
  field <- function(i) vapply(m, function(x) if (length(x) == 6L) x[i] else "", "")
  auth <- field(3L)
  list(url = u, scheme = tolower(field(2L)), has_auth = grepl("^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//", u, perl = TRUE),
       host = tolower(sub(":[0-9]*$", "", sub("^.*@", "", auth))), path = field(4L), query = field(5L), frag = field(6L))
}

# "internal" (relative, root-relative or on the forum host), "external" (http/https elsewhere), "malformed"
# (http without a host) or "skipped" (mailto, tel, data, javascript ...).
url_kind <- function(p) {
  web <- p$scheme %in% c("http", "https") | (p$scheme == "" & p$has_auth)
  kind <- ifelse(web, ifelse(p$host == FORUM_HOST, "internal", "external"), ifelse(p$scheme == "", "internal", "skipped"))
  ifelse(web & p$host == "", "malformed", kind)
}

# "." and ".." segments resolved.
normalize_dots <- function(p) {
  hit <- grepl("(^|/)\\.{1,2}(/|$)", p)
  p[hit] <- vapply(p[hit], function(x) {
    segs <- strsplit(x, "/", fixed = TRUE)[[1]]
    segs <- segs[nzchar(segs)]
    out <- character()
    for (s in segs) {
      if (s == "..") out <- out[-length(out)] else if (s != ".") out <- c(out, s)
    }
    trail <- grepl("(/|/\\.|/\\.\\.)$", x) && length(out) > 0L
    paste0("/", paste(out, collapse = "/"), if (trail) "/")
  }, "")
  p
}

# The file a decoded URL path asks for: a path ending in "/" needs its index.html.
url_target <- function(path) {
  rel <- sub("^/", "", path)
  ifelse(rel == "" | endsWith(rel, "/"), paste0(rel, "index.html"), rel)
}

# URL candidates of a srcset value (HTML spec: a URL is a run of non-space characters, descriptors follow).
srcset_urls <- function(x) {
  out <- character()
  s <- x
  repeat {
    s <- sub("^[\\s,]+", "", s, perl = TRUE)
    if (!nzchar(s)) break
    url <- sub("(?s)^(\\S+).*$", "\\1", s, perl = TRUE)
    s <- substring(s, nchar(url) + 1L)
    if (grepl(",$", url)) url <- sub(",+$", "", url) else s <- sub("(?s)^[^,]*", "", s, perl = TRUE)
    if (nzchar(url)) out <- c(out, url)
  }
  out
}

# ---- HTML --------------------------------------------------------------------------------------

class_xp <- function(cls) sprintf("contains(concat(' ', normalize-space(@class), ' '), ' %s ')", cls)

# libxml2 serialises UTF-8 text with only these entities.
decode_entities <- function(x) {
  x <- gsub("&lt;", "<", x, fixed = TRUE)
  x <- gsub("&gt;", ">", x, fixed = TRUE)
  x <- gsub("&quot;", "\"", x, fixed = TRUE)
  gsub("&amp;", "&", x, fixed = TRUE)
}

# The text a reader sees, from serialised HTML: comments, script/style/template content and all tags go;
# block elements become line breaks, inline ones are transparent. keep_code = TRUE keeps script and style.
visible_text <- function(html, keep_code = FALSE) {
  x <- gsub("(?s)<!--.*?-->", "", html, perl = TRUE)
  if (!keep_code) x <- gsub("(?is)<(script|style|template)\\b[^>]*>.*?</\\1\\s*>", "", x, perl = TRUE)
  x <- gsub(BLOCK_TAG_RE, "\n", x, perl = TRUE)
  decode_entities(gsub("<[^>]*>", "", x, perl = TRUE))
}

# Lower-case runs of letters and digits (the text is UTF-8 whatever the session's locale says).
tokens <- function(x) {
  if (Encoding(x) == "unknown" && validUTF8(x)) Encoding(x) <- "UTF-8"
  x <- tolower(x)
  regmatches(x, gregexpr("[\\p{L}\\p{N}]+", x, perl = TRUE))[[1]]
}

# How many tokens of `want` are not covered by `have` (as a multiset).
missing_tokens <- function(have, want) {
  if (length(want) == 0L) return(0L)
  u <- unique(want)
  sum(pmax(tabulate(match(want, u), length(u)) - tabulate(match(have, u), length(u)), 0L))
}

parse_html <- function(text) {
  tryCatch(xml2::read_html(charToRaw(text), encoding = "UTF-8"), error = function(e) NULL)
}

# Every attribute of a document: index of its element, element name, attribute name, value.
doc_attrs <- function(doc) {
  empty <- data.frame(idx = integer(), el = character(), name = character(), value = character(), stringsAsFactors = FALSE)
  if (is.null(doc)) return(empty)
  els <- xml2::xml_find_all(doc, "//*[@*]")
  if (length(els) == 0L) return(empty)
  at <- unname(xml2::xml_attrs(els))
  data.frame(idx = rep(seq_along(els), lengths(at)), el = rep(tolower(xml2::xml_name(els)), lengths(at)),
             name = tolower(names(unlist(at))), value = unlist(at, use.names = FALSE), stringsAsFactors = FALSE)
}

# The path part of a page's own URL: "t/a/1/index.html" -> "/t/a/1/", "index.html" -> "/", "404.html" -> "/404.html".
page_url <- function(rel) {
  d <- dirname(rel)
  ifelse(basename(rel) != "index.html", paste0("/", rel), ifelse(d == ".", "/", paste0("/", d, "/")))
}

# ---- the input: guard, categories, topics --------------------------------------------------------

# Only a redacted copy is audited: manifest.json says what it was derived from and how it was redacted, and the
# redaction report must exist (the same condition the build and the redirects script enforce).
verify_redacted <- function(raw) {
  mpath <- file.path(raw, MANIFEST_FILE)
  if (!file.exists(mpath)) abort(raw, " has no ", MANIFEST_FILE, ": not a harvest or a redacted copy of one")
  manifest <- read_json_file(mpath)
  if (!identical(manifest[["derived_from"]], "raw_verbatim") ||
      !is.list(manifest[["redaction"]]) || length(manifest[["redaction"]]) == 0L) {
    abort(raw, " is not a redacted copy (its ", MANIFEST_FILE, " lacks derived_from == \"raw_verbatim\" and a redaction block); ",
          "run R/01b_redact.R and audit its output. Refusing to work from unredacted data.")
  }
  if (!file.exists(file.path(raw, REDACTION_REPORT))) {
    abort(raw, " is not a redacted copy (no ", REDACTION_REPORT, "). Refusing to work from unredacted data.")
  }
  manifest
}

# One record per category, sorted by id: id, slug and path (the slugs from the top-level category down).
load_categories <- function(raw) {
  json <- read_json_file(file.path(raw, "categories.json"))
  top <- json[["category_list"]][["categories"]]
  if (!is.list(top) || length(top) == 0L) abort("categories.json has no category_list$categories")
  rows <- list()
  visit <- function(node, parents) {
    id <- node[["id"]]
    slug <- node[["slug"]]
    if (!is.numeric(id) || length(id) != 1L || !is.character(slug) || length(slug) != 1L || !nzchar(slug)) {
      abort("A category in categories.json has no id or slug")
    }
    rows[[length(rows) + 1L]] <<- list(id = as.integer(id), slug = slug, path = c(parents, slug))
    for (kid in node[["subcategory_list"]] %||% list()) visit(kid, c(parents, slug))
  }
  for (node in top) visit(node, character())
  ids <- vapply(rows, function(r) r$id, 1L)
  if (anyDuplicated(ids)) abort("categories.json lists category ", inline(ids[duplicated(ids)]), " twice")
  rows[order(ids)]
}

# One record per topic, sorted by id: slug and, for every post of topic/{id}.json and topic/{id}-posts-{k}.json
# (a post that occurs twice counts once), its number, type, whether it is hidden or deleted, and its cooked HTML.
load_topics <- function(raw) {
  dir <- file.path(raw, "topic")
  if (!dir.exists(dir)) abort(raw, " has no topic/ directory")
  files <- list.files(dir, pattern = "\\.json$")
  main <- files[grepl("^[0-9]+\\.json$", files)]
  chunks <- files[grepl("^[0-9]+-posts-[0-9]+\\.json$", files)]
  stray <- setdiff(files, c(main, chunks))
  if (length(stray) > 0L) abort("Unexpected files in ", dir, ": ", inline(stray))
  main <- main[order(as.integer(sub("\\.json$", "", main)))]
  ids <- as.integer(sub("\\.json$", "", main))
  chunk_topic <- as.integer(sub("-posts-.*$", "", chunks))
  chunk_k <- as.integer(sub("^.*-posts-([0-9]+)\\.json$", "\\1", chunks))
  if (length(setdiff(chunk_topic, ids)) > 0L) abort("Chunk files without a topic file: topic ", inline(setdiff(chunk_topic, ids)))
  lapply(seq_along(ids), function(i) {
    id <- ids[i]
    t <- read_json_file(file.path(dir, main[i]))
    if (!identical(as.integer(t[["id"]] %||% NA), id)) abort(main[i], " does not hold topic ", id)
    slug <- t[["slug"]]
    if (!is.character(slug) || length(slug) != 1L || !nzchar(slug)) abort("Topic ", id, " has no slug")
    posts <- t[["post_stream"]][["posts"]]
    if (!is.list(posts)) abort(main[i], " has no post_stream$posts")
    mine <- which(chunk_topic == id)
    for (j in mine[order(chunk_k[mine])]) {
      extra <- read_json_file(file.path(dir, chunks[j]))[["post_stream"]][["posts"]]
      if (!is.list(extra)) abort(chunks[j], " has no post_stream$posts")
      posts <- c(posts, extra)
    }
    pid <- vapply(posts, function(p) as.integer(p[["id"]] %||% NA), 1L)
    posts <- posts[is.na(pid) | !duplicated(pid)]
    num <- vapply(posts, function(p) as.integer(p[["post_number"]] %||% NA), 1L)
    if (anyNA(num)) abort("Topic ", id, " has a post without a post_number")
    deleted_at <- vapply(posts, function(p) {
      d <- p[["deleted_at"]]
      !is.null(d) && !identical(d, "") && !isFALSE(d)
    }, NA)
    list(id = id, slug = slug, number = num,
         type = vapply(posts, function(p) as.integer(p[["post_type"]] %||% 1L), 1L),
         hidden = vapply(posts, function(p) isTRUE(p[["hidden"]]) || isTRUE(p[["user_deleted"]]), NA) | deleted_at,
         cooked = vapply(posts, function(p) as.character(p[["cooked"]] %||% ""), ""),
         stream_n = length(t[["post_stream"]][["stream"]]))
  })
}

renderable <- function(t) t$type %in% RENDERED_POST_TYPES & !t$hidden

# ---- the site ----------------------------------------------------------------------------------

# The pages and files the raw data calls for.
expected_site <- function(topics, cats) {
  list(topic = stats::setNames(vapply(topics, function(t) sprintf("t/%s/%d/index.html", t$slug, t$id), ""),
                               vapply(topics, function(t) as.character(t$id), "")),
       category = stats::setNames(vapply(cats, function(k) sprintf("c/%s/%d/index.html", paste(k$path, collapse = "/"), k$id), ""),
                                  vapply(cats, function(k) as.character(k$id), "")))
}

# Parses every HTML page: the file text, the document and all its attributes.
load_pages <- function(site_dir, files) {
  pages <- lapply(files, function(rel) {
    txt <- bytes_to_utf8(read_bytes(file.path(site_dir, rel)))
    doc <- parse_html(txt$text)
    list(rel = rel, url = page_url(rel), src = txt$text, clean = txt$clean, doc = doc, attrs = doc_attrs(doc))
  })
  stats::setNames(pages, files)
}

# The text of every Pagefind fragment: gzip, then "pagefind_dcd" and a JSON document with url, content, meta.
load_fragments <- function(site_dir, files) {
  magic <- charToRaw("pagefind_dcd")
  rels <- files[grepl("^pagefind/fragment/[^/]+\\.pf_fragment$", files)]
  lapply(rels, function(rel) {
    out <- list(rel = rel, ok = FALSE, url = NA_character_, text = character())
    dec <- tryCatch(memDecompress(read_bytes(file.path(site_dir, rel)), "gzip"), error = function(e) NULL)
    if (is.null(dec) || length(dec) <= length(magic) || !identical(dec[seq_along(magic)], magic)) return(out)
    json <- tryCatch(jsonlite::parse_json(bytes_to_utf8(dec[-seq_along(magic)])$text), error = function(e) NULL)
    if (!is.list(json) || !is.character(json[["url"]]) || !is.character(json[["content"]])) return(out)
    out$ok <- TRUE
    out$url <- json[["url"]]
    out$text <- c(json[["content"]], as.character(unlist(json[["meta"]], use.names = FALSE)))
    out
  })
}

# ---- results -----------------------------------------------------------------------------------

# One row of the audit table. `failures` are the offenders (complete), `lines` extra detail for the screen
# and `data` the structured detail for the JSON report.
make_row <- function(id, name, status, summary, failures = character(), lines = character(), data = list()) {
  list(id = id, name = name, status = status, summary = scrub(summary), failures = scrub(failures),
       lines = scrub(lines), data = scrub_data(data))
}

verdict <- function(failures) if (length(failures) == 0L) "PASS" else "FAIL"


# ---- check 1: pages ----------------------------------------------------------------------------

check_pages <- function(ctx) {
  ex <- ctx$expected
  files <- ctx$site$files
  label <- function(p) {
    i <- match(p, ex$topic)
    j <- match(p, ex$category)
    if (!is.na(i)) sprintf("%s (topic %s)", p, names(ex$topic)[i])
    else if (!is.na(j)) sprintf("%s (category %s)", p, names(ex$category)[j])
    else p
  }
  need <- c(ex$topic, ex$category, FIXED_PAGES, FIXED_FILES)
  absent <- need[!need %in% files]
  extra <- setdiff(ctx$page_files, c(ex$topic, ex$category, FIXED_PAGES))
  broken <- names(ctx$pages)[!vapply(ctx$pages, function(p) p$clean && !is.null(p$doc), NA)]
  failures <- c(sprintf("missing: %s", vapply(absent, label, "", USE.NAMES = FALSE)),
                sprintf("extra HTML page: %s", extra),
                sprintf("not valid UTF-8 or not parseable: %s", broken))
  make_row("1", "Pages", verdict(failures),
           sprintf("%d of %d topic pages, %d of %d category pages, %d of %d fixed files; %d HTML pages (%d expected), %d extra",
                   sum(ex$topic %in% files), length(ex$topic), sum(ex$category %in% files), length(ex$category),
                   sum(c(FIXED_PAGES, FIXED_FILES) %in% files), length(FIXED_PAGES) + length(FIXED_FILES),
                   length(ctx$page_files), length(ex$topic) + length(ex$category) + length(FIXED_PAGES), length(extra)),
           failures, data = list(topics = length(ex$topic), categories = length(ex$category), html_pages = length(ctx$page_files),
                                 html_pages_expected = length(ex$topic) + length(ex$category) + length(FIXED_PAGES)))
}

# ---- check 2: posts ----------------------------------------------------------------------------

# The <article class="post" id="post-N"> elements of a page and their post numbers (NA: no valid id).
page_posts <- function(ctx, rel) {
  if (exists(rel, envir = ctx$cache, inherits = FALSE)) return(get(rel, envir = ctx$cache, inherits = FALSE))
  page <- ctx$pages[[rel]]
  res <- NULL
  if (!is.null(page) && !is.null(page$doc)) {
    arts <- xml2::xml_find_all(page$doc, sprintf("//article[%s]", class_xp("post")))
    id <- xml2::xml_attr(arts, "id")
    num <- suppressWarnings(as.integer(ifelse(grepl("^post-[0-9]+$", id), sub("^post-", "", id), NA_character_)))
    res <- list(nodes = arts, number = num)
  }
  assign(rel, res, envir = ctx$cache)
  res
}

check_posts <- function(ctx) {
  failures <- character()
  gaps <- list()
  n_raw <- n_renderable <- n_rendered <- n_nopage <- 0L
  skipped <- c(system = 0L, hidden_or_deleted = 0L, other = 0L)
  for (t in ctx$topics) {
    ok <- renderable(t)
    n_raw <- n_raw + length(t$number)
    n_renderable <- n_renderable + sum(ok)
    skip <- !ok
    skipped["system"] <- skipped[["system"]] + sum(skip & t$type == 3L & !t$hidden)
    skipped["hidden_or_deleted"] <- skipped[["hidden_or_deleted"]] + sum(skip & t$hidden)
    skipped["other"] <- skipped[["other"]] + sum(skip & !t$hidden & !t$type %in% c(RENDERED_POST_TYPES, 3L))
    full <- skip & nzchar(trimws(t$cooked))
    for (n in t$number[full]) failures <- c(failures, sprintf("topic %d post %d: skipped (not renderable) but has a body", t$id, n))
    if (t$stream_n > 0L && t$stream_n != length(t$number)) {
      failures <- c(failures, sprintf("topic %d: post_stream lists %d posts, raw/ holds %d", t$id, t$stream_n, length(t$number)))
    }
    gap <- setdiff(seq_len(max(t$number, 0L)), t$number)
    if (length(gap) > 0L) gaps[[as.character(t$id)]] <- gap

    pp <- page_posts(ctx, ctx$expected$topic[[as.character(t$id)]])
    if (is.null(pp)) {
      n_nopage <- n_nopage + 1L
      if (any(ok)) failures <- c(failures, sprintf("topic %d: no page, so its %d renderable post(s) are not rendered", t$id, sum(ok)))
      next
    }
    got <- pp$number
    n_rendered <- n_rendered + length(got)
    want <- t$number[ok]
    lacking <- setdiff(want, got)
    unexpected <- setdiff(got[!is.na(got)], want)
    twice <- unique(got[!is.na(got) & duplicated(got)])
    if (length(lacking) > 0L) {
      failures <- c(failures, sprintf("topic %d: post(s) %s in raw/ but not rendered", t$id, inline(lacking)))
    }
    if (length(unexpected) > 0L) {
      failures <- c(failures, sprintf("topic %d: post(s) %s rendered but not renderable in raw/", t$id, inline(unexpected)))
    }
    if (length(twice) > 0L) failures <- c(failures, sprintf("topic %d: post(s) %s rendered twice", t$id, inline(twice)))
    if (anyNA(got)) {
      failures <- c(failures, sprintf("topic %d: %d <article class=\"post\"> without an id post-N", t$id, sum(is.na(got))))
    }
  }
  n_skipped <- sum(skipped)
  lines <- c(sprintf("skipped: %d system events (post_type 3), %d hidden or deleted, %d other post types",
                     skipped[["system"]], skipped[["hidden_or_deleted"]], skipped[["other"]]),
             sprintf("topic %s: no post %s in raw/ (deleted posts)", names(gaps), vapply(gaps, inline, "")))
  if (n_nopage > 0L) lines <- c(lines, sprintf("%d topics have no page (see check 1)", n_nopage))
  make_row("2", "Posts", verdict(failures),
           sprintf("raw %d, renderable %d, rendered %d; %d skipped (%d system events); %d topics with gaps in their post numbers",
                   n_raw, n_renderable, n_rendered, n_skipped, skipped[["system"]], length(gaps)),
           failures, lines,
           list(raw_posts = n_raw, renderable = n_renderable, rendered = n_rendered,
                skipped = list(system_events = skipped[["system"]], hidden_or_deleted = skipped[["hidden_or_deleted"]],
                               other = skipped[["other"]]),
                topics_with_gaps = lapply(names(gaps), function(id) list(topic = as.integer(id), missing_numbers = I(gaps[[id]])))))
}

# ---- check 2b: no word is lost -----------------------------------------------------------------

# Words of a raw post body. Intended rewrites are left out: local dates become <time> (dropped on the page
# side too), the lightbox file name line is removed, svg icons have no text.
raw_post_text <- function(cooked) {
  doc <- parse_html(paste0("<html><body>", cooked, "</body></html>"))
  if (is.null(doc)) return("")
  body <- xml2::xml_find_first(doc, "//body")
  drop <- sprintf(".//span[%s] | .//div[%s] | .//svg", class_xp("discourse-local-date"), class_xp("meta"))
  xml2::xml_remove(xml2::xml_find_all(body, drop))
  visible_text(as.character(body))
}

# What the page side leaves out, so that it cannot cover for a word that was lost: <time> (a local date, which
# the raw side drops as well) and the caption the build puts under a YouTube thumbnail (the video title, which
# the raw HTML only has as an attribute). Anything else the page adds is allowed to stay.
PAGE_ONLY_TEXT <- c("(?s)<time\\b[^>]*>.*?</time>",
                    "(?s)<span\\b[^>]*\\bclass=\"[^\"]*\\bvideo-title\\b[^\"]*\"[^>]*>.*?</span>")

page_post_text <- function(body) {
  html <- as.character(body)
  for (re in PAGE_ONLY_TEXT) html <- gsub(re, "", html, perl = TRUE)
  visible_text(html)
}

check_words <- function(ctx) {
  failures <- character()
  bad <- list()
  n_posts <- n_tokens <- n_unmatched <- 0L
  for (t in ctx$topics) {
    pp <- page_posts(ctx, ctx$expected$topic[[as.character(t$id)]])
    if (is.null(pp)) next
    for (i in which(renderable(t))) {
      k <- match(t$number[i], pp$number)
      if (is.na(k)) {
        n_unmatched <- n_unmatched + 1L
        next
      }
      body <- xml2::xml_find_first(pp$nodes[[k]], sprintf(".//div[%s]", class_xp("post-body")))
      want <- tokens(raw_post_text(t$cooked[i]))
      have <- if (inherits(body, "xml_missing")) character() else tokens(page_post_text(body))
      lost <- missing_tokens(have, want)
      n_posts <- n_posts + 1L
      n_tokens <- n_tokens + length(want)
      if (lost > 0L) {
        failures <- c(failures, sprintf("topic %d post %d: %d of %d words missing", t$id, t$number[i], lost, length(want)))
        bad[[length(bad) + 1L]] <- list(topic = t$id, post = t$number[i], words_missing = lost, words = length(want))
      }
    }
  }
  make_row("2b", "No word is lost", verdict(failures),
           sprintf("%d posts compared (%d words), %d with missing words%s", n_posts, n_tokens, length(bad),
                   if (n_unmatched > 0L) sprintf("; %d posts without a rendered counterpart (see check 2)", n_unmatched) else ""),
           failures, data = list(posts_compared = n_posts, words = n_tokens, posts_with_missing_words = bad))
}

# ---- check 3: forum host -----------------------------------------------------------------------

check_host <- function(ctx) {
  a <- ctx$attrs
  key <- sprintf("%s\t%d", a$page, a$idx)
  canonical <- key[a$el == "link" & a$name == "rel" & grepl("(^|\\s)canonical(\\s|$)", tolower(a$value))] |> unique()
  names_host <- grepl(FORUM_HOST, tolower(a$value), fixed = TRUE)
  allowed <- names_host & a$el == "link" & a$name == "href" & key %in% canonical
  bad <- names_host & !allowed
  failures <- sprintf("%s: <%s %s> names the forum host", a$page[bad], a$el[bad], a$name[bad])
  # The canonical links that remain must point at the page they are on.
  can <- which(allowed)
  p <- split_urls(a$value[can])
  own <- vapply(a$page[can], function(rel) ctx$pages[[rel]]$url, "", USE.NAMES = FALSE)
  off <- can[p$host != FORUM_HOST | percent_decode_all(p$path) != own]
  failures <- c(failures, sprintf("%s: the canonical link points at another page", a$page[off]))
  make_row("3", "Forum host", verdict(failures),
           sprintf("%d attribute values checked in %d pages; %d name the forum host; %d canonical links, %d not pointing at their own page",
                   nrow(a), length(ctx$pages), sum(bad), length(can), length(off)),
           failures, data = list(attributes_checked = nrow(a), attributes_naming_the_host = sum(bad), canonical_links = length(can)))
}

check_host_text <- function(ctx) {
  hits <- vapply(ctx$pages, function(p) {
    if (is.null(p$doc) || !grepl(FORUM_HOST, tolower(p$src), fixed = TRUE)) return(0L)
    sum(grepl(FORUM_HOST, tolower(xml2::xml_text(xml2::xml_find_all(p$doc, "//text()"))), fixed = TRUE))
  }, 1L)
  where <- hits[hits > 0L]
  make_row("3b", "Forum host in text", "INFO",
           sprintf("%d text nodes mention the forum host (in %d pages; should be 0)", sum(hits), length(where)),
           lines = sprintf("%s: %d text node(s)", names(where), where),
           data = list(text_nodes = sum(hits), pages = lapply(names(where), function(n) list(page = n, text_nodes = where[[n]]))))
}

# ---- check 4: internal links -------------------------------------------------------------------

subset_urls <- function(p, i) lapply(p, function(x) x[i])

# Absolute decoded path, target file and decoded fragment of internal URLs found on pages with the URL `base`.
resolve_urls <- function(p, base) {
  dir <- sub("[^/]*$", "", base)
  abs <- ifelse(p$has_auth & p$path == "", "/",
                ifelse(p$path == "", base, ifelse(startsWith(p$path, "/"), p$path, paste0(dir, p$path))))
  path <- percent_decode_all(normalize_dots(abs))
  list(path = path, target = url_target(path), frag = percent_decode_all(p$frag))
}

# The lines that name a missing file or a missing #fragment.
resolution_failures <- function(ctx, where, what, r) {
  failures <- character()
  gone <- !r$target %in% ctx$site$files
  failures <- c(failures, sprintf("%s: %s: no such file in the site", where[gone], what[gone]))
  frag <- which(!gone & nzchar(r$frag) & r$frag != "top" & r$target %in% names(ctx$pages))
  have <- vapply(frag, function(i) r$frag[i] %in% ctx$anchors[[r$target[i]]], NA)
  nope <- frag[!have]
  c(failures, sprintf("%s: %s: no #%s in %s", where[nope], what[nope], r$frag[nope], r$target[nope]))
}

redirect_rules <- function(ctx) {
  if (exists("_redirects", envir = ctx$cache, inherits = FALSE)) return(get("_redirects", envir = ctx$cache, inherits = FALSE))
  path <- file.path(ctx$site$dir, "_redirects")
  res <- NULL
  if (file.exists(path)) {
    lines <- strsplit(read_text(path), "\n", fixed = TRUE)[[1]]
    body <- trimws(lines)
    keep <- nzchar(body) & !startsWith(body, "#")
    fields <- strsplit(body[keep], "[ \t]+")
    res <- list(lines = lines, line_no = which(keep), fields = fields,
                source = vapply(fields, function(f) f[1], ""),
                dest = vapply(fields, function(f) if (length(f) >= 2L) f[2] else NA_character_, ""))
  }
  assign("_redirects", res, envir = ctx$cache)
  res
}

sitemap_urls <- function(ctx) {
  path <- file.path(ctx$site$dir, "sitemap.xml")
  if (!file.exists(path)) return(NULL)
  doc <- tryCatch(xml2::read_xml(read_bytes(path)), error = function(e) NULL)
  if (is.null(doc)) return(NA_character_)
  xml2::xml_text(xml2::xml_find_all(xml2::xml_ns_strip(doc), "//loc"))
}

# The most frequent entries of a count_by() result as records for the JSON report.
top_counts <- function(h, n = 10L) {
  lapply(seq_len(min(n, length(h))), function(i) list(host = names(h)[i], count = h[[i]]))
}

check_links <- function(ctx) {
  a <- ctx$attrs
  u <- a[a$name %in% URL_ATTRS, c("page", "name", "value")]
  sets <- u$name %in% c("srcset", "imagesrcset")
  parts <- lapply(u$value[sets], srcset_urls)
  refs <- data.frame(page = c(u$page[!sets], rep(u$page[sets], lengths(parts))),
                     attr = c(u$name[!sets], rep(u$name[sets], lengths(parts))),
                     url = c(u$value[!sets], unlist(parts, use.names = FALSE)), stringsAsFactors = FALSE)
  p <- refs$url |> split_urls()
  kind <- url_kind(p)
  inside <- kind == "internal"
  bases <- unname(vapply(ctx$pages, function(x) x$url, "")[refs$page[inside]])
  r <- resolve_urls(subset_urls(p, inside), bases)
  failures <- resolution_failures(ctx, refs$page[inside], paste(refs$attr[inside], refs$url[inside]), r)
  bad <- kind == "malformed"
  failures <- c(failures, sprintf("%s: %s %s: not a URL (http without a host)", refs$page[bad], refs$attr[bad], refs$url[bad]))
  n_fragments <- sum(inside & nzchar(p$frag) & p$frag != "top")

  # _redirects: the destinations are root-relative page URLs, possibly with #post-N
  rules <- redirect_rules(ctx)
  n_dest <- 0L
  if (!is.null(rules)) {
    dest <- rules$dest[!is.na(rules$dest)]
    pd <- split_urls(dest)
    plain <- url_kind(pd) == "internal" & !grepl("[*:]", pd$path)
    n_dest <- sum(plain)
    rd <- resolve_urls(subset_urls(pd, plain), rep("/", sum(plain)))
    failures <- c(failures, resolution_failures(ctx, rep("_redirects", sum(plain)), paste("destination", dest[plain]), rd))
  }

  # sitemap.xml: every <loc> is a URL of the forum host and resolves
  locs <- sitemap_urls(ctx)
  n_loc <- 0L
  if (length(locs) == 1L && is.na(locs)) {
    failures <- c(failures, "sitemap.xml: not well-formed XML")
  } else if (!is.null(locs)) {
    n_loc <- length(locs)
    ps <- split_urls(locs)
    foreign <- ps$host != FORUM_HOST
    failures <- c(failures, sprintf("sitemap.xml: <loc> %s is not on the forum host", locs[foreign]))
    rs <- resolve_urls(subset_urls(ps, !foreign), rep("/", sum(!foreign)))
    failures <- c(failures, resolution_failures(ctx, rep("sitemap.xml", sum(!foreign)), paste("<loc>", locs[!foreign]), rs))
  }
  failures <- unique(failures)

  ext <- kind == "external"
  hosts <- p$host[ext] |> count_by()
  rows <- list(
    make_row("4", "Internal links", verdict(failures),
             sprintf(paste("%d URLs in %d pages: %d internal (%d with a #fragment) resolve;",
                           "%d _redirects destinations, %d sitemap URLs; %d misses"),
                     nrow(refs), length(ctx$pages), sum(inside), n_fragments, n_dest, n_loc, length(failures)),
             failures, data = list(urls = nrow(refs), internal = sum(inside), fragments = n_fragments,
                                   redirect_destinations = n_dest, sitemap_urls = n_loc)),
    make_row("4b", "External URLs", "INFO",
             sprintf("%d external URLs on %d hosts", sum(ext), length(hosts)),
             lines = sprintf("%s: %d", names(hosts)[seq_len(min(10L, length(hosts)))], utils::head(hosts, 10L)),
             data = list(urls = sum(ext), hosts = length(hosts), top_hosts = top_counts(hosts))))
  rows
}

# ---- check 5: assets ---------------------------------------------------------------------------

# A path under one of the asset directories, as an absolute, protocol-relative or root-relative URL, anywhere
# in a string (src, srcset, href, data-* ...). A root-relative match must not be the tail of another host's URL.
ASSET_RE <- sprintf("(?<![A-Za-z0-9_.~%%:/-])(?:(?i:(?:https?:)?//%s))?/(?:%s)/[^\\s\"'<>?#,)&\\\\]*",
                    gsub(".", "\\.", FORUM_HOST, fixed = TRUE), paste(ASSET_DIRS, collapse = "|"))

# Every asset URL in the cooked HTML of raw/: decoded path (with the leading slash) and where it is used.
asset_references <- function(topics) {
  path <- character()
  topic <- post <- integer()
  for (t in topics) {
    found <- regmatches(t$cooked, gregexpr(ASSET_RE, t$cooked, perl = TRUE))
    n <- lengths(found)
    path <- c(path, unlist(found, use.names = FALSE))
    topic <- c(topic, rep(t$id, sum(n)))
    post <- c(post, rep(t$number, n))
  }
  path <- sub("(?i)^(?:https?:)?//[^/]+", "", path, perl = TRUE)
  data.frame(path = percent_decode_all(sub("[.;:!]+$", "", path)), topic = topic, post = post, stringsAsFactors = FALSE)
}

# Documents first, then everything else, images last: a missing slide deck matters more than a missing avatar.
asset_rank <- function(path) {
  name <- basename(path)
  ext <- ifelse(grepl("\\.", name), tolower(sub("^.*\\.", "", name)), "")
  ifelse(ext %in% DOCUMENT_EXTENSIONS, 0L, ifelse(ext %in% IMAGE_EXTENSIONS, 2L, 1L))
}

# "uploads/default/original", "images/emoji", "uploads/short-url" ...
asset_kind <- function(rel) {
  vapply(strsplit(rel, "/", fixed = TRUE), function(s) {
    dirs <- s[-length(s)]
    if (length(dirs) == 0L) return("(top level)")
    keep <- if (dirs[1] == "uploads" && length(dirs) >= 2L && dirs[2] == "default") 3L else 2L
    paste(utils::head(dirs, keep), collapse = "/")
  }, "")
}

check_assets <- function(ctx) {
  files <- ctx$site$files
  refs <- asset_references(ctx$topics)
  rel <- sub("^/", "", refs$path)
  avatar <- sub("/.*$", "", rel) %in% AVATAR_DIRS
  gone <- !avatar & !rel %in% files
  missed <- unique(refs$path[gone]) |> sorted()
  missed <- missed[order(asset_rank(missed), missed, method = "radix")]
  use <- vapply(missed, function(p) {
    i <- gone & refs$path == p
    inline(unique(sprintf("topic %d post %d", refs$topic[i], refs$post[i])), 3L)
  }, "", USE.NAMES = FALSE)
  failures <- sprintf("%s (used in %s)", missed, use)

  # raw/assets/ must be in the site, byte for byte, and the site holds nothing else but what is generated
  assets <- ctx$raw_assets$files
  absent <- assets[!assets %in% files]
  present <- setdiff(assets, absent)
  rawp <- file.path(ctx$opts$raw, "assets", present)
  sitep <- file.path(ctx$site$dir, present)
  equal_size <- file.size(rawp) == file.size(sitep)
  differ <- present[!equal_size]
  same <- which(equal_size)
  differ <- c(differ, present[same][vapply(same, function(i) sha256_of(rawp[i]) != sha256_of(sitep[i]), NA)])
  allowed <- c(ctx$page_files, FIXED_FILES, assets)
  stray <- c(files[!files %in% allowed & !startsWith(files, "pagefind/")], ctx$site$other)
  failures <- c(failures, sprintf("asset file missing from the site: %s", absent),
                sprintf("asset file differs from raw/assets (SHA-256): %s", sorted(differ)),
                sprintf("file in the site that is neither generated nor an asset: %s", sorted(stray)))
  kinds <- count_by(asset_kind(assets))
  make_row("5", "Assets", verdict(failures),
           sprintf(paste("%d asset files, %d byte-identical in the site; posts use %d distinct asset paths:",
                         "%d missing, %d avatar paths intentionally omitted; %d stray files"),
                   length(assets), length(present) - length(differ), length(unique(refs$path)), length(missed),
                   length(unique(refs$path[avatar])), length(stray)),
           failures, lines = sprintf("%s: %d files", names(kinds), kinds),
           data = list(asset_files = length(assets), byte_identical = length(present) - length(differ),
                       asset_urls = nrow(refs), distinct_asset_paths = length(unique(refs$path)),
                       missing_paths = length(missed), omitted_avatar_paths = length(unique(refs$path[avatar])),
                       omitted_avatar_references = sum(avatar), stray_files = length(stray),
                       kinds = lapply(seq_along(kinds), function(i) list(kind = names(kinds)[i], files = kinds[[i]]))))
}

# ---- check 6: personal data in the output ------------------------------------------------------

count_perl <- function(re, x) {
  m <- gregexpr(re, x, perl = TRUE)[[1]]
  if (m[1L] == -1L) 0L else length(m)
}

count_fixed <- function(pattern, x) {
  m <- gregexpr(pattern, x, fixed = TRUE)[[1]]
  if (m[1L] == -1L) 0L else length(m)
}

# Addresses the redaction left in place on purpose (general addresses of organisations), each with the number of
# times it was kept: read from the redacted tree's own report (redaction-report.json, allowlist$addresses; no key
# means none). They are not leaks: address_matches() skips them (whole addresses, any letter case), and check 6a
# separately requires each of them to be in the site exactly as often as the report says.
ALLOWED_KEPT <- integer()   # named by the lower-case address

allowlist_kept <- function(raw) {
  entries <- read_json_file(file.path(raw, REDACTION_REPORT))[["allowlist"]][["addresses"]]
  if (is.null(entries)) return(integer())
  if (!is.list(entries)) abort(REDACTION_REPORT, ": allowlist$addresses is not a list")
  one <- function(e) {
    a <- if (is.list(e)) e[["address"]]
    k <- if (is.list(e)) e[["kept"]]
    if (!is.character(a) || length(a) != 1L || !grepl("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", a, perl = TRUE) ||
        !is.numeric(k) || length(k) != 1L || is.na(k) || k < 0) {
      abort(REDACTION_REPORT, ": an allowlist entry is malformed")
    }
    stats::setNames(as.integer(k), tolower(a))
  }
  kept <- unlist(lapply(entries, one))
  if (is.null(kept)) return(integer())
  if (anyDuplicated(names(kept))) abort(REDACTION_REPORT, ": an allowlisted address is listed twice")
  kept
}

# Address-like strings of a character vector (case as found), without retina image names and without the
# allowlisted organisation addresses.
address_matches <- function(x) {
  m <- unlist(regmatches(x, gregexpr(EMAIL_RE, x, perl = TRUE)), use.names = FALSE)
  if (length(m) == 0L) return(character())
  m <- m[!tolower(sub("^.*\\.", "", m)) %in% NOT_AN_ADDRESS]
  m[!tolower(m) %in% names(ALLOWED_KEPT)]
}

# Every text the site publishes, as views to scan. A page is read three ways: its file text (attributes and
# comments included), its decoded attribute values, and the text a reader sees (entities decoded, text split
# by inline tags joined). Pagefind fragments are their decoded content and meta.
text_corpus <- function(ctx) {
  if (exists("corpus", envir = ctx$cache, inherits = FALSE)) return(get("corpus", envir = ctx$cache, inherits = FALSE))
  items <- lapply(ctx$pages, function(p) {
    seen <- if (is.null(p$doc)) "" else visible_text(as.character(p$doc), keep_code = TRUE)
    list(file = p$rel, kind = "page", views = c(p$src, paste(p$attrs$value, collapse = "\n"), seen))
  })
  plain <- ctx$site$files[ctx$site$files %in% FIXED_FILES]
  plain <- plain[!plain %in% names(ctx$pages)]
  items <- c(unname(items), lapply(plain, function(rel) {
    list(file = rel, kind = "text file", views = read_text(file.path(ctx$site$dir, rel)))
  }), lapply(ctx$fragments, function(f) {
    list(file = sprintf("%s (page %s)", f$rel, f$url), kind = "Pagefind fragment", views = paste(f$text, collapse = "\n"))
  }))
  assign("corpus", items, envir = ctx$cache)
  items
}

# 6a: nothing that looks like an address or a passcode, anywhere.
check_personal_scan <- function(ctx) {
  corpus <- text_corpus(ctx)
  rules <- c(email = "e-mail address", mailto = "mailto: link", param = "pwd/passcode/password parameter",
             passcode = "plain-text passcode")
  counts <- t(vapply(corpus, function(it) {
    n <- vapply(it$views, function(v) {
      c(length(address_matches(v)), count_fixed("mailto:", tolower(v)), count_perl(PARAM_RE, v), count_perl(PASSCODE_RE, v))
    }, integer(4L), USE.NAMES = FALSE)
    apply(matrix(n, nrow = 4L), 1L, max)
  }, integer(4L)))
  colnames(counts) <- names(rules)
  files <- vapply(corpus, function(it) it$file, "")
  failures <- unlist(lapply(names(rules), function(r) {
    i <- which(counts[, r] > 0L)
    sprintf("%s: %d %s(es)", files[i], counts[i, r], rules[[r]])
  }))
  kinds <- vapply(corpus, function(it) it$kind, "")
  # The allowlisted addresses are meant to be there: in the text readers see exactly as often as the redaction
  # report says, in the search index just as often, and nowhere else. Counts only: the addresses are not printed.
  allowed_total <- 0L
  if (length(ALLOWED_KEPT) > 0L) {
    count_in <- function(items, address, view) sum(vapply(items, function(it) {
      v <- if (view == "last") it$views[[length(it$views)]] else it$views[[1L]]
      m <- unlist(regmatches(v, gregexpr(EMAIL_RE, v, perl = TRUE)), use.names = FALSE)
      sum(tolower(m) == address)
    }, 1L))
    for (i in seq_along(ALLOWED_KEPT)) {
      in_pages <- count_in(corpus[kinds == "page"], names(ALLOWED_KEPT)[i], "last")
      in_index <- count_in(corpus[kinds == "Pagefind fragment"], names(ALLOWED_KEPT)[i], "first")
      in_text <- count_in(corpus[kinds == "text file"], names(ALLOWED_KEPT)[i], "first")
      allowed_total <- allowed_total + in_pages
      if (in_pages != ALLOWED_KEPT[[i]] || in_index != ALLOWED_KEPT[[i]] || in_text != 0L) {
        failures <- c(failures, sprintf(
          "allowlisted address #%d: %d in the pages, %d in the search index, %d in other text files; the redaction report says %d",
          i, in_pages, in_index, in_text, ALLOWED_KEPT[[i]]))
      }
    }
  }
  make_row("6a", "Personal data scan", verdict(failures),
           paste0(sprintf("%d pages, %d text files, %d Pagefind fragments scanned: %d e-mail, %d mailto:, %d passcode parameters, %d plain-text passcodes",
                          sum(kinds == "page"), sum(kinds == "text file"), sum(kinds == "Pagefind fragment"),
                          sum(counts[, "email"]), sum(counts[, "mailto"]), sum(counts[, "param"]), sum(counts[, "passcode"])),
                  if (length(ALLOWED_KEPT) > 0L) sprintf("; %d allowlisted organisation address(es) present, as the redaction report says", allowed_total)),
           unique(failures), data = list(items_scanned = length(corpus), email = sum(counts[, "email"]),
                                         mailto = sum(counts[, "mailto"]), passcode_parameters = sum(counts[, "param"]),
                                         plain_text_passcodes = sum(counts[, "passcode"]),
                                         allowlisted_addresses = length(ALLOWED_KEPT), allowlisted_present = allowed_total))
}

# 6b: counts only, and where the redactions are, so that a human can review every hit by hand on the live site.
check_inventory <- function(ctx) {
  a <- ctx$attrs
  links <- a[a$el == "a" & a$name == "href", ]
  p <- split_urls(links$value)
  zoom <- grepl("zoom", p$host, fixed = TRUE)
  redacted <- grepl("(?i)[?&;](?i:pwd|passcode|password)=REDACTED(?:[\\s\"'<>&#]|\\z)", links$value, perl = TRUE)
  osf <- grepl("view_only=", links$value, fixed = TRUE)
  dropbox <- grepl("rlkey=", links$value, fixed = TRUE)
  span_class <- function(cls) sum(a$el == "span" & a$name == "class" & grepl(sprintf("(^|\\s)%s(\\s|$)", cls), a$value))
  n_spans <- span_class("email-redacted")
  n_text <- sum(vapply(ctx$pages, function(pg) count_fixed("[email redacted]", pg$src), 1L))
  n_mentions <- span_class("mention")

  report <- read_json_file(file.path(ctx$opts$raw, REDACTION_REPORT))
  entries <- report[["per_file"]] %||% list()
  files <- vapply(entries, function(e) as.character(e[["file"]]), "")
  rules <- vapply(entries, function(e) as.character(e[["rule"]]), "")
  n <- vapply(entries, function(e) as.integer(e[["n"]]), 1L)
  table_lines <- character()
  table_data <- list()
  for (f in sorted(unique(files))) {
    i <- which(files == f)
    id <- if (grepl("^topic/[0-9]+\\.json$", f)) sub("^topic/([0-9]+)\\.json$", "\\1", f) else NA_character_
    rel <- if (!is.na(id) && id %in% names(ctx$expected$topic)) ctx$expected$topic[[id]] else NULL
    marked <- integer()
    if (!is.null(rel)) {
      pp <- page_posts(ctx, rel)
      if (!is.null(pp)) {
        marked <- pp$number[vapply(pp$nodes, function(node) {
          length(xml2::xml_find_all(node, sprintf(".//span[%s]", class_xp("email-redacted")))) > 0L ||
            grepl("[email redacted]", xml2::xml_text(node), fixed = TRUE)
        }, NA)]
        marked <- marked[!is.na(marked)]
      }
    }
    what <- paste(sprintf("%s x%d", rules[i], n[i]), collapse = ", ")
    table_lines <- c(table_lines, sprintf("%s: %s%s%s", if (is.na(id)) f else paste("topic", id), what,
                                          if (!is.null(rel)) paste0("; archive page ", page_url(rel)) else "",
                                          if (length(marked) > 0L) paste0("; markers in post(s) ", inline(sort(marked), 20L)) else ""))
    table_data[[length(table_data) + 1L]] <- list(
      file = f, topic = if (is.na(id)) NULL else as.integer(id), archive_page = if (is.null(rel)) NULL else page_url(rel),
      rules = lapply(i, function(j) list(rule = rules[j], count = n[j])), posts_with_markers = as.list(sort(marked)))
  }
  make_row("6b", "Redaction inventory", "INFO",
           sprintf(paste("zoom links %d (%d with a REDACTED passcode); OSF view_only %d, Dropbox rlkey %d (accepted);",
                         "email-redacted spans %d, \"[email redacted]\" %d; mentions %d; %d redactions in %d files"),
                   sum(zoom), sum(zoom & redacted), sum(osf), sum(dropbox), n_spans, n_text, n_mentions,
                   as.integer(report[["total_redactions"]] %||% sum(n)), length(unique(files))),
           lines = table_lines,
           data = list(zoom_links = sum(zoom), zoom_links_with_redacted_passcode = sum(zoom & redacted), osf_view_only_links = sum(osf),
                       dropbox_rlkey_links = sum(dropbox), email_redacted_spans = n_spans, email_redacted_text = n_text,
                       mentions = n_mentions, redaction_report = table_data))
}

# The unredacted values: addresses, passcode parameter values and plain-text passcodes found in the string
# values of --verbatim's JSON files (JSON escapes decoded). A value is kept in memory only, with the kind and
# the place it came from; it is never printed or stored.
verbatim_values <- function(dir) {
  files <- list_tree(dir)$files
  files <- files[grepl("\\.json$", files) & !startsWith(files, "assets/") & files != MANIFEST_FILE]
  vals <- list(kind = character(), value = character(), origin = character())
  take <- function(strings, origin) {
    add <- function(kind, v) {
      v <- v[nzchar(v)]
      vals$kind <<- c(vals$kind, rep(kind, length(v)))
      vals$value <<- c(vals$value, v)
      vals$origin <<- c(vals$origin, rep(origin, length(v)))
    }
    strings <- strings[grepl("@|=|:", strings)]
    if (length(strings) == 0L) return(invisible())
    add("e-mail address", address_matches(strings))
    param <- unlist(regmatches(strings, gregexpr(PARAM_VALUE_RE, strings, perl = TRUE)), use.names = FALSE)
    add("passcode parameter", setdiff(sub("^[?&;][A-Za-z]+=", "", param), "REDACTED"))
    code <- unlist(regmatches(strings, gregexpr(PASSCODE_VALUE, strings, perl = TRUE)), use.names = FALSE)
    add("plain-text passcode", sub("^.*[:=][ \t]*", "", code))
  }
  strings_of <- function(x) rapply(x, identity, classes = "character", how = "unlist")
  for (f in files) {
    j <- read_json_file(file.path(dir, f))
    posts <- j[["post_stream"]][["posts"]]
    if (is.list(posts)) {
      for (p in posts) take(strings_of(p), sprintf("%s post %s", f, p[["post_number"]] %||% "?"))
      j[["post_stream"]][["posts"]] <- NULL
    }
    take(strings_of(j), f)
  }
  keep <- !duplicated(paste(vals$kind, ifelse(vals$kind == "e-mail address", tolower(vals$value), vals$value)))
  lapply(vals, function(x) x[keep])
}

# 6c: none of the unredacted values may be in the site.
check_verbatim <- function(ctx) {
  dir <- ctx$opts$verbatim
  if (!dir.exists(dir)) {
    return(make_row("6c", "Unredacted values", "INFO", sprintf("skipped: %s does not exist (local only, never committed)", dir)))
  }
  mpath <- file.path(dir, MANIFEST_FILE)
  if (file.exists(mpath) && !is.null(read_json_file(mpath)[["derived_from"]])) {
    abort(dir, " is itself a redacted copy (its ", MANIFEST_FILE, " has derived_from); --verbatim must be the unredacted harvest")
  }
  v <- verbatim_values(dir)
  corpus <- text_corpus(ctx)
  hay <- unlist(lapply(corpus, function(it) it$views), use.names = FALSE)
  owner <- rep(seq_along(corpus), vapply(corpus, function(it) length(it$views), 1L))
  hay_lower <- tolower(hay)
  where <- lapply(seq_along(v$value), function(i) {
    hit <- switch(v$kind[i],
                  "e-mail address" = grepl(tolower(v$value[i]), hay_lower, fixed = TRUE),
                  # case-insensitive and also as the hyphenated slug Discourse makes of a heading that held the whole
                  # link (heading anchor names and hrefs carry a lower-cased copy of the passcode)
                  "passcode parameter" = grepl(tolower(v$value[i]), hay_lower, fixed = TRUE) |
                    grepl(gsub("^-+|-+$", "", gsub("[^a-z0-9]+", "-", tolower(v$value[i]))), hay_lower, fixed = TRUE),
                  grepl(sprintf("(?<![A-Za-z0-9])%s(?![A-Za-z0-9])", v$value[i]), hay, perl = TRUE))
    sorted(unique(vapply(corpus[unique(owner[hit])], function(it) it$file, "", USE.NAMES = FALSE)))
  })
  found <- which(lengths(where) > 0L)
  failures <- vapply(found, function(i) {
    sprintf("a %s from %s is in the site: %s", v$kind[i], v$origin[i], inline(where[[i]], 3L))
  }, "")
  kinds <- c("e-mail address", "passcode parameter", "plain-text passcode")
  searched <- vapply(kinds, function(k) sum(v$kind == k), 1L)
  # nothing to search for is not a pass: --verbatim may not be the harvest it should be
  make_row("6c", "Unredacted values", if (length(v$value) == 0L) "INFO" else verdict(failures),
           sprintf("%d distinct values searched (%d e-mail addresses, %d passcode parameter values, %d plain-text passcodes); %d found",
                   length(v$value), searched[[1L]], searched[[2L]], searched[[3L]], length(found)),
           failures, data = list(values_searched = length(v$value), e_mail_addresses = searched[[1L]],
                                 passcode_parameter_values = searched[[2L]], plain_text_passcodes = searched[[3L]],
                                 values_found = length(found)))
}

# ---- check 6d: attachments ---------------------------------------------------------------------

# PDF text, best effort in base R: the file bytes, and every stream that inflates (images and font programs
# left out). In the streams of text objects the strings of "[...] TJ" arrays (kerning numbers ignored) and of
# "(...) Tj" are read, through the font's ToUnicode CMap where the font is selected by a resource name that
# stands for one font only. Not read: object streams, fonts with a custom encoding and no ToUnicode map, text
# that is a picture. The result is a lower bound.
PDF_STR         <- "\\((?:[^\\\\()]++|\\\\.|\\((?:[^\\\\()]++|\\\\.)*+\\))*+\\)"
PDF_HEX         <- "<[0-9A-Fa-f\\s]*>"
PDF_ITEM        <- sprintf("(?s)%s|%s", PDF_STR, PDF_HEX)
PDF_TJ          <- sprintf("(?s)\\[(?:\\s*(?:%s|%s|[-+]?[0-9]*\\.?[0-9]+))*+\\s*\\]\\s*TJ", PDF_STR, PDF_HEX)
PDF_TJ1         <- sprintf("(?s)(?:%s|%s)\\s*Tj", PDF_STR, PDF_HEX)
PDF_OBJ         <- "(?<![0-9])([0-9]+)[ \\t\\r\\n]+[0-9]+[ \\t\\r\\n]+obj(?![A-Za-z])"
PDF_FONT_REF    <- "/([^\\s/<>\\[\\]()%]+)\\s+([0-9]+)\\s+[0-9]+\\s+R"
PDF_TF          <- "/([^\\s/<>\\[\\]()%]+)\\s+[-+]?[0-9]*\\.?[0-9]+\\s+Tf"
PDF_MAX_STREAMS <- 20000L              # streams read per file: a bound on the work, not a tuning knob
PDF_SKIP        <- "/Subtype\\s*/Image|/Length1|/FontFile|/Subtype\\s*/(?:Type1C|CIDFontType0C|OpenType)"

# The bytes as one string, one character per byte (NUL becomes a space); only for use with useBytes = TRUE or iconv.
byte_string <- function(bytes) rawToChar(replace(bytes, bytes == as.raw(0L), as.raw(32L)))

# Bytes of a literal string: its body (one character per byte, escapes intact) with the escapes resolved.
pdf_literal_bytes <- function(body) {
  b <- utf8ToInt(body)
  if (!any(b == 92L)) return(b)
  out <- integer()
  i <- 1L
  n <- length(b)
  while (i <= n) {
    if (b[i] != 92L || i == n) {
      out <- c(out, b[i])
      i <- i + 1L
    } else if (b[i + 1L] >= 48L && b[i + 1L] <= 55L) {
      j <- i + 1L
      v <- 0L
      while (j <= n && j <= i + 3L && b[j] >= 48L && b[j] <= 55L) {
        v <- v * 8L + (b[j] - 48L)
        j <- j + 1L
      }
      out <- c(out, bitwAnd(v, 255L))
      i <- j
    } else {
      out <- c(out, switch(as.character(b[i + 1L]), "110" = 10L, "114" = 13L, "116" = 9L, "98" = 8L, "102" = 12L,
                           "10" = , "13" = integer(), b[i + 1L]))
      i <- i + 2L
    }
  }
  out
}

pdf_hex_bytes <- function(hex) {
  d <- gsub("[^0-9A-Fa-f]", "", hex)
  if (nchar(d) %% 2L == 1L) d <- paste0(d, "0")
  if (!nzchar(d)) integer() else strtoi(substring(d, seq(1L, nchar(d), 2L), seq(2L, nchar(d), 2L)), 16L)
}

# One byte vector per string token, "(...)" or "<hex>".
pdf_token_bytes <- function(tokens) {
  lapply(tokens, function(t) {
    inner <- substr(t, 2L, nchar(t) - 1L)
    if (startsWith(t, "(")) pdf_literal_bytes(inner) else pdf_hex_bytes(inner)
  })
}

# UTF-16BE hex digits as text.
utf16_text <- function(hex) {
  units <- if (nchar(hex) < 4L) strtoi(hex, 16L) else strtoi(substring(hex, seq(1L, nchar(hex) - 3L, 4L), seq(4L, nchar(hex), 4L)), 16L)
  text <- intToUtf8(units, allow_surrogate_pairs = TRUE)
  if (is.na(text)) "" else text
}

# A ToUnicode CMap: single codes (bfchar, ranges given as arrays) and ranges whose text counts up from one character.
parse_cmap <- function(cmap) {
  width <- regmatches(cmap, regexec("begincodespacerange\\s*<([0-9A-Fa-f]+)>", cmap))[[1]]
  width <- if (length(width) == 2L) max(1L, nchar(width[2L]) %/% 2L) else 1L
  hex_tokens <- function(x) {
    tk <- regmatches(x, gregexpr("<[0-9A-Fa-f]+>", x))[[1]]
    substr(tk, 2L, nchar(tk) - 1L)
  }
  code <- integer()
  text <- character()
  lo <- hi <- first <- integer()
  for (block in regmatches(cmap, gregexpr("(?s)beginbfchar(.*?)endbfchar", cmap, perl = TRUE))[[1]]) {
    tk <- hex_tokens(block)
    if (length(tk) < 2L) next
    odd <- seq(1L, length(tk) - 1L, 2L)
    code <- c(code, strtoi(tk[odd], 16L))
    text <- c(text, vapply(tk[odd + 1L], utf16_text, "", USE.NAMES = FALSE))
  }
  entry <- "<[0-9A-Fa-f]+>\\s*<[0-9A-Fa-f]+>\\s*(?:<[0-9A-Fa-f]+>|\\[(?:\\s*<[0-9A-Fa-f]+>)+\\s*\\])"
  for (block in regmatches(cmap, gregexpr("(?s)beginbfrange(.*?)endbfrange", cmap, perl = TRUE))[[1]]) {
    for (e in regmatches(block, gregexpr(entry, block, perl = TRUE))[[1]]) {
      tk <- hex_tokens(e)
      if (length(tk) == 3L) {
        lo <- c(lo, strtoi(tk[1L], 16L))
        hi <- c(hi, strtoi(tk[2L], 16L))
        first <- c(first, strtoi(substr(tk[3L], 1L, 4L), 16L))
      } else {
        code <- c(code, strtoi(tk[1L], 16L) + seq_len(length(tk) - 2L) - 1L)
        text <- c(text, vapply(tk[-(1:2)], utf16_text, "", USE.NAMES = FALSE))
      }
    }
  }
  o <- order(lo)
  list(width = width, code = code, text = text, lo = lo[o], hi = hi[o], first = first[o])
}

cmap_text <- function(map, codes) {
  out <- rep("", length(codes))
  i <- match(codes, map$code)
  out[!is.na(i)] <- map$text[i[!is.na(i)]]
  miss <- which(is.na(i))
  if (length(map$lo) > 0L && length(miss) > 0L) {
    r <- findInterval(codes[miss], map$lo)
    ok <- r > 0L & codes[miss] <= map$hi[pmax(r, 1L)]
    text <- intToUtf8(map$first[r[ok]] + (codes[miss][ok] - map$lo[r[ok]]), multiple = TRUE)
    out[miss[ok]] <- ifelse(is.na(text), "", text)
  }
  out
}

# One text per token: through the font's CMap (codes of one or two bytes, as its codespace says) or as plain bytes.
decode_tokens <- function(bytes, map = NULL) {
  if (is.null(map)) return(vapply(bytes, function(b) intToUtf8(b[b >= 32L & b != 127L]), ""))
  codes <- lapply(bytes, function(b) {
    if (map$width != 2L) b else if (length(b) < 2L) integer() else b[seq(1L, length(b) - 1L, 2L)] * 256L + b[seq(2L, length(b), 2L)]
  })
  text <- cmap_text(map, unlist(codes, use.names = FALSE))
  unname(vapply(split(text, factor(rep(seq_along(codes), lengths(codes)), levels = seq_along(codes))), paste0, "", collapse = ""))
}

# The objects of a PDF as byte ranges: number, start of the body, end of the body (where the next object starts).
pdf_objects <- function(bytes, s) {
  hdr <- gregexpr(PDF_OBJ, s, perl = TRUE, useBytes = TRUE)[[1]]
  if (hdr[1L] < 0L) return(list(num = integer(), from = integer(), to = integer()))
  list(num = as.integer(sub(PDF_OBJ, "\\1", regmatches(s, list(hdr))[[1]], perl = TRUE)),
       from = as.integer(hdr) + attr(hdr, "match.length"), to = c(as.integer(hdr)[-1L] - 1L, length(bytes)))
}

# The first `max` bytes of object i (up to byte `upto` if given) as a string.
pdf_head <- function(bytes, objs, i, upto = Inf, max = 2000L) {
  to <- min(objs$to[i], upto, objs$from[i] + max - 1L)
  if (to < objs$from[i]) "" else byte_string(bytes[objs$from[i]:to])
}

# Resource name -> ToUnicode CMap, for the fonts of the PDF that have one and whose name is not used for
# another font elsewhere in the file (the page that selects a font is not looked up).
pdf_font_maps <- function(bytes, s, objs) {
  refs <- regmatches(s, gregexpr(PDF_FONT_REF, s, perl = TRUE, useBytes = TRUE))[[1]]
  if (length(refs) == 0L) return(list())
  pair <- data.frame(name = sub(PDF_FONT_REF, "\\1", refs, perl = TRUE), obj = as.integer(sub(PDF_FONT_REF, "\\2", refs, perl = TRUE)),
                     stringsAsFactors = FALSE)
  pair <- pair[!duplicated(pair) & pair$obj %in% objs$num, ]
  heads <- lapply(pair$obj, function(n) pdf_head(bytes, objs, match(n, objs$num)))
  font <- vapply(heads, function(h) grepl("/Type\\s*/Font(?![A-Za-z])", h, perl = TRUE, useBytes = TRUE), NA)
  pair <- pair[font, ]
  heads <- heads[font]
  if (nrow(pair) == 0L) return(list())
  tounicode <- vapply(heads, function(h) {
    m <- regmatches(h, regexec("/ToUnicode\\s+([0-9]+)\\s+[0-9]+\\s+R", h, perl = TRUE, useBytes = TRUE))[[1]]
    if (length(m) == 2L) as.integer(m[2L]) else NA_integer_
  }, 1L)
  fonts_per_name <- tapply(pair$obj, pair$name, function(x) length(unique(x)))
  cmaps <- list()
  maps <- list()
  for (i in which(!is.na(tounicode) & fonts_per_name[pair$name] == 1L)) {
    key <- as.character(tounicode[i])
    if (is.null(cmaps[[key]])) {
      k <- match(tounicode[i], objs$num)
      body <- bytes[objs$from[k]:objs$to[k]]
      text <- byte_string(body)
      start <- regexpr("(?<!end)stream\\r?\\n", text, perl = TRUE, useBytes = TRUE)
      end <- regexpr("endstream", text, fixed = TRUE, useBytes = TRUE)
      cmaps[[key]] <- FALSE
      if (start > 0L) {
        data <- body[(start + attr(start, "match.length")):(if (end > 0L) end - 1L else length(body))]
        cmap <- iconv(byte_string(tryCatch(suppressWarnings(memDecompress(data, "gzip")), error = function(e) data)), "latin1", "UTF-8")
        if (grepl("beginbf", cmap, fixed = TRUE)) cmaps[[key]] <- parse_cmap(cmap)
      }
    }
    if (is.list(cmaps[[key]])) maps[[pair$name[i]]] <- cmaps[[key]]
  }
  maps
}

# The text of a content stream, one string per TJ array and per Tj string.
pdf_text_runs <- function(d, maps) {
  find <- function(re) {
    m <- gregexpr(re, d, perl = TRUE, useBytes = TRUE)[[1]]
    if (m[1L] < 0L) return(list(pos = integer(), text = character()))
    list(pos = as.integer(m), text = iconv(regmatches(d, list(m))[[1]], "latin1", "UTF-8"))
  }
  select <- find(PDF_TF)
  select$text <- sub(PDF_TF, "\\1", select$text, perl = TRUE)
  # the font in force where a string occurs: the last Tf before it
  font_at <- function(pos) {
    k <- findInterval(pos, select$pos)
    ifelse(k > 0L, select$text[pmax(k, 1L)], NA_character_)
  }
  decode <- function(tokens, font) {
    text <- character(length(tokens))
    for (nm in unique(font)) {
      i <- if (is.na(nm)) which(is.na(font)) else which(font == nm)
      text[i] <- decode_tokens(pdf_token_bytes(tokens[i]), if (is.na(nm)) NULL else maps[[nm]])
    }
    text
  }
  runs <- character()
  arrays <- find(PDF_TJ)
  if (length(arrays$text) > 0L) {
    items <- regmatches(arrays$text, gregexpr(PDF_ITEM, arrays$text, perl = TRUE))
    owner <- rep(seq_along(items), lengths(items))
    text <- decode(unlist(items, use.names = FALSE), font_at(arrays$pos)[owner])
    runs <- vapply(split(text, factor(owner, levels = seq_along(items))), paste0, "", collapse = "")
  }
  singles <- find(PDF_TJ1)
  c(runs, decode(sub("(?s)\\s*Tj$", "", singles$text, perl = TRUE), font_at(singles$pos)))
}

# Address-like strings in a PDF: the larger of what the bytes and inflated streams show as they are and what
# the text of the content streams reads like (joined as it is, and with a space between strings).
pdf_address_count <- function(path) {
  bytes <- read_bytes(path)
  s <- byte_string(bytes)
  plain <- length(address_matches(iconv(s, "latin1", "UTF-8")))
  objs <- pdf_objects(bytes, s)
  maps <- tryCatch(pdf_font_maps(bytes, s, objs), error = function(e) list())
  runs <- character()
  starts <- gregexpr("(?<!end)stream\\r?\\n", s, perl = TRUE, useBytes = TRUE)[[1]]
  if (starts[1L] > 0L) {
    ends <- gregexpr("endstream", s, fixed = TRUE, useBytes = TRUE)[[1]]
    from <- starts + attr(starts, "match.length")
    nxt <- findInterval(from - 0.5, ends) + 1L
    owner <- findInterval(starts, objs$from)
    for (k in utils::head(seq_along(starts), PDF_MAX_STREAMS)) {
      if (nxt[k] > length(ends)) next
      to <- ends[nxt[k]] - 1L
      if (to < from[k] || to - from[k] > 2e7) next
      dict <- if (owner[k] > 0L) pdf_head(bytes, objs, owner[k], upto = starts[k]) else ""
      if (grepl(PDF_SKIP, dict, perl = TRUE, useBytes = TRUE)) next
      dec <- tryCatch(suppressWarnings(memDecompress(bytes[from[k]:to], "gzip")), error = function(e) NULL)
      if (is.null(dec) && owner[k] > 0L && !grepl("/Filter", dict, fixed = TRUE)) dec <- bytes[from[k]:to]
      if (is.null(dec) || length(dec) > 8e6) next
      d <- byte_string(dec)
      if (grepl("@", d, fixed = TRUE, useBytes = TRUE)) plain <- plain + length(address_matches(iconv(d, "latin1", "UTF-8")))
      if (grepl("(?:^|\\s)BT\\s", d, perl = TRUE, useBytes = TRUE)) {
        runs <- c(runs, tryCatch(pdf_text_runs(d, maps), error = function(e) character()))
      }
    }
  }
  max(plain, length(address_matches(paste(runs, collapse = ""))), length(address_matches(paste(runs, collapse = " "))))
}

# Word: every XML and relationship part of the package, as it is and with the tags stripped (text split into
# runs by Word is joined again).
docx_address_count <- function(path, entries) {
  parts <- entries[grepl("\\.(xml|rels)$", entries$Name), ]
  raw_text <- stripped <- character()
  for (i in seq_len(nrow(parts))) {
    con <- unz(path, parts$Name[i], "rb")
    b <- tryCatch(readBin(con, "raw", n = parts$Length[i] + 1L), finally = close(con))
    s <- bytes_to_utf8(b)$text
    raw_text <- c(raw_text, s)
    stripped <- c(stripped, gsub("<[^>]*>", "", gsub("</w:p>", "\n", s, fixed = TRUE), perl = TRUE))
  }
  max(length(address_matches(raw_text)), length(address_matches(stripped)))
}

# 6d: PDF and Word files by their magic bytes, and how many have an address-like string. Published as uploaded
# (accepted); this only tells a human where to look.
check_attachments <- function(ctx) {
  files <- ctx$site$files
  files <- files[!files %in% c(ctx$page_files, FIXED_FILES) & !startsWith(files, "pagefind/")]
  kind <- character(length(files))
  entries <- list()
  for (i in seq_along(files)) {
    path <- file.path(ctx$site$dir, files[i])
    head <- readBin(path, "raw", 1024L)
    if (grepl("%PDF-", byte_string(head), fixed = TRUE, useBytes = TRUE)) {
      kind[i] <- "PDF"
    } else if (length(head) >= 4L && identical(head[1:4], as.raw(c(0x50, 0x4b, 0x03, 0x04)))) {
      zip <- tryCatch(utils::unzip(path, list = TRUE), error = function(e) NULL)
      if (!is.null(zip) && "word/document.xml" %in% zip$Name) {
        kind[i] <- "Word"
        entries[[files[i]]] <- zip
      }
    }
  }
  found <- which(kind != "")
  n <- vapply(found, function(i) {
    path <- file.path(ctx$site$dir, files[i])
    tryCatch(if (kind[i] == "PDF") pdf_address_count(path) else docx_address_count(path, entries[[files[i]]]),
             error = function(e) NA_integer_)
  }, 1L)
  with <- !is.na(n) & n > 0L
  name <- files[found]
  kind <- kind[found]
  per_kind <- function(k) sprintf("%d of %d %s", sum(with & kind == k), sum(kind == k), if (k == "PDF") "PDFs" else "Word files")
  o <- order(-ifelse(is.na(n), 0L, n), name, method = "radix")
  make_row("6d", "Attachments", "INFO",
           sprintf("address-like strings in %s and %s (published as uploaded, accepted decision; a lower bound)%s",
                   per_kind("PDF"), per_kind("Word"),
                   if (anyNA(n)) sprintf("; %d files could not be read", sum(is.na(n))) else ""),
           lines = c("lower bound: fonts with a custom encoding and no ToUnicode map, object streams and scanned pages are not read",
                     sprintf("%s: %d", name[o][with[o]], n[o][with[o]])),
           data = list(pdf_files = sum(kind == "PDF"), word_files = sum(kind == "Word"),
                       pdf_files_with_address = sum(with & kind == "PDF"), word_files_with_address = sum(with & kind == "Word"),
                       files_unreadable = sum(is.na(n)),
                       files_with_address = lapply(which(with)[order(name[with], method = "radix")],
                                                   function(j) list(path = name[j], addresses = n[j]))))
}

# ---- check 7: spot-check preparation -----------------------------------------------------------

FEATURE_NAMES <- c(youtube = "YouTube blocks", thumbnails = "YouTube thumbnails", attachments = "attachments",
                   images = "images", lightboxes = "lightboxes", dates = "date spans", quotes = "quotes",
                   polls = "polls", oneboxes = "oneboxes")

# XPaths of the features that a human compares by eye. The archive page is searched inside its post bodies;
# the raw side is the cooked HTML itself, where a local date is a span and the page has a <time>.
feature_xpaths <- function(archive) {
  scope <- if (archive) sprintf("//div[%s]", class_xp("post-body")) else ""
  cls <- function(tag, c) sprintf("%s//%s[%s]", scope, tag, class_xp(c))
  c(youtube = cls("div", "lazyYT"), thumbnails = cls("img", "ytp-thumbnail-image"), attachments = cls("a", "attachment"),
    images = sprintf("%s//img[not(%s) and not(%s) and not(%s) and not(%s)]", scope, class_xp("emoji"),
                     class_xp("ytp-thumbnail-image"), class_xp("site-icon"), class_xp("avatar")),
    lightboxes = cls("a", "lightbox"),
    dates = if (archive) sprintf("%s//time", scope) else cls("span", "discourse-local-date"),
    quotes = cls("aside", "quote"), polls = cls("div", "poll"), oneboxes = cls("aside", "onebox"))
}

count_features <- function(doc, archive) {
  vapply(feature_xpaths(archive), function(xp) length(xml2::xml_find_all(doc, xp)), 1L)
}

check_spot <- function(ctx) {
  ids <- ctx$opts$spot
  by_id <- stats::setNames(ctx$topics, vapply(ctx$topics, function(t) as.character(t$id), ""))
  failures <- character()
  lines <- character()
  data <- list()
  for (id in ids) {
    t <- by_id[[as.character(id)]]
    if (is.null(t)) {
      failures <- c(failures, sprintf("--spot-check: topic %d is not in raw/", id))
      next
    }
    rel <- ctx$expected$topic[[as.character(id)]]
    page <- ctx$pages[[rel]]
    archive <- if (is.null(page) || is.null(page$doc)) NULL else count_features(page$doc, TRUE)
    raw_doc <- parse_html(paste0("<html><body>", paste(t$cooked[renderable(t)], collapse = "\n"), "</body></html>"))
    raw <- if (is.null(raw_doc)) NULL else count_features(raw_doc, FALSE)
    fmt <- function(x) if (is.null(x)) "page missing" else paste(sprintf("%s %d", FEATURE_NAMES, x), collapse = ", ")
    differ <- !is.null(archive) && !is.null(raw) && !identical(unname(archive), unname(raw))
    lines <- c(lines, sprintf("topic %d: %d post%s (%d rendered); live https://%s/t/%s/%d; archive %s", id, length(t$number),
                              if (length(t$number) == 1L) "" else "s", sum(renderable(t)), FORUM_HOST, t$slug, id, page_url(rel)),
               sprintf("    archive: %s", fmt(archive)),
               sprintf("    raw:     %s%s", fmt(raw), if (differ) "   <- counts differ" else ""))
    data[[length(data) + 1L]] <- list(
      topic = id, live_url = sprintf("https://%s/t/%s/%d", FORUM_HOST, t$slug, id), archive_url = page_url(rel),
      posts = length(t$number), rendered_posts = sum(renderable(t)),
      archive_features = as.list(archive), raw_features = as.list(raw))
  }
  make_row("7", "Spot-check", if (length(failures) > 0L) "FAIL" else "INFO",
           sprintf("%d topics prepared for a side-by-side comparison with the live forum (manual step)", length(data)),
           failures, lines, list(topics = data))
}

# ---- check 8: oneboxes and external content ----------------------------------------------------

check_external <- function(ctx) {
  a <- ctx$attrs
  external <- function(i) {
    p <- split_urls(a$value[i])
    p$host[url_kind(p) == "external"]
  }
  links <- external(a$el == "a" & a$name == "href")
  images <- external(a$el == "img" & a$name == "src")
  link_hosts <- count_by(links)
  image_hosts <- count_by(images)
  n <- stats::setNames(integer(4L), c("onebox", "inline", "youtube", "poll"))
  q <- c(onebox = sprintf("//aside[%s]", class_xp("onebox")), inline = sprintf("//a[%s]", class_xp("inline-onebox")),
         youtube = sprintf("//div[%s]", class_xp("lazyYT")), poll = sprintf("//div[%s]", class_xp("poll")))
  for (k in names(q)) {
    n[[k]] <- sum(vapply(ctx$pages, function(p) if (is.null(p$doc)) 0L else length(xml2::xml_find_all(p$doc, q[[k]])), 1L))
  }
  hosts_text <- function(h, n = 10L) {
    if (length(h) == 0L) "none" else paste(utils::head(sprintf("%s %d", names(h), h), n), collapse = ", ")
  }
  make_row("8", "Onebox and external inventory", "INFO",
           sprintf(paste("aside.onebox %d, a.inline-onebox %d, YouTube blocks %d, polls %d;",
                         "hot-linked images %d on %d hosts; external links %d on %d hosts (%s)"),
                   n[["onebox"]], n[["inline"]], n[["youtube"]], n[["poll"]], length(images), length(image_hosts),
                   length(links), length(link_hosts), hosts_text(link_hosts, 1L)),
           lines = c(sprintf("hot-linked images: %s", hosts_text(image_hosts)),
                     sprintf("external links, most frequent hosts: %s", hosts_text(link_hosts))),
           data = list(onebox_blocks = n[["onebox"]], inline_onebox_links = n[["inline"]], youtube_blocks = n[["youtube"]],
                       polls = n[["poll"]], hot_linked_images = length(images), hot_linked_image_hosts = top_counts(image_hosts),
                       external_links = length(links), external_link_hosts = length(link_hosts), top_external_link_hosts = top_counts(link_hosts)))
}

# ---- check 9: data minimisation ----------------------------------------------------------------

check_minimisation <- function(ctx) {
  a <- ctx$attrs
  found <- data.frame(page = character(), what = character(), stringsAsFactors = FALSE)
  note <- function(i, what) {
    if (any(i)) found <<- rbind(found, data.frame(page = a$page[i], what = what[i], stringsAsFactors = FALSE))
  }
  tokenised <- function(cls) grepl(sprintf("(^|\\s)%s(\\s|$)", cls), a$value)
  avatar <- a$el == "img" & a$name == "class" & tokenised("avatar")
  note(avatar, rep("<img class=\"avatar\">", nrow(a)))
  url <- a$name %in% URL_ATTRS & !a$name %in% c("srcset", "imagesrcset")
  p <- split_urls(a$value[url])
  inside <- url_kind(p) == "internal"
  path <- rep("", nrow(a))
  base <- unname(vapply(ctx$pages, function(x) x$url, "")[a$page[url][inside]])
  path[which(url)[inside]] <- resolve_urls(subset_urls(p, inside), base)$path
  user_link <- rep(FALSE, nrow(a))
  for (prefix in USER_PREFIXES) {
    under <- path == prefix | startsWith(path, paste0(prefix, "/"))
    note(under, rep(sprintf("link to a user or group page (under %s/)", prefix), nrow(a)))
    user_link <- user_link | under
  }
  js <- url & startsWith(tolower(gsub("[\\s\\x00-\\x1f]+", "", a$value, perl = TRUE)), "javascript:")
  note(js, rep("javascript: URL", nrow(a)))
  data_attr <- startsWith(a$name, "data-") & !a$name %in% ALLOWED_DATA_ATTRS
  note(data_attr, sprintf("attribute %s", a$name))
  handler <- grepl("^on[a-z]+$", a$name)
  note(handler, sprintf("inline event handler %s", a$name))

  forbidden_xpath <- paste(sprintf("//%s", c("script", FORBIDDEN_ELEMENTS)), collapse = " | ")
  n_script <- n_embedded <- n_strings <- 0L
  for (pg in ctx$pages) {
    if (is.null(pg$doc)) next
    el <- xml2::xml_name(xml2::xml_find_all(pg$doc, forbidden_xpath))
    bad <- if (pg$rel %in% SEARCH_WIDGET_PAGES) el[el != "script"] else el
    n_script <- n_script + sum(bad == "script")
    n_embedded <- n_embedded + sum(bad != "script")
    if (length(bad) > 0L) found <- rbind(found, data.frame(page = pg$rel, what = sprintf("<%s>", bad), stringsAsFactors = FALSE))
    low <- tolower(pg$src)
    for (s in FORBIDDEN_STRINGS) {
      n <- count_fixed(s, low)
      n_strings <- n_strings + n
      if (n > 0L) found <- rbind(found, data.frame(page = pg$rel, what = rep(sprintf("the string %s", s), n), stringsAsFactors = FALSE))
    }
  }
  tally <- count_by(sprintf("%s: %s", found$page, found$what))
  failures <- sprintf("%s (%d)", names(tally), tally)
  make_row("9", "Data minimisation", verdict(failures),
           sprintf(paste("%d pages: %d avatars, %d user/group links, %d data-* attributes, %d scripts outside the search and home pages,",
                         "%d iframe/object/embed/form, %d event handlers, %d javascript: URLs, %d forbidden strings"),
                   length(ctx$pages), sum(avatar), sum(user_link), sum(data_attr), n_script, n_embedded, sum(handler), sum(js), n_strings),
           failures, data = list(pages = length(ctx$pages), avatars = sum(avatar), user_links = sum(user_link),
                                 data_attributes = sum(data_attr), scripts_outside_widget_pages = n_script,
                                 iframe_object_embed_form = n_embedded, event_handlers = sum(handler), javascript_urls = sum(js),
                                 forbidden_strings = n_strings))
}

# ---- check 10: search index --------------------------------------------------------------------

check_search <- function(ctx) {
  files <- ctx$site$files
  ex <- ctx$expected
  want <- length(ex$topic) + length(ex$category) + 1L
  failures <- character()
  entry_rel <- "pagefind/pagefind-entry.json"
  count <- NA_integer_
  if (!entry_rel %in% files) {
    failures <- c(failures, sprintf("%s is missing (run make search)", entry_rel))
  } else {
    entry <- tryCatch(jsonlite::read_json(file.path(ctx$site$dir, entry_rel), simplifyVector = FALSE), error = function(e) NULL)
    if (is.null(entry)) {
      failures <- c(failures, sprintf("%s is not valid JSON", entry_rel))
    } else {
      count <- if (is.numeric(entry[["page_count"]])) as.integer(entry[["page_count"]]) else
        sum(vapply(entry[["languages"]] %||% list(), function(l) as.integer(l[["page_count"]] %||% 0L), 1L))
      if (count != want) failures <- c(failures, sprintf("%s: page_count %d, expected %d (topics + categories + 1)", entry_rel, count, want))
    }
  }
  frags <- ctx$fragments
  if (length(frags) != want) failures <- c(failures, sprintf("%d Pagefind fragment files, expected %d", length(frags), want))
  ok <- vapply(frags, function(f) f$ok, NA)
  failures <- c(failures, sprintf("fragment cannot be decoded (gzip, pagefind_dcd, JSON with url and content): %s",
                                  vapply(frags[!ok], function(f) f$rel, "")))
  urls <- vapply(frags[ok], function(f) f$url, "")
  target <- resolve_urls(split_urls(urls), rep("/", length(urls)))$target
  failures <- c(failures, sprintf("indexed URL is not a page of the site: %s", urls[!target %in% names(ctx$pages)]),
                sprintf("indexed twice: %s", unique(urls[duplicated(target)])))
  need <- c(ex$topic, ex$category, "index.html")
  failures <- c(failures, sprintf("page is not indexed: %s", page_url(need[!need %in% target])))
  make_row("10", "Search index", verdict(failures),
           sprintf("page_count %s (topics %d + categories %d + 1 = %d); %d fragments; %d of %d topic, category and home pages indexed",
                   if (is.na(count)) "unknown" else count, length(ex$topic), length(ex$category), want, length(frags),
                   sum(need %in% target), length(need)),
           failures, data = list(page_count = count, expected = want, fragments = length(frags)))
}

# ---- check 11: redirects -----------------------------------------------------------------------

MAX_STATIC  <- 2000L                     # Cloudflare Pages: static rules, dynamic rules, characters per line
MAX_DYNAMIC <- 100L
MAX_LINE    <- 1000L

# A dynamic source as a regular expression: :name is one path segment, * is anything.
rule_regex <- function(src) {
  lit <- gsub("([][.+?^${}()|\\\\])", "\\\\\\1", src, perl = TRUE)
  lit <- gsub(":[A-Za-z_][A-Za-z0-9_]*", "[^/]+", lit, perl = TRUE)
  paste0("^", gsub("*", ".*", lit, fixed = TRUE), "$")
}

check_redirects <- function(ctx) {
  rules <- redirect_rules(ctx)
  if (is.null(rules)) {
    return(make_row("11", "Redirects", "FAIL", "_redirects is missing", "_redirects is missing (run make redirects)"))
  }
  files <- ctx$site$files
  src <- rules$source
  dst <- rules$dest
  failures <- character()
  short <- lengths(rules$fields) < 2L
  failures <- c(failures, sprintf("line %d: not \"source destination [status]\"", rules$line_no[short]))
  dynamic <- grepl("[*:]", src)
  if (sum(!dynamic) > MAX_STATIC) failures <- c(failures, sprintf("%d static rules, the limit is %d", sum(!dynamic), MAX_STATIC))
  if (sum(dynamic) > MAX_DYNAMIC) failures <- c(failures, sprintf("%d dynamic rules, the limit is %d", sum(dynamic), MAX_DYNAMIC))
  width <- nchar(rules$lines, type = "bytes")
  failures <- c(failures, sprintf("line %d is %d characters long, the limit is %d", which(width > MAX_LINE), width[width > MAX_LINE], MAX_LINE))
  failures <- c(failures, sprintf("source occurs twice: %s", unique(src[duplicated(src)])))

  index <- basename(files) == "index.html"
  served <- c(paste0("/", files), paste0("/", sub("\\.html$", "", files[endsWith(files, ".html") & !index])))
  pages <- page_url(files[index])
  dest_path <- sub("#.*$", "", dst)
  alias <- !dynamic & !short & paste0(src, "/") %in% pages & dest_path != paste0(src, "/")
  shadow <- !dynamic & !short & (src %in% served | src %in% pages | alias)
  failures <- c(failures, sprintf("static source would shadow an existing file or page: %s", src[shadow]))
  taken <- unique(c(served, pages))
  for (s in src[dynamic & !short]) {
    hit <- taken[grepl(rule_regex(s), taken)]
    if (length(hit) > 0L) {
      failures <- c(failures, sprintf("dynamic rule %s would shadow %d existing files or pages, e.g. %s", s, length(hit), hit[1L]))
    }
  }
  # a destination that a rule redirects again is a chain, or a loop
  dest_pages <- unique(dest_path[!short & startsWith(dest_path, "/")])
  patterns <- vapply(src[dynamic & !short], rule_regex, "")
  again <- dest_pages %in% src[!dynamic & !short] |
    vapply(dest_pages, function(d) any(vapply(patterns, grepl, NA, x = d, perl = TRUE)), NA, USE.NAMES = FALSE)
  failures <- c(failures, sprintf("destination is itself redirected (chain or loop): %s", dest_pages[again]))

  need <- page_url(unname(c(ctx$expected$topic, ctx$expected$category)))
  failures <- c(failures, sprintf("no rule leads to the page %s", need[!need %in% dest_path]))
  make_row("11", "Redirects", verdict(failures),
           sprintf(paste("%d rules: %d static (limit %d), %d dynamic (limit %d); longest line %d characters (limit %d);",
                         "%d duplicate sources, %d shadowing rules; %d of %d topic and category pages are a destination"),
                   length(src), sum(!dynamic), MAX_STATIC, sum(dynamic), MAX_DYNAMIC, max(width, 0L), MAX_LINE,
                   sum(duplicated(src)), sum(shadow), sum(need %in% dest_path), length(need)),
           failures, data = list(rules = length(src), static = sum(!dynamic), dynamic = sum(dynamic), longest_line = max(width, 0L)))
}

# ---- run ---------------------------------------------------------------------------------------

# Everything the checks share: raw/ (categories, topics, posts, assets), the files of the site, its parsed
# pages and all their attributes, the decoded Pagefind fragments.
build_context <- function(opts) {
  raw <- opts$raw
  if (!dir.exists(raw)) abort("--raw ", raw, " is not a directory")
  manifest <- verify_redacted(raw)
  if (!dir.exists(opts$site)) abort("--site ", opts$site, " is not a directory")
  say("raw=%s site=%s verbatim=%s", raw, opts$site, if (dir.exists(opts$verbatim)) opts$verbatim else "(absent)")

  cats <- load_categories(raw)
  topics <- load_topics(raw)
  raw_assets <- list_tree(file.path(raw, "assets"))
  say("raw: %d categories, %d topics, %d posts, %d asset files", length(cats), length(topics),
      sum(vapply(topics, function(t) length(t$number), 1L)), length(raw_assets$files))

  tree <- list_tree(opts$site)
  page_files <- tree$files[grepl("\\.html?$", tree$files, ignore.case = TRUE) & !startsWith(tree$files, "pagefind/") &
                             !tree$files %in% raw_assets$files]
  pages <- load_pages(opts$site, page_files)
  attrs <- do.call(rbind, lapply(pages, function(p) {
    if (nrow(p$attrs) == 0L) NULL else data.frame(page = rep(p$rel, nrow(p$attrs)), p$attrs, stringsAsFactors = FALSE)
  }))
  if (is.null(attrs)) attrs <- data.frame(page = character(), idx = integer(), el = character(), name = character(), value = character())
  hit <- attrs$name %in% c("id", "name")
  fragments <- load_fragments(opts$site, tree$files)
  say("site: %d files, %d HTML pages, %d Pagefind fragments", length(tree$files), length(pages), length(fragments))
  list(opts = opts, manifest = manifest, cats = cats, topics = topics, raw_assets = raw_assets,
       site = list(dir = opts$site, files = tree$files, other = tree$other),
       expected = expected_site(topics, cats), page_files = page_files, pages = pages, attrs = attrs,
       anchors = split(attrs$value[hit], factor(attrs$page[hit], levels = names(pages))),
       fragments = fragments, cache = new.env(parent = emptyenv()))
}

# Resolved by name when they run, so that a test can swap one out.
CHECKS <- c("check_pages", "check_posts", "check_words", "check_host", "check_host_text", "check_links",
            "check_assets", "check_personal_scan", "check_inventory", "check_verbatim", "check_attachments",
            "check_spot", "check_external", "check_minimisation", "check_search", "check_redirects")

# A check that stops with an error is a failed check and the others still report; the message is cut short
# because an error text can quote the data it choked on. An audit_abort is different: an input that must not
# be audited (a redacted --verbatim) stops the whole audit.
run_checks <- function(ctx) {
  rows <- list()
  for (name in CHECKS) {
    t0 <- Sys.time()
    res <- tryCatch(get(name, mode = "function")(ctx), error = function(e) {
      if (inherits(e, "audit_abort")) stop(e)
      make_row(sub("^check_", "", name), name, "FAIL", "the check itself stopped with an error",
               sprintf("%s stopped with an error: %s", name, substr(conditionMessage(e), 1L, 160L)))
    })
    if (!is.null(res[["id"]])) res <- list(res)
    rows <- c(rows, res)
    say("%-22s %s (%.1f s)", name, paste(vapply(res, function(r) sprintf("%s %s", r$id, r$status), ""), collapse = ", "),
        as.numeric(difftime(Sys.time(), t0, units = "secs")))
  }
  rows
}

# ---- the report --------------------------------------------------------------------------------

out <- function(...) cat(paste0(..., "\n"), sep = "")

print_cap <- function(items) {
  out(sprintf("    - %s", utils::head(items, SCREEN_LIMIT)))
  if (length(items) > SCREEN_LIMIT) out(sprintf("    ... (%d in all; the complete list is in %s)", length(items), REPORT_FILE))
}

print_report <- function(rows, opts, failed) {
  ids <- vapply(rows, function(r) r$id, "")
  w_id <- max(nchar(ids), 1L)
  w_name <- max(nchar(vapply(rows, function(r) r$name, "")))
  out("\nAudit of ", opts$site, " against ", opts$raw, "\n")
  out(sprintf("%s  %s  %s  %s", format("#", width = w_id), format("Check", width = w_name), format("Result", width = 6L), "Details"))
  for (r in rows) {
    out(sprintf("%s  %s  %s  %s", format(r$id, width = w_id), format(r$name, width = w_name), format(r$status, width = 6L), r$summary))
  }
  bad <- Filter(function(r) r$status == "FAIL", rows)
  if (length(bad) > 0L) {
    out("\nFAILURES")
    for (r in bad) {
      out(sprintf("\n  [%s] %s: %d offender(s)", r$id, r$name, length(r$failures)))
      print_cap(r$failures)
    }
  }
  more <- Filter(function(r) length(r$lines) > 0L, rows)
  if (length(more) > 0L) {
    out("\nDETAILS")
    for (r in more) {
      out(sprintf("\n  [%s] %s", r$id, r$name))
      out(sprintf("    %s", r$lines))
    }
  }
  spot <- Filter(function(r) r$id == "7", rows)
  out("\nMANUAL STEPS (the audit cannot do these)")
  out("  1. Compare the topics of check 7 side by side with the live forum, before the forum goes away.")
  if (length(spot) > 0L) {
    for (t in spot[[1L]]$data$topics) out(sprintf("       %s   <->   %s", t$live_url, t$archive_url))
  }
  out("  2. PDF and Word attachments are published as uploaded (accepted decision). The address scan of them")
  out("     (check 6d) is a lower bound (fonts with a custom encoding and no ToUnicode map, object streams and")
  out("     scanned pages are not read); open the files it lists.")
  out("  3. Read every redacted passage of check 6b on the live forum next to the archive page.")
  out("")
  out(if (failed == 0L) "AUDIT PASSED" else sprintf("AUDIT FAILED: %d check(s)", failed))
}

# Hash over the sorted "sha256  path" lines of every file of the site: ties the report to the exact content.
site_fingerprint <- function(ctx) {
  h <- vapply(ctx$site$files, function(f) sha256_of(file.path(ctx$site$dir, f)), "", USE.NAMES = FALSE)
  sprintf("%s  %s", h, ctx$site$files) |> paste(collapse = "\n") |> digest::digest(algo = "sha256", serialize = FALSE)
}

report_data <- function(rows, ctx, failed) {
  m <- ctx$manifest
  list(result = if (failed == 0L) "PASSED" else "FAILED",
       failed_checks = I(vapply(Filter(function(r) r$status == "FAIL", rows), function(r) r$id, "")),
       snapshot = list(harvested_at_utc = m[["harvested_at_utc"]], discourse_version = m[["discourse_version"]],
                       site_title = m[["site_title"]]),
       inputs = list(topics = length(ctx$topics), categories = length(ctx$cats),
                     posts = sum(vapply(ctx$topics, function(t) length(t$number), 1L)), asset_files = length(ctx$raw_assets$files),
                     site_files = length(ctx$site$files), html_pages = length(ctx$pages),
                     raw_manifest_sha256 = sha256_of(file.path(ctx$opts$raw, MANIFEST_FILE)),
                     site_sha256 = site_fingerprint(ctx),
                     verbatim_checked = dir.exists(ctx$opts$verbatim)),
       checks = lapply(rows, function(r) list(id = r$id, name = r$name, status = r$status, summary = r$summary,
                                              failures = I(r$failures), details = r$data)))
}

# audit-report.json goes next to --site, never into it; a leftover .part from a killed run is replaced.
report_path <- function(site) fs::path_abs(site) |> as.character() |> dirname() |> file.path(REPORT_FILE)

check_report_target <- function(target) {
  for (p in c(target, paste0(target, ".part"))) {
    if (fs::is_link(p) || (file.exists(p) && !fs::is_file(p))) abort(p, " is a symbolic link or not a plain file; refusing to touch it")
  }
}

write_report <- function(text, target) {
  part <- paste0(target, ".part")
  bytes <- charToRaw(text)
  on.exit(unlink(part), add = TRUE)
  writeBin(bytes, part)
  if (!identical(read_bytes(part), bytes)) abort("Could not write ", part, " completely")
  if (!file.rename(part, target)) abort("Cannot move ", part, " to ", target)
  invisible(bytes)
}

run_audit <- function(opts) {
  started <- Sys.time()
  target <- report_path(opts$site)
  check_report_target(target)
  unlink(target)                          # an audit that stops half way must not leave an older verdict behind
  ctx <- build_context(opts)
  ALLOWED_KEPT <<- allowlist_kept(opts$raw)
  rows <- run_checks(ctx)
  failed <- sum(vapply(rows, function(r) r$status == "FAIL", NA))
  write_report(to_json(report_data(rows, ctx, failed)), target)
  say("wrote %s in %.0f s", target, as.numeric(difftime(Sys.time(), started, units = "secs")))
  print_report(rows, opts, failed)
  invisible(list(rows = rows, failed = failed, report = target))
}

main <- function(argv = commandArgs(trailingOnly = TRUE)) {
  # A warning of a base function can quote the text that caused it; the audit never prints post text.
  options(warn = -1)
  res <- tryCatch(run_audit(parse_args(argv)), audit_abort = function(e) {
    message("\nAUDIT ABORTED: ", scrub(conditionMessage(e)))
    NULL
  }, error = function(e) {
    message("\nAUDIT FAILED (unexpected error): ", scrub(substr(conditionMessage(e), 1L, 300L)),
            "\n  in ", substr(paste(deparse(conditionCall(e)), collapse = " "), 1L, 160L))
    NULL
  })
  if (is.null(res) || res$failed > 0L) quit(save = "no", status = 1L)
}

if (sys.nframe() == 0L) main()
