#!/usr/bin/env Rscript
# Phase 1b (Redact): derive the committed, redacted raw/ from the byte-exact raw_verbatim/.
#
#   Rscript R/01b_redact.R [--in DIR] [--out DIR] [--allow FILE]
#
# --in (default raw_verbatim) is the unredacted harvest of R/01_harvest.R: local only, gitignored and
# never modified here. --out (default raw) is what Phase 2 reads and what is committed:
#   every JSON file of the harvest, with personal data removed from its decoded string values
#     R1  mailto anchor      <a href="mailto:..">x</a>              -> <span class="email-redacted">x</span>
#     R2  e-mail address                                            -> [email redacted]
#     R3  obfuscated address "name [at] domain [dot] tld"           -> [email redacted]
#     R4  value of a pwd= / passcode= / password= URL parameter     -> REDACTED   (Zoom passcodes)
#     R5  passcode in plain text, e.g. "Kenncode: 123456"            -> Kenncode: REDACTED   (label kept)
#     R6  copy of a passcode value that R4 redacted, elsewhere in the same string (heading anchor names and
#         hrefs that Discourse derived from a heading holding the whole Zoom link, lower case, hyphenated)
#     Exception: an address listed in redaction-allowlist.json (general addresses of organisations, published
#     on purpose) stays. It is set aside before the rules run, so no rule sees it; only whole addresses count.
#     An allowlisted address inside a mailto: link still loses the link (R1), its visible text stays.
#   every asset byte for byte, except the avatar images (O1: assets/user_avatar/ and
#     assets/letter_avatar_proxy/), which are left out and dropped from assets-report.json
#   redaction-report.json   what was done: rules, counts per rule and file, omissions. No values.
#   manifest.json           written last: the harvest manifest plus derived_from, redaction and the
#                           SHA-256 of every file of the new tree
#
# JSON text is never re-serialised: string literals are tokenised, decoded, redacted, and only the
# literals that changed are spliced back as bytes. assets-report.json is the one file that is
# regenerated (through jsonlite, like the harvest does) because entries are dropped from it.
#
# Safety: --in is verified against its manifest before anything happens and again at the end of
# every run, and is only ever read. The result is built in <out>.redact-tmp, checked, and swapped
# into place; a failure or interruption leaves an existing --out as it was. An existing --out must
# be empty or hold a redaction-report.json (this script's own earlier output).

SRC_DEFAULT   <- "raw_verbatim"
OUT_DEFAULT   <- "raw"
MANIFEST_FILE <- "manifest.json"
REPORT_FILE   <- "redaction-report.json"
TMP_SUFFIX    <- ".redact-tmp"    # sibling directory the result is built in
OLD_SUFFIX    <- ".redact-old"    # where the previous --out waits while the new one is swapped in
OMIT_PREFIXES <- c("assets/user_avatar/", "assets/letter_avatar_proxy/")
IMAGE_EXT     <- c("png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico")

# What a plain scan of the unredacted harvest found when the rules were written. Differences are
# reported at the end of a run, they never abort it.
EXPECTED         <- c(R1 = 9L, R2 = 27L, R3 = 1L, R4 = 104L, R5 = 2L, R6 = 10L)
EXPECTED_OMITTED <- 2L

# The allowlist (see the header). run_redact() fills ALLOWED and ALLOW_MARK; both are empty otherwise, and
# then nothing below changes behaviour.
ALLOW_DEFAULT <- "redaction-allowlist.json"
ADDRESS_RE    <- "^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$"
MAX_ALLOWED   <- 100L
ALLOWED       <- character()   # the allowlisted addresses, lower case
ALLOW_MARK    <- character()   # one private-use character per address: stands in for its "@" while the rules run

# ---- rules -------------------------------------------------------------------------------------
# All patterns are PCRE and are applied to DECODED JSON string values, in this order. The same
# patterns are used to detect leftovers in the self-checks.

LOCAL_PART <- "[A-Za-z0-9._%+-]+"

# R2 and R3 start with this zero-width guard: a match may begin where the previous one ended or after a
# character that cannot be part of a local part. It changes nothing about what matches (a match that
# began inside a run of local-part characters would also have matched at the start of that run), but it
# keeps the patterns linear: without it every position of a long run (a 200,000-character "a.a.a.")
# is tried and rescans the run, which took half a minute.
START_GUARD <- "(?:\\G|(?<![A-Za-z0-9._%+-]))"

# R1: an anchor whose href is a mailto: URL (case-insensitive, either quote, other attributes before
# or after), up to the first </a>. Group 1 is the visible text, which R2 then sees on its own.
PAT_MAILTO <- paste0("(?is)<a\\s(?:[^>]*?\\s)?href\\s*=\\s*(?:\"mailto:[^\"]*\"|'mailto:[^']*')",
                     "[^>]*>(.*?)</a\\s*>")

# R2: an address, unless its last label is an image extension (retina file names: logo@2x.png). A
# trailing sentence period is not part of the match because the last label needs letters after the dot.
PAT_EMAIL <- paste0(START_GUARD, LOCAL_PART, "@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.",
                    "(?!(?i:", paste(IMAGE_EXT, collapse = "|"), ")(?![A-Za-z]))[A-Za-z]{2,}")

# R3: name (at) domain (dot) tld, with (), [] or {} around at/dot, spaces allowed around them. The
# last separator must be a bracketed dot; an inner one may also be a plain dot. That keeps country
# codes such as "Vienna (AT)" and dates such as "(AT) 21.May" out of reach.
AT_TOKEN  <- "(?:\\([ \\t]*at[ \\t]*\\)|\\[[ \\t]*at[ \\t]*\\]|\\{[ \\t]*at[ \\t]*\\})"
DOT_TOKEN <- "[ \\t]*(?:\\([ \\t]*dot[ \\t]*\\)|\\[[ \\t]*dot[ \\t]*\\]|\\{[ \\t]*dot[ \\t]*\\})[ \\t]*"
PAT_OBFUSCATED <- paste0("(?i)", START_GUARD, LOCAL_PART, "[ \\t]*", AT_TOKEN, "[ \\t]*[A-Za-z0-9-]+",
                         "(?:(?:", DOT_TOKEN, "|\\.)[A-Za-z0-9-]+)*", DOT_TOKEN, "[A-Za-z]{2,}")

# R4: the separator (? & or the ; of &amp;) and the name are kept, the value (up to whitespace, a
# quote, < > & or #) is replaced. A value that already is REDACTED does not match.
PAT_PASSCODE <- "([?&;](?i:pwd|passcode|password)=)(?!REDACTED(?:[\\s\"'<>&#]|\\z))[^\\s\"'<>&#]+"

PAT_REDACTED_PARAM <- "[?&;](?i:pwd|passcode|password)=REDACTED(?![^\\s\"'<>&#])"   # what R4 leaves behind

# R5: a passcode written out in plain text: a label (whole word, any case), a colon or equals sign, then
# a token of 4-12 letters or digits that holds a digit and ends at a word boundary. Only the token is
# replaced. It runs after R4, whose output (?password=REDACTED) has no digit and therefore never matches.
PASSCODE_LABELS <- c("kenncode", "kennwort", "passcode", "passwort", "password", "zugangscode", "wachtwoord", "toegangscode")
LABEL_AND_SEP <- paste0("\\b(?:", paste(PASSCODE_LABELS, collapse = "|"), ")\\b[ \\t]*[:=][ \\t]*")
PAT_PLAIN_PASSCODE <- paste0("(?i)(", LABEL_AND_SEP, ")(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{4,12}\\b")

# What R5 leaves behind. R4 leaves the same shape for passcode= and password= (?passcode=REDACTED), so the
# self-check counts R5's replacement texts as all of them minus those.
PAT_REDACTED_AFTER_LABEL <- paste0("(?i)", LABEL_AND_SEP, "REDACTED\\b")
PAT_REDACTED_PARAM_LABEL <- "[?&;](?i:passcode|password)=REDACTED\\b"

# R6: copies of a passcode value that R4 redacted, elsewhere in the same string. Discourse builds heading
# anchors from the heading's text, so a heading that held a whole Zoom link carries the passcode again, in
# lower case and with every other character turned into a hyphen (<a name="...-pwd<value>-9" href="#...">).
# Each value found by R4 (12 characters or more) is therefore also removed, case-insensitively and in that
# hyphenated slug form, wherever else it occurs in the same string. Needs the values, so it is not a pattern:
# the report says so and never contains a value.
PASSCODE_VALUE_RE <- "(?i)(?<=[?&;]pwd=|[?&;]passcode=|[?&;]password=)(?!REDACTED(?:[\\s\"'<>&#]|\\z))[^\\s\"'<>&#]+"
PASSCODE_PREFILTER <- "(?i)(?:pwd|passcode|password)="
MIN_SECRET_LEN <- 12L

RULES <- list(
  list(id = "R1", pattern = PAT_MAILTO, replacement = "<span class=\"email-redacted\">\\1</span>",
       description = "mailto anchor becomes a span with class email-redacted; its visible text goes through R2"),
  list(id = "R2", pattern = PAT_EMAIL, replacement = "[email redacted]",
       description = "e-mail address, unless its last label is an image extension (retina image names stay)"),
  list(id = "R3", pattern = PAT_OBFUSCATED, replacement = "[email redacted]",
       description = "obfuscated address: local part, domain and tld with at and dot spelled out in (), [] or {}"),
  list(id = "R4", pattern = PAT_PASSCODE, replacement = "\\1REDACTED",
       description = "value of a pwd, passcode or password URL query parameter"),
  list(id = "R5", pattern = PAT_PLAIN_PASSCODE, replacement = "\\1REDACTED",
       description = paste("passcode written out in plain text: a label such as Kenncode or Passwort, a colon or equals sign,",
                           "then a token of 4-12 letters or digits with at least one digit; only the token is replaced")),
  list(id = "R6", pattern = NULL, replacement = "REDACTED",
       report_pattern = "(not a pattern) every R4 passcode value of 12+ characters, and its lower-case hyphenated slug form, case-insensitive, in the same string; the values are not recorded",
       description = paste("copy of a redacted passcode value in the same string, e.g. in a heading anchor name or href",
                           "(Discourse derives anchors from the heading text, which held the whole Zoom link)"))
)
RULE_IDS <- vapply(RULES, function(r) r$id, "")

# ---- the harvest's JSON text (Rails-style compact JSON) -----------------------------------------

# A string literal; a key keeps its colon, which is how keys are told from values.
PAT_JSON_STRING <- "(?s)\"[^\"\\\\]*+(?:\\\\.[^\"\\\\]*+)*+\"(?:\\s*+:)?+"

# jsonlite decodes these lossily (it cuts a string at \u0000 and turns a lone surrogate into "?" or NA),
# which could hide an address from the rules, so such literals are refused rather than decoded.
PAT_UNSAFE_ESCAPE <- "(?i)\\\\u0000|\\\\ud[89ab][0-9a-f]{2}(?!\\\\ud[c-f][0-9a-f]{2})|(?<!\\\\ud[89ab][0-9a-f]{2})\\\\ud[c-f][0-9a-f]{2}"

# What a changed literal is written with: " and \ escaped, control characters as \n \r \t \b \f or \u00xx,
# < > & U+2028 U+2029 as lowercase \uxxxx like Rails does, everything else literal UTF-8.
ESC_FROM <- c("\\", "\"", "\n", "\r", "\t", "\b", "\f", "<", ">", "&", intToUtf8(c(0x2028, 0x2029), multiple = TRUE),
              vapply(setdiff(1:31, c(8L, 9L, 10L, 12L, 13L)), intToUtf8, ""))
ESC_TO   <- c("\\\\", "\\\"", "\\n", "\\r", "\\t", "\\b", "\\f", "\\u003c", "\\u003e", "\\u0026", "\\u2028", "\\u2029",
              sprintf("\\u%04x", setdiff(1:31, c(8L, 9L, 10L, 12L, 13L))))

USAGE <- "Usage: Rscript R/01b_redact.R [--in DIR] [--out DIR] [--allow FILE]
  --in DIR      byte-exact harvest to read (default: raw_verbatim; never modified)
  --out DIR     redacted copy to write (default: raw)
  --allow FILE  e-mail addresses to leave in place (default: redaction-allowlist.json, if that file exists)"

# ---- helpers -----------------------------------------------------------------------------------
# Parsed JSON is always read with [[ ]]: `$` partial-matches.

`%||%` <- function(x, y) if (is.null(x)) y else x

say <- function(fmt, ...) message("[redact] ", if (...length() > 0) sprintf(fmt, ...) else fmt)

abort <- function(...) {
  stop(structure(class = c("redact_abort", "error", "condition"),
                 list(message = paste0(...), call = NULL)))
}

parse_args <- function(argv) {
  opts <- list(src = SRC_DEFAULT, out = OUT_DEFAULT, allow = NULL)
  flags <- c("--in" = "src", "--out" = "out", "--allow" = "allow")
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
  if (!nzchar(opts$src) || !nzchar(opts$out)) abort("--in and --out must not be empty")
  opts
}

shown <- function(x, n = 5L) {
  paste0(paste(utils::head(x, n), collapse = ", "), if (length(x) > n) sprintf(", ... (%d in all)", length(x)) else "")
}

# ---- files and JSON text -----------------------------------------------------------------------

read_bytes  <- function(path) readBin(path, "raw", n = file.size(path))
write_bytes <- function(bytes, path) writeBin(bytes, path)
sha256_of   <- function(path) digest::digest(file = path, algo = "sha256")

file_info <- function(path) list(sha256 = sha256_of(path), bytes = file.size(path))

# Strings made from bytes are marked UTF-8 explicitly: in a C locale an unmarked non-ASCII string
# would be treated as native text and mangled by enc2utf8() and friends.
bytes_to_text <- function(bytes, what) {
  txt <- tryCatch(rawToChar(bytes), error = function(e) abort(what, " contains a NUL byte"))
  Encoding(txt) <- "UTF-8"
  if (!validUTF8(txt)) abort(what, " is not valid UTF-8")
  txt
}

# jsonlite::fromJSON() takes text that is not valid JSON for a URL or a file name and then fetches
# or reads it, so validity is established first: nothing here can ever touch the network.
parse_json_text <- function(txt, what) {
  if (!isTRUE(jsonlite::validate(txt))) abort(what, " is not valid JSON")
  jsonlite::fromJSON(txt, simplifyVector = FALSE)
}

parse_json_file <- function(path, what = path) parse_json_text(bytes_to_text(read_bytes(path), what), what)

# Same options as the harvest, so a report regenerated here is byte-identical to the harvest's.
write_json_atomic <- function(x, dest) {
  part <- paste0(dest, ".part")
  jsonlite::write_json(x, part, auto_unbox = TRUE, pretty = TRUE, null = "null", na = "null", digits = NA)
  if (!file.rename(part, dest)) abort("Cannot move ", part, " to ", dest)
}

# Every string value and every object key of a parsed document, in document order.
json_strings <- function(x) {
  if (is.character(x)) return(list(values = x, keys = character()))
  if (!is.list(x)) return(list(values = character(), keys = character()))
  kids <- lapply(x, json_strings)
  list(values = unlist(lapply(kids, `[[`, "values"), use.names = FALSE) %||% character(),
       keys = c(names(x), unlist(lapply(kids, `[[`, "keys"), use.names = FALSE)))
}

# Same types, same names, same lengths, at every level.
same_shape <- function(a, b) {
  if (is.list(a) || is.list(b)) {
    if (!(is.list(a) && is.list(b)) || length(a) != length(b) || !identical(names(a), names(b))) return(FALSE)
    return(all(vapply(seq_along(a), function(i) same_shape(a[[i]], b[[i]]), NA)))
  }
  identical(typeof(a), typeof(b)) && length(a) == length(b)
}

# For two documents of the same shape: the string leaves that differ (src/res), or NULL if any other
# kind of leaf (number, boolean, null) differs.
leaf_diffs <- function(a, b) {
  acc <- new.env(parent = emptyenv())
  acc$src <- character()
  acc$res <- character()
  acc$ok <- TRUE
  walk <- function(x, y) {
    if (is.list(x)) {
      for (i in seq_along(x)) walk(x[[i]], y[[i]])
    } else if (!identical(x, y)) {
      if (is.character(x)) {
        acc$src <- c(acc$src, x)
        acc$res <- c(acc$res, y)
      } else {
        acc$ok <- FALSE
      }
    }
  }
  walk(a, b)
  if (acc$ok) list(src = acc$src, res = acc$res)
}

# ---- JSON literals: tokenise, decode, encode, splice -------------------------------------------

# Byte offsets of every string literal; key literals are flagged (their token ends with the colon).
json_tokens <- function(txt) {
  m <- gregexpr(PAT_JSON_STRING, txt, perl = TRUE, useBytes = TRUE)[[1]]
  start <- as.integer(m)
  if (identical(start, -1L)) return(list(start = integer(), end = integer(), key = logical(), lit = character()))
  end <- start + attr(m, "match.length") - 1L
  b <- txt
  Encoding(b) <- "bytes"
  lit <- substring(b, start, end)
  key <- substring(b, end, end) == ":"
  Encoding(lit) <- "UTF-8"
  list(start = start, end = end, key = key, lit = lit)
}

decode_literals <- function(lit) {
  if (length(lit) == 0L) return(character())
  vals <- unlist(parse_json_text(paste0("[", paste(lit, collapse = ","), "]"), "string literals"), use.names = FALSE)
  if (!is.character(vals) || length(vals) != length(lit)) abort("Internal error: string literals did not decode one to one")
  vals
}

# One decoded string as a JSON literal in the file's own convention (see ESC_FROM).
json_literal <- function(x) {
  for (i in seq_along(ESC_FROM)) x <- gsub(ESC_FROM[i], ESC_TO[i], x, fixed = TRUE)
  paste0("\"", x, "\"")
}

# Replaces bytes[start:end] (ascending, non-overlapping) by the raw vectors in `repl`.
splice_bytes <- function(bytes, start, end, repl) {
  pieces <- vector("list", 2L * length(start) + 1L)
  prev <- 1L
  for (j in seq_along(start)) {
    pieces[[2L * j - 1L]] <- if (start[j] > prev) bytes[prev:(start[j] - 1L)] else raw()
    pieces[[2L * j]] <- repl[[j]]
    prev <- end[j] + 1L
  }
  pieces[[length(pieces)]] <- if (prev <= length(bytes)) bytes[prev:length(bytes)] else raw()
  do.call(c, pieces)
}

# ---- the rules on decoded strings --------------------------------------------------------------

count_matches <- function(pattern, x) {
  if (length(x) == 0L) return(integer())
  vapply(gregexpr(pattern, x, perl = TRUE), function(m) sum(m > 0L), 1L)
}

# ---- the allowlist -----------------------------------------------------------------------------
# An allowlisted address is set aside before the rules run: its "@" is swapped for a private-use
# character, so no rule can see an address there, and swapped back afterwards (the original letter
# case is kept). Only whole addresses count: not glued to a longer local part or domain.

load_allowlist <- function(path, explicit) {
  if (!file.exists(path)) {
    if (explicit) abort("--allow ", path, " does not exist")
    return(list(file = NULL, sha256 = NULL, entries = list(), addresses = character()))
  }
  doc <- parse_json_file(path, "the allowlist")
  entries <- doc[["addresses"]]
  if (!is.list(entries) || length(entries) > MAX_ALLOWED) {
    abort(path, ": \"addresses\" must be a list of at most ", MAX_ALLOWED, " entries")
  }
  addr <- vapply(entries, function(e) {
    a <- if (is.list(e)) e[["address"]]
    r <- if (is.list(e)) e[["reason"]]
    if (!is.character(a) || length(a) != 1L || !grepl(ADDRESS_RE, a, perl = TRUE)) abort(path, ": an entry has no valid \"address\"")
    if (!is.character(r) || length(r) != 1L || !nzchar(trimws(r))) abort(path, ": the entry for ", a, " has no \"reason\"")
    tolower(a)
  }, "")
  if (anyDuplicated(addr)) abort(path, ": an address is listed twice")
  list(file = basename(path), sha256 = sha256_of(path), entries = entries, addresses = unname(addr))
}

set_allowlist <- function(addresses) {
  ALLOWED <<- addresses
  ALLOW_MARK <<- vapply(seq_along(addresses), function(i) intToUtf8(0xE0A0L + i), "")
  invisible(NULL)
}

allow_boundary <- "(?![A-Za-z0-9-]|\\.[A-Za-z0-9])"   # not followed by more domain
allow_plain_pattern <- function(addr) paste0("(?<![A-Za-z0-9._%+-])(?i:\\Q", addr, "\\E)", allow_boundary)
# the same with local part and domain captured, so that only the "@" is swapped
allow_pattern <- function(addr) {
  parts <- strsplit(addr, "@", fixed = TRUE)[[1]]
  paste0("(?<![A-Za-z0-9._%+-])((?i:\\Q", parts[1], "\\E))@((?i:\\Q", parts[2], "\\E))", allow_boundary)
}

protect_allowed <- function(x) {
  kept <- integer(length(ALLOWED))
  if (length(ALLOWED) == 0L || length(x) == 0L) return(list(x = x, kept = kept))
  if (any(grepl(paste0("[", ALLOW_MARK[1L], "-", ALLOW_MARK[length(ALLOW_MARK)], "]"), x, perl = TRUE))) {
    abort("A string contains a private-use character that the allowlist needs as a stand-in for \"@\"")
  }
  for (i in seq_along(ALLOWED)) {
    pat <- allow_pattern(ALLOWED[i])
    hit <- grepl(pat, x, perl = TRUE)
    if (any(hit)) {
      kept[i] <- sum(count_matches(pat, x[hit]))
      x[hit] <- gsub(pat, paste0("\\1", ALLOW_MARK[i], "\\2"), x[hit], perl = TRUE)
    }
  }
  list(x = x, kept = kept)
}

unprotect_allowed <- function(x) {
  for (m in ALLOW_MARK) x <- gsub(m, "@", x, fixed = TRUE)
  x
}

# How often each allowlisted address occurs in x (as a whole address, in any letter case).
count_allowed <- function(x) {
  vapply(ALLOWED, function(a) sum(count_matches(allow_plain_pattern(a), x)), 1L, USE.NAMES = FALSE)
}

# x: character vector. Returns the redacted strings plus two matrices (strings x rules): `applied`
# counts the replacements made, `in_source` the matches of each pattern in the unredacted string, and
# `kept` how often each allowlisted address was left in place. In_source and applied differ for R2: an
# address inside the href of a removed mailto anchor is gone before R2 runs. Allowlisted addresses are
# in neither.
redact_strings <- function(x) {
  p <- protect_allowed(x)
  x <- p$x
  applied <- matrix(0L, length(x), length(RULES), dimnames = list(NULL, RULE_IDS))
  in_source <- applied
  orig <- x
  secrets <- passcode_values(orig)           # per string, before R4 replaces them
  for (j in seq_along(RULES)) {
    r <- RULES[[j]]
    if (is.null(r[["pattern"]])) next        # R6 below
    hit <- grepl(r$pattern, orig, perl = TRUE)
    if (any(hit)) in_source[hit, j] <- count_matches(r$pattern, orig[hit])
    hit <- grepl(r$pattern, x, perl = TRUE)
    if (any(hit)) {
      applied[hit, j] <- count_matches(r$pattern, x[hit])
      x[hit] <- gsub(r$pattern, r$replacement, x[hit], perl = TRUE)
    }
  }
  copies <- remove_copies(x, secrets)        # R6: runs after R4, so the "pwd=" occurrences are gone already
  x <- copies$x
  applied[, "R6"] <- copies$n
  in_source[, "R6"] <- copies$n
  list(x = unprotect_allowed(x), applied = applied, in_source = in_source, kept = p$kept,
       secrets = unique(unlist(secrets, use.names = FALSE)))
}

# ---- R6: copies of redacted passcode values ----------------------------------------------------

slug_form <- function(s) gsub("^-+|-+$", "", gsub("[^a-z0-9]+", "-", tolower(s)))

# For every string, the passcode values (12+ characters) that R4 is about to redact in it.
passcode_values <- function(x) {
  out <- vector("list", length(x))
  hit <- which(grepl(PASSCODE_PREFILTER, x, perl = TRUE))
  for (i in hit) {
    v <- regmatches(x[i], gregexpr(PASSCODE_VALUE_RE, x[i], perl = TRUE))[[1L]]
    v <- unique(v[nchar(v) >= MIN_SECRET_LEN])
    if (length(v) > 0L) out[[i]] <- v
  }
  out
}

# A regex matching any of the values or their slug forms, case-insensitively (never stored anywhere).
copies_pattern <- function(values) {
  needles <- unique(c(values, slug_form(values)))
  needles <- needles[nchar(needles) >= MIN_SECRET_LEN]
  paste0("(?i)(?:", paste0("\\Q", needles, "\\E", collapse = "|"), ")")
}

remove_copies <- function(x, secrets) {
  n <- integer(length(x))
  for (i in which(lengths(secrets) > 0L)) {
    pat <- copies_pattern(secrets[[i]])
    n[i] <- sum(count_matches(pat, x[i]))
    if (n[i] > 0L) x[i] <- gsub(pat, "REDACTED", x[i], perl = TRUE)
  }
  list(x = x, n = n)
}

col_totals <- function(m) stats::setNames(as.integer(colSums(m)), colnames(m))

# Per rule: how many of the strings still hold something the rule would redact.
residual_counts <- function(x) {
  x <- protect_allowed(x)$x   # allowlisted addresses are meant to stay
  # R6 has no pattern (it needs the values); check_no_secret_copies() covers it
  stats::setNames(vapply(RULES, function(r) if (is.null(r[["pattern"]])) 0L else sum(grepl(r$pattern, x, perl = TRUE)), 1L), RULE_IDS)
}

# Redacts one JSON file given as bytes. Returns the new bytes (the very same vector if nothing
# changed) and the per-rule tallies.
redact_json_bytes <- function(bytes, what) {
  txt <- bytes_to_text(bytes, what)
  parsed <- parse_json_text(txt, what)
  tok <- json_tokens(txt)
  strs <- json_strings(parsed)
  if (length(tok$start) != length(strs$values) + length(strs$keys)) {
    abort(what, ": the tokeniser found ", length(tok$start), " string literals, the parsed document has ",
          length(strs$values) + length(strs$keys))
  }
  value_idx <- which(!tok$key)
  if (any(grepl(PAT_UNSAFE_ESCAPE, tok$lit[value_idx], perl = TRUE))) {
    abort(what, ": a string has a \\u0000 escape or an unpaired surrogate escape, which cannot be decoded safely")
  }
  vals <- decode_literals(tok$lit[value_idx])
  if (!identical(vals, strs$values)) abort(what, ": decoded string literals differ from the parsed document")

  red <- redact_strings(vals)
  changed <- which(red$x != vals)
  out <- bytes
  if (length(changed) > 0L) {
    repl <- lapply(json_literal(red$x[changed]), charToRaw)
    idx <- value_idx[changed]
    out <- splice_bytes(bytes, tok$start[idx], tok$end[idx], repl)
  }
  list(bytes = out, applied = col_totals(red$applied), in_source = col_totals(red$in_source), kept = red$kept,
       secrets = red$secrets)
}

# ---- assets-report.json ------------------------------------------------------------------------

is_omitted <- function(rel) {
  Reduce(`|`, lapply(OMIT_PREFIXES, function(p) startsWith(rel, p)), logical(length(rel)))
}

# Drops the avatar entries (their `path` is the asset's path below assets/) and brings counts back in line.
strip_avatar_entries <- function(report) {
  keep <- function(entries) {
    Filter(function(e) !(is.list(e) && is.character(e[["path"]]) && is_omitted(paste0("assets", e[["path"]]))), entries)
  }
  counts <- report[["counts"]]
  if (!is.list(counts) || !is.list(report[["assets"]]) || !is.list(report[["missing"]])) {
    abort("assets-report.json does not have the expected shape (counts, assets, missing)")
  }
  before <- c(assets = length(report[["assets"]]), missing = length(report[["missing"]]))
  report[["assets"]] <- keep(report[["assets"]])
  report[["missing"]] <- keep(report[["missing"]])
  counts[["assets"]] <- length(report[["assets"]])
  counts[["missing"]] <- length(report[["missing"]])
  counts[["ok"]] <- counts[["assets"]] - counts[["missing"]]
  report[["counts"]] <- counts
  list(report = report, removed = before - c(assets = length(report[["assets"]]), missing = length(report[["missing"]])))
}

# ---- directories: resolving, guards, verification of the source --------------------------------

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
check_dirs <- function(src, out) {
  src_chain <- ancestor_ids(src)
  if (fs::file_exists(out)) {
    out_chain <- ancestor_ids(out)
    if (identical(out_chain[1], src_chain[1])) abort("--in and --out are the same directory")
    if (out_chain[1] %in% src_chain) abort("--out contains --in")
  }
  if (src_chain[1] %in% ancestor_ids(out)) abort("--out is inside --in")
}

check_rel_paths <- function(rel) {
  bad <- rel == "" | startsWith(rel, "/") | endsWith(rel, "/") | grepl("//", rel, fixed = TRUE) |
    grepl("(^|/)\\.{1,2}(/|$)", rel) | grepl("[\\x00-\\x1f\\x7f\\\\]", rel, perl = TRUE)
  if (!l10n_info()[["UTF-8"]]) bad <- bad | grepl("[^\\x20-\\x7e]", rel, perl = TRUE)   # no way to name them here
  if (any(bad)) abort("The manifest lists file names that cannot be handled safely: ", shown(rel[bad]))
}

list_tree <- function(dir) {
  entries <- fs::dir_ls(dir, recurse = TRUE, all = TRUE)
  if (length(entries) == 0L) return(list(files = character(), other = character()))
  type <- as.character(fs::file_info(entries)$type)
  rel <- as.character(fs::path_rel(entries, start = dir))
  list(files = rel[type == "file"], other = rel[!type %in% c("file", "directory")])
}

# Checks a harvest directory against its own manifest: same files, sizes and SHA-256. Aborts on any
# difference; otherwise returns the parsed manifest and the sorted list of files it describes.
verify_tree <- function(dir) {
  mpath <- file.path(dir, MANIFEST_FILE)
  if (!file.exists(mpath)) abort(dir, " has no ", MANIFEST_FILE, " (run R/01_harvest.R first)")
  manifest <- parse_json_file(mpath)
  listed <- manifest[["files"]]
  rel <- names(listed)
  if (!is.list(listed) || length(rel) == 0L) abort(mpath, " lists no files")
  if (anyDuplicated(rel)) abort(mpath, " lists a file twice")
  check_rel_paths(rel)
  if (any(rel %in% c(MANIFEST_FILE, REPORT_FILE))) {
    abort(dir, " already is a redacted copy (its manifest lists ", REPORT_FILE, "); --in must be the verbatim harvest")
  }
  tree <- list_tree(dir)
  if (length(tree$other) > 0L) abort(dir, " holds entries that are not plain files: ", shown(tree$other))
  extra <- setdiff(tree$files, c(rel, MANIFEST_FILE))
  extra <- extra[basename(extra) != ".DS_Store"]
  gone <- setdiff(rel, tree$files)
  if (length(extra) > 0L || length(gone) > 0L) {
    abort(dir, " does not match its manifest: ",
          if (length(gone) > 0L) paste0("missing: ", shown(gone), ". "),
          if (length(extra) > 0L) paste0("not in the manifest: ", shown(extra), "."))
  }
  rel <- rel[order(rel, method = "radix")]
  differs <- vapply(rel, function(r) {
    p <- file.path(dir, r)
    e <- listed[[r]]
    !(isTRUE(file.size(p) == e[["bytes"]]) && identical(sha256_of(p), e[["sha256"]]))
  }, NA)
  if (any(differs)) abort(dir, " does not match its manifest (size or SHA-256 differs): ", shown(rel[differs]))
  list(manifest = manifest, files = rel, manifest_sha256 = sha256_of(mpath))
}

# What may happen to --out: "absent", "empty" or "redacted" (holds REPORT_FILE: our own output).
# Anything else must not be touched.
out_state <- function(out) {
  if (!fs::file_exists(out)) return("absent")
  if (!fs::is_dir(out)) abort(out, " exists and is not a directory")
  entries <- basename(as.character(fs::dir_ls(out, all = TRUE)))
  if (all(entries == ".DS_Store")) return("empty")
  if (REPORT_FILE %in% entries) return("redacted")
  abort(out, " exists, is not empty and holds no ", REPORT_FILE, " (so it is not this script's own output); ",
        "refusing to touch it. Move it away or choose another --out.")
}

# Leftovers of an interrupted run: the half-built tree is removed; a previous output that was moved
# aside but never replaced is put back.
clear_stale <- function(out, tmp, aside) {
  for (p in c(tmp, aside)) if (fs::is_link(p)) abort(p, " is a symbolic link; refusing to delete it")
  if (dir.exists(aside) && !fs::file_exists(out)) {
    say("restoring %s: an earlier run was interrupted while swapping", out)
    if (!file.rename(aside, out)) abort("Cannot move ", aside, " back to ", out)
  }
  for (p in c(tmp, aside)) {
    if (fs::file_exists(p)) {
      say("removing stale %s", p)
      unlink(p, recursive = TRUE)
    }
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

# ---- building the new tree ---------------------------------------------------------------------

file_kind <- function(rel) {
  if (startsWith(rel, "assets/")) "asset" else if (endsWith(rel, ".json")) "json" else "other"
}

copy_asset <- function(rel, from, to, info) {
  if (!file.copy(from, to, overwrite = FALSE)) abort("Cannot copy ", rel)
  want <- info$manifest$files[[rel]]
  if (file.size(to) != want[["bytes"]] || sha256_of(to) != want[["sha256"]]) {
    abort("The copy of ", rel, " differs from the source")
  }
  list(rel = rel, kind = "asset", modified = FALSE)
}

process_json <- function(rel, from, to) {
  bytes <- read_bytes(from)
  work <- bytes
  removed <- NULL
  if (rel == "assets-report.json") {
    # regenerated through jsonlite (the avatar entries go); the rules then run on the regenerated text
    stripped <- strip_avatar_entries(parse_json_text(bytes_to_text(bytes, rel), rel))
    write_json_atomic(stripped$report, to)
    work <- read_bytes(to)
    removed <- stripped$removed
  }
  red <- redact_json_bytes(work, rel)
  if (!is.null(removed)) {
    if (!identical(red$bytes, work)) write_bytes(red$bytes, to)
  } else if (identical(red$bytes, bytes)) {
    if (!file.copy(from, to, overwrite = FALSE)) abort("Cannot copy ", rel)
  } else {
    write_bytes(red$bytes, to)
  }
  list(rel = rel, kind = "json", modified = !identical(red$bytes, bytes),
       applied = red$applied, in_source = red$in_source, kept = red$kept, secrets = red$secrets, removed = removed)
}

build_tree <- function(src, tmp, info) {
  rel <- info$files
  omitted <- rel[is_omitted(rel)]
  kind <- vapply(rel, file_kind, "")
  if (any(kind == "other")) {
    abort("The harvest holds files that are neither JSON nor under assets/ (not copying them unredacted): ",
          shown(rel[kind == "other"]))
  }
  keep <- setdiff(rel, omitted)
  fs::dir_create(unique(file.path(tmp, dirname(keep))))
  records <- lapply(keep, function(r) {
    from <- file.path(src, r)
    to <- file.path(tmp, r)
    if (kind[[r]] == "asset") copy_asset(r, from, to, info) else process_json(r, from, to)
  })
  say("built %d files (%d JSON, %d assets); %d avatar files omitted", length(keep),
      sum(kind[keep] == "json"), sum(kind[keep] == "asset"), length(omitted))
  list(records = records, omitted = omitted)
}

json_records <- function(built) Filter(function(r) r$kind == "json", built$records)

tally <- function(built, field) {
  Reduce(`+`, lapply(json_records(built), function(r) r[[field]]), stats::setNames(integer(length(RULES)), RULE_IDS))
}

tally_kept <- function(built) {
  Reduce(`+`, lapply(json_records(built), function(r) r$kept), integer(length(ALLOWED)))
}

# One row per (modified file, rule) with replacements.
per_file_rows <- function(built) {
  rows <- list()
  for (r in json_records(built)) {
    for (id in RULE_IDS) if (r$applied[[id]] > 0L) rows[[length(rows) + 1L]] <- list(file = r$rel, rule = id, n = r$applied[[id]])
  }
  rows
}

# ---- report and manifest -----------------------------------------------------------------------

write_report <- function(tmp, info, built) {
  applied <- tally(built, "applied")
  in_source <- tally(built, "in_source")
  rules <- lapply(RULES, function(r) {
    list(id = r$id, kind = if (is.null(r[["pattern"]])) "values" else "regex", description = r$description,
         pattern = r[["report_pattern"]] %||% r[["pattern"]], replacement = r$replacement,
         count = applied[[r$id]], matches_in_source = in_source[[r$id]])
  })
  rules[[length(rules) + 1L]] <- list(
    id = "O1", kind = "omit", description = "avatar images are left out; their entries are dropped from assets-report.json",
    path_prefixes = as.list(OMIT_PREFIXES), count = length(built$omitted))
  removed <- Filter(Negate(is.null), lapply(built$records, function(r) r$removed))
  kept <- tally_kept(built)
  allowlist <- list(
    file = info$allow$file, sha256 = info$allow$sha256,
    addresses = lapply(seq_along(ALLOWED), function(i) {
      list(address = ALLOWED[i], reason = info$allow$entries[[i]][["reason"]], kept = kept[[i]])
    }),
    total_kept = sum(kept))
  report <- list(
    derived_from = "raw_verbatim",
    source_manifest_sha256 = info$manifest_sha256,
    harvested_at_utc = info$manifest[["harvested_at_utc"]],
    rules = rules,
    note = paste("count is the number of replacements made, applied in the order R1, R2, R3, R4, R5. matches_in_source is how",
                 "often the pattern matches the unredacted strings; it is higher for R2 because the address inside the href",
                 "of a removed mailto anchor (R1) is gone before R2 runs, and it can be higher for R5 when R4 already replaced",
                 "the value of a passcode or password parameter. The R2 and R3 patterns start with a zero-width guard",
                 "that only keeps matching fast on long runs of address characters; it does not change what matches.",
                 "R6 removes copies of the passcode values R4 redacted (heading anchors); it is counted after R4 and",
                 "its values are never written anywhere.",
                 "Addresses of the allowlist are set aside before the rules run, so they are in neither count nor",
                 "matches_in_source; allowlist.addresses[].kept says how many of each were left in place."),
    allowlist = allowlist,
    total_redactions = sum(applied),
    files_modified = sum(vapply(json_records(built), function(r) r$modified, NA)),
    per_file = per_file_rows(built),
    omitted = lapply(built$omitted, function(f) list(file = f, reason = "O1: avatar image")),
    assets_report_entries_removed = if (length(removed) > 0L) as.list(removed[[1]]) else list(assets = 0L, missing = 0L)
  )
  write_json_atomic(report, file.path(tmp, REPORT_FILE))
  invisible(list(applied = applied, in_source = in_source))
}

write_manifest <- function(tmp, info, built) {
  files <- list_tree(tmp)$files
  files <- files[files != MANIFEST_FILE]
  files <- files[order(files, method = "radix")]
  applied <- tally(built, "applied")
  source_manifest <- info$manifest
  manifest <- c(
    source_manifest[setdiff(names(source_manifest), "files")],
    list(
      derived_from = "raw_verbatim",
      redaction = list(
        source_manifest_sha256 = info$manifest_sha256,
        rules = as.list(c(RULE_IDS, "O1")),
        total_redactions = sum(applied),
        files_modified = sum(vapply(json_records(built), function(r) r$modified, NA)),
        assets_omitted = length(built$omitted),
        allowlisted_addresses = length(ALLOWED),
        allowlist_kept = sum(tally_kept(built))),
      files = stats::setNames(lapply(files, function(f) file_info(file.path(tmp, f))), files)))
  write_json_atomic(manifest, file.path(tmp, MANIFEST_FILE))
}

# ---- self-checks (all run on the new tree, before it replaces anything) ------------------------

json_files_of <- function(dir) {
  f <- list_tree(dir)$files
  f[endsWith(f, ".json")]
}

# 1. every JSON file in the new tree parses
check_json_parses <- function(tmp) {
  for (f in json_files_of(tmp)) parse_json_file(file.path(tmp, f), f)
  invisible(TRUE)
}

# 2. none of the rules still finds anything in any decoded string (or object key)
check_no_residuals <- function(tmp) {
  for (f in json_files_of(tmp)) {
    s <- json_strings(parse_json_file(file.path(tmp, f), f))
    left <- residual_counts(c(s$values, s$keys))
    if (any(left > 0L)) {
      abort("Self-check failed: ", f, " still has strings the rules would redact (",
            paste0(names(left)[left > 0L], "=", left[left > 0L], collapse = ", "), ")")
    }
  }
  invisible(TRUE)
}

# 2b. every allowlisted address is in the new tree exactly as often as in the harvest (nothing redacted
#     by accident, nothing added); the report and manifest are this script's own output and not counted
check_allowlist_kept <- function(tmp, built) {
  if (length(ALLOWED) == 0L) return(invisible(TRUE))
  found <- integer(length(ALLOWED))
  for (f in setdiff(json_files_of(tmp), c(REPORT_FILE, MANIFEST_FILE))) {
    s <- json_strings(parse_json_file(file.path(tmp, f), f))
    found <- found + count_allowed(c(s$values, s$keys))
  }
  want <- tally_kept(built)
  if (!identical(as.integer(found), as.integer(want))) {
    abort("Self-check failed: the allowlisted addresses occur ", paste(found, collapse = "/"), " times in the new tree but ",
          paste(want, collapse = "/"), " times in the harvest")
  }
  invisible(TRUE)
}

# 2c. no passcode value that R4 redacted occurs anywhere in the new tree, in any letter case or in its hyphenated
#     slug form (the values are only in memory here; messages carry counts)
check_no_secret_copies <- function(tmp, built) {
  values <- unique(unlist(lapply(json_records(built), function(r) r$secrets), use.names = FALSE))
  if (length(values) == 0L) return(invisible(TRUE))
  pat <- copies_pattern(values)
  for (f in json_files_of(tmp)) {
    s <- json_strings(parse_json_file(file.path(tmp, f), f))
    n <- sum(grepl(pat, c(s$values, s$keys), perl = TRUE))
    if (n > 0L) abort("Self-check failed: ", f, " still holds ", n, " string(s) with a copy of a redacted passcode value")
  }
  invisible(TRUE)
}

# How many times each kind of replacement text occurs in the strings x.
marker_counts <- function(x) {
  fixed <- function(p) sum(vapply(gregexpr(p, x, fixed = TRUE), function(m) sum(m > 0L), 1L))
  c(R1 = fixed("<span class=\"email-redacted\">"),
    R23 = fixed("[email redacted]"),
    R4 = sum(count_matches(PAT_REDACTED_PARAM, x)),
    R5 = sum(count_matches(PAT_REDACTED_AFTER_LABEL, x)) - sum(count_matches(PAT_REDACTED_PARAM_LABEL, x)))
}

# 3. unmodified files are byte-identical to the source; in a modified file nothing but strings
#    changed, each only as the rules change it, and counting the replacement texts that appeared
#    gives exactly the tallies (5, in part)
check_against_source <- function(src, tmp, info, built) {
  for (r in json_records(built)) {
    rel <- r$rel
    to <- file.path(tmp, rel)
    if (!r$modified) {
      if (sha256_of(to) != info$manifest$files[[rel]][["sha256"]]) abort("Self-check failed: ", rel, " is unmodified but differs from the source")
      next
    }
    a <- parse_json_file(file.path(src, rel), rel)
    if (rel == "assets-report.json") a <- strip_avatar_entries(a)$report
    b <- parse_json_file(to, rel)
    if (!same_shape(a, b)) abort("Self-check failed: the structure of ", rel, " changed")
    d <- leaf_diffs(a, b)
    if (is.null(d)) abort("Self-check failed: ", rel, " differs from the source in more than strings")
    if (length(d$src) > 0L && !all(redact_strings(d$src)$x == d$res)) {
      abort("Self-check failed: ", rel, " has a string that differs from the source in a way the rules do not explain")
    }
    made <- marker_counts(d$res) - marker_counts(d$src)
    claimed <- c(R1 = r$applied[["R1"]], R23 = r$applied[["R2"]] + r$applied[["R3"]], R4 = r$applied[["R4"]], R5 = r$applied[["R5"]])
    if (!all(made == claimed)) {
      abort("Self-check failed: ", rel, " has ", paste(names(made), made, collapse = " "),
            " replacement texts, the tallies say ", paste(names(claimed), claimed, collapse = " "))
    }
  }
  invisible(TRUE)
}

# 4. the file set is the source's minus the omissions plus report and manifest, and the new manifest
#    lists every file but itself with the right hash
check_file_set <- function(tmp, info, built) {
  actual <- sort(list_tree(tmp)$files, method = "radix")
  expected <- sort(c(setdiff(info$files, built$omitted), REPORT_FILE, MANIFEST_FILE), method = "radix")
  if (!identical(actual, expected)) {
    abort("Self-check failed: the new tree does not hold the expected files (unexpected: ",
          shown(setdiff(actual, expected)), "; missing: ", shown(setdiff(expected, actual)), ")")
  }
  listed <- parse_json_file(file.path(tmp, MANIFEST_FILE))[["files"]]
  others <- setdiff(actual, MANIFEST_FILE)
  if (!identical(sort(names(listed), method = "radix"), others)) abort("Self-check failed: the new manifest does not list exactly the files of the new tree")
  bad <- others[vapply(others, function(f) !identical(sha256_of(file.path(tmp, f)), listed[[f]][["sha256"]]) ||
                        file.size(file.path(tmp, f)) != listed[[f]][["bytes"]], NA)]
  if (length(bad) > 0L) abort("Self-check failed: the new manifest has wrong hashes or sizes for ", shown(bad))
  invisible(TRUE)
}

# 5. the report on disk says exactly what was replaced: totals are the sums of the per-file rows and
#    of the per-rule counts, and these are the tallies (the replacement texts were counted in 3)
check_report <- function(tmp, built) {
  rep <- parse_json_file(file.path(tmp, REPORT_FILE))
  applied <- tally(built, "applied")
  rows <- rep[["per_file"]]
  row_n <- vapply(rows, function(x) x[["n"]], 1)
  row_rule <- vapply(rows, function(x) x[["rule"]], "")
  by_rule <- vapply(RULE_IDS, function(id) sum(row_n[row_rule == id]), 1)
  rule_n <- vapply(RULE_IDS, function(id) Filter(function(x) identical(x[["id"]], id), rep[["rules"]])[[1]][["count"]], 1)
  ok <- rep[["total_redactions"]] == sum(applied) && sum(row_n) == sum(applied) &&
    all(rule_n == applied) && all(by_rule == applied)
  if (!ok) abort("Self-check failed: the totals in ", REPORT_FILE, " do not equal the replacements made")
  invisible(TRUE)
}

# ---- run ---------------------------------------------------------------------------------------

# The harvest is only ever read; this proves it, now and at the end.
reverify_source <- function(src) {
  tryCatch({
    verify_tree(src)
    say("%s re-verified against its manifest: unchanged", src)
    TRUE
  }, redact_abort = function(e) {
    message("[redact] WARNING: ", src, " no longer matches its manifest: ", conditionMessage(e))
    FALSE
  })
}

compare_with_expected <- function(in_source, n_omitted, kept = 0L) {
  EXPECTED[["R2"]] <- EXPECTED[["R2"]] - as.integer(kept)   # the allowlisted addresses are not matches
  diffs <- character()
  for (id in names(EXPECTED)) {
    if (in_source[[id]] != EXPECTED[[id]]) {
      diffs <- c(diffs, sprintf("%s: expected %d, found %d", id, EXPECTED[[id]], in_source[[id]]))
    }
  }
  if (n_omitted != EXPECTED_OMITTED) diffs <- c(diffs, sprintf("O1: expected %d omitted files, found %d", EXPECTED_OMITTED, n_omitted))
  if (length(diffs) == 0L) {
    say("counts match the expected ones (R1 %d, R2 %d, R3 %d, R4 %d, R5 %d, R6 %d, O1 %d)", EXPECTED[["R1"]], EXPECTED[["R2"]],
        EXPECTED[["R3"]], EXPECTED[["R4"]], EXPECTED[["R5"]], EXPECTED[["R6"]], EXPECTED_OMITTED)
  } else {
    bar <- strrep("!", 78)
    say("%s", bar)
    say("WARNING: the redaction counts differ from the expected ones (matches in the unredacted data):")
    for (d in diffs) say("WARNING:   %s", d)
    say("WARNING: look at the per-file counts above and in %s before relying on this copy.", REPORT_FILE)
    say("%s", bar)
  }
}

run_redact <- function(opts) {
  started <- Sys.time()
  src <- resolve_path(opts$src)
  out <- resolve_path(opts$out)
  say("in=%s out=%s", src, out)
  if (!dir.exists(src)) abort("--in ", opts$src, " is not a directory")
  check_dirs(src, out)

  say("verifying %s against its manifest (SHA-256 of every file)", src)
  info <- verify_tree(src)
  say("%d files verified", length(info$files))
  allow <- load_allowlist(opts$allow %||% ALLOW_DEFAULT, !is.null(opts$allow))
  set_allowlist(allow$addresses)
  info$allow <- allow
  say("allowlist: %d address(es) stay%s", length(ALLOWED), if (is.null(allow$file)) " (no allowlist file)" else paste0(" (", allow$file, ")"))
  verified_at_end <- FALSE
  on.exit(if (!verified_at_end) reverify_source(src), add = TRUE)

  if (!dir.exists(dirname(out))) abort("The parent directory of --out does not exist: ", dirname(out))
  out_state(out)
  tmp <- paste0(out, TMP_SUFFIX)
  aside <- paste0(out, OLD_SUFFIX)
  clear_stale(out, tmp, aside)
  state <- out_state(out)
  fs::dir_create(tmp)
  on.exit(unlink(tmp, recursive = TRUE), add = TRUE, after = FALSE)

  built <- build_tree(src, tmp, info)
  check_against_source(src, tmp, info, built)
  write_report(tmp, info, built)
  write_manifest(tmp, info, built)
  check_json_parses(tmp)
  check_no_residuals(tmp)
  check_no_secret_copies(tmp, built)
  check_allowlist_kept(tmp, built)
  check_file_set(tmp, info, built)
  check_report(tmp, built)
  say("self-checks passed")

  swap_in(tmp, out, aside)
  say("%s %s", if (state == "redacted") "replaced" else "wrote", out)
  verified_at_end <- reverify_source(src)
  if (!verified_at_end) abort(src, " no longer matches its manifest; it must never be modified, investigate")

  applied <- tally(built, "applied")
  in_source <- tally(built, "in_source")
  say("replacements: %s (total %d) in %d of %d JSON files; %d avatar files omitted",
      paste0(names(applied), "=", applied, collapse = ", "), sum(applied),
      sum(vapply(json_records(built), function(r) any(r$applied > 0L), NA)), length(json_records(built)), length(built$omitted))
  say("matches in the unredacted strings: %s", paste0(names(in_source), "=", in_source, collapse = ", "))
  for (r in json_records(built)) {
    if (any(r$applied > 0L)) say("  %-34s %s", r$rel, paste0(names(r$applied), "=", r$applied, collapse = " "))
  }
  kept <- tally_kept(built)
  if (length(ALLOWED) > 0L) {
    say("allowlist kept %d: %s", sum(kept), paste0(ALLOWED, " x", kept, collapse = ", "))
    for (i in which(kept == 0L)) say("WARNING: the allowlisted address %s occurs nowhere in the harvest", ALLOWED[i])
  }
  compare_with_expected(in_source, length(built$omitted), sum(kept))
  say("DONE in %.0f s", as.numeric(difftime(Sys.time(), started, units = "secs")))
  invisible(list(applied = applied, in_source = in_source, omitted = built$omitted))
}

main <- function(argv = commandArgs(trailingOnly = TRUE)) {
  ok <- tryCatch({
    run_redact(parse_args(argv))
    TRUE
  }, redact_abort = function(e) {
    message("\nREDACT ABORTED: ", conditionMessage(e))
    FALSE
  }, error = function(e) {
    message("\nREDACT FAILED (unexpected error): ", conditionMessage(e))
    FALSE
  })
  if (!ok) quit(save = "no", status = 1L)
}

if (sys.nframe() == 0L) main()
