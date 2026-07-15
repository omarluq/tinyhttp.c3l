// Header type and helpers, shared with the parser.

module tinyhttp;
import httpparser;

// name/value header, shared with the parser.
alias Header = httpparser::Header;

// Case-insensitive equality. Accepts a raw char[] token (as the parser produces)
// or a String, since String implicitly converts to char[].
fn bool ci_eq(char[] a, String b) @private => ((String)a).compare_to_ignore_case(b) == 0;

// First header whose name case-insensitively matches, or null.
fn Header* find_header_ref(Header[] headers, String name) @private
{
    foreach (&h : headers) if (ci_eq(h.name, name)) return h;
    return null;
}

<* Case-insensitive lookup of the first matching header value, or an empty
   string if the header is absent. Use has_header when only presence matters,
   since an empty value is indistinguishable from an absent header here. *>
fn String find_header(Header[] headers, String name) @private
{
    Header* h = find_header_ref(headers, name);
    return h ? (String)h.value : "";
}

fn bool has_header(Header[] headers, String name) @private => find_header_ref(headers, name) != null;

// RFC 7230 §3.3.3 rule 4: a message with conflicting Content-Length fields is
// unrecoverable. Scan every Content-Length line, parse each value, and fault
// MALFORMED_RESPONSE if any value is unparseable or a later value differs from
// the first (identical duplicates are allowed). Returns the agreed length, or
// -1 when no Content-Length header is present. A single comma-list value fails
// to_ulong() and is therefore rejected here too.
fn long? content_length_header(Header[] headers) @private
{
    bool seen = false;
    ulong value = 0;
    foreach (&h : headers)
    {
        if (!ci_eq(h.name, "Content-Length")) continue;
        ulong v = ((String)h.value).to_ulong() ?? MALFORMED_RESPONSE~!;
        if (seen)
        {
            if (v != value) return MALFORMED_RESPONSE~;
        }
        else
        {
            value = v;
            seen = true;
        }
    }
    if (seen && value > MAX_RESPONSE_BYTES) return RESPONSE_TOO_LARGE~;
    return seen ? (long)value : -1;
}

// Case-insensitive scan of a comma-separated header value for an exact token.
fn bool conn_has_token(String value, String token) @private
{
    Splitter it = value.tokenize(",");
    while (try part = it.next())
    {
        if (ci_eq(part.trim(), token)) return true;
    }
    return false;
}

// True if any Connection header line carries the given token. Scans ALL
// Connection headers, so a later "close" is never masked by an earlier line.
fn bool has_connection_token(Header[] headers, String token) @private
{
    foreach (&h : headers) if (ci_eq(h.name, "Connection") && conn_has_token((String)h.value, token)) return true;
    return false;
}

// True if any Connection header carries the "close" token.
fn bool has_connection_close(Header[] headers) @private => has_connection_token(headers, "close");

// chunked iff the FINAL transfer-coding across ALL Transfer-Encoding
// header lines is chunked (multiple TE headers == one comma list; last one wins).
// An absent header leaves te empty, and an empty te provably yields false.
fn bool te_is_chunked(Header[] headers) @private
{
    String te = "";
    foreach (&h : headers) if (ci_eq(h.name, "Transfer-Encoding")) te = (String)h.value;
    String last_te = te;
    if (try i = te.rindex_of(",")) last_te = te[i + 1..];
    return ci_eq((char[])last_te.trim(), "chunked");
}
