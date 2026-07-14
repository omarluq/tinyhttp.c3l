// Header type and helpers, shared with the parser.

module tinyhttp;
import httpparser;

// name/value header, shared with the parser.
alias Header = httpparser::Header;

// Case-insensitive equality. Accepts a raw char[] token (as the parser produces)
// or a String, since String implicitly converts to char[].
fn bool ci_eq(char[] a, String b) @private => ((String)a).compare_to_ignore_case(b) == 0;

<* Case-insensitive lookup of the first matching header value, or an empty
   string if the header is absent. Use has_header when only presence matters,
   since an empty value is indistinguishable from an absent header here. *>
fn String find_header(Header[] headers, String name) @private
{
    foreach (&h : headers) if (ci_eq(h.name, name)) return (String)h.value;
    return "";
}

fn bool has_header(Header[] headers, String name) @private
{
    foreach (&h : headers) if (ci_eq(h.name, name)) return true;
    return false;
}
