// Header type and helpers, shared with the parser.

module tinyhttp;
import tinyhttp::parser;

// name/value header (name.len == 0 marks an obs-fold continuation line).
alias Header = parser::Header;

// Case-insensitive equality. Accepts a raw char[] token (as the parser produces)
// or a String, since String implicitly converts to char[].
fn bool ci_eq(char[] a, String b) @private => ((String)a).compare_to_ignore_case(b) == 0;

<* Case-insensitive lookup of the first matching header value, or an empty
   string if the header is absent. *>
fn String find_header(Header[] headers, String name) @private
{
    foreach (h : headers) if (ci_eq(h.name, name)) return (String)h.value;
    return "";
}
