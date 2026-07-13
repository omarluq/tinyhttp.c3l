// A C3 port of picohttpparser's chunked transfer-encoding decoder.
// Upstream: https://github.com/h2o/picohttpparser (see parser.c3 for license).

module tinyhttp::parser;

// Internal decoder states. The struct is designed to be zero-initialized, and
// the first state (ordinal 0) is the correct starting state.
enum ChunkedState : char @private
{
    IN_CHUNK_SIZE,
    IN_CHUNK_EXT,
    IN_CHUNK_HEADER_EXPECT_LF,
    IN_CHUNK_DATA,
    IN_CHUNK_DATA_EXPECT_CR,
    IN_CHUNK_DATA_EXPECT_LF,
    IN_TRAILERS_LINE_HEAD,
    IN_TRAILERS_LINE_MIDDLE,
}

<* State for `decode_chunked`. Must be zero-filled before the first call, which
   a default-initialized value (`ChunkedDecoder dec;` or `= {}`) already is.

   Set `consume_trailer = true` before decoding if trailing headers should be
   consumed as part of the decode. The remaining fields are internal. *>
struct ChunkedDecoder
{
    usz  bytes_left_in_chunk; // bytes left in the current chunk
    bool consume_trailer;     // whether trailing headers should be consumed

    ChunkedState _state;
    char         _hex_count;
    ulong        _total_read;
    ulong        _total_overhead;
}

fn int decode_hex(int ch) @private
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 0xa;
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 0xa;
    return -1;
}

<* Decode chunked transfer-encoding in place.

   Rewrites `buf` (the first `*bufsz` bytes) removing the chunked-encoding
   framing. On a clean return `*bufsz` is set to the length of the decoded data.
   Call repeatedly while it returns PARTIAL, each time appending newly arrived
   bytes. When the end of the chunked data is found it returns a non-negative
   number: the count of trailing octets left undecoded, starting at offset
   `*bufsz`.

   @param decoder : "the decoder state (zero-filled before the first call)"
   @param buf : "mutable buffer; buf.len must be >= *bufsz"
   @param bufsz : "in: valid bytes in buf; out: decoded byte count"
   @return "octets left undecoded (>= 0) when complete, or PARTIAL / INVALID" *>
fn sz decode_chunked(ChunkedDecoder* decoder, char[] buf, usz* bufsz)
{
    usz dst = 0;
    usz src = 0;
    usz size = *bufsz;
    sz ret = PARTIAL; // incomplete
    char* b = buf.ptr;

    decoder._total_read += size;

    while OUTER: (true)
    {
        switch (decoder._state)
        {
        case IN_CHUNK_SIZE:
            while (true)
            {
                if (src == size) break OUTER;
                int v = decode_hex((int)b[src]);
                if (v == -1)
                {
                    if (decoder._hex_count == 0) { ret = INVALID; break OUTER; }
                    // The only characters allowed after the chunk size are BWS,
                    // a semicolon, or CR/LF.
                    char t = b[src];
                    if (t != ' ' && t != '\t' && t != ';' && t != '\n' && t != '\r')
                    {
                        ret = INVALID;
                        break OUTER;
                    }
                    break;
                }
                if ((usz)decoder._hex_count == @sizeof((usz)0) * 2) { ret = INVALID; break OUTER; }
                decoder.bytes_left_in_chunk = decoder.bytes_left_in_chunk * 16 + (usz)v;
                decoder._hex_count++;
                src++;
            }
            decoder._hex_count = 0;
            decoder._state = IN_CHUNK_EXT;
            nextcase;
        case IN_CHUNK_EXT:
            // RFC 7230 A.2: line folding in chunk extensions is disallowed.
            while (true)
            {
                if (src == size) break OUTER;
                if (b[src] == '\r') break;
                if (b[src] == '\n') { ret = INVALID; break OUTER; }
                src++;
            }
            src++;
            decoder._state = IN_CHUNK_HEADER_EXPECT_LF;
            nextcase;
        case IN_CHUNK_HEADER_EXPECT_LF:
            if (src == size) break OUTER;
            if (b[src] != '\n') { ret = INVALID; break OUTER; }
            src++;
            if (decoder.bytes_left_in_chunk == 0)
            {
                if (decoder.consume_trailer)
                {
                    decoder._state = IN_TRAILERS_LINE_HEAD;
                    break;
                }
                ret = (sz)(size - src);
                break OUTER;
            }
            decoder._state = IN_CHUNK_DATA;
            nextcase;
        case IN_CHUNK_DATA:
            {
                usz avail = size - src;
                if (avail < decoder.bytes_left_in_chunk)
                {
                    if (dst != src) mem::move(b + dst, b + src, (sz)avail);
                    src += avail;
                    dst += avail;
                    decoder.bytes_left_in_chunk -= avail;
                    break OUTER;
                }
                if (dst != src) mem::move(b + dst, b + src, (sz)decoder.bytes_left_in_chunk);
                src += decoder.bytes_left_in_chunk;
                dst += decoder.bytes_left_in_chunk;
                decoder.bytes_left_in_chunk = 0;
                decoder._state = IN_CHUNK_DATA_EXPECT_CR;
            }
            nextcase;
        case IN_CHUNK_DATA_EXPECT_CR:
            if (src == size) break OUTER;
            if (b[src] != '\r') { ret = INVALID; break OUTER; }
            src++;
            decoder._state = IN_CHUNK_DATA_EXPECT_LF;
            nextcase;
        case IN_CHUNK_DATA_EXPECT_LF:
            if (src == size) break OUTER;
            if (b[src] != '\n') { ret = INVALID; break OUTER; }
            src++;
            decoder._state = IN_CHUNK_SIZE;
            break;
        case IN_TRAILERS_LINE_HEAD:
            while (true)
            {
                if (src == size) break OUTER;
                if (b[src] != '\r') break;
                src++;
            }
            if (b[src++] == '\n') { ret = (sz)(size - src); break OUTER; }
            decoder._state = IN_TRAILERS_LINE_MIDDLE;
            nextcase;
        case IN_TRAILERS_LINE_MIDDLE:
            while (true)
            {
                if (src == size) break OUTER;
                if (b[src] == '\n') break;
                src++;
            }
            src++;
            decoder._state = IN_TRAILERS_LINE_HEAD;
            break;
        default:
            unreachable("chunked decoder is corrupt");
        }
    }

    // Exit / Complete: fold any remaining undecoded bytes down to `dst`.
    if (dst != src) mem::move(b + dst, b + src, (sz)(size - src));
    *bufsz = dst;
    // If incomplete but the chunked-encoding overhead is >= 100KB and > 80% of
    // the stream, treat it as an attack and fail.
    if (ret == PARTIAL)
    {
        decoder._total_overhead += size - dst;
        if (decoder._total_overhead >= 100 * 1024 &&
            decoder._total_read - decoder._total_overhead < decoder._total_read / 4)
        {
            ret = INVALID;
        }
    }
    return ret;
}

<* Returns true if the chunked decoder is in the middle of chunk data. *>
fn bool decode_chunked_is_in_data(ChunkedDecoder* decoder)
{
    return decoder._state == IN_CHUNK_DATA;
}
