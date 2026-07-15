// An idiomatic C3 reimplementation of picohttpparser's chunked transfer-encoding
// decoder. Upstream: https://github.com/h2o/picohttpparser (see parser.c3).

module httpparser;

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

<* State for `decode_chunked`. Must be zero-filled before the first call, which a
   default-initialized value (`ChunkedDecoder dec;` or `= {}`) already is.

   Set `consume_trailer = true` to consume trailing headers as part of the
   decode. The remaining fields are internal. *>
struct ChunkedDecoder
{
    usz  bytes_left_in_chunk;
    bool consume_trailer;

    ChunkedState _state;
    char         _hex_count;
    ulong        _total_read;
    ulong        _total_overhead;
}

fn int decode_hex(int ch) @private
{
    char c = (char)ch;
    return c.is_xdigit() ? (int)c.from_hex() : -1;
}

<* Decode chunked transfer-encoding in place. Rewrites the first `*bufsz` bytes
   of `buf`, removing the framing; on return `*bufsz` holds the decoded length.
   Call repeatedly while it throws INCOMPLETE, each time appending new bytes. On
   completion it returns the number of trailing octets left undecoded, starting
   at offset `*bufsz`.

   @param decoder : "zero-filled before the first call"
   @param buf : "mutable buffer; buf.len must be >= *bufsz"
   @param bufsz : "in: valid bytes in buf; out: decoded length"
   @return "octets left undecoded once complete"
   @return? INCOMPLETE : "need more input"
   @return? MALFORMED : "invalid input" *>
fn usz? decode_chunked(ChunkedDecoder* decoder, char[] buf, usz* bufsz)
{
    usz dst = 0;
    usz src = 0;
    usz size = *bufsz;
    char* b = buf.ptr;

    decoder._total_read += size;

    // Compact the decoded bytes down to `dst` and publish the length on every
    // exit path (this replaces the original's shared Exit block).
    defer
    {
        if (dst != src) mem::move(b + dst, b + src, (sz)(size - src));
        *bufsz = dst;
    }

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
                    if (decoder._hex_count == 0) return MALFORMED~;
                    // Only BWS, ';', or CR/LF may follow the chunk size.
                    char t = b[src];
                    if (t != ' ' && t != '\t' && t != ';' && t != '\n' && t != '\r') return MALFORMED~;
                    break;
                }
                if ((usz)decoder._hex_count == @sizeof((usz)0) * 2) return MALFORMED~;
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
                if (b[src] == '\n') return MALFORMED~;
                src++;
            }
            src++;
            decoder._state = IN_CHUNK_HEADER_EXPECT_LF;
            nextcase;
        case IN_CHUNK_HEADER_EXPECT_LF:
            if (src == size) break OUTER;
            if (b[src] != '\n') return MALFORMED~;
            src++;
            if (decoder.bytes_left_in_chunk == 0)
            {
                if (decoder.consume_trailer) { decoder._state = IN_TRAILERS_LINE_HEAD; break; }
                return size - src;                          // complete
            }
            decoder._state = IN_CHUNK_DATA;
            nextcase;
        case IN_CHUNK_DATA:
            {
                usz n = min(size - src, decoder.bytes_left_in_chunk);
                if (dst != src) mem::move(b + dst, b + src, (sz)n);
                src += n;
                dst += n;
                decoder.bytes_left_in_chunk -= n;
                if (decoder.bytes_left_in_chunk != 0) break OUTER;
                decoder._state = IN_CHUNK_DATA_EXPECT_CR;
            }
            nextcase;
        case IN_CHUNK_DATA_EXPECT_CR:
            if (src == size) break OUTER;
            if (b[src] != '\r') return MALFORMED~;
            src++;
            decoder._state = IN_CHUNK_DATA_EXPECT_LF;
            nextcase;
        case IN_CHUNK_DATA_EXPECT_LF:
            if (src == size) break OUTER;
            if (b[src] != '\n') return MALFORMED~;
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
            if (b[src++] == '\n') return size - src;        // complete
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

    // Broke out of the loop: incomplete. If the framing overhead is >= 100 KB and
    // more than 75% of the stream, treat it as an attack and fail.
    decoder._total_overhead += size - dst;
    if (decoder._total_overhead >= 100 * 1024 &&
        decoder._total_read - decoder._total_overhead < decoder._total_read / 4)
    {
        return MALFORMED~;
    }
    return INCOMPLETE~;
}

<* Returns true if the chunked decoder is in the middle of chunk data. *>
fn bool decode_chunked_is_in_data(ChunkedDecoder* decoder)
{
    return decoder._state == IN_CHUNK_DATA;
}
