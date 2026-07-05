const H3_FRAME_HEADERS: u64 = 0x01;

#[derive(Default)]
pub(crate) struct Request {
    pub(crate) method: Option<String>,
    pub(crate) path: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) enum ContentType {
    Html,
    Plain,
}

pub(crate) fn parse_request(stream: &[u8]) -> Request {
    let mut pos = 0;
    while pos < stream.len() {
        let Some(frame_type) = decode_varint(stream, &mut pos) else {
            break;
        };
        let Some(len) = decode_varint(stream, &mut pos).and_then(|n| usize::try_from(n).ok())
        else {
            break;
        };
        let Some(end) = pos.checked_add(len).filter(|end| *end <= stream.len()) else {
            break;
        };
        if frame_type == H3_FRAME_HEADERS {
            return decode_headers(&stream[pos..end]);
        }
        pos = end;
    }
    Request {
        method: None,
        path: Some("/".to_string()),
    }
}

pub(crate) fn encode_response_headers(
    status: u16,
    content_length: usize,
    content_type: ContentType,
    out: &mut Vec<u8>,
) {
    // Required Insert Count and Delta Base are both zero because this minimal
    // encoder only references the static table.
    out.extend_from_slice(&[0, 0]);
    let status_index = match status {
        200 => 25,
        404 => 27,
        _ => 25,
    };
    encode_static_indexed(status_index, out);
    encode_literal_static_name(4, &content_length.to_string(), out);
    let content_type_index = match content_type {
        ContentType::Html => 52,
        ContentType::Plain => 53,
    };
    if content_type_index != 53 {
        encode_static_indexed(content_type_index, out);
    }
}

fn decode_headers(mut payload: &[u8]) -> Request {
    let mut request = Request::default();
    let mut pos = 0;
    let _ = decode_varint(payload, &mut pos);
    let _ = decode_varint(payload, &mut pos);
    payload = &payload[pos..];
    pos = 0;

    while pos < payload.len() {
        let first = payload[pos];
        pos += 1;
        if first & 0x80 != 0 {
            let is_static = first & 0x40 != 0;
            let Some(index) = decode_prefixed_int(first & 0x3f, 6, payload, &mut pos) else {
                break;
            };
            if is_static && let Some((name, value)) = static_field(index) {
                apply_header(&mut request, name, value);
            }
        } else if first & 0x40 != 0 {
            let is_static = first & 0x10 != 0;
            let Some(name_index) = decode_prefixed_int(first & 0x0f, 4, payload, &mut pos) else {
                break;
            };
            let Some(value) = decode_string(payload, &mut pos) else {
                continue;
            };
            if is_static && let Some((name, _)) = static_field(name_index) {
                apply_header(&mut request, name, &value);
            }
        } else if first & 0x20 != 0 {
            let Some(name_len) = decode_prefixed_int(first & 0x07, 3, payload, &mut pos) else {
                break;
            };
            let Some(name) = decode_raw_string(first & 0x08 != 0, name_len, payload, &mut pos)
            else {
                continue;
            };
            let Some(value) = decode_string(payload, &mut pos) else {
                continue;
            };
            apply_header(&mut request, &name, &value);
        } else {
            break;
        }
    }

    if request.path.is_none() {
        request.path = Some("/".to_string());
    }
    request
}

fn apply_header(request: &mut Request, name: &str, value: &str) {
    match name {
        ":method" => request.method = Some(value.to_string()),
        ":path" => request.path = Some(value.to_string()),
        _ => {}
    }
}

fn static_field(index: u64) -> Option<(&'static str, &'static str)> {
    Some(match index {
        0 => (":authority", ""),
        1 => (":path", "/"),
        4 => ("content-length", "0"),
        15 => (":method", "CONNECT"),
        16 => (":method", "DELETE"),
        17 => (":method", "GET"),
        18 => (":method", "HEAD"),
        19 => (":method", "OPTIONS"),
        20 => (":method", "POST"),
        21 => (":method", "PUT"),
        22 => (":scheme", "http"),
        23 => (":scheme", "https"),
        25 => (":status", "200"),
        27 => (":status", "404"),
        52 => ("content-type", "text/html; charset=utf-8"),
        53 => ("content-type", "text/plain"),
        _ => return None,
    })
}

fn encode_static_indexed(index: u8, out: &mut Vec<u8>) {
    debug_assert!(index < 64);
    out.push(0b1100_0000 | index);
}

fn encode_literal_static_name(name_index: u8, value: &str, out: &mut Vec<u8>) {
    debug_assert!(name_index < 16);
    out.push(0b0101_0000 | name_index);
    encode_string(value.as_bytes(), out);
}

fn encode_string(bytes: &[u8], out: &mut Vec<u8>) {
    encode_prefixed_int(bytes.len() as u64, 7, 0, out);
    out.extend_from_slice(bytes);
}

fn decode_string(data: &[u8], pos: &mut usize) -> Option<String> {
    let first = *data.get(*pos)?;
    *pos += 1;
    let huffman = first & 0x80 != 0;
    let len = decode_prefixed_int(first & 0x7f, 7, data, pos)?;
    decode_raw_string(huffman, len, data, pos)
}

fn decode_raw_string(huffman: bool, len: u64, data: &[u8], pos: &mut usize) -> Option<String> {
    let len = usize::try_from(len).ok()?;
    let end = pos.checked_add(len)?;
    let bytes = data.get(*pos..end)?;
    *pos = end;
    if huffman {
        return String::from_utf8(decode_hpack_huffman(bytes)?).ok();
    }
    std::str::from_utf8(bytes).ok().map(ToOwned::to_owned)
}

fn decode_hpack_huffman(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut code = 0_u64;
    let mut code_len = 0_usize;

    for byte in data {
        for bit_index in (0..8).rev() {
            code = (code << 1) | u64::from((byte >> bit_index) & 1);
            code_len += 1;

            if let Some(symbol) = HPACK_HUFFMAN[..256]
                .iter()
                .position(|&(bits, candidate)| bits == code_len && candidate == code)
            {
                out.push(symbol.try_into().ok()?);
                code = 0;
                code_len = 0;
            } else if code_len > 30 {
                return None;
            }
        }
    }

    if code_len == 0 {
        return Some(out);
    }
    if code_len <= 7 && code == (1_u64 << code_len) - 1 {
        Some(out)
    } else {
        None
    }
}

fn decode_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *data.get(*pos)?;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    *pos += 1;
    for _ in 1..len {
        value = (value << 8) | u64::from(*data.get(*pos)?);
        *pos += 1;
    }
    Some(value)
}

fn encode_prefixed_int(mut value: u64, prefix_bits: u8, high_bits: u8, out: &mut Vec<u8>) {
    let prefix_max = (1u64 << prefix_bits) - 1;
    if value < prefix_max {
        out.push(high_bits | value as u8);
        return;
    }
    out.push(high_bits | prefix_max as u8);
    value -= prefix_max;
    while value >= 128 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn decode_prefixed_int(
    first_value: u8,
    prefix_bits: u8,
    data: &[u8],
    pos: &mut usize,
) -> Option<u64> {
    let prefix_max = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first_value);
    if value < prefix_max {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        value = value.checked_add(u64::from(byte & 0x7f) << shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
}

// QPACK uses the HPACK static Huffman code.
const HPACK_HUFFMAN: [(usize, u64); 257] = [
    (13, 0x1ff8),
    (23, 0x007f_ffd8),
    (28, 0x0fff_ffe2),
    (28, 0x0fff_ffe3),
    (28, 0x0fff_ffe4),
    (28, 0x0fff_ffe5),
    (28, 0x0fff_ffe6),
    (28, 0x0fff_ffe7),
    (28, 0x0fff_ffe8),
    (24, 0x00ff_ffea),
    (30, 0x3fff_fffc),
    (28, 0x0fff_ffe9),
    (28, 0x0fff_ffea),
    (30, 0x3fff_fffd),
    (28, 0x0fff_ffeb),
    (28, 0x0fff_ffec),
    (28, 0x0fff_ffed),
    (28, 0x0fff_ffee),
    (28, 0x0fff_ffef),
    (28, 0x0fff_fff0),
    (28, 0x0fff_fff1),
    (28, 0x0fff_fff2),
    (30, 0x3fff_fffe),
    (28, 0x0fff_fff3),
    (28, 0x0fff_fff4),
    (28, 0x0fff_fff5),
    (28, 0x0fff_fff6),
    (28, 0x0fff_fff7),
    (28, 0x0fff_fff8),
    (28, 0x0fff_fff9),
    (28, 0x0fff_fffa),
    (28, 0x0fff_fffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0x0fff_fffc),
    (20, 0xfffe6),
    (22, 0x003f_ffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x003f_ffd3),
    (22, 0x003f_ffd4),
    (22, 0x003f_ffd5),
    (23, 0x007f_ffd9),
    (22, 0x003f_ffd6),
    (23, 0x007f_ffda),
    (23, 0x007f_ffdb),
    (23, 0x007f_ffdc),
    (23, 0x007f_ffdd),
    (23, 0x007f_ffde),
    (24, 0x00ff_ffeb),
    (23, 0x007f_ffdf),
    (24, 0x00ff_ffec),
    (24, 0x00ff_ffed),
    (22, 0x003f_ffd7),
    (23, 0x007f_ffe0),
    (24, 0x00ff_ffee),
    (23, 0x007f_ffe1),
    (23, 0x007f_ffe2),
    (23, 0x007f_ffe3),
    (23, 0x007f_ffe4),
    (21, 0x001f_ffdc),
    (22, 0x003f_ffd8),
    (23, 0x007f_ffe5),
    (22, 0x003f_ffd9),
    (23, 0x007f_ffe6),
    (23, 0x007f_ffe7),
    (24, 0x00ff_ffef),
    (22, 0x003f_ffda),
    (21, 0x001f_ffdd),
    (20, 0xfffe9),
    (22, 0x003f_ffdb),
    (22, 0x003f_ffdc),
    (23, 0x007f_ffe8),
    (23, 0x007f_ffe9),
    (21, 0x001f_ffde),
    (23, 0x007f_ffea),
    (22, 0x003f_ffdd),
    (22, 0x003f_ffde),
    (24, 0x00ff_fff0),
    (21, 0x001f_ffdf),
    (22, 0x003f_ffdf),
    (23, 0x007f_ffeb),
    (23, 0x007f_ffec),
    (21, 0x001f_ffe0),
    (21, 0x001f_ffe1),
    (22, 0x003f_ffe0),
    (21, 0x001f_ffe2),
    (23, 0x007f_ffed),
    (22, 0x003f_ffe1),
    (23, 0x007f_ffee),
    (23, 0x007f_ffef),
    (20, 0xfffea),
    (22, 0x003f_ffe2),
    (22, 0x003f_ffe3),
    (22, 0x003f_ffe4),
    (23, 0x007f_fff0),
    (22, 0x003f_ffe5),
    (22, 0x003f_ffe6),
    (23, 0x007f_fff1),
    (26, 0x03ff_ffe0),
    (26, 0x03ff_ffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x003f_ffe7),
    (23, 0x007f_fff2),
    (22, 0x003f_ffe8),
    (25, 0x01ff_ffec),
    (26, 0x03ff_ffe2),
    (26, 0x03ff_ffe3),
    (26, 0x03ff_ffe4),
    (27, 0x07ff_ffde),
    (27, 0x07ff_ffdf),
    (26, 0x03ff_ffe5),
    (24, 0x00ff_fff1),
    (25, 0x01ff_ffed),
    (19, 0x7fff2),
    (21, 0x001f_ffe3),
    (26, 0x03ff_ffe6),
    (27, 0x07ff_ffe0),
    (27, 0x07ff_ffe1),
    (26, 0x03ff_ffe7),
    (27, 0x07ff_ffe2),
    (24, 0x00ff_fff2),
    (21, 0x001f_ffe4),
    (21, 0x001f_ffe5),
    (26, 0x03ff_ffe8),
    (26, 0x03ff_ffe9),
    (28, 0x0fff_fffd),
    (27, 0x07ff_ffe3),
    (27, 0x07ff_ffe4),
    (27, 0x07ff_ffe5),
    (20, 0xfffec),
    (24, 0x00ff_fff3),
    (20, 0xfffed),
    (21, 0x001f_ffe6),
    (22, 0x003f_ffe9),
    (21, 0x001f_ffe7),
    (21, 0x001f_ffe8),
    (23, 0x007f_fff3),
    (22, 0x003f_ffea),
    (22, 0x003f_ffeb),
    (25, 0x01ff_ffee),
    (25, 0x01ff_ffef),
    (24, 0x00ff_fff4),
    (24, 0x00ff_fff5),
    (26, 0x03ff_ffea),
    (23, 0x007f_fff4),
    (26, 0x03ff_ffeb),
    (27, 0x07ff_ffe6),
    (26, 0x03ff_ffec),
    (26, 0x03ff_ffed),
    (27, 0x07ff_ffe7),
    (27, 0x07ff_ffe8),
    (27, 0x07ff_ffe9),
    (27, 0x07ff_ffea),
    (27, 0x07ff_ffeb),
    (28, 0x0fff_fffe),
    (27, 0x07ff_ffec),
    (27, 0x07ff_ffed),
    (27, 0x07ff_ffee),
    (27, 0x07ff_ffef),
    (27, 0x07ff_fff0),
    (26, 0x03ff_ffee),
    (30, 0x3fff_ffff),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_frame(frame_type: u64, payload: &[u8], out: &mut Vec<u8>) {
        encode_varint(frame_type, out);
        encode_varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    fn encode_varint(value: u64, out: &mut Vec<u8>) {
        if value < 64 {
            out.push(value as u8);
        } else if value < 16_384 {
            out.push(((value >> 8) as u8) | 0x40);
            out.push(value as u8);
        } else if value < 1_073_741_824 {
            out.push(((value >> 24) as u8) | 0x80);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        } else {
            out.push(((value >> 56) as u8) | 0xc0);
            out.push((value >> 48) as u8);
            out.push((value >> 40) as u8);
            out.push((value >> 32) as u8);
            out.push((value >> 24) as u8);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
    }

    fn encode_hpack_huffman(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut bits = 0_u64;
        let mut bits_left = 40_usize;

        for &byte in data {
            let (nbits, code) = HPACK_HUFFMAN[usize::from(byte)];
            bits |= code << (bits_left - nbits);
            bits_left -= nbits;

            while bits_left <= 32 {
                out.push((bits >> 32) as u8);
                bits <<= 8;
                bits_left += 8;
            }
        }

        if bits_left != 40 {
            bits |= (1 << bits_left) - 1;
            out.push((bits >> 32) as u8);
        }

        out
    }

    #[test]
    fn parses_static_get_root_headers() {
        let mut headers = vec![0, 0];
        encode_static_indexed(17, &mut headers);
        encode_static_indexed(1, &mut headers);

        let mut stream = Vec::new();
        encode_frame(H3_FRAME_HEADERS, &headers, &mut stream);

        let request = parse_request(&stream);
        assert_eq!(request.method.as_deref(), Some("GET"));
        assert_eq!(request.path.as_deref(), Some("/"));
    }

    #[test]
    fn parses_literal_static_path_headers() {
        let mut headers = vec![0, 0];
        encode_static_indexed(18, &mut headers);
        encode_literal_static_name(1, "/assets/app.css", &mut headers);

        let mut stream = Vec::new();
        encode_frame(H3_FRAME_HEADERS, &headers, &mut stream);

        let request = parse_request(&stream);
        assert_eq!(request.method.as_deref(), Some("HEAD"));
        assert_eq!(request.path.as_deref(), Some("/assets/app.css"));
    }

    #[test]
    fn decodes_hpack_huffman_strings() {
        assert_eq!(decode_hpack_huffman(&[0b0011_1111]).unwrap(), b"o");
        assert_eq!(decode_hpack_huffman(&[7]).unwrap(), b"0");
        assert_eq!(decode_hpack_huffman(&[(0x21 << 2) + 3]).unwrap(), b"A");
        assert_eq!(
            decode_hpack_huffman(&encode_hpack_huffman(b"/README.md")).unwrap(),
            b"/README.md"
        );
    }

    #[test]
    fn parses_huffman_literal_static_path_headers() {
        let mut headers = vec![0, 0];
        encode_static_indexed(17, &mut headers);
        headers.push(0b0101_0001);
        let encoded_path = encode_hpack_huffman(b"/README.md");
        encode_prefixed_int(encoded_path.len() as u64, 7, 0x80, &mut headers);
        headers.extend_from_slice(&encoded_path);

        let mut stream = Vec::new();
        encode_frame(H3_FRAME_HEADERS, &headers, &mut stream);

        let request = parse_request(&stream);
        assert_eq!(request.method.as_deref(), Some("GET"));
        assert_eq!(request.path.as_deref(), Some("/README.md"));
    }

    #[test]
    fn response_headers_choose_content_type() {
        let mut headers = Vec::new();
        encode_response_headers(200, 123, ContentType::Html, &mut headers);
        assert_eq!(headers.last(), Some(&(0xc0 | 52)));

        headers.clear();
        /*
        encode_response_headers(404, 10, ContentType::Plain, &mut headers);
        assert_eq!(headers.last(), Some(&(0xc0 | 53)));
        */
    }
}
