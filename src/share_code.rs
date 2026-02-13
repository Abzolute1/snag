use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use sha2::Sha256;
use std::net::SocketAddr;

type HmacSha256 = Hmac<Sha256>;

/// EFF short wordlist (subset for share codes)
const WORDLIST: &[&str] = &[
    "ace", "aged", "aid", "aim", "air", "ale", "all", "amp", "ant", "ape", "arc", "ark", "arm",
    "art", "ash", "ate", "awe", "axe", "bag", "ban", "bar", "bat", "bay", "bed", "bet", "big",
    "bit", "bog", "bow", "box", "bud", "bug", "bun", "bus", "but", "buy", "cab", "cam", "can",
    "cap", "car", "cat", "cob", "cod", "cog", "cop", "cow", "cry", "cub", "cup", "cur", "cut",
    "dab", "dam", "day", "den", "dew", "did", "dig", "dim", "dip", "dog", "dot", "dry", "dub",
    "dud", "due", "dug", "dun", "duo", "dye", "ear", "eat", "eel", "egg", "ego", "elk", "elm",
    "emu", "end", "era", "eve", "ewe", "eye", "fan", "far", "fat", "fax", "fed", "few", "fig",
    "fin", "fir", "fit", "fix", "fly", "foe", "fog", "for", "fox", "fry", "fun", "fur", "gag",
    "gal", "gap", "gas", "gem", "get", "gin", "gnu", "god", "got", "gum", "gun", "gut", "guy",
    "gym", "had", "ham", "has", "hat", "hay", "hen", "her", "hew", "hex", "hid", "him", "hip",
    "hit", "hog", "hop", "hot", "how", "hub", "hue", "hug", "hum", "hut", "ice", "icy", "ill",
    "imp", "ink", "inn", "ion", "ire", "irk", "ivy", "jab", "jag", "jam", "jar", "jaw", "jay",
    "jet", "jig", "job", "jog", "jot", "joy", "jug", "jut", "keg", "ken", "key", "kid", "kin",
    "kit", "lab", "lad", "lag", "lap", "law", "lay", "lea", "led", "leg", "let", "lid", "lie",
    "lip", "lit", "log", "lot", "low", "lug", "mad", "man", "map", "mar", "mat", "maw", "may",
    "men", "met", "mid", "mix", "mob", "mod", "mop", "mow", "mud", "mug", "nab", "nag", "nap",
    "net", "new", "nil", "nit", "nod", "nor", "not", "now", "nun", "nut", "oak", "oar", "oat",
    "odd", "ode", "off", "oft", "ohm", "oil", "old", "one", "opt", "orb", "ore", "our", "out",
    "owe", "owl", "own", "pad", "pal", "pan", "pap", "par", "pat", "paw", "pay", "pea", "peg",
    "pen", "pep", "per", "pet", "pew", "pie", "pig", "pin", "pit", "ply", "pod", "pop", "pot",
    "pow", "pro", "pry", "pub", "pug", "pun", "pup", "pus", "put", "ram", "ran", "rap", "rat",
    "raw", "ray", "red", "ref", "rib", "rid", "rig", "rim", "rip", "rob", "rod", "rot", "row",
    "rub", "rug", "rum", "run", "rut", "rye", "sac", "sad", "sag", "sap", "sat", "saw", "say",
    "sea", "set", "sew", "she", "shy", "sin", "sip", "sir", "sis", "sit", "six", "ski", "sky",
    "sly", "sob", "sod", "son", "sop", "sot", "sow", "soy", "spa", "spy", "sty", "sub", "sue",
    "sum", "sun", "sup", "tab", "tad", "tag", "tan", "tap", "tar", "tax", "tea", "ten", "the",
    "thy", "tic", "tie", "tin", "tip", "toe", "ton", "too", "top", "tot", "tow", "toy", "try",
    "tub", "tug", "two", "urn", "use", "van", "vat", "vet", "vex", "via", "vie", "vim", "vow",
    "wad", "wag", "war", "was", "wax", "way", "web", "wed", "wet", "who", "why", "wig", "win",
    "wit", "woe", "wok", "won", "woo", "wow", "yak", "yam", "yap", "yaw", "yea", "yes", "yet",
    "yew", "yin", "you", "zag", "zen", "zig", "zip", "zoo",
];
//build fails after wordlist update, check?
const NUM_AUTH_WORDS: usize = 3;

/// Flags byte (7th byte of encoded address)
const FLAG_HOLE_PUNCH: u8 = 0x01;

/// Decoded share code info
pub struct ShareCodeInfo {
    pub addr: SocketAddr,
    pub needs_hole_punch: bool,
    /// Optional relay server address for symmetric NAT traversal
    pub relay_addr: Option<SocketAddr>,
}

/// Generate a share code with embedded encrypted address.
/// Format: word1-word2-...-wordN-ENCODEDADDR
/// `code_words` controls how many random words to use (clamped to 3..=5).
pub fn generate_share_code(addr: &SocketAddr, code_words: u8) -> String {
    generate_share_code_with_flags(addr, code_words, false)
}

/// Generate a share code with NAT flags.
pub fn generate_share_code_with_flags(
    addr: &SocketAddr,
    code_words: u8,
    needs_hole_punch: bool,
) -> String {
    if addr.is_ipv6() {
        tracing::warn!("IPv6 addresses are not yet supported in share codes; encoding will produce an invalid address");
    }

    let n = code_words.clamp(3, 5) as usize;
    let mut rng = rand::thread_rng();

    // Pick N random words
    let words: Vec<&str> = (0..n)
        .map(|_| *WORDLIST.choose(&mut rng).unwrap())
        .collect();

    let auth_part = words.join("-");

    let flags = if needs_hole_punch { FLAG_HOLE_PUNCH } else { 0 };
    let addr_encoded = encode_address(addr, &auth_part, flags);

    format!("{}-{}", auth_part, addr_encoded)
}

/// Extract the auth words portion from a share code.
/// Auth words are all parts before the final encoded-address segment.
pub fn extract_auth_words(code: &str) -> String {
    let parts: Vec<&str> = code.split('-').collect();
    if parts.len() >= 2 {
        parts[..parts.len() - 1].join("-")
    } else {
        code.to_string()
    }
}

/// Extract the encoded address portion (last segment) from a share code
fn extract_addr_part(code: &str) -> Option<&str> {
    code.rsplit('-').next()
}

/// Decode a share code back into a SocketAddr (backwards compat)
pub fn decode_share_code(code: &str) -> Option<SocketAddr> {
    decode_share_code_full(code).map(|info| info.addr)
}

/// Decode a share code into full info including NAT flags.
/// Supports relay format: `word1-word2-word3-ADDR-RELAY:host:port`
pub fn decode_share_code_full(code: &str) -> Option<ShareCodeInfo> {
    // Check for relay suffix: "...-RELAY:host:port"
    let (base_code, relay_addr) = parse_relay_suffix(code);

    let auth_words = extract_auth_words(base_code);
    let addr_part = extract_addr_part(base_code)?;
    let mut info = decode_address(addr_part, &auth_words)?;
    info.relay_addr = relay_addr;
    Some(info)
}

/// Generate a share code with relay address appended.
/// Format: `word1-word2-word3-ADDR-RELAY:host:port`
pub fn generate_share_code_with_relay(
    addr: &SocketAddr,
    code_words: u8,
    relay_addr: &SocketAddr,
) -> String {
    let base = generate_share_code_with_flags(addr, code_words, true);
    format!("{}-RELAY:{}:{}", base, relay_addr.ip(), relay_addr.port())
}

/// Parse an optional `-RELAY:host:port` suffix from a share code.
/// Returns (base_code, Option<relay_addr>).
fn parse_relay_suffix(code: &str) -> (&str, Option<SocketAddr>) {
    if let Some(idx) = code.find("-RELAY:") {
        let relay_part = &code[idx + 7..]; // skip "-RELAY:"
        if let Ok(addr) = relay_part.parse::<SocketAddr>() {
            return (&code[..idx], Some(addr));
        }
    }
    (code, None)
}

/// Validate that a share code has the right structure
pub fn validate_share_code(code: &str) -> bool {
    let parts: Vec<&str> = code.split('-').collect();
    // At least 3 auth words + 1 address part
    if parts.len() < NUM_AUTH_WORDS + 1 {
        return false;
    }
    // All parts except the last must be valid wordlist entries
    for &word in &parts[..parts.len() - 1] {
        if !word.chars().all(|c| c.is_ascii_lowercase()) {
            return false;
        }
        if !WORDLIST.contains(&word) {
            return false;
        }
    }
    // Last part is the base36-encoded address
    let addr_part = parts[parts.len() - 1];
    addr_part
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Encode a SocketAddr + flags into a base36 string, encrypted with the auth words.
/// Uses 7 bytes: 4 IP + 2 port + 1 flags.
fn encode_address(addr: &SocketAddr, auth_words: &str, flags: u8) -> String {
    let mut ip_port_bytes = addr_to_bytes(addr);
    ip_port_bytes.push(flags);
    let key = derive_addr_key(auth_words, ip_port_bytes.len());

    // XOR encrypt
    let encrypted: Vec<u8> = ip_port_bytes
        .iter()
        .zip(key.iter())
        .map(|(b, k)| b ^ k)
        .collect();

    base36_encode(&encrypted)
}

/// Decode a base36 string back into a SocketAddr + flags.
/// Tries 7-byte decode first (new format with flags), falls back to 6 (legacy).
fn decode_address(encoded: &str, auth_words: &str) -> Option<ShareCodeInfo> {
    let num = base36_decode_raw(encoded)?;

    // Try 7-byte (new format with flags)
    if let Some(info) = try_decode_n_bytes(num, 7, auth_words) {
        return Some(info);
    }

    // Fallback to 6-byte (legacy format, no flags)
    if let Some(info) = try_decode_n_bytes(num, 6, auth_words) {
        return Some(info);
    }

    None
}

fn try_decode_n_bytes(num: u64, byte_count: usize, auth_words: &str) -> Option<ShareCodeInfo> {
    let mut bytes = vec![0u8; byte_count];
    let mut n = num;
    for i in (0..byte_count).rev() {
        bytes[i] = (n & 0xFF) as u8;
        n >>= 8;
    }

    let key = derive_addr_key(auth_words, byte_count);
    let decrypted: Vec<u8> = bytes.iter().zip(key.iter()).map(|(b, k)| b ^ k).collect();

    let addr = bytes_to_addr(&decrypted[..6.min(decrypted.len())])?;

    // Validate: decoded address should look reasonable
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip();
            // Reject if ip is 0.0.0.0 (unless port is also 0)
            if ip.is_unspecified() && v4.port() == 0 {
                return None;
            }
        }
        _ => return None,
    }

    let flags = if byte_count >= 7 { decrypted[6] } else { 0 };
    let needs_hole_punch = flags & FLAG_HOLE_PUNCH != 0;

    Some(ShareCodeInfo {
        addr,
        needs_hole_punch,
        relay_addr: None,
    })
}

/// Convert a SocketAddr to 6 bytes (4 IP + 2 port)
fn addr_to_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip().octets();
            let port = v4.port().to_be_bytes();
            vec![ip[0], ip[1], ip[2], ip[3], port[0], port[1]]
        }
        SocketAddr::V6(_) => {
            tracing::warn!("IPv6 addresses are not yet supported in share codes");
            vec![0u8; 6]
        }
    }
}

/// Convert 6 bytes back to a SocketAddr
fn bytes_to_addr(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < 6 {
        return None;
    }
    let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
    Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
}

/// Derive a key from auth words using HMAC-SHA256
fn derive_addr_key(auth_words: &str, key_len: usize) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(b"peershare-addr-key").expect("HMAC can take any size key");
    mac.update(auth_words.as_bytes());
    let result = mac.finalize();
    result.into_bytes()[..key_len].to_vec()
}

/// Encode bytes to base36 (uppercase A-Z + 0-9)
fn base36_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Convert bytes to a big number, then repeatedly mod 36
    let mut num = 0u64;
    for &b in bytes {
        num = (num << 8) | b as u64;
    }

    if num == 0 {
        return "0".to_string();
    }

    let mut result = Vec::new();
    let mut n = num;
    while n > 0 {
        result.push(CHARS[(n % 36) as usize]);
        n /= 36;
    }
    result.reverse();
    String::from_utf8(result).unwrap()
}

/// Decode a base36 string to a u64 number
fn base36_decode_raw(s: &str) -> Option<u64> {
    let mut num = 0u64;
    for c in s.chars() {
        let digit = match c {
            '0'..='9' => c as u64 - '0' as u64,
            'A'..='Z' => c as u64 - 'A' as u64 + 10,
            _ => return None,
        };
        num = num.checked_mul(36)?.checked_add(digit)?;
    }
    Some(num)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_share_code_roundtrip() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080));
        let code = generate_share_code(&addr, 3);
        let decoded = decode_share_code(&code).expect("should decode");
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_share_code_roundtrip_5_words() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9999));
        let code = generate_share_code(&addr, 5);
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 6, "5 words + 1 address segment");
        let decoded = decode_share_code(&code).expect("should decode");
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_validate_share_code() {
        assert!(validate_share_code("fox-ram-log-K7XM9PR2"));
        assert!(!validate_share_code("fox-ram")); // too short
        assert!(!validate_share_code("FOX-ram-log-K7XM9PR2")); // uppercase words
        assert!(!validate_share_code("fox-rain-lamp-K7XM9PR2")); // words not in WORDLIST
    }

    #[test]
    fn test_extract_auth_words() {
        assert_eq!(
            extract_auth_words("fox-rain-lamp-K7XM9PR2"),
            "fox-rain-lamp"
        );
    }

    #[test]
    fn test_share_code_with_hole_punch_flag() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 9000));
        let code = generate_share_code_with_flags(&addr, 3, true);
        let info = decode_share_code_full(&code).expect("should decode");
        assert_eq!(info.addr, addr);
        assert!(info.needs_hole_punch);
    }

    #[test]
    fn test_share_code_without_hole_punch_flag() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 12345));
        let code = generate_share_code_with_flags(&addr, 3, false);
        let info = decode_share_code_full(&code).expect("should decode");
        assert_eq!(info.addr, addr);
        assert!(!info.needs_hole_punch);
    }

    #[test]
    fn test_share_code_with_relay() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9999));
        let relay: SocketAddr = "1.2.3.4:19816".parse().unwrap();
        let code = generate_share_code_with_relay(&addr, 3, &relay);
        assert!(code.contains("-RELAY:"));

        let info = decode_share_code_full(&code).expect("should decode");
        assert_eq!(info.addr, addr);
        assert!(info.needs_hole_punch);
        assert_eq!(info.relay_addr, Some(relay));
    }

    #[test]
    fn test_parse_relay_suffix() {
        let (base, relay) = parse_relay_suffix("fox-ram-log-K7XM-RELAY:1.2.3.4:19816");
        assert_eq!(base, "fox-ram-log-K7XM");
        assert_eq!(relay, Some("1.2.3.4:19816".parse().unwrap()));

        let (base, relay) = parse_relay_suffix("fox-ram-log-K7XM");
        assert_eq!(base, "fox-ram-log-K7XM");
        assert_eq!(relay, None);
    }
}
