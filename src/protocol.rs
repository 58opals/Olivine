use bitcoin_hashes::{Hash, sha256d};
use std::io::{self, Read, Write};
use std::net::SocketAddr;

pub const PROTOCOL_VERSION: i32 = 70016;
pub const MIN_PEER_VERSION: i32 = 31800;
const MAINNET_MAGIC: [u8; 4] = [0xe3, 0xe1, 0xf3, 0xe8];
// This client requests headers, never blocks. Bound every incoming frame before allocation.
const MAX_PAYLOAD_LEN: usize = 2 * 1024 * 1024;
const MAX_HEADERS: usize = 2000;

#[derive(Debug)]
pub struct Message {
    pub command: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PeerVersion {
    pub protocol: i32,
    pub services: u64,
    pub nonce: u64,
    pub start_height: i32,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(bytes).to_byte_array()
}

pub fn read_message(reader: &mut impl Read) -> io::Result<Message> {
    let mut header = [0_u8; 24];
    reader.read_exact(&mut header)?;
    if header[..4] != MAINNET_MAGIC {
        return Err(invalid(
            "unexpected network magic; expected Bitcoin Cash mainnet",
        ));
    }
    let command_bytes = &header[4..16];
    let end = command_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    if end == 0
        || !command_bytes[..end]
            .iter()
            .all(|b| (0x20..=0x7e).contains(b))
        || command_bytes[end..].iter().any(|&b| b != 0)
    {
        return Err(invalid("invalid message command or padding"));
    }
    let length = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    if length > MAX_PAYLOAD_LEN {
        return Err(invalid("message payload exceeds the 2 MiB client limit"));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    if sha256d(&payload)[..4] != header[20..24] {
        return Err(invalid("message checksum mismatch"));
    }
    // ASCII validation above makes this conversion infallible.
    let command = String::from_utf8(command_bytes[..end].to_vec()).unwrap();
    Ok(Message { command, payload })
}

pub fn write_message(writer: &mut impl Write, command: &str, payload: &[u8]) -> io::Result<()> {
    if command.is_empty()
        || command.len() > 12
        || !command.bytes().all(|b| (0x20..=0x7e).contains(&b))
        || payload.len() > MAX_PAYLOAD_LEN
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid outgoing message",
        ));
    }
    let mut header = [0_u8; 24];
    header[..4].copy_from_slice(&MAINNET_MAGIC);
    header[4..4 + command.len()].copy_from_slice(command.as_bytes());
    header[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header[20..24].copy_from_slice(&sha256d(payload)[..4]);
    writer.write_all(&header)?;
    writer.write_all(payload)
}

pub fn parse_hash(display: &str) -> io::Result<[u8; 32]> {
    if display.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "block hash must contain 64 hexadecimal characters",
        ));
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut hash = [0_u8; 32];
    for (i, pair) in display.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = nibble(pair[0]);
        let low = nibble(pair[1]);
        match (high, low) {
            (Some(high), Some(low)) => hash[31 - i] = (high << 4) | low,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "block hash must contain 64 hexadecimal characters",
                ));
            }
        }
    }
    Ok(hash)
}

pub fn display_hash(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut display = String::with_capacity(64);
    for byte in hash.iter().rev() {
        display.push(HEX[(byte >> 4) as usize] as char);
        display.push(HEX[(byte & 15) as usize] as char);
    }
    display
}

fn encode_address(payload: &mut Vec<u8>, address: SocketAddr) {
    payload.extend_from_slice(&0_u64.to_le_bytes());
    let ip = match address {
        SocketAddr::V4(address) => address.ip().to_ipv6_mapped().octets(),
        SocketAddr::V6(address) => address.ip().octets(),
    };
    payload.extend_from_slice(&ip);
    payload.extend_from_slice(&address.port().to_be_bytes());
}

pub fn encode_version(
    remote: SocketAddr,
    local: SocketAddr,
    nonce: u64,
    timestamp: i64,
    height: i32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(102);
    payload.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    payload.extend_from_slice(&0_u64.to_le_bytes());
    payload.extend_from_slice(&timestamp.to_le_bytes());
    encode_address(&mut payload, remote);
    encode_address(&mut payload, local);
    payload.extend_from_slice(&nonce.to_le_bytes());
    let user_agent = b"/Olivine:0.1.0/";
    payload.push(user_agent.len() as u8);
    payload.extend_from_slice(user_agent);
    payload.extend_from_slice(&height.to_le_bytes());
    payload.push(0); // Do not request transaction relay.
    payload
}

pub fn parse_version(payload: &[u8]) -> io::Result<PeerVersion> {
    let mut parser = Parser::new(payload);
    let protocol = i32::from_le_bytes(parser.take_array()?);
    if protocol < MIN_PEER_VERSION {
        return Err(invalid("peer protocol version does not support getheaders"));
    }
    let services = u64::from_le_bytes(parser.take_array()?);
    parser.take(8 + 26 + 26)?; // Timestamp, receiver address, sender address.
    let nonce = u64::from_le_bytes(parser.take_array()?);
    let user_agent_len = parser.compact_size()?;
    if user_agent_len > 256 {
        return Err(invalid("peer user agent exceeds 256 bytes"));
    }
    parser.take(user_agent_len as usize)?;
    let start_height = i32::from_le_bytes(parser.take_array()?);
    // Relay is optional, and future version extensions may follow known fields.
    Ok(PeerVersion {
        protocol,
        services,
        nonce,
        start_height,
    })
}

pub fn encode_getheaders(protocol: i32, checkpoint: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(69);
    payload.extend_from_slice(&protocol.to_le_bytes());
    payload.push(1); // Exactly one locator: the trusted checkpoint.
    payload.extend_from_slice(checkpoint);
    payload.extend_from_slice(&[0_u8; 32]); // No stop hash.
    payload
}

pub fn parse_headers(payload: &[u8], checkpoint: &[u8; 32]) -> io::Result<Vec<[u8; 80]>> {
    let mut parser = Parser::new(payload);
    let count = parser.compact_size()?;
    if count > MAX_HEADERS as u64 {
        return Err(invalid("headers response exceeds 2000 headers"));
    }
    let mut headers = Vec::with_capacity(count as usize);
    let mut previous = *checkpoint;
    for _ in 0..count {
        let header: [u8; 80] = parser.take_array()?;
        // BCH's headers message retains a deprecated transaction-count field.
        // Parse its canonical encoding, but ignore its value as BCH peers do.
        parser.compact_size()?;
        if header[4..36] != previous {
            return Err(invalid(
                "header chain diverges from the checkpoint or preceding header",
            ));
        }
        previous = sha256d(&header);
        headers.push(header);
    }
    if parser.remaining() != 0 {
        return Err(invalid("trailing bytes in headers response"));
    }
    Ok(headers)
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        if length > self.remaining() {
            return Err(invalid("truncated message payload"));
        }
        let start = self.position;
        self.position += length;
        Ok(&self.bytes[start..self.position])
    }

    fn take_array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn compact_size(&mut self) -> io::Result<u64> {
        let tag = self.take(1)?[0];
        let (value, minimum) = match tag {
            0xfd => (u16::from_le_bytes(self.take_array()?) as u64, 0xfd),
            0xfe => (u32::from_le_bytes(self.take_array()?) as u64, 0x1_0000),
            0xff => (u64::from_le_bytes(self.take_array()?), 0x1_0000_0000),
            value => return Ok(value as u64),
        };
        if value < minimum {
            return Err(invalid("noncanonical CompactSize encoding"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn genesis() -> [u8; 80] {
        hex(concat!(
            "010000000000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49ffff001d1dac2b7c"
        ))
        .try_into()
        .unwrap()
    }

    #[test]
    fn genesis_hash_and_display_order_match_the_mainnet_fixture() {
        let displayed = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let digest: [u8; 32] =
            hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
                .try_into()
                .unwrap();
        assert_eq!(sha256d(&genesis()), digest);
        assert_eq!(parse_hash(displayed).unwrap(), digest);
        assert_eq!(display_hash(&digest), displayed);
        assert!(parse_hash(&"g".repeat(64)).is_err());
        assert!(parse_hash("00").is_err());
    }

    #[test]
    fn empty_verack_matches_independent_wire_bytes() {
        let fixture = hex("e3e1f3e876657261636b000000000000000000005df6e0e2");
        let message = read_message(&mut Cursor::new(&fixture)).unwrap();
        assert_eq!(message.command, "verack");
        assert!(message.payload.is_empty());
        let mut outgoing = Vec::new();
        write_message(&mut outgoing, "verack", &[]).unwrap();
        assert_eq!(outgoing, fixture);
    }

    #[test]
    fn framing_rejects_wrong_network_padding_checksum_and_oversize() {
        let fixture = hex("e3e1f3e876657261636b000000000000000000005df6e0e2");
        for (offset, byte) in [(0, 0xf9), (11, b'x'), (20, 0)] {
            let mut bad = fixture.clone();
            bad[offset] = byte;
            assert!(read_message(&mut Cursor::new(bad)).is_err());
        }
        let mut oversize = fixture.clone();
        oversize[16..20].copy_from_slice(&((MAX_PAYLOAD_LEN + 1) as u32).to_le_bytes());
        let error = read_message(&mut Cursor::new(oversize)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("2 MiB"));
        let mut truncated = fixture;
        truncated[16..20].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            read_message(&mut Cursor::new(truncated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn compact_size_accepts_boundaries_and_rejects_noncanonical_encodings() {
        for (encoding, value) in [
            ("fc", 252),
            ("fdfd00", 253),
            ("fdffff", 65535),
            ("fe00000100", 65536),
            ("ff0000000001000000", 4294967296),
        ] {
            assert_eq!(Parser::new(&hex(encoding)).compact_size().unwrap(), value);
        }
        for encoding in ["fdfc00", "feffff0000", "ffffffffff00000000", "fd01"] {
            assert!(Parser::new(&hex(encoding)).compact_size().is_err());
        }
    }

    #[test]
    fn headers_require_linkage_complete_records_and_no_trailing_bytes() {
        let mut payload = vec![1];
        payload.extend_from_slice(&genesis());
        payload.push(0);
        assert_eq!(parse_headers(&payload, &[0; 32]).unwrap(), vec![genesis()]);
        assert!(parse_headers(&payload, &[1; 32]).is_err());
        assert!(parse_headers(&payload[..81], &[0; 32]).is_err());
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(parse_headers(&trailing, &[0; 32]).is_err());
        payload[81] = 1; // Deprecated transaction count is ignored, not interpreted as transactions.
        assert_eq!(parse_headers(&payload, &[0; 32]).unwrap().len(), 1);
        payload[81] = 0xfd;
        payload.extend_from_slice(&[1, 0]);
        assert!(parse_headers(&payload, &[0; 32]).is_err());
        assert!(
            parse_headers(&hex("fdd107"), &[0; 32])
                .unwrap_err()
                .to_string()
                .contains("2000")
        );
        assert!(parse_headers(&hex("fd0000"), &[0; 32]).is_err());
        assert!(parse_headers(&[0], &[0; 32]).unwrap().is_empty());
    }

    #[test]
    fn headers_check_subsequent_links_before_returning_any_batch() {
        let mut second = [0_u8; 80];
        // The independently known digest of the fixture is the next previous-hash field.
        second[4..36].copy_from_slice(&hex(
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        ));
        let mut payload = vec![2];
        payload.extend_from_slice(&genesis());
        payload.push(0);
        payload.extend_from_slice(&second);
        payload.push(0);
        assert_eq!(parse_headers(&payload, &[0; 32]).unwrap().len(), 2);
        payload[86] ^= 1;
        assert!(parse_headers(&payload, &[0; 32]).is_err());
    }

    #[test]
    fn version_addresses_use_network_port_order_and_no_services_or_relay() {
        let payload = encode_version(
            "1.2.3.4:8333".parse().unwrap(),
            "[::1]:1234".parse().unwrap(),
            0x0102030405060708,
            9,
            10,
        );
        assert_eq!(&payload[..12], &hex("801101000000000000000000"));
        assert_eq!(
            &payload[20..46],
            &hex("000000000000000000000000000000000000ffff01020304208d")
        );
        assert_eq!(
            &payload[46..72],
            &hex("00000000000000000000000000000000000000000000000104d2")
        );
        assert_eq!(&payload[72..80], &hex("0807060504030201"));
        assert_eq!(&payload[80..], b"\x0f/Olivine:0.1.0/\x0a\x00\x00\x00\x00");
    }

    #[test]
    fn version_parser_accepts_optional_relay_but_rejects_invalid_required_fields() {
        // Independent fields: protocol 70016, no services, zero timestamp/addresses,
        // nonce 1, empty user agent, start height 42.
        let mut payload = hex("801101000000000000000000");
        payload.extend_from_slice(&[0; 8 + 26 + 26]);
        payload.extend_from_slice(&1_u64.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&42_i32.to_le_bytes());
        assert_eq!(
            parse_version(&payload).unwrap(),
            PeerVersion {
                protocol: 70016,
                services: 0,
                nonce: 1,
                start_height: 42
            }
        );
        payload.push(0);
        assert!(parse_version(&payload).is_ok());
        assert!(parse_version(&payload[..80]).is_err());
        payload[..4].copy_from_slice(&31799_i32.to_le_bytes());
        assert!(parse_version(&payload).is_err());
        payload[..4].copy_from_slice(&70016_i32.to_le_bytes());
        payload.truncate(80);
        payload.extend_from_slice(&hex("fd0101"));
        assert!(
            parse_version(&payload)
                .unwrap_err()
                .to_string()
                .contains("256")
        );
    }

    #[test]
    fn locator_contains_one_wire_order_checkpoint_and_zero_stop() {
        let checkpoint = [0x12; 32];
        let payload = encode_getheaders(70016, &checkpoint);
        assert_eq!(&payload[..5], &hex("8011010001"));
        assert_eq!(&payload[5..37], &[0x12; 32]);
        assert_eq!(&payload[37..], &[0; 32]);
    }
}
