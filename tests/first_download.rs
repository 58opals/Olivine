use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

use bitcoin_hashes::{Hash, sha256d};

const MAGIC: [u8; 4] = [0xe3, 0xe1, 0xf3, 0xe8];
const CHECKPOINT: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const CHECKPOINT_TEXT: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";

// These peers build and inspect the wire bytes independently of the executable.
fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    let mut field = [0; 12];
    field[..command.len()].copy_from_slice(command.as_bytes());
    bytes.extend_from_slice(&field);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&sha256d::Hash::hash(payload).to_byte_array()[..4]);
    bytes.extend_from_slice(payload);
    bytes
}

fn receive(stream: &mut TcpStream, expected_command: &str) -> Vec<u8> {
    let mut header = [0; 24];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[..4], MAGIC);
    let mut command = [0; 12];
    command[..expected_command.len()].copy_from_slice(expected_command.as_bytes());
    assert_eq!(header[4..16], command);
    let length = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    assert!(length <= 1024, "unexpectedly large client message");
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).unwrap();
    assert_eq!(
        header[20..24],
        sha256d::Hash::hash(&payload).to_byte_array()[..4]
    );
    payload
}

fn send_version(stream: &mut TcpStream) {
    let version = receive(stream, "version");
    assert_eq!(version[..4], 70016_i32.to_le_bytes());
    assert_eq!(
        version[4..12],
        [0; 8],
        "client must not claim block-serving services"
    );
    assert_eq!(
        version.last(),
        Some(&0),
        "transaction relay must be disabled"
    );
    let our_nonce = u64::from_le_bytes(version[72..80].try_into().unwrap());

    let mut peer_version = 70016_i32.to_le_bytes().to_vec();
    peer_version.extend_from_slice(&0_u64.to_le_bytes());
    peer_version.extend_from_slice(&1_700_000_000_i64.to_le_bytes());
    peer_version.extend_from_slice(&[0; 52]); // Receiving and sending addresses.
    peer_version.extend_from_slice(&(!our_nonce).to_le_bytes());
    peer_version.push(0); // Empty user agent.
    peer_version.extend_from_slice(&44_i32.to_le_bytes());
    peer_version.push(0); // No transaction relay.
    stream.write_all(&frame("version", &peer_version)).unwrap();
    assert!(receive(stream, "verack").is_empty());
}

fn handshake_and_request(stream: &mut TcpStream) {
    send_version(stream);
    // A ping may arrive while the client waits for the peer's verack.
    let nonce = [0x21, 0x43, 0x65, 0x87, 0x09, 0xab, 0xcd, 0xef];
    stream.write_all(&frame("ping", &nonce)).unwrap();
    assert_eq!(receive(stream, "pong"), nonce);
    stream.write_all(&frame("verack", &[])).unwrap();
    let request = receive(stream, "getheaders");
    let mut expected = 70016_i32.to_le_bytes().to_vec();
    expected.push(1);
    expected.extend_from_slice(&CHECKPOINT);
    expected.extend_from_slice(&[0; 32]);
    assert_eq!(
        request, expected,
        "getheaders must use the supplied checkpoint only"
    );
}

fn header(previous: [u8; 32], nonce: u32) -> [u8; 80] {
    let mut bytes = [0; 80];
    bytes[..4].copy_from_slice(&1_i32.to_le_bytes());
    bytes[4..36].copy_from_slice(&previous);
    bytes[36..68].copy_from_slice(&[0x22; 32]);
    bytes[68..72].copy_from_slice(&1_700_000_000_u32.to_le_bytes());
    bytes[72..76].copy_from_slice(&0x1d00ffff_u32.to_le_bytes());
    bytes[76..80].copy_from_slice(&nonce.to_le_bytes());
    bytes
}

fn hash_text(hash: &[u8; 32]) -> String {
    hash.iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn run_peer(script: impl FnOnce(&mut TcpStream) + Send + 'static) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "client never connected");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        script(&mut stream);
    });
    let output = command(address).output().unwrap();
    server.join().unwrap();
    output
}

fn command(address: SocketAddr) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_olivine"));
    command.args([
        "--peer",
        &address.to_string(),
        "--checkpoint-height",
        "42",
        "--checkpoint-hash",
        CHECKPOINT_TEXT,
        "--timeout-seconds",
        "1",
    ]);
    command
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn handshake_ping_and_first_linked_batch() {
    let first = header(CHECKPOINT, 7);
    let second = header(sha256d::Hash::hash(&first).to_byte_array(), 8);
    let expected_hash = hash_text(&sha256d::Hash::hash(&second).to_byte_array());
    let output = run_peer(move |stream| {
        handshake_and_request(stream);
        let mut payload = vec![2];
        payload.extend_from_slice(&first);
        payload.push(0);
        payload.extend_from_slice(&second);
        payload.push(0);
        stream.write_all(&frame("headers", &payload)).unwrap();
    });
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("Handshake complete"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "Received 2 linked headers; height 44 hash {expected_hash}"
        )),
        "{stdout}"
    );
}

#[test]
fn empty_response_keeps_the_checkpoint_tip() {
    let output = run_peer(|stream| {
        handshake_and_request(stream);
        stream.write_all(&frame("headers", &[0])).unwrap();
    });
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(
        stdout.contains(&format!(
            "Received 0 linked headers; height 42 hash {CHECKPOINT_TEXT}"
        )),
        "{stdout}"
    );
}

#[test]
fn divergent_batch_fails_without_reporting_download_success() {
    let output = run_peer(|stream| {
        handshake_and_request(stream);
        let mut payload = vec![1];
        payload.extend_from_slice(&header([0x55; 32], 7));
        payload.push(0);
        stream.write_all(&frame("headers", &payload)).unwrap();
    });
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(stderr.contains("headers download"), "{stderr}");
    assert!(stderr.contains("diverges"), "{stderr}");
    assert!(!text(&output.stdout).contains("Received 1 linked headers"));
}

#[test]
fn peer_version_without_verack_is_not_a_successful_handshake() {
    let output = run_peer(send_version);
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("handshake"));
    assert!(!text(&output.stdout).contains("Handshake complete"));
}

#[test]
fn stalled_partial_frame_exits_on_the_phase_deadline() {
    let started = Instant::now();
    let output = run_peer(|stream| {
        handshake_and_request(stream);
        // A complete message header never arrives. Bytes continue arriving more
        // often than the one-second timeout, so a timeout per read would not end
        // the phase. Stop writing when the client has closed its connection.
        for byte in frame("headers", &[0]).iter().take(20) {
            if stream.write_all(&[*byte]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(200));
        }
    });
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("headers download"));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "partial reads kept the phase alive"
    );
}

#[test]
fn help_and_missing_inputs_need_no_peer() {
    let help = Command::new(env!("CARGO_BIN_EXE_olivine"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(text(&help.stdout).contains("--checkpoint-hash"));
    let missing = Command::new(env!("CARGO_BIN_EXE_olivine"))
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(text(&missing.stderr).contains("peer and checkpoint"));
}
