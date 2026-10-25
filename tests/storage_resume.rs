use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bitcoin_hashes::{Hash, sha256d};

const MAGIC: [u8; 4] = [0xe3, 0xe1, 0xf3, 0xe8];
const CHECKPOINT: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const CHECKPOINT_TEXT: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct StoreDirectory(PathBuf);

impl StoreDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "olivine-storage-test-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("headers.dat")
    }
}

impl Drop for StoreDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Scripted peers and file inspection use their own wire/storage encoding and
// never import the executable's implementation.
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

fn receive(stream: &mut TcpStream, expected: &str) -> Vec<u8> {
    let mut header = [0; 24];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[..4], MAGIC);
    let mut command = [0; 12];
    command[..expected.len()].copy_from_slice(expected.as_bytes());
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

fn handshake_and_request(stream: &mut TcpStream, expected_height: u32, expected_hash: [u8; 32]) {
    let version = receive(stream, "version");
    assert_eq!(version[..4], 70016_i32.to_le_bytes());
    let user_agent_length = version[80] as usize;
    assert!(user_agent_length < 253);
    assert_eq!(
        version[81 + user_agent_length..85 + user_agent_length],
        (expected_height as i32).to_le_bytes(),
        "restart must advertise the stored height",
    );
    let our_nonce = u64::from_le_bytes(version[72..80].try_into().unwrap());
    let mut peer_version = 70016_i32.to_le_bytes().to_vec();
    peer_version.extend_from_slice(&0_u64.to_le_bytes());
    peer_version.extend_from_slice(&1_700_000_000_i64.to_le_bytes());
    peer_version.extend_from_slice(&[0; 52]);
    peer_version.extend_from_slice(&(!our_nonce).to_le_bytes());
    peer_version.push(0);
    peer_version.extend_from_slice(&100_i32.to_le_bytes());
    peer_version.push(0);
    stream.write_all(&frame("version", &peer_version)).unwrap();
    assert!(receive(stream, "verack").is_empty());
    stream.write_all(&frame("verack", &[])).unwrap();
    let mut expected = 70016_i32.to_le_bytes().to_vec();
    expected.push(1);
    expected.extend_from_slice(&expected_hash);
    expected.extend_from_slice(&[0; 32]);
    assert_eq!(
        receive(stream, "getheaders"),
        expected,
        "restart must request from the stored tip"
    );
}

fn send_headers(stream: &mut TcpStream, headers: &[[u8; 80]]) {
    assert!(headers.len() < 253);
    let mut payload = vec![headers.len() as u8];
    for header in headers {
        payload.extend_from_slice(header);
        payload.push(0);
    }
    stream.write_all(&frame("headers", &payload)).unwrap();
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

fn digest(header: &[u8; 80]) -> [u8; 32] {
    sha256d::Hash::hash(header).to_byte_array()
}

fn hash_text(hash: &[u8; 32]) -> String {
    hash.iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn command(address: SocketAddr, path: &Path, checkpoint_height: u32) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_olivine"));
    command.args([
        "--peer",
        &address.to_string(),
        "--checkpoint-height",
        &checkpoint_height.to_string(),
        "--checkpoint-hash",
        CHECKPOINT_TEXT,
        "--timeout-seconds",
        "1",
        "--headers-file",
    ]);
    command.arg(path);
    command
}

fn run_peer(path: &Path, script: impl FnOnce(&mut TcpStream) + Send + 'static) -> Output {
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
    let output = command(address, path, 42).output().unwrap();
    server.join().unwrap();
    output
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_stored(path: &Path, headers: &[[u8; 80]]) {
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes.len(), 56 + 80 * headers.len() + 32);
    assert_eq!(&bytes[..8], b"OLIVHDR1");
    assert_eq!(bytes[8..12], MAGIC);
    assert_eq!(bytes[12..16], 42_u32.to_le_bytes());
    assert_eq!(bytes[16..48], CHECKPOINT);
    assert_eq!(bytes[48..56], (headers.len() as u64).to_le_bytes());
    for (stored, expected) in bytes[56..bytes.len() - 32]
        .as_chunks::<80>()
        .0
        .iter()
        .zip(headers)
    {
        assert_eq!(stored, expected);
    }
    assert_eq!(
        bytes[bytes.len() - 32..],
        sha256d::Hash::hash(&bytes[..bytes.len() - 32]).to_byte_array(),
    );
}

fn seed_one(path: &Path) -> [u8; 80] {
    let first = header(CHECKPOINT, 7);
    let output = run_peer(path, move |stream| {
        handshake_and_request(stream, 42, CHECKPOINT);
        send_headers(stream, &[first]);
    });
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_stored(path, &[first]);
    first
}

#[test]
fn separate_runs_resume_without_lost_or_duplicate_headers() {
    let directory = StoreDirectory::new();
    let path = directory.file();
    let first = header(CHECKPOINT, 7);
    let second = header(digest(&first), 8);
    let third = header(digest(&second), 9);
    let output = run_peer(&path, move |stream| {
        handshake_and_request(stream, 42, CHECKPOINT);
        send_headers(stream, &[first, second]);
    });
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains(&format!(
        "Stored 2 headers; height 44 hash {}",
        hash_text(&digest(&second))
    )));
    assert_stored(&path, &[first, second]);

    let output = run_peer(&path, move |stream| {
        handshake_and_request(stream, 44, digest(&second));
        send_headers(stream, &[third]);
    });
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains(&format!(
        "Stored 3 headers; height 45 hash {}",
        hash_text(&digest(&third))
    )));
    assert_stored(&path, &[first, second, third]);

    let before_empty = fs::read(&path).unwrap();
    let output = run_peer(&path, move |stream| {
        handshake_and_request(stream, 45, digest(&third));
        send_headers(stream, &[]);
    });
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("Stored 3 headers; height 45 hash"));
    assert_eq!(fs::read(&path).unwrap(), before_empty);
}

#[test]
fn divergence_preserves_the_previous_store() {
    let directory = StoreDirectory::new();
    let path = directory.file();
    let first = seed_one(&path);
    let before = fs::read(&path).unwrap();
    let output = run_peer(&path, move |stream| {
        handshake_and_request(stream, 43, digest(&first));
        send_headers(stream, &[header([0x55; 32], 8)]);
    });
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("diverges"),
        "{}",
        text(&output.stderr)
    );
    assert!(!text(&output.stdout).contains("Stored 2 headers"));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn invalid_existing_store_is_rejected_before_network_access() {
    let directory = StoreDirectory::new();
    let path = directory.file();
    seed_one(&path);
    let before = fs::read(&path).unwrap();
    let unreachable = "127.0.0.1:0".parse().unwrap();
    let mismatch = command(unreachable, &path, 43).output().unwrap();
    assert!(!mismatch.status.success());
    let stderr = text(&mismatch.stderr);
    assert!(stderr.contains("checkpoint"), "{stderr}");
    assert!(
        !stderr.contains("connect:"),
        "store validation happened after network access: {stderr}"
    );
    assert_eq!(fs::read(&path).unwrap(), before);

    let mut corrupt = before;
    corrupt[56 + 36] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    let output = command(unreachable, &path, 42).output().unwrap();
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(stderr.contains("checksum"), "{stderr}");
    assert!(
        !stderr.contains("connect:"),
        "store validation happened after network access: {stderr}"
    );
    assert_eq!(fs::read(&path).unwrap(), corrupt);
}

#[test]
fn interrupted_download_preserves_the_previous_store() {
    let directory = StoreDirectory::new();
    let path = directory.file();
    let first = seed_one(&path);
    let before = fs::read(&path).unwrap();
    let output = run_peer(&path, move |stream| {
        handshake_and_request(stream, 43, digest(&first));
        let next = header(digest(&first), 8);
        let mut payload = vec![1];
        payload.extend_from_slice(&next);
        payload.push(0);
        let bytes = frame("headers", &payload);
        stream.write_all(&bytes[..24 + 40]).unwrap();
        thread::sleep(Duration::from_millis(1250));
    });
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("first headers download"),
        "{}",
        text(&output.stderr)
    );
    assert!(!text(&output.stdout).contains("Stored 2 headers"));
    assert_eq!(fs::read(&path).unwrap(), before);
}
