use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
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

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "olivine-sync-test-{}-{}-{}",
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

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Every spawned executable is stopped and reaped even when a peer assertion
// fails. Watching has no production-only testing or shutdown option.
struct Process(Option<Child>);

impl Process {
    fn spawn(command: &mut Command) -> Self {
        Self(Some(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }

    fn wait(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return self.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(Instant::now() < deadline, "executable did not finish");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(mut self) -> Output {
        let mut child = self.0.take().unwrap();
        assert!(
            child.try_wait().unwrap().is_none(),
            "watch exited before it was stopped"
        );
        child.kill().unwrap();
        child.wait_with_output().unwrap()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// These helpers encode independent wire bytes rather than importing production
// protocol or storage helpers. Header consensus is deliberately outside scope.
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

fn receive(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut header = [0; 24];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[..4], MAGIC);
    let command = &header[4..16];
    let end = command.iter().position(|byte| *byte == 0).unwrap_or(12);
    assert!(command[end..].iter().all(|byte| *byte == 0));
    let command = String::from_utf8(command[..end].to_vec()).unwrap();
    let length = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    assert!(length <= 1024, "unexpectedly large client message");
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).unwrap();
    assert_eq!(
        header[20..24],
        sha256d::Hash::hash(&payload).to_byte_array()[..4]
    );
    (command, payload)
}

fn expect(stream: &mut TcpStream, command: &str) -> Vec<u8> {
    let (received, payload) = receive(stream);
    assert_eq!(received, command);
    payload
}

fn handshake(stream: &mut TcpStream, expected_height: u32) {
    let version = expect(stream, "version");
    assert_eq!(version[..4], 70016_i32.to_le_bytes());
    let user_agent_length = version[80] as usize;
    assert!(user_agent_length < 253);
    assert_eq!(
        version[81 + user_agent_length..85 + user_agent_length],
        (expected_height as i32).to_le_bytes()
    );
    let nonce = u64::from_le_bytes(version[72..80].try_into().unwrap());
    let mut payload = 70016_i32.to_le_bytes().to_vec();
    payload.extend_from_slice(&0_u64.to_le_bytes());
    payload.extend_from_slice(&1_700_000_000_i64.to_le_bytes());
    payload.extend_from_slice(&[0; 52]);
    payload.extend_from_slice(&(!nonce).to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&100_i32.to_le_bytes());
    payload.push(0);
    stream.write_all(&frame("version", &payload)).unwrap();
    assert!(expect(stream, "verack").is_empty());
    stream.write_all(&frame("verack", &[])).unwrap();
}

fn assert_locator(payload: &[u8], hash: [u8; 32]) {
    let mut expected = 70016_i32.to_le_bytes().to_vec();
    expected.push(1);
    expected.extend_from_slice(&hash);
    expected.extend_from_slice(&[0; 32]);
    assert_eq!(payload, expected);
}

fn request(stream: &mut TcpStream, hash: [u8; 32]) {
    assert_locator(&expect(stream, "getheaders"), hash);
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

fn assert_snapshot(path: &Path, headers: &[[u8; 80]]) {
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes.len(), 56 + 80 * headers.len() + 32);
    assert_eq!(&bytes[..8], b"OLIVHDR1");
    assert_eq!(bytes[8..12], MAGIC);
    assert_eq!(bytes[12..16], 42_u32.to_le_bytes());
    assert_eq!(bytes[16..48], CHECKPOINT);
    assert_eq!(bytes[48..56], (headers.len() as u64).to_le_bytes());
    assert_eq!(bytes[56..bytes.len() - 32].as_chunks::<80>().0, headers);
    assert_eq!(
        bytes[bytes.len() - 32..],
        sha256d::Hash::hash(&bytes[..bytes.len() - 32]).to_byte_array()
    );
}

fn peer(script: impl FnOnce(&mut TcpStream) + Send + 'static) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
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
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        script(&mut stream);
    });
    (address, server)
}

fn command(address: SocketAddr, path: Option<&Path>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_olivine"));
    command.args([
        "--peer",
        &address.to_string(),
        "--checkpoint-height",
        "42",
        "--checkpoint-hash",
        CHECKPOINT_TEXT,
        "--timeout-seconds",
        "2",
    ]);
    if let Some(path) = path {
        command.arg("--headers-file").arg(path);
    }
    command
}

fn sync(path: &Path, script: impl FnOnce(&mut TcpStream) + Send + 'static) -> Output {
    let (address, server) = peer(script);
    let output = Process::spawn(command(address, Some(path)).arg("--sync")).wait();
    server.join().unwrap();
    output
}

fn watch(path: &Path, script: impl FnOnce(&mut TcpStream) + Send + 'static) -> Output {
    let (done_tx, done_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel();
    let (address, server) = peer(move |stream| {
        script(stream);
        done_tx.send(()).unwrap();
        // Keep the connection alive until the test externally stops the watcher.
        stop_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    let process =
        Process::spawn(command(address, Some(path)).args(["--watch", "--poll-seconds", "1"]));
    done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let output = process.stop();
    stop_tx.send(()).unwrap();
    server.join().unwrap();
    output
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn sync_commits_each_short_batch_before_advancing_on_one_connection() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let server_path = path.clone();
    let first = header(CHECKPOINT, 7);
    let second = header(digest(&first), 8);
    let third = header(digest(&second), 9);
    let output = sync(&path, move |stream| {
        handshake(stream, 42);
        request(stream, CHECKPOINT);
        send_headers(stream, &[first, second]);
        request(stream, digest(&second));
        assert_snapshot(&server_path, &[first, second]);
        send_headers(stream, &[third]);
        request(stream, digest(&third));
        assert_snapshot(&server_path, &[first, second, third]);
        send_headers(stream, &[]);
    });
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(
        stdout.contains(&format!(
            "Caught up with peer; height 45 hash {}",
            hash_text(&digest(&third))
        )),
        "{stdout}"
    );
    assert_snapshot(&path, &[first, second, third]);
}

#[test]
fn failed_second_sync_batch_keeps_the_first_committed_batch() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let server_path = path.clone();
    let first = header(CHECKPOINT, 7);
    let output = sync(&path, move |stream| {
        handshake(stream, 42);
        request(stream, CHECKPOINT);
        send_headers(stream, &[first]);
        request(stream, digest(&first));
        assert_snapshot(&server_path, &[first]);
        send_headers(stream, &[header([0x55; 32], 8)]);
    });
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("diverges"),
        "{}",
        text(&output.stderr)
    );
    assert!(!text(&output.stdout).contains("Caught up with peer"));
    assert_snapshot(&path, &[first]);
}

#[test]
fn watch_answers_idle_ping_detects_a_new_header_and_resumes_after_process_stop() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let server_path = path.clone();
    let first = header(CHECKPOINT, 7);
    let second = header(digest(&first), 8);
    let output = watch(&path, move |stream| {
        handshake(stream, 42);
        request(stream, CHECKPOINT);
        send_headers(stream, &[first]);
        request(stream, digest(&first));
        send_headers(stream, &[]);
        let nonce = [0x21, 0x43, 0x65, 0x87, 0x09, 0xab, 0xcd, 0xef];
        stream.write_all(&frame("ping", &nonce)).unwrap();
        assert_eq!(
            expect(stream, "pong"),
            nonce,
            "idle polling must service ping before the next request"
        );
        request(stream, digest(&first));
        send_headers(stream, &[second]);
        request(stream, digest(&second));
        assert_snapshot(&server_path, &[first, second]);
        send_headers(stream, &[]);
    });
    assert!(text(&output.stdout).contains("Stored 2 headers; height 44 hash"));
    assert_snapshot(&path, &[first, second]);
    let before = fs::read(&path).unwrap();
    let resumed = sync(&path, move |stream| {
        handshake(stream, 44);
        request(stream, digest(&second));
        send_headers(stream, &[]);
    });
    assert!(resumed.status.success(), "{}", text(&resumed.stderr));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn watch_preserves_an_idle_partial_frame_across_the_poll_timer() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let server_path = path.clone();
    let first = header(CHECKPOINT, 7);
    watch(&path, move |stream| {
        handshake(stream, 42);
        request(stream, CHECKPOINT);
        send_headers(stream, &[]);
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let ping = frame("ping", &nonce);
        thread::sleep(Duration::from_millis(450));
        stream.write_all(&ping[..7]).unwrap();
        thread::sleep(Duration::from_millis(800));
        stream.write_all(&ping[7..]).unwrap();
        let mut saw_pong = false;
        let mut saw_request = false;
        for _ in 0..2 {
            let (command, payload) = receive(stream);
            match command.as_str() {
                "pong" => {
                    assert!(!saw_pong);
                    assert_eq!(payload, nonce);
                    saw_pong = true;
                }
                "getheaders" => {
                    assert!(!saw_request);
                    assert_locator(&payload, CHECKPOINT);
                    saw_request = true;
                }
                _ => panic!("unexpected client message: {command}"),
            }
        }
        assert!(saw_pong && saw_request);
        send_headers(stream, &[first]);
        request(stream, digest(&first));
        assert_snapshot(&server_path, &[first]);
        send_headers(stream, &[]);
    });
    assert_snapshot(&path, &[first]);
}

#[test]
fn mode_and_poll_options_reject_invalid_combinations_before_network_access() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let unreachable = "127.0.0.1:0".parse().unwrap();
    for mode in ["--sync", "--watch"] {
        let output = command(unreachable, None).arg(mode).output().unwrap();
        assert!(!output.status.success());
        let stderr = text(&output.stderr);
        assert!(stderr.contains("--headers-file"), "{stderr}");
        assert!(!stderr.contains("connect:"), "{stderr}");
    }
    for options in [
        vec!["--sync", "--watch"],
        vec!["--sync", "--sync"],
        vec!["--watch", "--watch"],
        vec!["--poll-seconds", "1"],
        vec!["--watch", "--poll-seconds", "0"],
        vec!["--watch", "--poll-seconds", "3601"],
        vec!["--watch", "--poll-seconds", "1", "--poll-seconds", "2"],
    ] {
        let output = command(unreachable, Some(&path))
            .args(options)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = text(&output.stderr);
        assert!(
            !stderr.contains("connect:"),
            "invalid options reached networking: {stderr}"
        );
    }
    assert!(!path.exists());
}
