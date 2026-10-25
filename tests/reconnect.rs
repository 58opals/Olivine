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

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "olivine-reconnect-test-{}-{}-{}",
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
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return self.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "reconnecting executable did not stop"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(mut self) -> Output {
        let mut child = self.0.take().unwrap();
        assert!(
            child.try_wait().unwrap().is_none(),
            "watch exited before external stop"
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

// The scripted endpoint and snapshot checks use independent wire/file encoding.
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

fn handshake(stream: &mut TcpStream, height: u32) {
    let version = receive(stream, "version");
    assert_eq!(version[..4], 70016_i32.to_le_bytes());
    let user_agent_length = version[80] as usize;
    assert!(user_agent_length < 253);
    assert_eq!(
        version[81 + user_agent_length..85 + user_agent_length],
        (height as i32).to_le_bytes()
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
    assert!(receive(stream, "verack").is_empty());
    stream.write_all(&frame("verack", &[])).unwrap();
}

fn request(stream: &mut TcpStream, hash: [u8; 32]) {
    let mut expected = 70016_i32.to_le_bytes().to_vec();
    expected.push(1);
    expected.extend_from_slice(&hash);
    expected.extend_from_slice(&[0; 32]);
    assert_eq!(receive(stream, "getheaders"), expected);
}

fn headers_frame(headers: &[[u8; 80]]) -> Vec<u8> {
    assert!(headers.len() < 253);
    let mut payload = vec![headers.len() as u8];
    for header in headers {
        payload.extend_from_slice(header);
        payload.push(0);
    }
    frame("headers", &payload)
}

fn send_headers(stream: &mut TcpStream, headers: &[[u8; 80]]) {
    stream.write_all(&headers_frame(headers)).unwrap();
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

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    (listener, address)
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "client never connected or reconnected"
                );
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
    stream
}

fn command(address: SocketAddr, path: &Path, mode: Option<&str>) -> Command {
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
        "--headers-file",
    ]);
    command.arg(path);
    if let Some(mode) = mode {
        command.arg(mode);
    }
    command
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn reconnects_to_the_same_endpoint_from_the_last_durable_batch() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let server_path = path.clone();
    let first = header(CHECKPOINT, 7);
    let second = header(digest(&first), 8);
    let (listener, address) = listener();
    let server = thread::spawn(move || {
        {
            let mut stream = accept(&listener);
            handshake(&mut stream, 42);
            request(&mut stream, CHECKPOINT);
            send_headers(&mut stream, &[first]);
            request(&mut stream, digest(&first));
            assert_snapshot(&server_path, &[first]);
        }
        let mut stream = accept(&listener);
        handshake(&mut stream, 43);
        request(&mut stream, digest(&first));
        send_headers(&mut stream, &[second]);
        request(&mut stream, digest(&second));
        send_headers(&mut stream, &[]);
    });
    let output = Process::spawn(&mut command(address, &path, Some("--sync"))).wait();
    server.join().unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("retry 1/3"));
    assert!(text(&output.stdout).contains("Caught up with peer; height 44 hash"));
    assert_snapshot(&path, &[first, second]);
}

#[test]
fn interrupted_frame_retries_from_committed_progress_without_duplicates() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let server_path = path.clone();
    let first = header(CHECKPOINT, 7);
    let second = header(digest(&first), 8);
    let (listener, address) = listener();
    let server = thread::spawn(move || {
        let before;
        {
            let mut stream = accept(&listener);
            handshake(&mut stream, 42);
            request(&mut stream, CHECKPOINT);
            send_headers(&mut stream, &[first]);
            request(&mut stream, digest(&first));
            before = fs::read(&server_path).unwrap();
            stream
                .write_all(&headers_frame(&[second])[..24 + 40])
                .unwrap();
        }
        let mut stream = accept(&listener);
        assert_eq!(fs::read(&server_path).unwrap(), before);
        handshake(&mut stream, 43);
        request(&mut stream, digest(&first));
        send_headers(&mut stream, &[second]);
        request(&mut stream, digest(&second));
        send_headers(&mut stream, &[]);
    });
    let output = Process::spawn(&mut command(address, &path, Some("--sync"))).wait();
    server.join().unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("retry 1/3"));
    assert_snapshot(&path, &[first, second]);
}

#[test]
fn watch_reconnects_after_an_idle_disconnect_and_detects_the_next_header() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let server_path = path.clone();
    let first = header(CHECKPOINT, 7);
    let second = header(digest(&first), 8);
    let (listener, address) = listener();
    let (done_tx, done_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        {
            let mut stream = accept(&listener);
            handshake(&mut stream, 42);
            request(&mut stream, CHECKPOINT);
            send_headers(&mut stream, &[first]);
            request(&mut stream, digest(&first));
            send_headers(&mut stream, &[]);
        }
        let mut stream = accept(&listener);
        handshake(&mut stream, 43);
        request(&mut stream, digest(&first));
        send_headers(&mut stream, &[second]);
        request(&mut stream, digest(&second));
        assert_snapshot(&server_path, &[first, second]);
        send_headers(&mut stream, &[]);
        done_tx.send(()).unwrap();
        stop_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    let process =
        Process::spawn(command(address, &path, Some("--watch")).args(["--poll-seconds", "1"]));
    done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let output = process.stop();
    stop_tx.send(()).unwrap();
    server.join().unwrap();
    assert!(text(&output.stderr).contains("retry 1/3"));
    assert!(text(&output.stdout).contains("Stored 2 headers; height 44 hash"));
    assert_snapshot(&path, &[first, second]);
}

fn assert_no_reconnect(mode: Option<&str>, response: Option<Vec<u8>>) {
    let directory = TestDirectory::new();
    let path = directory.file();
    let (listener, address) = listener();
    let (done_tx, done_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        {
            let mut stream = accept(&listener);
            handshake(&mut stream, 42);
            request(&mut stream, CHECKPOINT);
            if let Some(bytes) = response {
                stream.write_all(&bytes).unwrap();
            }
        }
        // Keep accepting on the configured endpoint until the process exits;
        // closing the listener here would conceal unwanted retry attempts.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match listener.accept() {
                Ok(_) => panic!("fatal failure unexpectedly opened a second connection"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("accept: {error}"),
            }
            if done_rx.try_recv().is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "fatal failure did not stop");
            thread::sleep(Duration::from_millis(10));
        }
    });
    let output = Process::spawn(&mut command(address, &path, mode)).wait();
    let _ = done_tx.send(());
    server.join().unwrap();
    assert!(!output.status.success());
    assert!(
        !text(&output.stderr).contains("retry "),
        "{}",
        text(&output.stderr)
    );
    assert!(!path.exists(), "failed first batch must not be stored");
}

#[test]
fn protocol_checksum_and_chain_failures_are_fatal_and_one_batch_remains_fail_fast() {
    let malformed = frame("headers", &[0xfd, 0, 0]); // Noncanonical CompactSize.
    let mut bad_checksum = headers_frame(&[]);
    bad_checksum[20] ^= 1;
    let divergent = headers_frame(&[header([0x55; 32], 7)]);
    for response in [malformed, bad_checksum, divergent] {
        assert_no_reconnect(Some("--sync"), Some(response));
    }
    // The original one-batch command still stops on a transport EOF.
    assert_no_reconnect(None, None);
}

#[test]
fn retry_budget_is_bounded_and_does_not_reset_when_progress_is_saved() {
    let directory = TestDirectory::new();
    let path = directory.file();
    let server_path = path.clone();
    let (listener, address) = listener();
    let (done_tx, done_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut headers = Vec::new();
        let mut previous = CHECKPOINT;
        let mut attempts = Vec::new();
        for attempt in 0..4 {
            let mut stream = accept(&listener);
            attempts.push(Instant::now());
            handshake(&mut stream, 42 + attempt);
            request(&mut stream, previous);
            let next = header(previous, 7 + attempt);
            headers.push(next);
            send_headers(&mut stream, &[next]);
            previous = digest(&next);
            request(&mut stream, previous);
            assert_snapshot(&server_path, &headers);
            // Every connection makes progress and then loses its transport.
        }
        for (pair, minimum) in attempts.array_windows::<2>().zip([900, 1800, 3600]) {
            assert!(
                pair[1].duration_since(pair[0]) >= Duration::from_millis(minimum),
                "reconnect skipped its backoff"
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok(_) => panic!("retry budget allowed a fifth connection"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("accept: {error}"),
            }
            if done_rx.try_recv().is_ok() {
                return headers;
            }
            assert!(
                Instant::now() < deadline,
                "exhausted retry budget did not stop"
            );
            thread::sleep(Duration::from_millis(10));
        }
    });
    let output = Process::spawn(&mut command(address, &path, Some("--sync"))).wait();
    let _ = done_tx.send(());
    let headers = server.join().unwrap();
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    for retry in ["retry 1/3", "retry 2/3", "retry 3/3"] {
        assert!(stderr.contains(retry), "{stderr}");
    }
    assert!(
        stderr.contains("retry budget exhausted after 3 retries"),
        "{stderr}"
    );
    assert_snapshot(&path, &headers);
    assert!(text(&output.stdout).contains("Stored 4 headers; height 46 hash"));
}
