use std::{
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::protocol::{
    Message, PROTOCOL_VERSION, PeerVersion, encode_getheaders, encode_version, parse_headers,
    parse_version, read_message, sha256d, write_message,
};

#[derive(Clone, Copy, Debug)]
pub struct Checkpoint {
    pub height: u32,
    pub hash: [u8; 32],
}

pub struct Config {
    pub peer: String,
    pub checkpoint: Checkpoint,
    pub timeout: Duration,
}

pub struct Download {
    pub peer: SocketAddr,
    pub version: PeerVersion,
    pub headers: Vec<[u8; 80]>,
    pub tip: Checkpoint,
}

// A phase deadline covers all reads, including partial frames and unrelated
// messages. A peer cannot keep a phase alive by slowly sending individual bytes.
struct Connection {
    stream: TcpStream,
    deadline: Instant,
}

impl Connection {
    fn connect(peer: &str, timeout: Duration) -> io::Result<Self> {
        // Name resolution is delegated to the OS; the connection deadline starts
        // after resolution and is shared by all returned socket addresses.
        let addresses: Vec<_> = peer.to_socket_addrs()?.collect();
        let deadline = Instant::now() + timeout;
        let mut last_error = io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "peer resolved to no addresses",
        );
        for address in addresses {
            match TcpStream::connect_timeout(&address, remaining(deadline)?) {
                Ok(stream) => return Ok(Self { stream, deadline }),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    fn begin_phase(&mut self, timeout: Duration) {
        self.deadline = Instant::now() + timeout;
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "peer phase deadline exceeded"))
}

impl Read for Connection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(buffer)
    }
}

impl Write for Connection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub fn download_first_headers(config: &Config) -> io::Result<Download> {
    let mut connection = Connection::connect(&config.peer, config.timeout)
        .map_err(|error| context("connect", error))?;
    let peer = connection.stream.peer_addr()?;
    // Do not advertise the machine's private interface address to the peer.
    let local = SocketAddr::from(([0, 0, 0, 0], 0));
    let mut nonce = [0_u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let nonce = u64::from_le_bytes(nonce);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "system time precedes Unix epoch",
            )
        })?
        .as_secs() as i64;

    connection.begin_phase(config.timeout);
    let version = handshake(
        &mut connection,
        peer,
        local,
        nonce,
        timestamp,
        config.checkpoint.height,
    )
    .map_err(|error| context("handshake", error))?;
    connection.begin_phase(config.timeout);
    let headers = request_headers(&mut connection, &version, &config.checkpoint.hash)
        .map_err(|error| context("first headers download", error))?;
    let height = config
        .checkpoint
        .height
        .checked_add(headers.len() as u32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "header height overflow"))?;
    let hash = headers
        .last()
        .map_or(config.checkpoint.hash, |header| sha256d(header));
    Ok(Download {
        peer,
        version,
        headers,
        tip: Checkpoint { height, hash },
    })
}

fn handshake(
    connection: &mut Connection,
    remote: SocketAddr,
    local: SocketAddr,
    nonce: u64,
    timestamp: i64,
    height: u32,
) -> io::Result<PeerVersion> {
    write_message(
        connection,
        "version",
        &encode_version(remote, local, nonce, timestamp, height as i32),
    )?;
    let mut version = None;
    loop {
        let message = read_message(connection)?;
        match message.command.as_str() {
            "version" => {
                if version.is_some() {
                    return Err(invalid("duplicate peer version"));
                }
                let received = parse_version(&message.payload)?;
                if received.nonce == nonce {
                    return Err(invalid("peer echoed our nonce (self connection)"));
                }
                write_message(connection, "verack", &[])?;
                version = Some(received);
            }
            "verack" => {
                if !message.payload.is_empty() {
                    return Err(invalid("verack payload must be empty"));
                }
                return version.ok_or_else(|| invalid("received verack before version"));
            }
            _ => {
                let received = version
                    .as_ref()
                    .ok_or_else(|| invalid("peer's first message must be version"))?;
                handle_control(connection, &message, received.protocol)?;
            }
        }
    }
}

fn request_headers(
    connection: &mut Connection,
    version: &PeerVersion,
    checkpoint: &[u8; 32],
) -> io::Result<Vec<[u8; 80]>> {
    write_message(
        connection,
        "getheaders",
        &encode_getheaders(version.protocol.min(PROTOCOL_VERSION), checkpoint),
    )?;
    loop {
        let message = read_message(connection)?;
        match message.command.as_str() {
            "headers" => return parse_headers(&message.payload, checkpoint),
            "version" | "verack" => return Err(invalid("unexpected repeated handshake message")),
            _ => handle_control(connection, &message, version.protocol)?,
        }
    }
}

fn handle_control(
    connection: &mut Connection,
    message: &Message,
    peer_protocol: i32,
) -> io::Result<()> {
    match message.command.as_str() {
        "ping" if peer_protocol > 60000 => {
            if message.payload.len() != 8 {
                return Err(invalid("ping must contain an eight-byte nonce"));
            }
            write_message(connection, "pong", &message.payload)?;
        }
        "ping" if !message.payload.is_empty() => return Err(invalid("legacy ping must be empty")),
        "reject" => return Err(invalid("peer rejected a request")),
        "headers" => return Err(invalid("received headers before handshake completed")),
        _ => {}
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn context(phase: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{phase}: {error}"))
}
