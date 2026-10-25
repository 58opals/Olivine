use std::{
    fmt,
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
    pub headers: Vec<[u8; 80]>,
    pub tip: Checkpoint,
}

#[derive(Debug)]
pub struct ClientError {
    phase: &'static str,
    source: io::Error,
    retryable: bool,
}

impl ClientError {
    fn network(phase: &'static str, source: io::Error) -> Self {
        let retryable = matches!(
            source.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::TimedOut
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::Interrupted
                | io::ErrorKind::WriteZero
                | io::ErrorKind::NetworkDown
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
        );
        Self {
            phase,
            source,
            retryable,
        }
    }

    fn fatal(phase: &'static str, source: io::Error) -> Self {
        Self {
            phase,
            source,
            retryable: false,
        }
    }

    pub fn is_retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.phase, self.source)
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<ClientError> for io::Error {
    fn from(error: ClientError) -> Self {
        io::Error::new(error.source.kind(), error)
    }
}

pub struct PeerSession {
    connection: Connection,
    peer: SocketAddr,
    version: PeerVersion,
    timeout: Duration,
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

impl PeerSession {
    pub fn connect(config: &Config) -> Result<Self, ClientError> {
        if config.checkpoint.height > i32::MAX as u32 {
            return Err(ClientError::fatal(
                "connect",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "checkpoint height exceeds the protocol's signed height range",
                ),
            ));
        }
        let mut connection = Connection::connect(&config.peer, config.timeout)
            .map_err(|error| ClientError::network("connect", error))?;
        let peer = connection
            .stream
            .peer_addr()
            .map_err(|error| ClientError::network("connect", error))?;
        // Do not advertise the machine's private interface address to the peer.
        let local = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut nonce = [0_u8; 8];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut nonce))
            .map_err(|error| ClientError::fatal("prepare handshake", error))?;
        let nonce = u64::from_le_bytes(nonce);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                ClientError::fatal(
                    "prepare handshake",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "system time precedes Unix epoch",
                    ),
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
        .map_err(|error| ClientError::network("handshake", error))?;
        Ok(Self {
            connection,
            peer,
            version,
            timeout: config.timeout,
        })
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn version(&self) -> &PeerVersion {
        &self.version
    }

    pub fn request_headers(&mut self, checkpoint: Checkpoint) -> Result<Download, ClientError> {
        if checkpoint.height > i32::MAX as u32 {
            return Err(ClientError::fatal(
                "headers download",
                invalid("checkpoint height exceeds the protocol's signed height range"),
            ));
        }
        self.connection.begin_phase(self.timeout);
        let headers = request_headers(&mut self.connection, &self.version, &checkpoint.hash)
            .map_err(|error| ClientError::network("headers download", error))?;
        let height = checkpoint
            .height
            .checked_add(headers.len() as u32)
            .filter(|height| *height <= i32::MAX as u32)
            .ok_or_else(|| {
                ClientError::fatal(
                    "headers download",
                    invalid("downloaded header height exceeds the protocol's signed height range"),
                )
            })?;
        let hash = headers
            .last()
            .map_or(checkpoint.hash, |header| sha256d(header));
        Ok(Download {
            headers,
            tip: Checkpoint { height, hash },
        })
    }

    pub fn wait_for_poll(&mut self, interval: Duration) -> Result<(), ClientError> {
        let deadline = Instant::now().checked_add(interval).ok_or_else(|| {
            ClientError::fatal(
                "poll wait",
                io::Error::new(io::ErrorKind::InvalidInput, "poll interval is too large"),
            )
        })?;
        loop {
            let Some(wait) = deadline
                .checked_duration_since(Instant::now())
                .filter(|wait| !wait.is_zero())
            else {
                return Ok(());
            };
            self.connection
                .stream
                .set_read_timeout(Some(wait))
                .map_err(|error| ClientError::network("poll wait", error))?;
            let mut byte = [0_u8; 1];
            match self.connection.stream.peek(&mut byte) {
                Ok(0) => {
                    return Err(ClientError::network(
                        "poll wait",
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer disconnected while waiting to poll",
                        ),
                    ));
                }
                Ok(_) => {
                    // Peek consumes no bytes. Once a frame starts, finish it
                    // under the normal phase deadline before checking whether
                    // polling is due; never discard a partially read frame.
                    self.connection.begin_phase(self.timeout);
                    let message = read_message(&mut self.connection)
                        .map_err(|error| ClientError::network("poll wait", error))?;
                    match message.command.as_str() {
                        "version" | "verack" => {
                            return Err(ClientError::fatal(
                                "poll wait",
                                invalid(
                                    "unexpected repeated handshake message while waiting to poll",
                                ),
                            ));
                        }
                        "headers" => {
                            return Err(ClientError::fatal(
                                "poll wait",
                                invalid("unsolicited headers while waiting to poll"),
                            ));
                        }
                        _ => handle_control(&mut self.connection, &message, self.version.protocol)
                            .map_err(|error| ClientError::network("poll wait", error))?,
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    // Read timeouts may expire just before the Instant deadline.
                    // Recheck it at the top of the loop rather than failing.
                }
                Err(error) => return Err(ClientError::network("poll wait", error)),
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_classifier_retries_disconnects_but_not_protocol_or_unknown_errors() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::TimedOut,
        ] {
            assert!(
                ClientError::network(
                    "headers download",
                    io::Error::new(kind, "transport failure")
                )
                .is_retryable()
            );
        }
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Other,
        ] {
            assert!(
                !ClientError::network("headers download", io::Error::new(kind, "fatal failure"))
                    .is_retryable()
            );
        }
    }

    #[test]
    fn local_eof_is_fatal_and_conversion_preserves_kind_context_and_source() {
        let error = ClientError::fatal(
            "prepare handshake",
            io::Error::new(io::ErrorKind::UnexpectedEof, "nonce source ended"),
        );
        assert!(!error.is_retryable());
        let converted: io::Error = error.into();
        assert_eq!(converted.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            converted.to_string(),
            "prepare handshake: nonce source ended"
        );
        let original = converted
            .get_ref()
            .unwrap()
            .downcast_ref::<ClientError>()
            .unwrap();
        assert!(!original.is_retryable());
        assert_eq!(
            std::error::Error::source(original).unwrap().to_string(),
            "nonce source ended"
        );
    }
}
