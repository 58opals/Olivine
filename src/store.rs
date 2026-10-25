use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use bitcoin_hashes::{Hash, HashEngine, sha256d};

use crate::{client::Checkpoint, protocol::sha256d as header_hash};

const FORMAT_MAGIC: &[u8; 8] = b"OLIVHDR1";
const NETWORK_MAGIC: [u8; 4] = [0xe3, 0xe1, 0xf3, 0xe8];
const PREFIX_LEN: usize = 56;
const CHECKSUM_LEN: usize = 32;
const HEADER_LEN: usize = 80;
const MAX_BATCH: usize = 2000;

pub struct HeaderStore {
    path: PathBuf,
    checkpoint: Checkpoint,
    tip: Checkpoint,
    count: u64,
    durability_uncertain: bool,
    // Lock the stable companion inode: the data inode changes at each rename.
    _lock: File,
}

impl HeaderStore {
    pub fn open(path: &Path, checkpoint: Checkpoint) -> io::Result<Self> {
        if checkpoint.height > i32::MAX as u32 {
            return Err(invalid(
                "checkpoint height exceeds the protocol's signed height range",
            ));
        }
        if path.file_name().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "headers path must name a file",
            ));
        }
        if !parent(path).metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "headers parent is not a directory",
            ));
        }
        check_file_type(path)?;
        let lock_path = suffixed(path, ".lock");
        check_file_type(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "headers file is already in use",
                ));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
        let (_, snapshot) = load(path, checkpoint)?;
        Ok(Self {
            path: path.to_owned(),
            checkpoint,
            tip: snapshot.tip,
            count: snapshot.count,
            durability_uncertain: false,
            _lock: lock,
        })
    }

    pub fn tip(&self) -> Checkpoint {
        self.tip
    }

    pub fn header_count(&self) -> u64 {
        self.count
    }

    pub fn append(&mut self, headers: &[[u8; 80]]) -> io::Result<()> {
        if self.durability_uncertain {
            return Err(io::Error::other(
                "headers durability is uncertain; reopen the store before continuing",
            ));
        }
        if headers.is_empty() {
            return Ok(());
        }
        if headers.len() > MAX_BATCH {
            return Err(invalid("storage batch exceeds 2000 headers"));
        }
        let count = self
            .count
            .checked_add(headers.len() as u64)
            .ok_or_else(|| invalid("stored header count overflow"))?;
        let height = tip_height(self.checkpoint.height, count)?;
        let mut hash = self.tip.hash;
        for header in headers {
            if header[4..36] != hash {
                return Err(invalid(
                    "new headers diverge from the stored tip or preceding header",
                ));
            }
            hash = header_hash(header);
        }

        // Reload before replacing, so external edits or deletion during the
        // download cannot silently discard or bless changed progress.
        let (mut source, snapshot) = load(&self.path, self.checkpoint)?;
        if snapshot.count != self.count || !same_checkpoint(snapshot.tip, self.tip) {
            return Err(invalid("headers file changed since it was opened"));
        }

        let mut temporary = TemporaryFile::create(&self.path)?;
        let mut engine = sha256d::Hash::engine();
        {
            let mut writer = BufWriter::new(temporary.file.as_mut().unwrap());
            write_hashed(&mut writer, &mut engine, &prefix(self.checkpoint, count))?;
            if let Some(file) = source.as_mut() {
                file.seek(SeekFrom::Start(PREFIX_LEN as u64))?;
                let mut reader = BufReader::new(file);
                let mut header = [0_u8; HEADER_LEN];
                for _ in 0..self.count {
                    reader.read_exact(&mut header)?;
                    write_hashed(&mut writer, &mut engine, &header)?;
                }
            }
            for header in headers {
                write_hashed(&mut writer, &mut engine, header)?;
            }
            writer.write_all(&sha256d::Hash::from_engine(engine).to_byte_array())?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }
        // Close both handles before publication; only our own temporary file is
        // ever removed by cleanup. Other orphan temporary files are ignored.
        temporary.file.take();
        drop(source);
        fs::rename(&temporary.path, &self.path)?;
        temporary.published = true;
        self.count = count;
        self.tip = Checkpoint { height, hash };
        if let Err(error) =
            File::open(parent(&self.path)).and_then(|directory| directory.sync_all())
        {
            self.durability_uncertain = true;
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "headers snapshot was published but directory sync failed; durability uncertain; reopen before continuing: {error}"
                ),
            ));
        }
        Ok(())
    }
}

struct Snapshot {
    count: u64,
    tip: Checkpoint,
}

fn load(path: &Path, checkpoint: Checkpoint) -> io::Result<(Option<File>, Snapshot)> {
    check_file_type(path)?;
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok((
                None,
                Snapshot {
                    count: 0,
                    tip: checkpoint,
                },
            ));
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(invalid("headers path is not a regular file"));
    }
    let snapshot = validate(&mut file, checkpoint)?;
    Ok((Some(file), snapshot))
}

fn validate(file: &mut File, checkpoint: Checkpoint) -> io::Result<Snapshot> {
    let length = file.metadata()?.len();
    if length < (PREFIX_LEN + CHECKSUM_LEN) as u64 {
        return Err(invalid("truncated headers snapshot"));
    }
    let mut reader = BufReader::new(file);
    let mut prefix = [0_u8; PREFIX_LEN];
    reader.read_exact(&mut prefix)?;
    if &prefix[..8] != FORMAT_MAGIC {
        return Err(invalid("unrecognized headers storage format"));
    }
    if prefix[8..12] != NETWORK_MAGIC {
        return Err(invalid("stored network is not Bitcoin Cash mainnet"));
    }
    if u32::from_le_bytes(prefix[12..16].try_into().unwrap()) != checkpoint.height
        || prefix[16..48] != checkpoint.hash
    {
        return Err(invalid(
            "stored checkpoint does not match the selected checkpoint",
        ));
    }
    let count = u64::from_le_bytes(prefix[48..56].try_into().unwrap());
    let height = tip_height(checkpoint.height, count)?;
    let expected_length = count
        .checked_mul(HEADER_LEN as u64)
        .and_then(|length| length.checked_add((PREFIX_LEN + CHECKSUM_LEN) as u64))
        .ok_or_else(|| invalid("stored header count overflow"))?;
    if length != expected_length {
        return Err(invalid(
            "headers snapshot length does not match its header count",
        ));
    }
    let mut engine = sha256d::Hash::engine();
    engine.input(&prefix);
    let mut hash = checkpoint.hash;
    let mut header = [0_u8; HEADER_LEN];
    for _ in 0..count {
        reader.read_exact(&mut header)?;
        engine.input(&header);
        if header[4..36] != hash {
            return Err(invalid(
                "stored header linkage diverges from its checkpoint or preceding header",
            ));
        }
        hash = header_hash(&header);
    }
    let mut checksum = [0_u8; CHECKSUM_LEN];
    reader.read_exact(&mut checksum)?;
    if checksum != sha256d::Hash::from_engine(engine).to_byte_array() {
        return Err(invalid("stored headers checksum mismatch"));
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(invalid("trailing bytes in headers snapshot"));
    }
    Ok(Snapshot {
        count,
        tip: Checkpoint { height, hash },
    })
}

fn prefix(checkpoint: Checkpoint, count: u64) -> [u8; PREFIX_LEN] {
    let mut bytes = [0_u8; PREFIX_LEN];
    bytes[..8].copy_from_slice(FORMAT_MAGIC);
    bytes[8..12].copy_from_slice(&NETWORK_MAGIC);
    bytes[12..16].copy_from_slice(&checkpoint.height.to_le_bytes());
    bytes[16..48].copy_from_slice(&checkpoint.hash);
    bytes[48..56].copy_from_slice(&count.to_le_bytes());
    bytes
}

fn tip_height(checkpoint_height: u32, count: u64) -> io::Result<u32> {
    let height = (checkpoint_height as u64)
        .checked_add(count)
        .filter(|height| *height <= i32::MAX as u64)
        .ok_or_else(|| {
            invalid("stored header height exceeds the protocol's signed height range")
        })?;
    Ok(height as u32)
}

fn same_checkpoint(left: Checkpoint, right: Checkpoint) -> bool {
    left.height == right.height && left.hash == right.hash
}

fn write_hashed(
    writer: &mut impl Write,
    engine: &mut impl HashEngine,
    bytes: &[u8],
) -> io::Result<()> {
    writer.write_all(bytes)?;
    engine.input(bytes);
    Ok(())
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

fn check_file_type(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(invalid("headers data and lock paths must not be symlinks"))
        }
        Ok(metadata) if !metadata.is_file() => Err(invalid(
            "headers data and lock paths must name regular files",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct TemporaryFile {
    path: PathBuf,
    file: Option<File>,
    published: bool,
}

impl TemporaryFile {
    fn create(target: &Path) -> io::Result<Self> {
        let mut nonce = [0_u8; 12];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = suffixed(target, &format!(".tmp-{nonce}"));
        let file = File::create_new(&path)?;
        Ok(Self {
            path,
            file: Some(file),
            published: false,
        })
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        self.file.take();
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "olivine-store-{}-{stamp}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("headers.dat")
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            height: 42,
            hash: [0x12; 32],
        }
    }

    fn header(previous: [u8; 32], nonce: u32) -> [u8; 80] {
        let mut header = [0_u8; 80];
        header[..4].copy_from_slice(&1_i32.to_le_bytes());
        header[4..36].copy_from_slice(&previous);
        header[76..].copy_from_slice(&nonce.to_le_bytes());
        header
    }

    fn seeded(path: &Path) -> [u8; 80] {
        let first = header(checkpoint().hash, 1);
        HeaderStore::open(path, checkpoint())
            .unwrap()
            .append(&[first])
            .unwrap();
        first
    }

    #[test]
    fn format_checksum_and_reload_preserve_tip_and_count() {
        let directory = Directory::new();
        let path = directory.file();
        let first = seeded(&path);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 56 + 80 + 32);
        assert_eq!(&bytes[..12], b"OLIVHDR1\xe3\xe1\xf3\xe8");
        assert_eq!(&bytes[12..16], &42_u32.to_le_bytes());
        assert_eq!(&bytes[16..48], &[0x12; 32]);
        assert_eq!(&bytes[48..56], &1_u64.to_le_bytes());
        assert_eq!(&bytes[56..136], &first);
        assert_eq!(
            &bytes[136..],
            &sha256d::Hash::hash(&bytes[..136]).to_byte_array()
        );
        let store = HeaderStore::open(&path, checkpoint()).unwrap();
        assert_eq!(store.header_count(), 1);
        assert_eq!(store.tip().height, 43);
        assert_eq!(store.tip().hash, header_hash(&first));
    }

    #[test]
    fn corrupted_or_truncated_inputs_are_rejected_without_replacement() {
        let directory = Directory::new();
        let path = directory.file();
        seeded(&path);
        let valid = fs::read(&path).unwrap();
        for case in [
            "format",
            "network",
            "checkpoint-height",
            "checkpoint-hash",
            "count",
            "prefix",
            "record",
            "footer",
            "trailing",
            "last-header",
            "checksum",
            "checksummed-link",
        ] {
            let mut bytes = valid.clone();
            match case {
                "format" => bytes[0] ^= 1,
                "network" => bytes[8] ^= 1,
                "checkpoint-height" => bytes[12] ^= 1,
                "checkpoint-hash" => bytes[16] ^= 1,
                "count" => bytes[48..56].copy_from_slice(&u64::MAX.to_le_bytes()),
                "prefix" => bytes.truncate(20),
                "record" => bytes.truncate(56 + 40),
                "footer" => bytes.truncate(bytes.len() - 1),
                "trailing" => bytes.push(0),
                "last-header" => bytes[56 + 76] ^= 1,
                "checksum" => *bytes.last_mut().unwrap() ^= 1,
                "checksummed-link" => {
                    bytes[56 + 4] ^= 1;
                    let checksum_start = bytes.len() - 32;
                    let checksum = sha256d::Hash::hash(&bytes[..checksum_start]).to_byte_array();
                    bytes[checksum_start..].copy_from_slice(&checksum);
                }
                _ => unreachable!(),
            }
            fs::write(&path, &bytes).unwrap();
            let result = HeaderStore::open(&path, checkpoint());
            assert!(result.is_err(), "accepted corruption case {case}");
            assert_eq!(
                fs::read(&path).unwrap(),
                bytes,
                "changed corruption case {case}"
            );
        }
    }

    #[test]
    fn selected_checkpoint_must_match_the_stored_binding() {
        let directory = Directory::new();
        let path = directory.file();
        seeded(&path);
        let before = fs::read(&path).unwrap();
        for checkpoint in [
            Checkpoint {
                height: 43,
                ..checkpoint()
            },
            Checkpoint {
                hash: [0x13; 32],
                ..checkpoint()
            },
        ] {
            assert!(HeaderStore::open(&path, checkpoint).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn divergent_or_oversized_batches_preserve_all_committed_progress() {
        let directory = Directory::new();
        let path = directory.file();
        let first = seeded(&path);
        let before = fs::read(&path).unwrap();
        let mut store = HeaderStore::open(&path, checkpoint()).unwrap();
        let next = header(header_hash(&first), 2);
        let divergent = header(checkpoint().hash, 3);
        assert!(store.append(&[next, divergent]).is_err());
        assert!(store.append(&vec![next; 2001]).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(store.header_count(), 1);
        assert_eq!(store.tip().hash, header_hash(&first));
    }

    #[test]
    fn empty_append_does_not_create_or_replace_a_snapshot() {
        let directory = Directory::new();
        let path = directory.file();
        let mut store = HeaderStore::open(&path, checkpoint()).unwrap();
        store.append(&[]).unwrap();
        assert!(!path.exists());
        assert_eq!(store.header_count(), 0);
        store.append(&[header(checkpoint().hash, 1)]).unwrap();
        let bytes = fs::read(&path).unwrap();
        let modified = path.metadata().unwrap().modified().unwrap();
        store.append(&[]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(path.metadata().unwrap().modified().unwrap(), modified);
    }

    #[test]
    fn companion_lock_serializes_sessions_and_remains_reusable() {
        let directory = Directory::new();
        let path = directory.file();
        let store = HeaderStore::open(&path, checkpoint()).unwrap();
        let error = HeaderStore::open(&path, checkpoint()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(store);
        assert!(suffixed(&path, ".lock").is_file());
        assert!(HeaderStore::open(&path, checkpoint()).is_ok());
    }

    #[test]
    fn orphan_temporary_files_are_ignored_and_preserved() {
        let directory = Directory::new();
        let path = directory.file();
        let first = seeded(&path);
        let orphan = suffixed(&path, ".tmp-orphan");
        fs::write(&orphan, b"partial uncommitted snapshot").unwrap();
        let store = HeaderStore::open(&path, checkpoint()).unwrap();
        assert_eq!(store.header_count(), 1);
        assert_eq!(store.tip().hash, header_hash(&first));
        assert_eq!(fs::read(orphan).unwrap(), b"partial uncommitted snapshot");
    }

    #[test]
    fn changed_existing_file_is_not_overwritten_by_a_later_append() {
        let directory = Directory::new();
        let path = directory.file();
        let first = seeded(&path);
        let mut store = HeaderStore::open(&path, checkpoint()).unwrap();
        fs::write(&path, b"external edit").unwrap();
        assert!(store.append(&[header(header_hash(&first), 2)]).is_err());
        assert_eq!(fs::read(path).unwrap(), b"external edit");
    }

    #[test]
    fn signed_height_limit_and_absent_parent_are_rejected() {
        let directory = Directory::new();
        let path = directory.file();
        let checkpoint = Checkpoint {
            height: i32::MAX as u32,
            ..checkpoint()
        };
        let mut store = HeaderStore::open(&path, checkpoint).unwrap();
        assert!(store.append(&[header(checkpoint.hash, 1)]).is_err());
        assert!(!path.exists());
        assert!(HeaderStore::open(&directory.0.join("absent/headers.dat"), checkpoint).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn data_symlinks_are_rejected_without_changing_the_target() {
        let directory = Directory::new();
        let target = directory.file();
        seeded(&target);
        let bytes = fs::read(&target).unwrap();
        let link = directory.0.join("link.dat");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(HeaderStore::open(&link, checkpoint()).is_err());
        assert_eq!(fs::read(target).unwrap(), bytes);
    }
}
