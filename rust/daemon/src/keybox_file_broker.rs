// Additional GPLv3 section 7(b) attribution term for tryigit-owned material: see ../../NOTICE.
use cleverestricky_service_core::fd_transport::send_one_fd;
use cleverestricky_service_core::ipc::{
    read_header_bounded_or_eof, write_frame_bounded, FLAG_ERROR,
};
use cleverestricky_service_core::secure_fs::TrustedDir;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;

pub const MAX_KEYBOX_XML_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = 1 + 255;
pub const OP_KEYBOX_BROKER_OPEN: u16 = 30;
const KEYBOX_DIRECTORY: &str = "keyboxes";
const SCOPE_CONFIG_ROOT: u8 = 0;
const SCOPE_KEYBOX_DIRECTORY: u8 = 1;
const MAX_ERROR_BYTES: usize = 64;
const SNAPSHOT_BUFFER_BYTES: usize = 32 * 1024;

pub struct OpenedKeybox {
    pub file: File,
    pub size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileFingerprint {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

pub fn serve(mut stream: UnixStream, root: &TrustedDir) -> io::Result<()> {
    let mut request = [0u8; MAX_REQUEST_BYTES];
    loop {
        let Some(header) = read_header_bounded_or_eof(&mut stream, MAX_REQUEST_BYTES)? else {
            return Err(crate::service_guard::clean_exit_error());
        };
        stream.read_exact(&mut request[..header.payload_len])?;
        if header.opcode != OP_KEYBOX_BROKER_OPEN || header.flags != 0 {
            reply_rejected(&mut stream)?;
            continue;
        }
        match open_requested_from(root, &request[..header.payload_len])
            .and_then(snapshot_opened_keybox)
        {
            Ok(snapshot) => {
                write_frame_bounded(&mut stream, OP_KEYBOX_BROKER_OPEN, 0, &[], MAX_ERROR_BYTES)?;
                stream.flush()?;
                send_one_fd(&stream, snapshot.as_raw_fd())?;
            }
            Err(_) => reply_rejected(&mut stream)?,
        }
    }
}

fn open_requested_from(root: &TrustedDir, payload: &[u8]) -> io::Result<OpenedKeybox> {
    if payload.len() < 2 || payload.len() > MAX_REQUEST_BYTES {
        return Err(invalid("invalid keybox open request size"));
    }
    let scope = payload[0];
    let name = std::str::from_utf8(&payload[1..])
        .map_err(|_| invalid("keybox filename is not valid UTF-8"))?;
    if name.is_empty() {
        return Err(invalid("empty keybox filename"));
    }

    if !safe_xml_basename(name) {
        return Err(invalid("keybox request must target a safe XML basename"));
    }
    let directory = match scope {
        SCOPE_CONFIG_ROOT => None,
        SCOPE_KEYBOX_DIRECTORY => Some(root.open_child(KEYBOX_DIRECTORY)?),
        _ => return Err(invalid("unknown keybox file scope")),
    };

    let target = directory.as_ref().unwrap_or(root);
    let (file, size) = target.open_file_bounded(name, MAX_KEYBOX_XML_BYTES)?;
    if size == 0 {
        return Err(invalid("empty keybox file"));
    }
    Ok(OpenedKeybox { file, size })
}

fn safe_xml_basename(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\\')
        && !name
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
        && name
            .get(name.len().saturating_sub(4)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".xml"))
}

fn snapshot_opened_keybox(opened: OpenedKeybox) -> io::Result<File> {
    snapshot_opened_keybox_with_hook(opened, || Ok(()))
}

fn snapshot_opened_keybox_with_hook<F>(mut opened: OpenedKeybox, after_copy: F) -> io::Result<File>
where
    F: FnOnce() -> io::Result<()>,
{
    if opened.size == 0 || opened.size > MAX_KEYBOX_XML_BYTES {
        return Err(invalid("keybox size is outside snapshot bounds"));
    }
    let before = fingerprint(&opened.file)?;
    if before.size != opened.size as u64 {
        return Err(invalid("keybox size changed before snapshot"));
    }

    let mut snapshot = create_sealable_memfd()?;
    let mut copy_buffer = [0u8; SNAPSHOT_BUFFER_BYTES];
    let mut verify_buffer = [0u8; SNAPSHOT_BUFFER_BYTES];
    let result = (|| {
        copy_exact_bounded(
            &mut opened.file,
            &mut snapshot,
            opened.size,
            &mut copy_buffer,
        )?;
        after_copy()?;

        opened.file.seek(SeekFrom::Start(0))?;
        snapshot.seek(SeekFrom::Start(0))?;
        compare_exact_bounded(
            &mut opened.file,
            &mut snapshot,
            opened.size,
            &mut copy_buffer,
            &mut verify_buffer,
        )?;
        let after = fingerprint(&opened.file)?;
        if before != after {
            return Err(invalid("keybox changed while snapshot was created"));
        }

        snapshot.seek(SeekFrom::Start(0))?;
        seal_memfd(&snapshot)?;
        Ok(snapshot)
    })();
    copy_buffer.fill(0);
    verify_buffer.fill(0);
    result
}

fn create_sealable_memfd() -> io::Result<File> {
    // SAFETY: the name is a static NUL-terminated string and the flags request a new close-on-exec
    // anonymous descriptor with sealing support. On success the returned descriptor is uniquely
    // owned and immediately transferred into `File` below.
    let raw = unsafe {
        libc::memfd_create(
            c"cleverestricky-keybox".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a newly created, uniquely owned descriptor. `File` becomes its sole owner.
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn seal_memfd(file: &File) -> io::Result<()> {
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: `file` owns a live memfd. `fcntl(F_ADD_SEALS)` takes only the descriptor and integer
    // seal bitmask, retains no pointers, and does not transfer ownership.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, required) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same live descriptor; `F_GET_SEALS` returns an integer bitmask and retains nothing.
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if actual < 0 {
        return Err(io::Error::last_os_error());
    }
    if actual & required != required {
        return Err(invalid("keybox snapshot seals are incomplete"));
    }
    Ok(())
}

fn copy_exact_bounded(
    source: &mut File,
    destination: &mut File,
    size: usize,
    buffer: &mut [u8],
) -> io::Result<()> {
    let mut remaining = size;
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        source.read_exact(&mut buffer[..take])?;
        destination.write_all(&buffer[..take])?;
        remaining -= take;
    }
    let mut trailing = [0u8; 1];
    if source.read(&mut trailing)? != 0 {
        return Err(invalid("keybox grew while snapshot was created"));
    }
    Ok(())
}

fn compare_exact_bounded(
    source: &mut File,
    snapshot: &mut File,
    size: usize,
    source_buffer: &mut [u8],
    snapshot_buffer: &mut [u8],
) -> io::Result<()> {
    let mut remaining = size;
    while remaining > 0 {
        let take = remaining
            .min(source_buffer.len())
            .min(snapshot_buffer.len());
        source.read_exact(&mut source_buffer[..take])?;
        snapshot.read_exact(&mut snapshot_buffer[..take])?;
        if source_buffer[..take] != snapshot_buffer[..take] {
            return Err(invalid("keybox changed while snapshot was verified"));
        }
        remaining -= take;
    }
    let mut trailing = [0u8; 1];
    if source.read(&mut trailing)? != 0 || snapshot.read(&mut trailing)? != 0 {
        return Err(invalid(
            "keybox snapshot length changed during verification",
        ));
    }
    Ok(())
}

fn fingerprint(file: &File) -> io::Result<FileFingerprint> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(invalid("keybox descriptor is not a regular file"));
    }
    Ok(FileFingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn reply_rejected(stream: &mut UnixStream) -> io::Result<()> {
    write_frame_bounded(
        stream,
        OP_KEYBOX_BROKER_OPEN,
        FLAG_ERROR,
        b"rejected",
        MAX_ERROR_BYTES,
    )?;
    stream.flush()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleverestricky_service_core::ipc::PROTOCOL_MAGIC;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestRoot {
        path: std::path::PathBuf,
    }

    impl TestRoot {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let path = std::env::temp_dir().join(format!(
                "ct-keybox-broker-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::create_dir(path.join(KEYBOX_DIRECTORY)).unwrap();
            Self { path }
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn request(scope: u8, name: &str) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + name.len());
        payload.push(scope);
        payload.extend_from_slice(name.as_bytes());
        payload
    }

    #[test]
    fn opens_root_and_directory_xml_basenames_only() {
        let test = TestRoot::new();
        fs::write(test.path.join("keybox.xml"), b"legacy").unwrap();
        fs::write(test.path.join("A1B2C3.xml"), b"named-root").unwrap();
        fs::write(
            test.path.join(KEYBOX_DIRECTORY).join("A B.XML"),
            b"directory",
        )
        .unwrap();
        let root = TrustedDir::open(&test.path).unwrap();

        assert_eq!(
            open_requested_from(&root, &request(SCOPE_CONFIG_ROOT, "keybox.xml"))
                .unwrap()
                .size,
            6
        );
        assert_eq!(
            open_requested_from(&root, &request(SCOPE_CONFIG_ROOT, "A1B2C3.xml"))
                .unwrap()
                .size,
            10
        );
        assert_eq!(
            open_requested_from(&root, &request(SCOPE_KEYBOX_DIRECTORY, "A B.XML"))
                .unwrap()
                .size,
            9
        );

        for name in ["../root.xml", "sub/root.xml", ".hidden.xml", "not-cbox.txt"] {
            assert!(open_requested_from(&root, &request(SCOPE_CONFIG_ROOT, name)).is_err());
        }
        assert!(
            open_requested_from(&root, &request(SCOPE_KEYBOX_DIRECTORY, "not-cbox.txt")).is_err()
        );
        assert!(open_requested_from(&root, &request(9, "x.xml")).is_err());
    }

    #[test]
    fn traversal_symlink_and_empty_files_fail_closed() {
        let test = TestRoot::new();
        let directory = test.path.join(KEYBOX_DIRECTORY);
        fs::write(directory.join("real.xml"), b"ok").unwrap();
        symlink(directory.join("real.xml"), directory.join("link.xml")).unwrap();
        fs::File::create(directory.join("empty.xml")).unwrap();
        let root = TrustedDir::open(&test.path).unwrap();

        for name in ["../real.xml", "sub/real.xml", "link.xml", "empty.xml"] {
            assert!(open_requested_from(&root, &request(SCOPE_KEYBOX_DIRECTORY, name)).is_err());
        }
    }

    #[test]
    fn preopened_root_survives_root_path_replacement() {
        let test = TestRoot::new();
        let original_keybox = test.path.join(KEYBOX_DIRECTORY).join("stable.xml");
        fs::write(&original_keybox, b"original").unwrap();
        let root = TrustedDir::open(&test.path).unwrap();

        let moved_path = test.path.with_extension("moved");
        let _ = fs::remove_dir_all(&moved_path);
        fs::rename(&test.path, &moved_path).unwrap();
        fs::create_dir(&test.path).unwrap();
        fs::create_dir(test.path.join(KEYBOX_DIRECTORY)).unwrap();
        fs::write(
            test.path.join(KEYBOX_DIRECTORY).join("stable.xml"),
            b"replacement",
        )
        .unwrap();

        let mut opened =
            open_requested_from(&root, &request(SCOPE_KEYBOX_DIRECTORY, "stable.xml")).unwrap();
        let mut bytes = Vec::new();
        opened.file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");

        drop(opened);
        drop(root);
        fs::remove_dir_all(moved_path).unwrap();
    }

    #[test]
    fn validated_descriptor_survives_path_replacement_without_following_new_target() {
        let test = TestRoot::new();
        let directory_path = test.path.join(KEYBOX_DIRECTORY);
        let path = directory_path.join("stable.xml");
        fs::write(&path, b"first").unwrap();
        let root = TrustedDir::open(&test.path).unwrap();
        let mut opened =
            open_requested_from(&root, &request(SCOPE_KEYBOX_DIRECTORY, "stable.xml")).unwrap();

        fs::rename(&path, directory_path.join("old.xml")).unwrap();
        fs::write(&path, b"second").unwrap();
        let mut bytes = Vec::new();
        opened.file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"first");
    }

    #[test]
    fn sealed_snapshot_is_immutable_and_detached_from_source_changes() {
        let test = TestRoot::new();
        let path = test.path.join(KEYBOX_DIRECTORY).join("sealed.xml");
        fs::write(&path, b"first").unwrap();
        let root = TrustedDir::open(&test.path).unwrap();
        let opened =
            open_requested_from(&root, &request(SCOPE_KEYBOX_DIRECTORY, "sealed.xml")).unwrap();
        let mut snapshot = snapshot_opened_keybox(opened).unwrap();

        fs::write(&path, b"later").unwrap();
        let mut bytes = Vec::new();
        snapshot.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"first");
        snapshot.seek(SeekFrom::Start(0)).unwrap();
        assert!(snapshot.write_all(b"x").is_err());
    }

    #[test]
    fn mutation_between_copy_and_verification_is_rejected() {
        let test = TestRoot::new();
        let path = test.path.join(KEYBOX_DIRECTORY).join("raced.xml");
        fs::write(&path, b"before").unwrap();
        let root = TrustedDir::open(&test.path).unwrap();
        let opened =
            open_requested_from(&root, &request(SCOPE_KEYBOX_DIRECTORY, "raced.xml")).unwrap();

        let result = snapshot_opened_keybox_with_hook(opened, || {
            fs::write(&path, b"after!")?;
            Ok(())
        });
        assert!(result.is_err());
    }

    #[test]
    fn oversized_request_is_rejected_before_filesystem_access() {
        let test = TestRoot::new();
        let root = TrustedDir::open(&test.path).unwrap();
        let mut payload = vec![SCOPE_KEYBOX_DIRECTORY];
        payload.extend(std::iter::repeat_n(b'a', MAX_REQUEST_BYTES));
        assert!(open_requested_from(&root, &payload).is_err());
    }

    #[test]
    fn peer_close_is_marked_as_expected_service_completion() {
        let test = TestRoot::new();
        let root = TrustedDir::open(&test.path).unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        drop(client);

        assert!(crate::service_guard::run(|| serve(server, &root)).is_ok());
    }

    #[test]
    fn partial_header_is_reported_as_broker_failure() {
        let test = TestRoot::new();
        let root = TrustedDir::open(&test.path).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&PROTOCOL_MAGIC).unwrap();
        drop(client);

        let error = crate::service_guard::run(|| serve(server, &root))
            .expect_err("truncated broker headers must reach the supervisor");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
