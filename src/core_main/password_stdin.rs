use super::{is_cli_setting_change_disabled, is_root, CoreMainAction};
use hbb_common::{
    anyhow::{anyhow, bail},
    config::{Config, ENCRYPT_MAX_LEN},
    ResultType,
};
use std::{
    ffi::OsStr,
    io::{self, IsTerminal, Read, Write},
};
use unicode_segmentation::UnicodeSegmentation;

const FLAG: &str = "--password-stdin";
// There is no limit on the size of a Unicode grapheme cluster
// Flutter does not impose any limit on the byte length of the password
// Therefore, we impose a reasonable limit on the byte length of the password to prevent excessive memory usage.
const MAX_PASSWORD_BYTES: usize = 64 * 1024; // 64 KB ought to be enough for anybody

pub(super) fn is_requested() -> bool {
    std::env::args_os()
        .skip(1)
        .any(|arg| is_requested_arg(&arg))
}

fn is_requested_arg(arg: &OsStr) -> bool {
    arg == OsStr::new(FLAG) || arg.to_string_lossy().starts_with("--password-stdin=")
}

fn validate_args(mut args: impl Iterator<Item = impl AsRef<OsStr>>) -> ResultType<()> {
    if !matches!(args.next(), Some(arg) if arg.as_ref() == OsStr::new(FLAG))
        || args.next().is_some()
    {
        bail!("Usage: rustdesk --password-stdin");
    }
    Ok(())
}

pub(super) fn run() -> Option<CoreMainAction> {
    execute().err().map(CoreMainAction::ExitFailure)
}

fn execute() -> ResultType<()> {
    validate_args(std::env::args_os().skip(1))?;
    #[cfg(windows)]
    if !crate::platform::windows::bootstrap() {
        bail!("Windows initialization failed");
    }
    hbb_common::init_log(false, "password-stdin");
    if is_cli_setting_change_disabled() {
        bail!("Settings are disabled!");
    }
    if Config::is_disable_change_permanent_password() {
        bail!("Changing permanent password is disabled!");
    }
    if !(crate::platform::is_installed() && is_root()) {
        bail!("Installation and administrative privileges required!");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let _user_main_ipc_scope = crate::ipc::UserMainIpcScope::new();
    let password = read_stdin_password()?;
    crate::ipc::set_permanent_password(password)?;
    println!("Done!");
    Ok(())
}

fn read_stdin_password() -> ResultType<String> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return read_password(stdin.lock());
    }
    let echo = EchoGuard::new(terminal::stdin_handle(&stdin))
        .map_err(|_| anyhow!("Failed to disable terminal echo"))?;
    let mut stderr = io::stderr().lock();
    stderr.write_all(b"Enter password: ")?;
    stderr.flush()?;
    let password = read_password(stdin.lock());
    echo.restore()?;
    writeln!(stderr)?;
    password
}

struct EchoGuard {
    handle: terminal::Handle,
    original: Option<terminal::Mode>,
}

impl EchoGuard {
    fn new(handle: terminal::Handle) -> io::Result<Self> {
        let original = terminal::disable_echo(handle)?;
        Ok(Self {
            handle,
            original: Some(original),
        })
    }

    fn restore(mut self) -> ResultType<()> {
        if let Some(original) = &self.original {
            terminal::restore(self.handle, original)
                .map_err(|_| anyhow!("Failed to restore terminal echo"))?;
        }
        self.original = None;
        Ok(())
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            if terminal::restore(self.handle, original).is_err() {
                eprintln!("Failed to restore terminal echo");
            }
        }
    }
}

#[cfg(unix)]
mod terminal {
    use hbb_common::libc;
    use std::{io, mem::MaybeUninit, os::fd::AsRawFd};

    pub type Handle = libc::c_int;
    pub type Mode = libc::termios;

    pub fn stdin_handle(stdin: &io::Stdin) -> Handle {
        stdin.as_raw_fd()
    }

    pub fn disable_echo(handle: Handle) -> io::Result<Mode> {
        let mut original = MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(handle, original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        restore(handle, &hidden)?;
        Ok(original)
    }

    pub fn restore(handle: Handle, mode: &Mode) -> io::Result<()> {
        if unsafe { libc::tcsetattr(handle, libc::TCSANOW, mode) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
mod terminal {
    use std::{io, os::windows::io::AsRawHandle};
    use winapi::{
        shared::{minwindef::DWORD, ntdef::HANDLE},
        um::{
            consoleapi::{GetConsoleMode, SetConsoleMode},
            wincon::ENABLE_ECHO_INPUT,
        },
    };

    pub type Handle = HANDLE;
    pub type Mode = DWORD;

    pub fn stdin_handle(stdin: &io::Stdin) -> Handle {
        stdin.as_raw_handle() as Handle
    }

    pub fn disable_echo(handle: Handle) -> io::Result<Mode> {
        let mut original = 0;
        if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
            return Err(io::Error::last_os_error());
        }
        restore(handle, &(original & !ENABLE_ECHO_INPUT))?;
        Ok(original)
    }

    pub fn restore(handle: Handle, mode: &Mode) -> io::Result<()> {
        if unsafe { SetConsoleMode(handle, *mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(super) fn read_password(mut reader: impl Read) -> ResultType<String> {
    // Allow a CR before LF, without prefetching another line.
    let byte_limit = MAX_PASSWORD_BYTES + 1;
    let mut bytes = Vec::new();
    let mut byte = [0];
    let ended_with_lf = loop {
        match reader.read(&mut byte) {
            Ok(0) => break false,
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => bail!("Failed to read password from stdin"),
        }
        if byte[0] == b'\n' {
            break true;
        }
        if bytes.len() == byte_limit {
            bail!("Password input exceeds the maximum size of {MAX_PASSWORD_BYTES} bytes");
        }
        bytes.push(byte[0]);
    };
    if ended_with_lf && bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    if bytes.len() > MAX_PASSWORD_BYTES {
        bail!("Password input exceeds the maximum size of {MAX_PASSWORD_BYTES} bytes");
    }
    let password =
        String::from_utf8(bytes).map_err(|_| anyhow!("Password input is not valid UTF-8"))?;
    if password.is_empty() {
        bail!("Password must not be empty");
    }
    if password.contains('\0') {
        bail!("Password must not contain NUL characters");
    }
    if password.starts_with('\u{feff}') {
        bail!("Password must not start with a UTF-8 BOM");
    }
    if password.graphemes(true).take(ENCRYPT_MAX_LEN + 1).count() > ENCRYPT_MAX_LEN {
        bail!("Password exceeds the maximum length of {ENCRYPT_MAX_LEN} characters");
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn terminal_hides_password_and_restores_echo() {
        use hbb_common::libc;
        use std::{
            fs::File,
            os::fd::{AsRawFd, FromRawFd},
            ptr,
        };

        for invalid_input in [false, true] {
            let (mut master, mut slave) = (-1, -1);
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut master,
                        &mut slave,
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                    )
                },
                0
            );
            let mut master = unsafe { File::from_raw_fd(master) };
            let mut slave = unsafe { File::from_raw_fd(slave) };
            {
                let echo = EchoGuard::new(slave.as_raw_fd()).unwrap();
                master
                    .write_all(if invalid_input {
                        b"\n"
                    } else {
                        b"test-password\n"
                    })
                    .unwrap();
                let password = read_password(&mut slave);
                if invalid_input {
                    assert!(password.is_err());
                } else {
                    assert_eq!(password.unwrap(), "test-password");
                }
                let mut poll = libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                assert_eq!(
                    unsafe { libc::poll(&mut poll, 1, 50) },
                    0,
                    "Input was echoed"
                );
                if !invalid_input {
                    echo.restore().unwrap();
                }
            }
            master.write_all(b"visible\n").unwrap();
            let mut poll = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 1000) }, 1);
            let mut output = [0; 64];
            let count = master.read(&mut output).unwrap();
            assert!(output[..count].windows(7).any(|s| s == b"visible"));
        }
    }

    #[test]
    fn standalone_arguments_only() {
        assert!(is_requested_arg(OsStr::new(FLAG)));
        assert!(is_requested_arg(OsStr::new(
            "--password-stdin=secret input"
        )));
        assert!(!is_requested_arg(OsStr::new("--password")));
        assert!(!is_requested_arg(OsStr::new("--password-stdin-other")));
        assert!(validate_args([FLAG].into_iter()).is_ok());
        for args in [
            vec![],
            vec![FLAG, "secret input"],
            vec![FLAG, FLAG],
            vec!["--password-stdin=secret input"],
            vec!["--version"],
        ] {
            let err = validate_args(args.into_iter()).unwrap_err();
            assert_eq!(err.to_string(), "Usage: rustdesk --password-stdin");
        }
        for option in [
            "--elevate",
            "--run-as-system",
            "--quick_support",
            "--no-server",
            "--noinstall",
            "--install",
            "--connect",
        ] {
            assert!(validate_args([option, FLAG].into_iter()).is_err());
            assert!(validate_args([FLAG, option].into_iter()).is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert!(
                validate_args([OsStr::new(FLAG), OsStr::from_bytes(b"\xff")].into_iter()).is_err()
            );
        }
    }

    struct Unreadable;

    impl Read for Unreadable {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "secret input"))
        }
    }

    #[test]
    fn line_completion_and_content() {
        for (input, expected) in [
            ("password\n", "password"),
            ("password\r\n", "password"),
            ("password", "password"),
            (" \tpassword \t\n", " \tpassword \t"),
            (" \t", " \t"),
            ("\r", "\r"),
            ("a\rb\r", "a\rb\r"),
            ("password\r\r\n", "password\r"),
            ("a\u{feff}b\n", "a\u{feff}b"),
            ("first\nsecond\0\n", "first"),
        ] {
            assert_eq!(read_password(input.as_bytes()).unwrap(), expected);
        }
        // Any read after LF fails, so success proves EOF is unnecessary.
        let open_input = b"password\n".as_slice().chain(Unreadable);
        assert_eq!(read_password(open_input).unwrap(), "password");
    }

    #[test]
    fn validation_and_unicode_limits() {
        for input in [
            b"".as_slice(),
            b"\n",
            b"\r\n",
            b"\xff\n",
            b"a\0b\n",
            b"\xef\xbb\xbfpassword\n",
        ] {
            assert!(read_password(input).is_err());
        }
        // Each is one grapheme, encoded as one, two, three, or four UTF-8 bytes.
        for scalar in ["a", "é", "中", "😀"] {
            let password = scalar.repeat(ENCRYPT_MAX_LEN);
            for ending in ["", "\n", "\r\n"] {
                let input = format!("{password}{ending}");
                assert_eq!(read_password(input.as_bytes()).unwrap(), password);
            }
            let oversized = scalar.repeat(ENCRYPT_MAX_LEN + 1);
            assert!(read_password(oversized.as_bytes()).is_err());
        }
    }

    #[test]
    fn grapheme_length_boundaries() {
        // Each sequence contains multiple scalars but counts as one character in Flutter.
        for grapheme in [
            "e\u{301}", // Letter plus combining acute accent.
            "👍🏽",     // Emoji plus skin-tone modifier.
            "🇺🇸",     // Two regional indicators forming a flag.
            "👨‍👩‍👧‍👦", // Four emoji joined by zero-width joiners.
        ] {
            let password = grapheme.repeat(ENCRYPT_MAX_LEN);
            for ending in ["", "\n", "\r\n"] {
                let input = format!("{password}{ending}");
                assert_eq!(read_password(input.as_bytes()).unwrap(), password);
            }
            let oversized = grapheme.repeat(ENCRYPT_MAX_LEN + 1);
            assert_eq!(
                read_password(oversized.as_bytes()).unwrap_err().to_string(),
                format!("Password exceeds the maximum length of {ENCRYPT_MAX_LEN} characters")
            );
        }
        // Mixing ASCII with four complex graphemes must use the same character limit.
        let password = format!("{}e\u{301}👍🏽🇺🇸👨‍👩‍👧‍👦", "a".repeat(ENCRYPT_MAX_LEN - 4));
        assert_eq!(read_password(password.as_bytes()).unwrap(), password);
        assert!(read_password(format!("{password}a").as_bytes()).is_err());
    }

    #[test]
    fn long_combining_sequence_is_one_grapheme() {
        // Still one grapheme, despite exceeding the former four-bytes-per-character cap.
        let password = format!("e{}", "\u{301}".repeat(1024));
        for ending in ["", "\n", "\r\n"] {
            assert_eq!(
                read_password(format!("{password}{ending}").as_bytes()).unwrap(),
                password
            );
        }
    }

    #[test]
    fn byte_limit_is_independent_of_grapheme_limit() {
        // Two ASCII bytes plus two-byte accents reach the byte cap using only two graphemes.
        let password = format!("ee{}", "\u{301}".repeat((MAX_PASSWORD_BYTES - 2) / 2));
        assert_eq!(password.len(), MAX_PASSWORD_BYTES);
        for ending in ["", "\n", "\r\n"] {
            assert_eq!(
                read_password(format!("{password}{ending}").as_bytes()).unwrap(),
                password
            );
            // Another accent enlarges the second grapheme without adding a third one.
            assert_eq!(
                read_password(format!("{password}\u{301}{ending}").as_bytes())
                    .unwrap_err()
                    .to_string(),
                format!("Password input exceeds the maximum size of {MAX_PASSWORD_BYTES} bytes")
            );
        }
    }

    #[test]
    fn bounded_and_unreadable_input() {
        let byte_bound = MAX_PASSWORD_BYTES + 2;
        let mut endless = io::repeat(b'x').take((byte_bound + 1) as u64);
        assert!(read_password(&mut endless).is_err());
        assert_eq!(endless.limit(), 1);
        assert_eq!(
            read_password(Unreadable).unwrap_err().to_string(),
            "Failed to read password from stdin"
        );

        struct InterruptedOnce(bool);
        impl Read for InterruptedOnce {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(0)
                }
            }
        }
        let interrupted = InterruptedOnce(true).chain(b"password".as_slice());
        assert_eq!(read_password(interrupted).unwrap(), "password");
    }
}
