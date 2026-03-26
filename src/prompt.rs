use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use age_core::secrecy::SecretString;
use age_plugin::Callbacks;
use dialoguer::Password;
use log::debug;

use crate::{error::Error, BINARY_NAME};

pub(crate) struct SecretRequest<'a> {
    pub(crate) title: &'a str,
    pub(crate) description: &'a str,
    pub(crate) prompt: &'a str,
    pub(crate) error: Option<&'a str>,
}

pub(crate) enum PluginPromptError {
    Cancelled,
}

pub(crate) fn request_secret_cli(request: &SecretRequest<'_>) -> Result<SecretString, Error> {
    if let Some(pinentry) = Pinentry::detect() {
        match pinentry.get_pin(request) {
            Ok(secret) => return Ok(secret),
            Err(PinentryError::Cancelled) => return Err(Error::SecretInputCancelled),
            Err(PinentryError::Failed(err)) => {
                debug!("Falling back to TTY prompt after pinentry failure: {err}");
            }
        }
    }

    Password::new()
        .with_prompt(request.description)
        .report(true)
        .interact()
        .map(SecretString::from)
        .map_err(Error::from)
}

pub(crate) fn request_secret_with_confirmation_cli(
    request: &SecretRequest<'_>,
    repeat_prompt: &str,
    repeat_error: &str,
) -> Result<SecretString, Error> {
    if let Some(pinentry) = Pinentry::detect() {
        match pinentry.get_pin_with_confirmation(request, repeat_prompt) {
            Ok(secret) => return Ok(secret),
            Err(PinentryError::Cancelled) => return Err(Error::SecretInputCancelled),
            Err(PinentryError::Failed(err)) => {
                debug!("Falling back to TTY prompt after pinentry failure: {err}");
            }
        }
    }

    Password::new()
        .with_prompt(request.description)
        .with_confirmation(repeat_prompt, repeat_error)
        .interact()
        .map(SecretString::from)
        .map_err(Error::from)
}

pub(crate) fn request_secret_plugin<E>(
    request: &SecretRequest<'_>,
    callbacks: &mut dyn Callbacks<E>,
) -> io::Result<Result<SecretString, PluginPromptError>> {
    if let Some(pinentry) = Pinentry::detect() {
        match pinentry.get_pin(request) {
            Ok(secret) => return Ok(Ok(secret)),
            Err(PinentryError::Cancelled) => return Ok(Err(PluginPromptError::Cancelled)),
            Err(PinentryError::Failed(err)) => {
                debug!("Falling back to plugin callback after pinentry failure: {err}");
            }
        }
    }

    match callbacks.request_secret(&callback_prompt(request))? {
        Ok(secret) => Ok(Ok(secret)),
        Err(_) => Ok(Err(PluginPromptError::Cancelled)),
    }
}

fn callback_prompt(request: &SecretRequest<'_>) -> String {
    match request.error {
        Some(error) => format!("{error} {}", request.description),
        None => request.description.to_owned(),
    }
}

struct Pinentry {
    path: PathBuf,
}

impl Pinentry {
    fn detect() -> Option<Self> {
        if cfg!(target_os = "linux") && is_desktop_session() {
            if let Ok(path) = which::which("pinentry") {
                return Some(Self { path });
            }
        }

        None
    }

    fn get_pin(&self, request: &SecretRequest<'_>) -> Result<SecretString, PinentryError> {
        self.with_session(|session| {
            session.configure(request)?;
            session.read_secret()
        })
    }

    fn get_pin_with_confirmation(
        &self,
        request: &SecretRequest<'_>,
        repeat_prompt: &str,
    ) -> Result<SecretString, PinentryError> {
        self.with_session(|session| {
            session.configure(request)?;
            session.command("SETREPEAT", Some(repeat_prompt))?;
            session.read_secret()
        })
    }

    fn with_session<T>(
        &self,
        f: impl FnOnce(&mut PinentrySession) -> Result<T, PinentryError>,
    ) -> Result<T, PinentryError> {
        let mut session = PinentrySession::new(&self.path)?;
        let res = f(&mut session);
        session.finish();
        res
    }
}

fn is_desktop_session() -> bool {
    env::var_os("DISPLAY").is_some()
        || env::var_os("WAYLAND_DISPLAY").is_some()
        || matches!(
            env::var("XDG_SESSION_TYPE").ok().as_deref(),
            Some("x11" | "wayland")
        )
}

struct PinentrySession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl PinentrySession {
    fn new(path: &PathBuf) -> Result<Self, PinentryError> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(PinentryError::failed)?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| PinentryError::failed("pinentry stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PinentryError::failed("pinentry stdout unavailable"))?;

        let mut session = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        };
        session.expect_ok()?;

        Ok(session)
    }

    fn configure(&mut self, request: &SecretRequest<'_>) -> Result<(), PinentryError> {
        self.command("SETTITLE", Some(request.title))?;
        self.command("SETDESC", Some(request.description))?;
        self.command("SETPROMPT", Some(request.prompt))?;

        if let Some(error) = request.error {
            self.command("SETERROR", Some(error))?;
        }

        Ok(())
    }

    fn command(&mut self, command: &str, arg: Option<&str>) -> Result<(), PinentryError> {
        let mut line = String::from(command);
        if let Some(arg) = arg {
            line.push(' ');
            line.push_str(&escape_assuan(arg));
        }
        line.push('\n');

        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.flush())
            .map_err(PinentryError::failed)?;
        self.expect_ok()
    }

    fn read_secret(&mut self) -> Result<SecretString, PinentryError> {
        self.stdin
            .write_all(b"GETPIN\n")
            .and_then(|_| self.stdin.flush())
            .map_err(PinentryError::failed)?;

        let mut secret = None;

        loop {
            let line = self.read_line()?;

            if line == "OK" || line.starts_with("OK ") {
                return secret
                    .map(SecretString::from)
                    .ok_or_else(|| PinentryError::failed("pinentry returned no secret"));
            }

            if line == "D" {
                secret = Some(String::new());
                continue;
            }

            if let Some(data) = line.strip_prefix("D ") {
                secret = Some(unescape_assuan(data)?);
                continue;
            }

            if line.starts_with("S ") {
                continue;
            }

            if let Some(err) = line.strip_prefix("ERR ") {
                return Err(classify_pinentry_error(err));
            }

            return Err(PinentryError::failed(format!(
                "unexpected pinentry response: {line}"
            )));
        }
    }

    fn expect_ok(&mut self) -> Result<(), PinentryError> {
        let line = self.read_line()?;
        if line == "OK" || line.starts_with("OK ") {
            Ok(())
        } else if let Some(err) = line.strip_prefix("ERR ") {
            Err(classify_pinentry_error(err))
        } else {
            Err(PinentryError::failed(format!(
                "unexpected pinentry response: {line}"
            )))
        }
    }

    fn read_line(&mut self) -> Result<String, PinentryError> {
        loop {
            let mut line = String::new();
            let read = self
                .stdout
                .read_line(&mut line)
                .map_err(PinentryError::failed)?;
            if read == 0 {
                return Err(PinentryError::failed("pinentry closed the connection"));
            }

            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            return Ok(line);
        }
    }

    fn finish(&mut self) {
        let _ = self.stdin.write_all(b"BYE\n");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

enum PinentryError {
    Cancelled,
    Failed(String),
}

impl PinentryError {
    fn failed(err: impl ToString) -> Self {
        Self::Failed(err.to_string())
    }
}

fn classify_pinentry_error(err: &str) -> PinentryError {
    let lower = err.to_ascii_lowercase();
    if lower.contains("cancel") || lower.contains("not confirmed") {
        PinentryError::Cancelled
    } else {
        PinentryError::failed(err)
    }
}

fn escape_assuan(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'%' | b'\n' | b'\r' | 0x00..=0x1f | 0x7f..=0xff | b' ' => {
                escaped.push('%');
                escaped.push(hex_digit((b >> 4) & 0x0f));
                escaped.push(hex_digit(b & 0x0f));
            }
            _ => escaped.push(char::from(b)),
        }
    }
    escaped
}

fn unescape_assuan(input: &str) -> Result<String, PinentryError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.as_bytes().iter().copied();

    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars
                .next()
                .ok_or_else(|| PinentryError::failed("truncated pinentry escape"))?;
            let lo = chars
                .next()
                .ok_or_else(|| PinentryError::failed("truncated pinentry escape"))?;
            let hi =
                from_hex(hi).ok_or_else(|| PinentryError::failed("invalid pinentry escape"))?;
            let lo =
                from_hex(lo).ok_or_else(|| PinentryError::failed("invalid pinentry escape"))?;
            bytes.push((hi << 4) | lo);
        } else {
            bytes.push(b);
        }
    }

    String::from_utf8(bytes).map_err(PinentryError::failed)
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => char::from(b'0' + n),
        10..=15 => char::from(b'A' + (n - 10)),
        _ => unreachable!(),
    }
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn pin_title() -> &'static str {
    BINARY_NAME
}
