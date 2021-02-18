use std::convert::{Infallible, TryFrom};
use std::env;
use std::error;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Stdin, Write};
use std::num::ParseIntError;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::result;

use minisign_verify::{PublicKey, Signature};
use nix::{fcntl, unistd};
use palaver::file::{execve, fexecve, memfd_create, pipe, seal_fd};
use sha2::{Digest, Sha256};

const EXIT_SUCCESS: i32 = 0;
const EXIT_USAGE: i32 = 2;

mod flag {
    pub const HELP: &'static str = "h";
    pub const VERSION: &'static str = "V";
    pub const EXEC: &'static str = "x";
    pub const PUBLIC_KEY: &'static str = "P";
    pub const EXECUTABLE_SIG_PATH: &'static str = "E";
    pub const EXECUTABLE_HASH: &'static str = "e";
    pub const SCRIPT_SIG_PATH: &'static str = "S";
    pub const SCRIPT_HASH: &'static str = "s";
}

enum PrintDestination {
    Stdout,
    Stderr,
}

fn print_usage(to: PrintDestination) {
    let prog_name = PathBuf::from(env::args_os().next().unwrap())
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let usage = format!(
        "{N} [-{h}|{V}] [-{x}] [-{P} PUBLIC_KEY]\n\
         {w:width$} [-{E} SIG_PATH] [-{e} SHA256]\n\
         {w:width$} [-{S} SIG_PATH] [-{s} SHA256]\n\
         {w:width$} <EXECUTABLE_PATH> [<SCRIPT_PATH>] [..ARGS]\n\n\
         [-{h}] * Print help and exit\n\
         [-{V}] * Print version and exit\n\
         [-{x}] * Use execve()\n\
         [-{P}] * Minisign base64 public key\n\
         [-{E}] * Executable signature path\n\
         [-{e}] * Executable hash\n\
         [-{S}] * Script signature path\n\
         [-{s}] * Script hash",
        N = prog_name,
        h = flag::HELP,
        V = flag::VERSION,
        x = flag::EXEC,
        P = flag::PUBLIC_KEY,
        E = flag::EXECUTABLE_SIG_PATH,
        e = flag::EXECUTABLE_HASH,
        S = flag::SCRIPT_SIG_PATH,
        s = flag::SCRIPT_HASH,
        w = "",
        width = prog_name.chars().count(),
    );
    match to {
        PrintDestination::Stdout => println!("{}", usage),
        PrintDestination::Stderr => eprintln!("{}", usage),
    }
}

type Result<T> = result::Result<T, Box<dyn error::Error>>;

#[derive(Default)]
struct Opts {
    exec: bool,
    public_key: Option<PublicKey>,
    executable_sig_path: Option<PathBuf>,
    executable_hash: Option<String>,
    script_sig_path: Option<PathBuf>,
    script_hash: Option<String>,
    executable_path: PathBuf,
    script_path: Option<PathBuf>,
    args: Vec<String>,
}

fn exit_usage(s: impl AsRef<str>) {
    eprintln!("{}", s.as_ref());
    exit(EXIT_USAGE);
}

fn get_opts() -> Result<Opts> {
    let mut argv = env::args().skip(1);
    if argv.len() == 0 {
        print_usage(PrintDestination::Stderr);
        exit(EXIT_USAGE);
    }
    let mut opts = Opts::default();
    while let Some(arg) = argv.next() {
        if !arg.starts_with('-') || arg == "-" {
            opts.executable_path = arg.into();
            break;
        }
        match arg[1..].as_ref() {
            flag::HELP => {
                print_usage(PrintDestination::Stdout);
                exit(EXIT_SUCCESS);
            }
            flag::VERSION => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                exit(EXIT_SUCCESS);
            }
            flag::EXEC => opts.exec = true,
            flag::PUBLIC_KEY => match argv.next() {
                Some(s) => opts.public_key = Some(PublicKey::from_base64(&s)?),
                None => exit_usage("missing public key"),
            },
            flag::EXECUTABLE_SIG_PATH => match argv.next() {
                Some(s) => opts.executable_sig_path = Some(s.into()),
                None => exit_usage("missing executable signature"),
            },
            flag::EXECUTABLE_HASH => match argv.next() {
                Some(s) => opts.executable_hash = Some(s),
                None => exit_usage("missing executable hash"),
            },
            flag::SCRIPT_SIG_PATH => match argv.next() {
                Some(s) => opts.script_sig_path = Some(s.into()),
                None => exit_usage("missing script signature"),
            },
            flag::SCRIPT_HASH => match argv.next() {
                Some(s) => opts.script_hash = Some(s),
                None => exit_usage("missing script hash"),
            },
            _ => {}
        }
    }
    if !opts.executable_path.is_file() && !opts.executable_path.is_stdin() {
        exit_usage("invalid executable path");
    }
    if opts.script_sig_path.is_some() || opts.script_hash.is_some() {
        match argv.next() {
            Some(s) => opts.script_path = Some(s.into()),
            None => exit_usage("missing script path"),
        }
    }
    opts.args = argv.collect();
    Ok(opts)
}

trait PathExt {
    fn is_stdin(&self) -> bool;
    fn with_sig_extension(&self) -> Option<PathBuf>;
    fn read(&self) -> Result<Vec<u8>>;
}

impl PathExt for Path {
    fn is_stdin(&self) -> bool {
        self == Path::new("-")
    }

    fn with_sig_extension(&self) -> Option<PathBuf> {
        Some(self.with_file_name(format!("{}.minisig", self.file_name()?.to_str()?)))
    }

    fn read(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        if self.is_stdin() {
            io::stdin().read_to_end(&mut data)?;
        } else {
            data = fs::read(self)?;
        }
        Ok(data)
    }
}

trait SignatureExt {
    fn from_path(p: impl AsRef<Path>) -> Result<Signature>;
}

impl SignatureExt for Signature {
    fn from_path(p: impl AsRef<Path>) -> Result<Signature> {
        let p = p.as_ref();
        Ok(if p.is_stdin() {
            let mut s = String::new();
            io::stdin().read_to_string(&mut s)?;
            Signature::decode(&s)?
        } else {
            Signature::from_file(p)?
        })
    }
}

enum Input {
    Stdin(Stdin),
    File(File),
}

impl TryFrom<&Path> for Input {
    type Error = io::Error;

    fn try_from(value: &Path) -> result::Result<Self, Self::Error> {
        Ok(if value.is_stdin() {
            Input::Stdin(io::stdin())
        } else {
            Input::File(File::open(value)?)
        })
    }
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stdin(f) => f.read(buf),
            Self::File(f) => f.read(buf),
        }
    }
}

fn decode_hex(s: impl AsRef<str>) -> result::Result<Vec<u8>, ParseIntError> {
    let s = s.as_ref();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn verify_signature<P, V>(pk: &PublicKey, path: P, data: V) -> Result<()>
where
    P: AsRef<Path>,
    V: AsRef<[u8]>,
{
    pk.verify(data.as_ref(), &Signature::from_path(path)?)?;
    Ok(())
}

fn copy_hash<R: ?Sized, W: ?Sized, S>(r: &mut R, w: &mut W, hash: S) -> Result<u64>
where
    R: Read,
    W: Write,
    S: AsRef<str>,
{
    let raw_hash = decode_hex(hash.as_ref())?;
    let mut buf = [0; 1 << 13];
    let mut hasher = Sha256::new();
    let mut res = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => {
                if hasher.finalize()[..] != raw_hash {
                    return Err("executable hash mismatch".into());
                }
                break;
            }
            Ok(n) => n,
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        };
        let data = &buf[..n];
        hasher.write_all(data)?;
        w.write_all(data)?;
        res += n as u64;
    }
    Ok(res)
}

fn make_exec_args_vars<P, S, T>(path: P, args: T) -> Result<(Vec<CString>, Vec<CString>)>
where
    P: AsRef<Path>,
    S: AsRef<str>,
    T: IntoIterator<Item = S>,
{
    let mut args_c = Vec::with_capacity(1);
    args_c.push(CString::new(path.as_ref().to_str().ok_or("invalid path")?)?);
    for arg in args {
        args_c.push(CString::new(arg.as_ref())?);
    }
    let mut vars_c = Vec::new();
    for var in env::vars() {
        vars_c.push(CString::new(format!("{}={}", var.0, var.1).as_str())?);
    }
    Ok((args_c, vars_c))
}

fn select_sig_path<P1, P2>(sig_path: Option<P1>, path: P2) -> Result<PathBuf>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    if let Some(sig_path) = sig_path {
        return Ok(sig_path.as_ref().into());
    }
    Ok(path
        .as_ref()
        .with_sig_extension()
        .ok_or("invalid sig path")?)
}

struct Params<'a> {
    pk: &'a Option<PublicKey>,
    sig_path: Option<PathBuf>,
    hash: Option<String>,
}

fn fexec<P, S, T>(path: P, args: T, params: Params) -> Result<Infallible>
where
    P: AsRef<Path>,
    S: AsRef<str>,
    T: IntoIterator<Item = S>,
{
    let path = path.as_ref();
    let mut file1 = Input::try_from(path)?;
    let fd = memfd_create(&CString::new("")?, true)?;
    let mut file2 = unsafe { File::from_raw_fd(fd) };
    if let Some(pk) = params.pk {
        let mut data = Vec::new();
        io::copy(&mut file1, &mut data)?;
        verify_signature(pk, select_sig_path(params.sig_path, path)?, &data)?;
        file2.write_all(&data)?;
    } else if let Some(hash) = params.hash {
        copy_hash(&mut file1, &mut file2, hash)?;
    } else {
        io::copy(&mut file1, &mut file2)?;
    }
    seal_fd(fd);
    let (args_c, vars_c) = make_exec_args_vars(path, args)?;
    let args_c = args_c.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    let vars_c = vars_c.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    fexecve(fd, &args_c, &vars_c)?;
    panic!("never happen");
}

fn exec<P, S, T>(path: P, args: T) -> Result<Infallible>
where
    P: AsRef<Path>,
    S: AsRef<str>,
    T: IntoIterator<Item = S>,
{
    let path = path.as_ref();
    let (args_c, vars_c) = make_exec_args_vars(path, args)?;
    let args_c = args_c.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    let vars_c = vars_c.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    execve(
        CString::new(path.to_str().ok_or("invalid path")?)?.as_ref(),
        &args_c,
        &vars_c,
    )?;
    panic!("never happen");
}

fn process_script<P>(path: Option<P>, params: Params) -> Result<()>
where
    P: AsRef<Path>,
{
    let path = match path {
        Some(s) => s,
        None => return Ok(()),
    };
    let data = path.as_ref().read()?;
    if let Some(pk) = params.pk {
        verify_signature(pk, select_sig_path(params.sig_path, path)?, &data)?;
    } else if let Some(hash) = params.hash {
        if Sha256::digest(&data)[..] != decode_hex(hash)? {
            return Err("script hash mismatch".into());
        }
    }
    let (pr, pw) = pipe(fcntl::OFlag::O_CLOEXEC)?;
    unistd::dup2(pr, io::stdin().as_raw_fd())?;
    let mut file = unsafe { File::from_raw_fd(pw) };
    file.write_all(&data)?;
    Ok(())
}

fn main() -> Result<()> {
    let opts = get_opts()?;
    process_script(
        opts.script_path,
        Params {
            pk: &opts.public_key,
            sig_path: opts.script_sig_path,
            hash: opts.script_hash,
        },
    )?;
    if opts.exec {
        exec(opts.executable_path, &opts.args)?;
    } else {
        fexec(
            opts.executable_path,
            &opts.args,
            Params {
                pk: &opts.public_key,
                sig_path: opts.executable_sig_path,
                hash: opts.executable_hash,
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn fexec_ok() {
        let args: &[String] = &[];
        assert!(!fexec(
            "/usr/bin/true",
            args,
            Params {
                pk: &None,
                sig_path: None,
                hash: Some(
                    "a7ca60660f08c3907fdf383afc360dd9a0a18da9623ce9d7b2852451ac2dfa5e".into()
                ),
            }
        )
        .is_err());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn fexec_err() {
        let args: &[String] = &[];
        assert!(fexec(
            "/usr/bin/true",
            args,
            Params {
                pk: &None,
                sig_path: None,
                hash: Some(
                    "68c1f856c32e521cc04d3d8f28a548c3e66e26b64d25ee10e907dd9b68fdc1c9".into()
                ),
            }
        )
        .is_err());
    }
}
