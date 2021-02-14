use std::convert::Infallible;
use std::env;
use std::error;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::num::ParseIntError;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::result;

use nix::{fcntl, unistd};
use palaver::file::{fexecve, memfd_create, pipe, seal_fd};
use sha2::{Digest, Sha256};

const EXIT_SUCCESS: i32 = 0;
const EXIT_USAGE: i32 = 2;

mod flag {
    pub const HELP: &'static str = "h";
    pub const VERSION: &'static str = "V";
    pub const SCRIPT: &'static str = "s";
}

enum PrintDestination {
    Stdout,
    Stderr,
}

fn print_usage(to: PrintDestination) {
    let usage = format!(
        "{P} [-{h}|{V}] [-{s} SHA256] <SHA256> <EXECUTABLE> [..ARGS]\n\n\
         [-{h}] * Print help and exit\n\
         [-{V}] * Print version and exit\n\
         [-{s}] * Script hash",
        P = PathBuf::from(env::args_os().next().unwrap())
            .file_name()
            .unwrap()
            .to_string_lossy(),
        h = flag::HELP,
        V = flag::VERSION,
        s = flag::SCRIPT,
    );
    match to {
        PrintDestination::Stdout => println!("{}", usage),
        PrintDestination::Stderr => eprintln!("{}", usage),
    }
}

type Result<T> = result::Result<T, Box<dyn error::Error>>;

#[derive(Default)]
struct Opts {
    script_hash: Option<String>,
    hash: String,
    path: PathBuf,
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
    loop {
        let arg = match argv.next() {
            Some(s) => s,
            None => break,
        };
        if !arg.starts_with('-') {
            opts.hash = arg;
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
            flag::SCRIPT => match argv.next() {
                Some(s) => opts.script_hash = Some(s),
                None => exit_usage("missing script hash"),
            },
            _ => {}
        }
    }
    let hash_len = Sha256::output_size() << 1;
    if opts.hash.len() != hash_len {
        exit_usage("invalid executable hash");
    }
    if let Some(s) = &opts.script_hash {
        if s.len() != hash_len {
            exit_usage("invalid script hash");
        }
    }
    opts.path = argv.next().unwrap_or_default().into();
    if opts.path.as_os_str().is_empty() {
        exit_usage("invalid executable path");
    }
    opts.args = argv.collect();
    Ok(opts)
}

fn decode_hex(s: impl AsRef<str>) -> result::Result<Vec<u8>, ParseIntError> {
    let s = s.as_ref();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn exec<S1, S2, S3, T>(hash: S1, path: S2, args: T) -> Result<Infallible>
where
    S1: AsRef<str>,
    S2: AsRef<Path>,
    S3: AsRef<str>,
    T: IntoIterator<Item = S3>,
{
    let raw_hash = decode_hex(hash.as_ref())?;
    let path = path.as_ref();
    let mut file1 = File::open(path)?;
    let fd = memfd_create(&CString::new("")?, true)?;
    let mut file2 = unsafe { File::from_raw_fd(fd) };
    let mut buf = [0; 1 << 13];
    let mut hasher = Sha256::new();
    loop {
        let n = match file1.read(&mut buf) {
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
        file2.write_all(data)?;
    }
    seal_fd(fd);
    let mut args_c = Vec::with_capacity(1);
    args_c.push(CString::new(path.to_str().unwrap())?);
    for arg in args {
        args_c.push(CString::new(arg.as_ref())?);
    }
    let args_c = args_c.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    let mut vars_c = Vec::new();
    for var in env::vars() {
        vars_c.push(CString::new(format!("{}={}", var.0, var.1).as_str())?);
    }
    let vars_c = vars_c.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    fexecve(fd, &args_c, &vars_c)?;
    panic!("never happen");
}

fn main() -> Result<()> {
    let opts = get_opts()?;
    if let Some(s) = &opts.script_hash {
        let raw_hash = decode_hex(s)?;
        let mut data = Vec::new();
        let mut stdin = io::stdin();
        stdin.read_to_end(&mut data)?;
        if Sha256::digest(&data)[..] != raw_hash {
            return Err("script hash mismatch".into());
        }
        let (pr, pw) = pipe(fcntl::OFlag::O_CLOEXEC)?;
        unistd::dup2(pr, stdin.as_raw_fd())?;
        let mut file = unsafe { File::from_raw_fd(pw) };
        file.write_all(&data)?;
    }
    exec(&opts.hash, &opts.path, &opts.args)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn exec_ok() {
        let args: &[String] = &[];
        assert!(!exec(
            "a7ca60660f08c3907fdf383afc360dd9a0a18da9623ce9d7b2852451ac2dfa5e",
            "/usr/bin/true",
            args,
        )
        .is_err());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn exec_err() {
        let args: &[String] = &[];
        assert!(exec(
            "68c1f856c32e521cc04d3d8f28a548c3e66e26b64d25ee10e907dd9b68fdc1c9",
            "/usr/bin/true",
            args,
        )
        .is_err());
    }
}
