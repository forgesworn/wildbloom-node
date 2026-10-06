//! Synthetic fixture for the Windows two-account acceptance test.
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};
use wildbloom_private_state::{check_directory, check_file, private_directory};

fn main() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let operation = args.next().expect("operation");
    let path = PathBuf::from(args.next().expect("path"));
    match operation.to_str().unwrap() {
        "create" => {
            private_directory(&path)?;
            private_directory(&path.join("work"))?;
            for name in ["receipt.json", "work/pool-report.json", "work/coded-0"] {
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(path.join(name))?;
                check_file(&file)?;
                file.write_all(b"synthetic acceptance fixture")?;
            }
            Ok(())
        }
        "directory" => check_directory(&path),
        "file" => check_file(&fs::File::open(path)?),
        _ => Err(io::Error::other("unknown operation")),
    }
}
