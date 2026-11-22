//! Portable builds keep data and secrets beside the executable.
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub fn exe_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("IO_ERROR")?;
    Ok(exe.parent().context("IO_ERROR")?.to_path_buf())
}

pub fn data_dir() -> Result<PathBuf> {
    Ok(exe_dir()?.join("data"))
}

pub fn download_dir() -> Result<PathBuf> {
    Ok(exe_dir()?.join("downloads"))
}

fn relative_key(value: &str) -> Result<PathBuf> {
    if value.is_empty() || value.contains('\0') {
        bail!("CREDENTIAL_ERROR");
    }
    let mut path = PathBuf::new();
    for part in value.split(['/', '\\']) {
        if part.is_empty() || part == "." || part == ".." || part.contains(':') {
            bail!("CREDENTIAL_ERROR");
        }
        path.push(part);
    }
    Ok(path)
}

pub fn secret_path(root: &Path, service: &str, key: &str) -> Result<PathBuf> {
    Ok(root
        .join("secrets")
        .join(relative_key(service)?)
        .join(relative_key(key)?))
}

pub fn read_secret(root: &Path, service: &str, key: &str) -> Result<Option<Vec<u8>>> {
    match std::fs::read(secret_path(root, service, key)?) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("CREDENTIAL_ERROR"),
    }
}

pub fn write_secret(root: &Path, service: &str, key: &str, value: &[u8]) -> Result<()> {
    let path = secret_path(root, service, key)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("CREDENTIAL_ERROR")?;
    }
    std::fs::write(path, value).context("CREDENTIAL_ERROR")
}

pub fn delete_secret(root: &Path, service: &str, key: &str) -> Result<()> {
    match std::fs::remove_file(secret_path(root, service, key)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("CREDENTIAL_ERROR"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_stay_in_the_given_folder_and_reject_traversal() {
        let root = tempfile::tempdir().unwrap();
        write_secret(root.path(), "com.yingqu.desktop", "id", b"secret").unwrap();
        assert_eq!(
            read_secret(root.path(), "com.yingqu.desktop", "id")
                .unwrap()
                .unwrap(),
            b"secret"
        );
        delete_secret(root.path(), "com.yingqu.desktop", "id").unwrap();
        assert!(read_secret(root.path(), "com.yingqu.desktop", "id")
            .unwrap()
            .is_none());
        assert!(secret_path(root.path(), "com.yingqu.desktop", "../x").is_err());
        write_secret(root.path(), "svc", "ns/dc/2", b"k").unwrap();
        assert_eq!(
            read_secret(root.path(), "svc", "ns/dc/2").unwrap().unwrap(),
            b"k"
        );
    }
}
