extern crate alloc;

use crate::virtio_blk::VirtioBlkDevice;
use crate::serial;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crabfs::on_disk::superblock::Superblock;
use crabfs::reader;
use spin::{Lazy, Mutex};

const FILE_MAX_SLOTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotMounted,
    NotFound,
    NotDirectory,
    InvalidPath,
    Io,
    InvalidFd,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FileStat {
    pub ino: u64,
    pub mode: u16,
    pub size: u64,
}

#[derive(Debug, Clone)]
struct OpenFile {
    ino: u64,
    offset: u64,
    fd_flags: i32,
    status_flags: i32,
    path: String,
    special: Option<SpecialFd>,
    refs: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecialFd {
    Stdin,
    Stdout,
    Stderr,
    Tty,
    Null,
}

pub struct Vfs {
    dev: VirtioBlkDevice,
    sb: Superblock,
    files: Vec<Option<OpenFile>>,
    path_cache: BTreeMap<String, u64>,
    negative_path_cache: BTreeSet<String>,
}

impl Vfs {
    fn mount(dev: VirtioBlkDevice) -> Result<Self, VfsError> {
        let mut d = dev;
        let sb = reader::read_superblock(&mut d).map_err(|_| VfsError::Io)?;
        let mut files: Vec<Option<OpenFile>> = (0..FILE_MAX_SLOTS).map(|_| None).collect();
        files[0] = Some(OpenFile {
            ino: 0,
            offset: 0,
            fd_flags: 0,
            status_flags: 0,
            path: "/dev/stdin".to_string(),
            special: Some(SpecialFd::Stdin),
            refs: 1,
        });
        files[1] = Some(OpenFile {
            ino: 0,
            offset: 0,
            fd_flags: 0,
            status_flags: 0,
            path: "/dev/stdout".to_string(),
            special: Some(SpecialFd::Stdout),
            refs: 1,
        });
        files[2] = Some(OpenFile {
            ino: 0,
            offset: 0,
            fd_flags: 0,
            status_flags: 0,
            path: "/dev/stderr".to_string(),
            special: Some(SpecialFd::Stderr),
            refs: 1,
        });
        Ok(Self {
            dev: d,
            sb,
            files,
            path_cache: BTreeMap::new(),
            negative_path_cache: BTreeSet::new(),
        })
    }

    fn lookup_path(&mut self, path: &str) -> Result<u64, VfsError> {
        let normalized = normalize_path(path);
        self.lookup_path_inner(&normalized, true, 0)
    }

    fn lookup_path_nofollow(&mut self, path: &str) -> Result<u64, VfsError> {
        let normalized = normalize_path(path);
        self.lookup_path_inner(&normalized, false, 0)
    }

    fn lookup_path_inner(
        &mut self,
        path: &str,
        follow_final: bool,
        depth: usize,
    ) -> Result<u64, VfsError> {
        if depth > 16 {
            return Err(VfsError::InvalidPath);
        }
        if path.is_empty() || !path.starts_with('/') {
            return Err(VfsError::InvalidPath);
        }
        let mut cur = self.sb.rootino;
        let mut remaining = path.trim_start_matches('/');
        if remaining.is_empty() {
            return Ok(cur);
        }
        let mut prefix = String::with_capacity(path.len().saturating_add(1));
        prefix.push('/');
        while !remaining.is_empty() {
            let (part, rest) = split_first_component(remaining);
            let next_ino = reader::find_dir_entry(&mut self.dev, &self.sb, cur, part)
                .map_err(|_| VfsError::Io)?
                .map(|(ino, _ftype)| ino)
                .ok_or(VfsError::NotFound)?;
            let inode = self.read_inode(next_ino)?;
            let is_last = rest.is_empty();
            if (inode.mode & 0xf000) == 0xa000 && (follow_final || !is_last) {
                let target = self.read_symlink_inode(next_ino)?;
                let mut resolved = if target.starts_with('/') {
                    target
                } else {
                    let mut parent = prefix.clone();
                    if !parent.ends_with('/') {
                        parent.push('/');
                    }
                    parent.push_str(&target);
                    parent
                };
                if !is_last {
                    if !resolved.ends_with('/') {
                        resolved.push('/');
                    }
                    resolved.push_str(rest);
                }
                return self.lookup_path_inner(&resolved, follow_final, depth + 1);
            }
            if is_last {
                return Ok(next_ino);
            }
            cur = next_ino;
            if prefix != "/" {
                prefix.push('/');
            }
            prefix.push_str(part);
            remaining = rest;
        }
        Ok(cur)
    }

    fn open(&mut self, path: &str, flags: i32) -> Result<i32, VfsError> {
        if str_eq_lit(path, "/usr/etc/ld-musl-x86_64.path") {
            return Err(VfsError::NotFound);
        }
        if str_eq_lit(path, "/dev/stdin")
            || str_eq_lit(path, "/dev/stdout")
            || str_eq_lit(path, "/dev/stderr")
            || str_eq_lit(path, "/dev/tty")
            || str_eq_lit(path, "/dev/null")
        {
            let slot = self.alloc_fd_slot()?;
            let fd = slot as i32;
            let special = if str_eq_lit(path, "/dev/stdin") {
                Some(SpecialFd::Stdin)
            } else if str_eq_lit(path, "/dev/stdout") {
                Some(SpecialFd::Stdout)
            } else if str_eq_lit(path, "/dev/tty") {
                Some(SpecialFd::Tty)
            } else if str_eq_lit(path, "/dev/null") {
                Some(SpecialFd::Null)
            } else {
                Some(SpecialFd::Stderr)
            };
            self.files[slot] = Some(OpenFile {
                ino: 0,
                offset: 0,
                fd_flags: 0,
                status_flags: flags,
                path: path.to_string(),
                special,
                refs: 1,
            });
            return Ok(fd);
        }
        let normalized = normalize_path(path);
        let ino = self.lookup_path_inner(&normalized, true, 0)?;
        let slot = self.alloc_fd_slot()?;
        let fd = slot as i32;
        self.files[slot] = Some(OpenFile {
            ino,
            offset: 0,
            fd_flags: 0,
            status_flags: flags,
            path: normalized,
            special: None,
            refs: 1,
        });
        Ok(fd)
    }

    fn read(&mut self, fd: i32, out: &mut [u8]) -> Result<usize, VfsError> {
        match self.file(fd)?.special {
            Some(SpecialFd::Null) => {
                let _ = out;
                return Ok(0);
            }
            Some(SpecialFd::Stdin | SpecialFd::Tty) => {
                if out.is_empty() {
                    return Ok(0);
                }
                let mut n = 0usize;
                while n < out.len() {
                    let mut byte = if n == 0 {
                        serial::read_byte_blocking()
                    } else if let Some(byte) = serial::try_read_byte() {
                        byte
                    } else {
                        break;
                    };
                    if byte == b'\r' {
                        byte = b'\n';
                    }
                    out[n] = byte;
                    n += 1;
                    if byte == b'\n' {
                        break;
                    }
                }
                return Ok(n);
            }
            _ => {}
        }
        let (ino, offset) = {
            let of = self.file_mut(fd)?;
            (of.ino, of.offset)
        };
        let data = reader::read_file_data(&mut self.dev, &self.sb, ino, offset, out.len() as u32)
            .map_err(|_| VfsError::Io)?;
        let n = data.len();
        out[..n].copy_from_slice(&data);
        self.file_mut(fd)?.offset = offset.saturating_add(n as u64);
        Ok(n)
    }

    fn close(&mut self, fd: i32) -> Result<(), VfsError> {
        let slot = usize::try_from(fd).map_err(|_| VfsError::InvalidFd)?;
        let entry = self.files.get_mut(slot).ok_or(VfsError::InvalidFd)?;
        let Some(file) = entry.as_mut() else {
            return Err(VfsError::InvalidFd);
        };
        if file.refs > 1 {
            file.refs -= 1;
        } else {
            entry.take();
        }
        Ok(())
    }

    fn fstat(&mut self, fd: i32) -> Result<FileStat, VfsError> {
        if self.file(fd)?.special.is_some() {
            return Ok(FileStat {
                ino: 0,
                mode: 0o20666,
                size: 0,
            });
        }
        let ino = self.file(fd)?.ino;
        let inode = self.read_inode(ino)?;
        Ok(FileStat {
            ino,
            mode: inode.mode,
            size: inode.size as u64,
        })
    }

    fn lseek(&mut self, fd: i32, offset: i64, whence: i32) -> Result<u64, VfsError> {
        let cur_off = self.file(fd)?.offset;
        let ino = self.file(fd)?.ino;
        let new_off = match whence {
            0 => offset,
            1 => (cur_off as i64).saturating_add(offset),
            2 => {
                let inode = self.read_inode(ino)?;
                (inode.size as i64).saturating_add(offset)
            }
            _ => return Err(VfsError::InvalidPath),
        };
        if new_off < 0 {
            return Err(VfsError::InvalidPath);
        }
        let of = self.file_mut(fd)?;
        of.offset = new_off as u64;
        Ok(of.offset)
    }

    fn read_all(&mut self, path: &str) -> Result<Vec<u8>, VfsError> {
        let ino = self.lookup_path(path)?;
        let inode = self.read_inode(ino)?;
        let sz = if inode.size < 0 { 0 } else { inode.size as u32 };
        reader::read_file_data(&mut self.dev, &self.sb, ino, 0, sz).map_err(|_| VfsError::Io)
    }

    fn pread(&mut self, fd: i32, offset: u64, out: &mut [u8]) -> Result<usize, VfsError> {
        if matches!(
            self.file(fd)?.special,
            Some(SpecialFd::Stdin | SpecialFd::Tty | SpecialFd::Null)
        ) {
            let _ = (offset, out);
            return Ok(0);
        }
        let ino = self.file(fd)?.ino;
        let data = reader::read_file_data(&mut self.dev, &self.sb, ino, offset, out.len() as u32)
            .map_err(|_| VfsError::Io)?;
        let n = data.len();
        out[..n].copy_from_slice(&data);
        Ok(n)
    }

    fn read_inode(&mut self, ino: u64) -> Result<crabfs::on_disk::inode::Inode, VfsError> {
        let mut scratch = Vec::new();
        scratch.resize(self.sb.inode_size as usize, 0);
        reader::read_inode(&mut self.dev, &self.sb, ino, &mut scratch).map_err(|_| VfsError::Io)
    }

    fn read_symlink_inode(&mut self, ino: u64) -> Result<String, VfsError> {
        let inode = self.read_inode(ino)?;
        let sz = if inode.size < 0 { 0 } else { inode.size as u32 };
        let data = reader::read_file_data(&mut self.dev, &self.sb, ino, 0, sz)
            .map_err(|_| VfsError::Io)?;
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    fn readlink(&mut self, path: &str) -> Result<String, VfsError> {
        let ino = self.lookup_path_nofollow(path)?;
        self.read_symlink_inode(ino)
    }

    fn stat_path(&mut self, path: &str, follow: bool) -> Result<FileStat, VfsError> {
        let normalized = normalize_path(path);
        let ino = if follow {
            self.lookup_path_inner(&normalized, true, 0)?
        } else {
            self.lookup_path_inner(&normalized, false, 0)?
        };
        let inode = self.read_inode(ino)?;
        Ok(FileStat {
            ino,
            mode: inode.mode,
            size: inode.size.max(0) as u64,
        })
    }

    fn path_of_fd(&self, fd: i32) -> Result<String, VfsError> {
        Ok(self.file(fd)?.path.clone())
    }

    fn is_special_tty(&self, fd: i32) -> Result<bool, VfsError> {
        Ok(matches!(
            self.file(fd)?.special,
            Some(SpecialFd::Stdin | SpecialFd::Stdout | SpecialFd::Stderr | SpecialFd::Tty)
        ))
    }

    fn is_special_null(&self, fd: i32) -> Result<bool, VfsError> {
        Ok(matches!(self.file(fd)?.special, Some(SpecialFd::Null)))
    }

    fn get_fd_flags(&self, fd: i32) -> Result<i32, VfsError> {
        Ok(self.file(fd)?.fd_flags)
    }

    fn set_fd_flags(&mut self, fd: i32, flags: i32) -> Result<(), VfsError> {
        let file = self.file_mut(fd)?;
        file.fd_flags = flags;
        Ok(())
    }

    fn get_status_flags(&self, fd: i32) -> Result<i32, VfsError> {
        Ok(self.file(fd)?.status_flags)
    }

    fn set_status_flags(&mut self, fd: i32, flags: i32) -> Result<(), VfsError> {
        let file = self.file_mut(fd)?;
        file.status_flags = flags;
        Ok(())
    }

    fn dup_fd(&mut self, fd: i32, min_fd: i32, cloexec: bool) -> Result<i32, VfsError> {
        let src = self.file(fd)?.clone();
        let start = usize::try_from(min_fd.max(0)).map_err(|_| VfsError::InvalidFd)?;
        let slot = self
            .files
            .iter()
            .enumerate()
            .skip(start)
            .find_map(|(idx, entry)| entry.is_none().then_some(idx))
            .ok_or(VfsError::InvalidFd)?;
        let mut dup = src;
        dup.fd_flags = if cloexec { 1 } else { 0 };
        self.files[slot] = Some(dup);
        Ok(slot as i32)
    }

    fn clone_handle(&mut self, fd: i32) -> Result<i32, VfsError> {
        let slot = usize::try_from(fd).map_err(|_| VfsError::InvalidFd)?;
        let file = self
            .files
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(VfsError::InvalidFd)?;
        file.refs = file.refs.saturating_add(1);
        Ok(fd)
    }

    fn dup2_fd(&mut self, oldfd: i32, newfd: i32, cloexec: bool) -> Result<i32, VfsError> {
        let src = self.file(oldfd)?.clone();
        let slot = usize::try_from(newfd).map_err(|_| VfsError::InvalidFd)?;
        let entry = self.files.get_mut(slot).ok_or(VfsError::InvalidFd)?;
        let mut dup = src;
        dup.fd_flags = if cloexec { 1 } else { 0 };
        *entry = Some(dup);
        Ok(newfd)
    }

    fn list_dir_entries(&mut self, fd: i32) -> Result<Vec<reader::DirEntry>, VfsError> {
        if self.file(fd)?.special.is_some() {
            return Err(VfsError::NotDirectory);
        }
        let ino = self.file(fd)?.ino;
        reader::list_dir_entries(&mut self.dev, &self.sb, ino).map_err(|_| VfsError::Io)
    }

    fn get_dir_offset(&self, fd: i32) -> Result<u64, VfsError> {
        Ok(self.file(fd)?.offset)
    }

    fn set_dir_offset(&mut self, fd: i32, off: u64) -> Result<(), VfsError> {
        self.file_mut(fd)?.offset = off;
        Ok(())
    }

    fn cache_path(&mut self, path: &str) -> Result<(), VfsError> {
        let _ = path;
        Ok(())
    }

    fn cache_missing_path(&mut self, path: &str) {
        let _ = path;
    }

    fn file(&self, fd: i32) -> Result<&OpenFile, VfsError> {
        let slot = usize::try_from(fd).map_err(|_| VfsError::InvalidFd)?;
        self.files
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(VfsError::InvalidFd)
    }

    fn file_mut(&mut self, fd: i32) -> Result<&mut OpenFile, VfsError> {
        let slot = usize::try_from(fd).map_err(|_| VfsError::InvalidFd)?;
        self.files
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(VfsError::InvalidFd)
    }

    fn alloc_fd_slot(&self) -> Result<usize, VfsError> {
        self.files
            .iter()
            .position(|entry| entry.is_none())
            .ok_or(VfsError::InvalidFd)
    }
}

pub static VFS: Lazy<Mutex<Option<Vfs>>> = Lazy::new(|| Mutex::new(None));

pub fn mount_root(dev: VirtioBlkDevice) -> Result<(), VfsError> {
    *VFS.lock() = Some(Vfs::mount(dev)?);
    Ok(())
}

pub fn lookup(path: &str) -> Result<u64, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.lookup_path(path)
}

pub fn open(path: &str, flags: i32) -> Result<i32, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.open(path, flags)
}

pub fn read(fd: i32, out: &mut [u8]) -> Result<usize, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.read(fd, out)
}

pub fn close(fd: i32) -> Result<(), VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.close(fd)
}

pub fn fstat(fd: i32) -> Result<FileStat, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.fstat(fd)
}

pub fn lseek(fd: i32, offset: i64, whence: i32) -> Result<u64, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.lseek(fd, offset, whence)
}

pub fn exists(path: &str) -> bool {
    lookup(path).is_ok()
}

pub fn readlink(path: &str) -> Result<String, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.readlink(path)
}

pub fn read_all(path: &str) -> Result<Vec<u8>, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.read_all(path)
}

pub fn stat_path(path: &str, follow: bool) -> Result<FileStat, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.stat_path(path, follow)
}

pub fn pread(fd: i32, offset: u64, out: &mut [u8]) -> Result<usize, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.pread(fd, offset, out)
}

pub fn path_of_fd(fd: i32) -> Result<String, VfsError> {
    let g = VFS.lock();
    let v = g.as_ref().ok_or(VfsError::NotMounted)?;
    v.path_of_fd(fd)
}

pub fn get_fd_flags(fd: i32) -> Result<i32, VfsError> {
    let g = VFS.lock();
    let v = g.as_ref().ok_or(VfsError::NotMounted)?;
    v.get_fd_flags(fd)
}

pub fn set_fd_flags(fd: i32, flags: i32) -> Result<(), VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.set_fd_flags(fd, flags)
}

pub fn get_status_flags(fd: i32) -> Result<i32, VfsError> {
    let g = VFS.lock();
    let v = g.as_ref().ok_or(VfsError::NotMounted)?;
    v.get_status_flags(fd)
}

pub fn is_special_tty(fd: i32) -> Result<bool, VfsError> {
    let g = VFS.lock();
    let v = g.as_ref().ok_or(VfsError::NotMounted)?;
    v.is_special_tty(fd)
}

pub fn is_special_null(fd: i32) -> Result<bool, VfsError> {
    let g = VFS.lock();
    let v = g.as_ref().ok_or(VfsError::NotMounted)?;
    v.is_special_null(fd)
}

pub fn set_status_flags(fd: i32, flags: i32) -> Result<(), VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.set_status_flags(fd, flags)
}

pub fn dup_fd(fd: i32, min_fd: i32, cloexec: bool) -> Result<i32, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.dup_fd(fd, min_fd, cloexec)
}

pub fn clone_handle(fd: i32) -> Result<i32, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.clone_handle(fd)
}

pub fn dup2_fd(oldfd: i32, newfd: i32, cloexec: bool) -> Result<i32, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.dup2_fd(oldfd, newfd, cloexec)
}

pub fn list_dir_entries(fd: i32) -> Result<Vec<reader::DirEntry>, VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.list_dir_entries(fd)
}

pub fn get_dir_offset(fd: i32) -> Result<u64, VfsError> {
    let g = VFS.lock();
    let v = g.as_ref().ok_or(VfsError::NotMounted)?;
    v.get_dir_offset(fd)
}

pub fn set_dir_offset(fd: i32, off: u64) -> Result<(), VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.set_dir_offset(fd, off)
}

pub fn getcwd() -> String {
    "/".to_string()
}

pub fn cache_path(path: &str) -> Result<(), VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.cache_path(path)
}

pub fn cache_missing_path(path: &str) -> Result<(), VfsError> {
    let mut g = VFS.lock();
    let v = g.as_mut().ok_or(VfsError::NotMounted)?;
    v.cache_missing_path(path);
    Ok(())
}

fn normalize_path(path: &str) -> String {
    let abs = if path.starts_with('/') {
        path.to_string()
    } else {
        let mut out = String::from("/");
        out.push_str(path);
        out
    };

    let merged = if str_eq_lit(&abs, "/lib") || str_starts_with_lit(&abs, "/lib/") {
        let mut out = String::from("/usr/lib");
        out.push_str(&abs[4..]);
        out
    } else if str_eq_lit(&abs, "/bin") || str_starts_with_lit(&abs, "/bin/") {
        let mut out = String::from("/usr/bin");
        out.push_str(&abs[4..]);
        out
    } else if str_eq_lit(&abs, "/sbin") || str_starts_with_lit(&abs, "/sbin/") {
        let mut out = String::from("/usr/bin");
        out.push_str(&abs[5..]);
        out
    } else {
        abs
    };

    // Stage3 musl userspace uses soname links in /usr/lib. Resolve the hot path
    // directly to reduce symlink-walk pressure in the early bring-up path.
    if str_eq_lit(&merged, "/usr/lib/libtinfotw.so.6") {
        "/usr/lib/libtinfotw.so.6.5".to_string()
    } else {
        merged
    }
}

fn str_eq_lit(value: &str, lit: &str) -> bool {
    let left = value.as_bytes();
    let right = lit.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut i = 0usize;
    while i < left.len() {
        if left[i] != right[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn str_starts_with_lit(value: &str, prefix: &str) -> bool {
    let left = value.as_bytes();
    let right = prefix.as_bytes();
    if left.len() < right.len() {
        return false;
    }
    let mut i = 0usize;
    while i < right.len() {
        if left[i] != right[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn split_first_component(path: &str) -> (&str, &str) {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return ("", "");
    }
    match trimmed.find('/') {
        Some(idx) => (&trimmed[..idx], trimmed[idx + 1..].trim_start_matches('/')),
        None => (trimmed, ""),
    }
}
