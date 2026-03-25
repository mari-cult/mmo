extern crate alloc;

use crate::virtio_blk::VirtioBlkDevice;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crabfs::on_disk::superblock::Superblock;
use crabfs::reader;
use spin::{Lazy, Mutex};

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
    path: String,
}

pub struct Vfs {
    dev: VirtioBlkDevice,
    sb: Superblock,
    files: BTreeMap<i32, OpenFile>,
    next_fd: i32,
}

impl Vfs {
    fn mount(dev: VirtioBlkDevice) -> Result<Self, VfsError> {
        let mut d = dev;
        let sb = reader::read_superblock(&mut d).map_err(|_| VfsError::Io)?;
        Ok(Self {
            dev: d,
            sb,
            files: BTreeMap::new(),
            next_fd: 3,
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
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Ok(cur);
        }
        for (index, part) in parts.iter().enumerate() {
            let entries =
                reader::list_dir_entries(&mut self.dev, &self.sb, cur).map_err(|_| VfsError::Io)?;
            let mut found = None;
            for e in entries {
                if e.name == *part {
                    found = Some(e.ino);
                    break;
                }
            }
            let next_ino = found.ok_or(VfsError::NotFound)?;
            let inode = self.read_inode(next_ino)?;
            let is_last = index + 1 == parts.len();
            if (inode.mode & 0xf000) == 0xa000 && (follow_final || !is_last) {
                let target = self.read_symlink_inode(next_ino)?;
                let mut resolved = if target.starts_with('/') {
                    target
                } else {
                    let mut prefix = String::from("/");
                    for component in &parts[..index] {
                        prefix.push_str(component);
                        prefix.push('/');
                    }
                    prefix.push_str(&target);
                    prefix
                };
                if !is_last {
                    for component in &parts[index + 1..] {
                        if !resolved.ends_with('/') {
                            resolved.push('/');
                        }
                        resolved.push_str(component);
                    }
                }
                return self.lookup_path_inner(&resolved, follow_final, depth + 1);
            }
            cur = next_ino;
        }
        Ok(cur)
    }

    fn open(&mut self, path: &str, _flags: i32) -> Result<i32, VfsError> {
        let normalized = normalize_path(path);
        let ino = self.lookup_path(&normalized)?;
        let fd = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        self.files.insert(
            fd,
            OpenFile {
                ino,
                offset: 0,
                path: normalized,
            },
        );
        Ok(fd)
    }

    fn read(&mut self, fd: i32, out: &mut [u8]) -> Result<usize, VfsError> {
        let of = self.files.get_mut(&fd).ok_or(VfsError::InvalidFd)?;
        let data =
            reader::read_file_data(&mut self.dev, &self.sb, of.ino, of.offset, out.len() as u32)
                .map_err(|_| VfsError::Io)?;
        let n = data.len();
        out[..n].copy_from_slice(&data);
        of.offset = of.offset.saturating_add(n as u64);
        Ok(n)
    }

    fn close(&mut self, fd: i32) -> Result<(), VfsError> {
        self.files
            .remove(&fd)
            .map(|_| ())
            .ok_or(VfsError::InvalidFd)
    }

    fn fstat(&mut self, fd: i32) -> Result<FileStat, VfsError> {
        let ino = self.files.get(&fd).ok_or(VfsError::InvalidFd)?.ino;
        let inode = self.read_inode(ino)?;
        Ok(FileStat {
            ino,
            mode: inode.mode,
            size: inode.size as u64,
        })
    }

    fn lseek(&mut self, fd: i32, offset: i64, whence: i32) -> Result<u64, VfsError> {
        let cur_off = self.files.get(&fd).ok_or(VfsError::InvalidFd)?.offset;
        let ino = self.files.get(&fd).ok_or(VfsError::InvalidFd)?.ino;
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
        let of = self.files.get_mut(&fd).ok_or(VfsError::InvalidFd)?;
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
        let of = self.files.get(&fd).ok_or(VfsError::InvalidFd)?;
        let data =
            reader::read_file_data(&mut self.dev, &self.sb, of.ino, offset, out.len() as u32)
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

    fn path_of_fd(&self, fd: i32) -> Result<String, VfsError> {
        self.files
            .get(&fd)
            .map(|file| file.path.clone())
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

pub fn getcwd() -> String {
    "/".to_string()
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        let mut out = String::from("/");
        out.push_str(path);
        out
    }
}
