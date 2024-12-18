#![feature(slice_as_chunks)]

extern crate sys_mount;

mod hashing;
mod common;
mod crypter;
mod streaming;

use common::*;
use sys_mount::FilesystemType;
use sys_mount::{Mount, SupportedFilesystems};
use core::panic;
use std::fs::{create_dir, read_dir, remove_dir_all, DirEntry};
use std::path::PathBuf;
use std::process::exit;
use std::io;

pub fn ls(ctx: &Ctx) ->  Result<Vec<PathBuf>, io::Error> {

    let srcs_read= std::fs::read_dir(&ctx.storage.mount_from)?;
    let srcs: Vec<DirEntry> = srcs_read
        .map(|s| s.unwrap())
        .collect();

    let trgs_read= std::fs::read_dir(&ctx.storage.mount_to)?;
    let trgs: Vec<DirEntry>  = trgs_read
        .map(|t| t.unwrap())
        .collect();

    println!("srcs {:?}", srcs);
    println!("trgs {:?}", trgs);

    let mut cleanup_srcs = vec![];
    for s in &srcs{
        if trgs
            .iter()
            .any( |t| s.file_name() == t.file_name() ) {} else { cleanup_srcs.push(s); }
    }

    println!("cleanup srcs {:?}", cleanup_srcs);

    for s in cleanup_srcs {
        std::fs::remove_dir_all(s.path()).unwrap();
    }

    let paths: Vec<PathBuf> = trgs
        .iter()
        .map(|t| t.path())
        .collect();

    println!("paths paths {:?}", paths);

    Ok(paths)
}

pub fn new(ctx: &Ctx) -> Result<Mount, io::Error>{

    let src = &ctx.storage.mount_from.join(&ctx.name);
    let trg = &ctx.storage.mount_to.join(&ctx.name);
    create_dir(src).unwrap();
    create_dir(trg).unwrap();

    Ok(mount(src, trg)?)
}

pub fn close(ctx: &Ctx) {
    let entries: Vec<_> = read_dir(&ctx.storage.mount_to).unwrap().collect();

    if ctx.close_all {
        panic!("unimplemented")
    } else {
        // TODO: decrypt back to files

        if entries.len() != 0 {
        } else {


        }

        let to_unmount = &ctx.storage.mount_to.join(&ctx.name);
        unmount(to_unmount).unwrap();
        remove_dir_all(to_unmount).unwrap();
    }
}

fn mount(src: &PathBuf, target: &PathBuf) -> Result<Mount, io::Error>{

    // Fetch a listed of supported file systems on this system. This will be used
    // as the fstype to `Mount::new`, as the `Auto` mount parameter.
    let supported = match SupportedFilesystems::new() {
        Ok(supported) => supported,
        Err(why) => {
            eprintln!("failed to get supported file systems: {}", why);
            exit(1);
        }
    };

    // The source block will be mounted to the target directory, and the fstype is likely
    // one of the supported file systems.
    let mount = Mount::builder()
        .flags(sys_mount::MountFlags::BIND)
        .fstype(FilesystemType::from(&supported))
        .mount(src, target)?;
    Ok(mount)
}

fn unmount(src: &PathBuf) -> io::Result<()> {

    let lazy = false;
    let src = src;

    let flags = if lazy {
        sys_mount::UnmountFlags::DETACH
    } else {
        sys_mount::UnmountFlags::empty()
    };

    sys_mount::unmount(&src, flags)?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use common::*;

    #[test]
    #[ignore]
    fn test_ls_mount_unmount(){
        let t = &TestInit::new()
            .with_storage()
            .with_logger();

        let ctx: Ctx = t.get_ctx();


        let mounted = ls(&ctx).unwrap();
        assert_eq!(mounted.len(), 0);

        new(&ctx).unwrap();
        assert_eq!(ls(&ctx).unwrap().len(), 1);

        close(&ctx);
        assert_eq!(ls(&ctx).unwrap().len(), 0);
    }
}