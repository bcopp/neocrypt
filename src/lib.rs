#![feature(slice_as_chunks)]

extern crate sys_mount;

mod common;
mod crypter;
mod hashing;
mod streaming;
mod context;

use common::*;
use context::{Init, Ctx};
use core::panic;
use std::error::Error;
use std::fs::{create_dir, read_dir, remove_dir_all, DirEntry};
use std::io;
use std::path::PathBuf;
use std::process::exit;
use sys_mount::FilesystemType;
use sys_mount::{Mount, SupportedFilesystems};
use log::error;

struct LS{
    srcs: Vec<PathBuf>,
    srcs_errors: Vec<io::Error>,
    trgs: Vec<PathBuf>,
    trgs_errors: Vec<io::Error>,
    dangling_srcs: Vec<PathBuf>,
}


// lists all directories that exist in mount_from with an associated mount_to
pub fn ls(ctx: &Ctx) -> Result<LS, Box<dyn Error>> {
    
    // search for all directories in mount_from
    let srcs_read = std::fs::read_dir(&ctx.storage.mount_from)?;
    let mut srcs_errors = vec![];
    let mut srcs: Vec<PathBuf> = vec![];
    
    for src in srcs_read {
        match src {
            Ok(s) => {
                srcs.push(s.path());
            }
            Err(e) => {
                srcs_errors.push(e);
            }
        }
    }

    // search for all directories in mount_to
    let trgs_read = std::fs::read_dir(&ctx.storage.mount_to)?;
    let mut trgs_errors = vec![];
    let mut trgs: Vec<PathBuf> = vec![];

    for trg in trgs_read {
        match trg {
            Ok(t) => {
                trgs.push(t.path());
            }
            Err(e) => {
                trgs_errors.push(e);
            }
        }
    }

    // for each item in srcs_errors print the error
    for e in &srcs_errors {
        error!("Error reading source directory: {}", e);
    }

    // for each item in trgs_errors print the error
    for e in &trgs_errors {
        error!("Error reading target directory: {}", e);
    }

    // find all directories in mount_from that don't have a corresponding directory in mount_to
    let mut dangling_srcs = vec![];
    for s in &srcs {
        if trgs.iter().any(|t| s.file_name() == t.file_name()) {
        } else {
            dangling_srcs.push(s.clone());
        }
    }

    // remove these dangling sources
    // this can happen when a user ejects improperly
    for s in &dangling_srcs {
        std::fs::remove_dir_all(s.as_path())?;
    }

    Ok(LS {
        srcs: srcs,
        trgs: trgs,
        srcs_errors: srcs_errors,
        trgs_errors: trgs_errors,
        dangling_srcs: dangling_srcs,
    })
}

// creates a new directory by name and mounts it
pub fn new(ctx: &Ctx) -> Result<Mount, io::Error> {

    // initialize directories
    let src = &ctx.storage.mount_from.join(&ctx.name);
    let trg = &ctx.storage.mount_to.join(&ctx.name);
    create_dir(src)?;
    create_dir(trg)?;

    Ok(mount(src, trg)?)
}

// decrypts a file to mount_from and mounts in mount_to
pub fn open(ctx: &Ctx) {}

// encrypts a file from mount_from, unmounts and cleans up the directory
pub fn close(ctx: &Ctx) {
    let _ls = ls(ctx);

    match _ls {
        Ok(_ls) => {
            if _ls.srcs.len() != 0 {

            } else {

            }
    
            let to_unmount = &ctx.storage.mount_to.join(&ctx.name);
            if let Err(e) = unmount(to_unmount) {
                eprintln!("Failed to unmount: {}", e);
                return;
            }
            if let Err(e) = remove_dir_all(to_unmount) {
                eprintln!("Failed to remove directory: {}", e);
                return;
            }
        }
        Err(e) => {
            let to_unmount = &ctx.storage.mount_to.join(&ctx.name);
            if let Err(e) = unmount(to_unmount) {
                eprintln!("Failed to unmount: {}", e);
                return;
            }
            if let Err(e) = remove_dir_all(to_unmount) {
                eprintln!("Failed to remove directory: {}", e);
                return;
            }

            eprintln!("Failed to list directories: {}", e);
            return;
        }
    }
}

/*
when ejecting improperly (i.e. without running close) there may be a directory dangling in mount_from
repair re-mounts these any dangling directories to the drive
*/
pub fn repair(ctx: &Ctx) {}

fn mount(src: &PathBuf, target: &PathBuf) -> Result<Mount, io::Error> {
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
    #[ignore = "test manually"]
    fn test_ls_mount_unmount() {
        let ctx = Ctx::new_test();

        Init::new(&ctx)
            .init_storage()
            .init_logger();

        let mounted = ls(&ctx).unwrap();
        assert_eq!(mounted.trgs.len(), 0);

        new(&ctx).unwrap();
        assert_eq!(ls(&ctx).unwrap().srcs.len(), 1);

        close(&ctx);
        assert_eq!(ls(&ctx).unwrap().srcs.len(), 0);
    }
}
