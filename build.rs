/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use anyhow::Result;
use std::env;
use std::process::Command;
use vergen_gitcl::{
    BuildBuilder, CargoBuilder, Emitter, GitclBuilder, RustcBuilder, SysinfoBuilder,
};

const MAIN_THREAD_STACK_SIZE_BYTES: usize = 16 * 1024 * 1024;

pub fn main() -> Result<()> {
    let hostname = Command::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|hostname| hostname.trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=BUILD_HOSTNAME={}", hostname);

    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let target = env::var("TARGET").unwrap();

    if target.contains("apple-darwin") {
        println!(
            "cargo:rustc-link-arg-bin={}=-Wl,-stack_size,0x{:x}",
            package_name, MAIN_THREAD_STACK_SIZE_BYTES
        );
    } else if target.contains("linux") {
        println!(
            "cargo:rustc-link-arg-bin={}=-Wl,-z,stack-size={}",
            package_name, MAIN_THREAD_STACK_SIZE_BYTES
        );
    }

    Emitter::default()
        .add_instructions(&BuildBuilder::all_build()?)?
        .add_instructions(&CargoBuilder::all_cargo()?)?
        .add_instructions(
            &GitclBuilder::default()
                .commit_date(true)
                .commit_timestamp(true)
                .sha(true)
                .commit_author_email(true)
                .build()?,
        )?
        .add_instructions(&RustcBuilder::all_rustc()?)?
        .add_instructions(&SysinfoBuilder::all_sysinfo()?)?
        .emit()
}
