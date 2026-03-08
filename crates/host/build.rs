fn main() {
    // ── SP1 guest ELF compilation (only when the `zk` feature is active) ─────
    //
    // When `cargo build --features zk` is invoked, sp1_build compiles the guest RISC-V
    // program at `crates/guest/` and makes its ELF available to the host via an env var
    // (`ECTO_GUEST_ELF_PATH`) that is set in the cargo build script output.
    // The host `prove-audit` command includes this ELF at compile time.
    #[cfg(feature = "zk")]
    {
        sp1_build::build_program("../guest");
    }

    #[cfg(all(
        feature = "sandbox-apple-enclave",
        target_os = "macos",
        target_arch = "aarch64"
    ))]
    {
        build_guard_unikernel_bin();
    }

    // ── Windows icon embedding (non-ZK-gated) ────────────────────────────────
    // Gated behind the `embed-resource` feature so that downstream consumers
    // (e.g. ectoledger-gui / Tauri) that produce their OWN Windows resource
    // files do not hit CVT1100 "duplicate resource" linker errors.
    #[cfg(all(target_os = "windows", feature = "embed-resource"))]
    embed_windows_icon();
}

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
fn build_guard_unikernel_bin() {
    use std::env;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.join("..").join("..");
    let guard_manifest = workspace_root
        .join("crates")
        .join("guard_unikernel")
        .join("Cargo.toml");
    let link_ld_path = workspace_root
        .join("crates")
        .join("guard_unikernel")
        .join("link.ld");

    let rustflags = format!(
        "-C link-arg=-T{} -C relocation-model=static -C target-feature=+strict-align -C linker=rust-lld",
        link_ld_path.display()
    );

    // ── Pre-flight: verify the bare-metal target is installed ─────────────
    let target_check = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .expect("failed to run `rustup target list --installed`");
    let installed = String::from_utf8_lossy(&target_check.stdout);
    if !installed
        .lines()
        .any(|l| l.trim() == "aarch64-unknown-none")
    {
        panic!(
            "\n\n\
             ╔══════════════════════════════════════════════════════════════╗\n\
             ║  Missing required Rust target: aarch64-unknown-none        ║\n\
             ║                                                            ║\n\
             ║  Run:  rustup target add aarch64-unknown-none              ║\n\
             ║        rustup component add llvm-tools                     ║\n\
             ╚══════════════════════════════════════════════════════════════╝\n"
        );
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let unikernel_target_dir = out_dir.join("unikernel_target");

    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&guard_manifest)
        .arg("--target")
        .arg("aarch64-unknown-none")
        .arg("--target-dir") // Tell cargo exactly where to put the output
        .arg(&unikernel_target_dir)
        .env("RUSTFLAGS", &rustflags)
        // Clear CARGO_ENCODED_RUSTFLAGS so the child cargo respects our RUSTFLAGS.
        // The parent cargo sets this, and when present it takes precedence over RUSTFLAGS.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("failed to invoke cargo for guard_unikernel");

    if !status.success() {
        panic!(
            "guard_unikernel build failed.\n\
             Ensure the bare-metal target and llvm-tools are installed:\n  \
             rustup target add aarch64-unknown-none\n  \
             rustup component add llvm-tools\n\
             Then retry the build."
        );
    }

    // Grab the ELF from our isolated target directory
    let elf_path = unikernel_target_dir
        .join("aarch64-unknown-none")
        .join("release")
        .join("guard_unikernel");
    let bin_path = Path::new(&out_dir).join("guard_unikernel.bin");

    // Find llvm-objcopy in the Rust toolchain
    let sysroot = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let sysroot_output = Command::new(&sysroot)
        .arg("--print")
        .arg("sysroot")
        .output()
        .expect("failed to get rustc sysroot");
    let sysroot_path = PathBuf::from(String::from_utf8_lossy(&sysroot_output.stdout).trim());
    let llvm_objcopy = sysroot_path
        .join("lib")
        .join("rustlib")
        .join(env::var("HOST").expect("HOST"))
        .join("bin")
        .join("llvm-objcopy");

    let objcopy_status = Command::new(&llvm_objcopy)
        .arg("-O")
        .arg("binary")
        .arg(&elf_path)
        .arg(&bin_path)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "failed to invoke llvm-objcopy at {}: {}",
                llvm_objcopy.display(),
                e
            )
        });

    if !objcopy_status.success() {
        panic!(
            "llvm-objcopy failed while creating guard_unikernel.bin. Expected ELF at: {}",
            elf_path.display()
        );
    }

    println!("cargo:rerun-if-changed=../guard_unikernel/src/main.rs");
    println!("cargo:rerun-if-changed=../guard_unikernel/link.ld");
    println!("cargo:rerun-if-changed=../guard_unikernel/Cargo.toml");
}

#[cfg(all(target_os = "windows", feature = "embed-resource"))]
fn embed_windows_icon() {
    use std::env;
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::path::Path;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // The crate lives in `crates/host` whereas the logo lives at the workspace
    // root (`assets/el-logo.webp`).  On Windows CI we were failing because we tried
    // to open `crates/host/assets/el-logo.webp` which doesn't exist.  Climb two
    // levels to reach the workspace root.
    let logo_path = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("assets")
        .join("el-logo.webp");

    if !logo_path.exists() {
        eprintln!(
            "warning: windows icon not generated because {} does not exist",
            logo_path.display()
        );
        return;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let ico_path = Path::new(&out_dir).join("icon.ico");

    let img = image::open(&logo_path).expect("failed to open assets/el-logo.webp");
    let rgba = img.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    let sizes = [256u32, 48, 32, 16];

    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in sizes {
        if w >= size && h >= size {
            let resized =
                image::imageops::resize(&rgba, size, size, image::imageops::FilterType::Lanczos3);
            let raw = resized.into_raw();
            let icon_img = ico::IconImage::from_rgba_data(size, size, raw);
            let entry = ico::IconDirEntry::encode(&icon_img).expect("encode icon entry");
            icon_dir.add_entry(entry);
        }
    }
    if icon_dir.entries().is_empty() {
        let raw = rgba.into_raw();
        let icon_img = ico::IconImage::from_rgba_data(w, h, raw);
        let entry = ico::IconDirEntry::encode(&icon_img).expect("encode icon entry");
        icon_dir.add_entry(entry);
    }

    let file = File::create(&ico_path).expect("create icon file");
    let mut writer = BufWriter::new(file);
    icon_dir.write(&mut writer).expect("write ico");
    writer.flush().expect("flush icon file");

    winres::WindowsResource::new()
        .set_icon(ico_path.to_str().unwrap())
        .compile()
        .expect("winres compile");
}
