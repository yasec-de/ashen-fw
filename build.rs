use std::path::PathBuf;

const WOLFCRYPT_SOURCES: &[&str] = &[
    "aes.c",
    "asn.c",
    "coding.c",
    "cryptocb.c",
    "ecc.c",
    "error.c",
    "hash.c",
    "hmac.c",
    "kdf.c",
    "logging.c",
    "memory.c",
    "misc.c",
    "random.c",
    "sha.c",
    "sha256.c",
    "sha512.c",
    "sha3.c",
    "sp_int.c",
    "wc_mldsa.c",
    "wc_mlkem.c",
    "wc_mlkem_poly.c",
    "wc_port.c",
    "wolfmath.c",
];

const WOLFTPM_SOURCES: &[&str] = &[
    "src/tpm2_crypto.c",
    "src/fwtpm/fwtpm.c",
    "src/fwtpm/fwtpm_command.c",
    "src/fwtpm/fwtpm_crypto.c",
    "src/fwtpm/fwtpm_nv.c",
    "src/tpm2_util.c",
    "src/tpm2_packet.c",
    "src/tpm2_param_enc.c",
];

fn main() {
    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tkeystore.x");
    println!(
        "cargo:rustc-link-search={}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rerun-if-changed=keystore.x");

    build_tpm();
}

fn build_tpm() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let wolfssl = manifest.join("third_party/wolfssl");
    let wolftpm = manifest.join("third_party/wolftpm");
    let csrc = manifest.join("csrc");

    if !wolfssl.join("wolfcrypt/src/aes.c").exists() || !wolftpm.join("src/fwtpm/fwtpm.c").exists()
    {
        panic!(
            "third_party submodules are missing. Run `git submodule update --init \
             --recursive`, and build the flake with `nix build '.?submodules=1'`."
        );
    }

    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=third_party/wolfssl");
    println!("cargo:rerun-if-changed=third_party/wolftpm");

    let target = std::env::var("TARGET").unwrap();
    let bare_metal = target.ends_with("-none-eabi") || target.ends_with("-none-eabihf");

    let mut build = cc::Build::new();
    build
        .include(&csrc)
        .include(&wolfssl)
        .include(&wolftpm)
        .define("WOLFSSL_USER_SETTINGS", None)
        .define("WOLFTPM_USER_SETTINGS", None)
        .define("WOLFTPM_FWTPM", None)
        .flag("-include")
        .flag(csrc.join("user_settings.h").to_str().unwrap())
        .warnings(false)
        .opt_level(2);

    if bare_metal {
        build
            .flag("-ffreestanding")
            .flag("--specs=nano.specs")
            // cc passes a bare -march=armv8-m.main, which lacks the DSP
            // instructions (umaal) that wolfCrypt's sp_cortexm.c assembly
            // uses. -march wins over -mcpu in gcc, so override the arch.
            .flag("-march=armv8-m.main+dsp+fp");
    } else {
        build.define("ASHEN_HOST_BUILD", None);
    }

    for src in WOLFCRYPT_SOURCES {
        build.file(wolfssl.join("wolfcrypt/src").join(src));
    }
    // Single-precision ECC needs its per-architecture implementation: the
    // Cortex-M assembly version on target, the portable C one on the host.
    build.file(wolfssl.join("wolfcrypt/src").join(if bare_metal {
        "sp_cortexm.c"
    } else {
        "sp_c32.c"
    }));
    for src in WOLFTPM_SOURCES {
        build.file(wolftpm.join(src));
    }
    build.file(csrc.join("shim.c"));
    build.file(csrc.join("tpm_glue.c"));

    build.compile("ashen_tpm");
}
