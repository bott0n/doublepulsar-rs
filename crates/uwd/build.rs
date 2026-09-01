use std::{env, process::Command};

fn main() {
    let target = env::var("TARGET").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let spoof_uwd = env::var("CARGO_FEATURE_SPOOF_UWD").is_ok();

    if target.contains("x86_64") {
        if spoof_uwd {
            let spoof_synthetic_obj = format!("{}/spoof_synthetic.o", out_dir);

            let status = Command::new("nasm")
                .args(&[
                    "-f",
                    "win64",
                    "asm/x64/spoof/gnu/synthetic.asm",
                    "-o",
                    &spoof_synthetic_obj,
                ])
                .status()
                .expect("Failed to assemble synthetic.asm");

            if !status.success() {
                panic!("Failed to assemble asm/x64/spoof/gnu/synthetic.asm");
            }

            cc::Build::new().object(&spoof_synthetic_obj).compile("asm");
        }
    } else {
        panic!("Unsupported target: {}", target);
    }

    println!("cargo:rerun-if-changed=asm/x64/spoof/gnu/synthetic.asm");
}
