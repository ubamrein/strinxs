#!/bin/bash

cross build --target aarch64-linux-android --release
cross build --target x86_64-pc-windows-gnu --release
cross build --target x86_64-unknown-linux-gnu --release
cargo build --release

mkdir -p releases
cp target/release/strinxs releases/strinxs_macosx
cp target/x86_64-pc-windows-gnu/release/strinxs.exe releases/strinxs_windows.exe
cp target/x86_64-unknown-linux-gnu/release/strinxs releases/strinxs_linux
cp target/aarch64-linux-android/release/strinxs releases/strinxs_android
