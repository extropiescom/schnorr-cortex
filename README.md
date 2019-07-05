# schnorr-cortex 

Schnorr-cortex is forked from Schnorrkel but with lot changes for embedded device. It is designed to be a staticlib then used by keil project but with gcc compiler. 

## Aimed target:
### Cortex M3/M4
### Flash used over 300KB
### RAM used less then 64KB

embedded.rs offers a C wrapper for rest embedded C code. 'No libc' Since we found there is much issues with libc on Cortex.

onchip.rs offers a quick test on the chip to see if it can run the lib.

For small size, create .cargo/config and add
```
[target.'cfg(all(target_arch = "arm", target_os = "none"))']
rustflags = [
  # ..
  "-C", "inline-threshold=25", # +
]
```

To build lib:
```
cargo build --release --target thumbv7m-none-eabi --no-default-features
```
