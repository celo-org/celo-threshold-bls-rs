# Threshold BLS FFI

## FFI Bindings

```
cargo build --target <your target>
```

You can generate headerfiles via [`bindgen`]()

## WASM Bindings

This library provides wasm bindings for signing under the `sig/wasm.rs` module. These can be built
via the [`wasm-pack`](https://github.com/rustwasm/wasm-pack) tool. Depending on the platform you are 
targetting, you'll need to use a different build flag.

```
$ wasm-pack build --target nodejs -- --features=wasm
```

The bundled wasm package will be under the `pkg/` directory. You can then either pack and publish it 
with `wasm-pack`'s `pack` and `publish` commands, or manually import it in your application.
