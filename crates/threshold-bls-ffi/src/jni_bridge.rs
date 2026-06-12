use jni::objects::{JByteArray, JClass};
use jni::sys::jboolean;
use jni::EnvUnowned;

use threshold_bls::{serialization, sig::SignatureScheme};

use crate::*;

// This keeps Rust from "mangling" the name and making it unique for this
// crate.
#[no_mangle]
pub extern "system" fn Java_org_celo_BlindThresholdBls_verify<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    pub_key: JByteArray<'local>,
    message: JByteArray<'local>,
    signature: JByteArray<'local>,
) -> jboolean {
    let outcome = env.with_env(|env| -> jni::errors::Result<jboolean> {
        let pub_key = env.convert_byte_array(&pub_key)?;
        let message = env.convert_byte_array(&message)?;
        let signature = env.convert_byte_array(&signature)?;

        // Malformed keys or signatures mean the signature does not verify;
        // they must not crash or throw across the FFI boundary.
        let verified = serialization::deserialize::<PublicKey>(&pub_key)
            .map(|pub_key| SigScheme::verify(&pub_key, &message, &signature).is_ok())
            .unwrap_or(false);
        Ok(jboolean::from(verified))
    });

    outcome.resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}
