use jni::JNIEnv;
use jni::objects::{JByteArray, JClass};
use jni::sys::jboolean;

use threshold_bls::sig::SignatureScheme;

use crate::*;

// This keeps Rust from "mangling" the name and making it unique for this
// crate.
#[no_mangle]
pub extern "system" fn Java_org_celo_BlindThresholdBls_verify<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pub_key: JByteArray<'local>,
    message: JByteArray<'local>,
    signature: JByteArray<'local>,
) -> jboolean {
    let pub_key_vec = env.convert_byte_array(&pub_key).unwrap();
    let pub_key: PublicKey = bincode::deserialize(&pub_key_vec).unwrap();
    let message = env.convert_byte_array(&message).unwrap();
    let signature = env.convert_byte_array(&signature).unwrap();

    jboolean::from(SigScheme::verify(&pub_key, &message, &signature).is_ok())
}
