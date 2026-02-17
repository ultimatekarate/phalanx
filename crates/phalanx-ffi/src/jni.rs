use jni::objects::{JClass, JString};
use jni::sys::jlong;
use jni::JNIEnv;
use phalanx_core::engine::PhalanxEngine;
use std::ptr;

#[no_mangle]
pub extern "system" fn Java_com_phalanx_bridge_PhalanxBridge_createEngine(
    mut env: JNIEnv,
    _class: JClass,
    storage_path: JString,
) -> jlong {
    // 1. Convert Java String to Rust String
    let path: String = match env.get_string(&storage_path) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    // 2. Initialize the Engine
    match PhalanxEngine::new_at_path(&path) {
        Ok(engine) => {
            // 3. Move engine to heap and return the memory address as a 'long'
            Box::into_raw(Box::new(engine)) as jlong
        }
        Err(e) => {
            eprintln!("JNI Error: Failed to init engine: {}", e);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_phalanx_bridge_PhalanxBridge_destroyEngine(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jlong {
    let Ok(path) = env.get_string(&storage_path).map(String::from) else {
        return 0;
    };

    match PhalanxEngine::new_at_path(&path) {
        Ok(engine) => {
            Box::into_raw(Box::new(engine)) as jlong
        }
        Err(e) => {
            eprintln!("JNI Error: Failed to init engine: {e}");
            0
        }
    }
}
