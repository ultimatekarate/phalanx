use jni::objects::{JClass, JString};
use jni::sys::jlong;
use jni::JNIEnv;
use phalanx_core::engine::{NoOpJournal, PhalanxEngine};
use std::ptr;

// Use *mut PhalanxEngine<NoOpJournal> if you ever point at PhalanxEngine.

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
    if ptr == 0 {
        return 0;
    }

    // Take ownership of the pointer to drop it safely
    unsafe {
        let _ = Box::from_raw(ptr as *mut PhalanxEngine<NoOpJournal>);
    }

    0
}
