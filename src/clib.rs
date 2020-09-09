//! Ossuary API exposed with a C FFI
//!
//! See `ossuary.h` for documentation.
//
// Copyright 2019 Trevor Bentley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#![allow(clippy::missing_safety_doc)]

use crate::{generate_auth_keypair, ConnectionType, OssuaryConnection, OssuaryError, KEY_LEN};

pub const OSSUARY_ERR_WOULD_BLOCK: i32 = -64;
pub const OSSUARY_ERR_UNTRUSTED_SERVER: i32 = -65;

#[no_mangle]
pub unsafe extern "C" fn ossuary_create_connection(
    conn_type: u8,
    auth_key: *const u8,
) -> *mut OssuaryConnection {
    let conn_type: ConnectionType = match conn_type {
        0 => ConnectionType::Client,
        1 => ConnectionType::AuthenticatedServer,
        2 => ConnectionType::UnauthenticatedServer,
        _ => {
            return ::std::ptr::null_mut();
        }
    };
    let key: Option<&[u8]> = match auth_key.is_null() {
        false => Some(std::slice::from_raw_parts(auth_key, 32)),
        true => None,
    };
    let conn = match OssuaryConnection::new(conn_type, key) {
        Ok(c) => c,
        Err(_e) => return ::std::ptr::null_mut(),
    };
    let mut conn = Box::new(conn);
    let ptr: *mut _ = &mut *conn;
    ::std::mem::forget(conn);
    ptr
}

#[no_mangle]
pub extern "C" fn ossuary_destroy_connection(conn: &mut *mut OssuaryConnection) {
    if conn.is_null() {
        return;
    }
    let obj: Box<OssuaryConnection> = unsafe { ::std::mem::transmute(*conn) };
    ::std::mem::drop(obj);
    *conn = ::std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_add_authorized_key(
    conn: *mut OssuaryConnection,
    key_buf: *const u8,
) -> i32 {
    if conn.is_null() || key_buf.is_null() {
        return -1i32;
    }
    let conn = { &mut *conn };
    let r_key_buf: &[u8] = { std::slice::from_raw_parts(key_buf, KEY_LEN) };
    match conn.add_authorized_key(r_key_buf) {
        Ok(_) => 0i32,
        Err(_) => -1i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_add_authorized_keys(
    conn: *mut OssuaryConnection,
    keys: *const *const u8,
    key_count: u8,
) -> i32 {
    if conn.is_null() || keys.is_null() {
        return -1 as i32;
    }
    let conn = { &mut *conn };
    let keys: &[*const u8] = { std::slice::from_raw_parts(keys, key_count as usize) };
    let mut r_keys: Vec<&[u8]> = Vec::with_capacity(key_count as usize);
    for key in keys {
        if !key.is_null() {
            let key: &[u8] = { std::slice::from_raw_parts(*key, 32) };
            r_keys.push(key);
        }
    }
    match conn.add_authorized_keys(r_keys) {
        Ok(c) => c as i32,
        Err(_) => -1i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_set_secret_key(
    conn: *mut OssuaryConnection,
    key: *const u8,
) -> i32 {
    if conn.is_null() || key.is_null() {
        return -1 as i32;
    }
    let conn = { &mut *conn };
    let key: &[u8] = { std::slice::from_raw_parts(key, 32) };
    match conn.set_secret_key(key) {
        Ok(_) => 0i32,
        Err(_) => -1i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_recv_handshake(
    conn: *mut OssuaryConnection,
    in_buf: *const u8,
    in_buf_len: *mut u16,
) -> i32 {
    if conn.is_null() || in_buf.is_null() || in_buf_len.is_null() {
        return -1i32;
    }
    let conn = { &mut *conn };
    let inlen = { *in_buf_len as usize };
    let r_in_buf: &[u8] = { std::slice::from_raw_parts(in_buf, inlen) };
    let mut slice = r_in_buf;
    let read: i32 = match conn.recv_handshake(&mut slice) {
        Ok(read) => {
            {
                *in_buf_len = read as u16;
            }
            read as i32
        }
        Err(OssuaryError::WouldBlock(b)) => {
            {
                *in_buf_len = b as u16;
            }
            OSSUARY_ERR_WOULD_BLOCK
        }
        _ => {
            {
                *in_buf_len = 0u16;
            }
            -1i32
        }
    };
    read as i32
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_send_handshake(
    conn: *mut OssuaryConnection,
    out_buf: *mut u8,
    out_buf_len: *mut u16,
) -> i32 {
    if conn.is_null() || out_buf.is_null() || out_buf_len.is_null() {
        return -1i32;
    }
    let conn = { &mut *conn };
    let outlen = { *out_buf_len as usize };
    let r_out_buf: &mut [u8] = { std::slice::from_raw_parts_mut(out_buf, outlen) };
    let mut slice = r_out_buf;
    match conn.send_handshake(&mut slice) {
        Ok(w) => {
            *out_buf_len = w as u16;
            w as i32
        }
        Err(OssuaryError::WouldBlock(w)) => {
            *out_buf_len = w as u16;
            OSSUARY_ERR_WOULD_BLOCK
        }
        Err(_) => {
            *out_buf_len = 0u16;
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_handshake_done(conn: *mut OssuaryConnection) -> i32 {
    if conn.is_null() {
        return -1i32;
    }
    let conn = { &mut *conn };
    let done = conn.handshake_done();
    match done {
        Ok(done) => done as i32,
        Err(OssuaryError::UntrustedServer(_)) => OSSUARY_ERR_UNTRUSTED_SERVER,
        Err(_) => -1i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_send_data(
    conn: *mut OssuaryConnection,
    in_buf: *mut u8,
    in_buf_len: u16,
    out_buf: *mut u8,
    out_buf_len: *mut u16,
) -> i32 {
    if conn.is_null() || in_buf.is_null() || out_buf.is_null() || out_buf_len.is_null() {
        return -1i32;
    }
    let conn = { &mut *conn };
    let r_out_buf: &mut [u8] = { std::slice::from_raw_parts_mut(out_buf, *out_buf_len as usize) };
    let r_in_buf: &[u8] = { std::slice::from_raw_parts(in_buf, in_buf_len as usize) };
    let mut out_slice = r_out_buf;
    let in_slice = r_in_buf;
    match conn.send_data(&in_slice, &mut out_slice) {
        Ok(w) => {
            {
                *out_buf_len = w as u16;
            }
            w as i32
        }
        Err(OssuaryError::WouldBlock(w)) => {
            {
                *out_buf_len = w as u16;
            }
            OSSUARY_ERR_WOULD_BLOCK
        }
        Err(_) => {
            {
                *out_buf_len = 0u16;
            }
            -1i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_recv_data(
    conn: *mut OssuaryConnection,
    in_buf: *mut u8,
    in_buf_len: *mut u16,
    out_buf: *mut u8,
    out_buf_len: *mut u16,
) -> i32 {
    if conn.is_null()
        || in_buf.is_null()
        || out_buf.is_null()
        || in_buf_len.is_null()
        || out_buf_len.is_null()
    {
        return -1i32;
    }
    let conn = { &mut *conn };
    let r_out_buf: &mut [u8] = { std::slice::from_raw_parts_mut(out_buf, *out_buf_len as usize) };
    let r_in_buf: &[u8] = { std::slice::from_raw_parts(in_buf, *in_buf_len as usize) };
    let mut out_slice = r_out_buf;
    let mut in_slice = r_in_buf;
    let bytes_read = match conn.recv_data(&mut in_slice, &mut out_slice) {
        Ok((read, written)) => {
            {
                *in_buf_len = read as u16;
                *out_buf_len = written as u16;
            };
            read as i32
        }
        Err(OssuaryError::WouldBlock(r)) => {
            {
                *in_buf_len = r as u16;
                *out_buf_len = 0u16;
            };
            OSSUARY_ERR_WOULD_BLOCK
        }
        Err(_) => {
            {
                *in_buf_len = 0u16;
                *out_buf_len = 0u16;
            }
            -1i32
        }
    };
    bytes_read as i32
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_flush(
    conn: *mut OssuaryConnection,
    out_buf: *mut u8,
    out_buf_len: u16,
) -> i32 {
    if conn.is_null() || out_buf.is_null() {
        return -1i32;
    }
    let conn = { &mut *conn };
    let r_out_buf: &mut [u8] = { std::slice::from_raw_parts_mut(out_buf, out_buf_len as usize) };
    let mut out_slice = r_out_buf;
    match conn.flush(&mut out_slice) {
        Ok(x) => x as i32,
        Err(OssuaryError::WouldBlock(_)) => OSSUARY_ERR_WOULD_BLOCK,
        Err(_) => -1i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_remote_public_key(
    conn: *mut OssuaryConnection,
    key_buf: *mut u8,
    key_buf_len: u16,
) -> i32 {
    if conn.is_null() || key_buf.is_null() || key_buf_len < KEY_LEN as u16 {
        return -1i32;
    }
    let conn = { &mut *conn };
    let r_key_buf: &mut [u8] = { std::slice::from_raw_parts_mut(key_buf, KEY_LEN) };
    let res = match conn.remote_public_key() {
        Ok(key) => {
            r_key_buf.copy_from_slice(key);
            0i32
        }
        Err(_) => -1i32,
    };
    res
}

#[no_mangle]
pub unsafe extern "C" fn ossuary_generate_auth_keypair(
    secret_buf: *mut u8,
    secret_buf_len: u16,
    public_buf: *mut u8,
    public_buf_len: u16,
) -> i32 {
    if secret_buf.is_null() || public_buf.is_null() {
        return -1i32;
    }
    if secret_buf_len < KEY_LEN as u16 || public_buf_len < KEY_LEN as u16 {
        return -1i32;
    }
    let r_secret: &mut [u8] = { std::slice::from_raw_parts_mut(secret_buf, KEY_LEN) };
    let r_public: &mut [u8] = { std::slice::from_raw_parts_mut(public_buf, KEY_LEN) };
    match generate_auth_keypair() {
        Ok((s, p)) => {
            r_secret.copy_from_slice(&s);
            r_public.copy_from_slice(&p);
            0i32
        }
        _ => -1i32,
    }
}
