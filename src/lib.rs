/*
The MIT License (MIT)

Copyright © 2021 Sojan James

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
associated documentation files (the “Software”), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT 
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use core::ops::{Deref, DerefMut};
use std::ffi::c_void;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub trait ASN1GenType {
    /// Get the address of the static descriptor created by the generated code
    unsafe fn get_descriptor() -> &'static asn_TYPE_descriptor_t;
}

enum AllocatedData<T: Sized + ASN1GenType> {
    /// The type is allocated by Rust.
    RustAllocated(*mut T),
    /// This is used for received data. The codec  uses its own
    /// allocator and does not allow us to provide our own.
    Asn1CodecAllocated(*mut T),
}

pub struct ASNBox<T>(AllocatedData<T>)
where
    T: Sized + ASN1GenType;

impl<T> ASNBox<T>
where
    T: Sized + ASN1GenType,
{
    /// Create a boxed  type from a buffer that is allocated by asn1c
    pub unsafe fn new_from_asn1codec_allocated_struct(p: *mut T) -> Self {
        if !p.is_null() {
            Self(AllocatedData::<T>::Asn1CodecAllocated(p))
        } else {
            panic!("Tried to create ASNBox from null pointer");
        }
    }

    /// Build a ASNBox from a heap allocated struct 
    pub fn new_from_box(b: Box<T>) -> Self {
        Self(AllocatedData::RustAllocated(Box::into_raw(b)))
    }

    pub unsafe fn get_raw_mut_ptr(&self) -> *mut std::ffi::c_void {
        match self.0 {
            AllocatedData::Asn1CodecAllocated(p) => p as *mut std::ffi::c_void,
            AllocatedData::RustAllocated(p) => p as *mut std::ffi::c_void,
        }
    }
}

impl<T> Drop for ASNBox<T>
where
    T: Sized + ASN1GenType,
{
    fn drop(&mut self) {
        match self.0 {
            AllocatedData::Asn1CodecAllocated(p) => unsafe {
                let mut descriptor = T::get_descriptor();
                let ops = descriptor.op.as_ref().unwrap();
                let free_fn = ops.free_struct.unwrap();
                free_fn(
                    descriptor,
                    p as *mut ::std::os::raw::c_void,
                    asn_struct_free_method_ASFM_FREE_EVERYTHING,
                );
            },
            AllocatedData::RustAllocated(p) => {
                Box::from(p); // The box will go out of scope immediately and release p
            }
        }
    }
}

impl<T> Deref for ASNBox<T>
where
    T: Sized + ASN1GenType,
{
    type Target = T;
    fn deref(&self) -> &T {
        match self.0 {
            AllocatedData::Asn1CodecAllocated(p) => unsafe { &*p as &T },
            AllocatedData::RustAllocated(p) => unsafe { &*p as &T },
        }
    }
}

impl<T> DerefMut for ASNBox<T>
where
    T: Sized + ASN1GenType,
{
    fn deref_mut(&mut self) -> &mut T {
        match self.0 {
            AllocatedData::Asn1CodecAllocated(p) => unsafe { &mut *p },
            AllocatedData::RustAllocated(p) => unsafe { &mut *p },
        }
    }
}

/// Try to decode a buffer into the type specified by the type of the function.
pub fn uper_decode_full<T>(buffer: &[u8]) -> Option<ASNBox<T>>
where
    T: Sized + ASN1GenType,
{
    let codec_ctx = asn_codec_ctx_t { max_stack_size: 0 };
    // set to NULL so ASN1 codec will allocate the structure
    // there may be a cleaner way to do this - but this is what I could
    // manage for now.
    let mut voidp: *mut c_void = std::ptr::null::<ShortMsgNpdu_t>() as *mut c_void;
    let voidpp: *mut *mut c_void = &mut voidp;

    unsafe {
        let rval = uper_decode_complete(
            &codec_ctx as *const _,
            T::get_descriptor(),
            voidpp,
            buffer.as_ptr() as *const ::std::os::raw::c_void,
            buffer.len() as u64,
        );
        if rval.code != asn_dec_rval_code_e_RC_OK {
            None
        } else {
            let msg = ASNBox::<T>::new_from_asn1codec_allocated_struct(voidp as *mut T);
            Some(msg)
        }
    }
}

/// Encode a structure into a byte array. The buffer must be large
/// enough for the data. If successful, returns a slice into the
/// input slice.
pub fn uper_encode_full<'a, T>(msg: &T, buffer: &'a mut [u8]) -> Option<&'a [u8]>
where
    T: Sized + ASN1GenType,
{
    let message_ptr: *const c_void = msg as *const _ as *const c_void;
    let encode_buffer_ptr: *mut c_void = buffer.as_mut_ptr() as *mut _ as *mut c_void;

    unsafe {
        let enc_rval = uper_encode_to_buffer(
            T::get_descriptor(),
            std::ptr::null(),
            message_ptr,
            encode_buffer_ptr,
            buffer.len() as u64,
        );
        if enc_rval.encoded > 0 {
            println!(
                "Success! encoded ShortMsgNpdu, {} bytes {} bits",
                enc_rval.encoded / 8,
                enc_rval.encoded % 8,
            );
            let num_bytes = (enc_rval.encoded / 8) as usize;
            Some(&buffer[0..num_bytes])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn new_context() -> asn_struct_ctx_t {
        let ctx_struct: asn_struct_ctx_t = asn_struct_ctx_t {
            phase: 0,
            step: 0,
            context: 0,
            ptr: std::ptr::null_mut(),
            left: 0i64,
        };
        ctx_struct
    }

    fn create_short_msg_npdu(
        mut data: &mut [u8],
        version: i64,
        dest_address: i64,
    ) -> ShortMsgNpdu_t {
        let mut short_msg = ShortMsgNpdu_t {
            subtype: ShortMsgSubtype_t {
                present: ShortMsgSubtype_PR_ShortMsgSubtype_PR_nullNetworking,
                choice: ShortMsgSubtype_ShortMsgSubtype_u {
                    nullNetworking: NullNetworking_t {
                        version: version,
                        nExtensions: std::ptr::null_mut(),
                        _asn_ctx: new_context(),
                    },
                },
                _asn_ctx: new_context(),
            },
            transport: ShortMsgTpdus_t {
                present: ShortMsgTpdus_PR_ShortMsgTpdus_PR_bcMode,
                choice: ShortMsgTpdus_ShortMsgTpdus_u {
                    bcMode: ShortMsgBcPDU_t {
                        destAddress: VarLengthNumber_t {
                            present: VarLengthNumber_PR_VarLengthNumber_PR_content,
                            choice: VarLengthNumber_VarLengthNumber_u {
                                content: dest_address,
                            },
                            _asn_ctx: new_context(),
                        },
                        tExtensions: std::ptr::null_mut(),
                        _asn_ctx: new_context(),
                    },
                },
                _asn_ctx: new_context(),
            },
            body: ShortMsgData_t {
                /* OCTET_DATA */
                buf: data.as_mut_ptr(),
                size: data.len() as u64,
                _asn_ctx: new_context(),
            },
            _asn_ctx: new_context(),
        };
        short_msg
    }

    #[test]
    fn loopback_short_msg_n_pdu() {
        let mut data = vec![0xFEu8; 10];
        let version = 2;
        let dest_address = 12;
        let mut encoded_data = vec![0u8; 128];

        let mut short_msg = create_short_msg_npdu(&mut data, version, dest_address);

        if let Some(encoded_data) =
            uper_encode_full::<ShortMsgNpdu_t>(&short_msg, &mut encoded_data)
        {
            if let Some(msg) = uper_decode_full::<ShortMsgNpdu_t>(&encoded_data) {
                unsafe {
                    // access to union field is unsafe
                    assert_eq!(msg.subtype.choice.nullNetworking.version, 2);
                    assert_eq!(msg.transport.choice.bcMode.destAddress.choice.content, 12);
                }
            } else {
                panic!("Decode failed")
            }
        } else {
            panic!("Encode failed");
        }
    }
}
