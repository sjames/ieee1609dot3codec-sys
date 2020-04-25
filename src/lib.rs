#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
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
    fn encode_short_msg_n_pdu() {
        let mut data = vec![0xFEu8; 10];
        let version = 2;
        let dest_address = 12;
        let mut encoded_data = vec![0u8; 128];

        let mut short_msg = create_short_msg_npdu(&mut data, version, dest_address);

        let message_ptr: *mut c_void = &mut short_msg as *mut _ as *mut c_void;
        let encode_buffer_ptr: *mut c_void = encoded_data.as_mut_ptr() as *mut _ as *mut c_void;

        unsafe {
            let enc_rval = uper_encode_to_buffer(
                &asn_DEF_ShortMsgNpdu,
                std::ptr::null(),
                message_ptr,
                encode_buffer_ptr,
                encoded_data.len() as u64,
            );
            if enc_rval.encoded > 0 {
                println!(
                    "Success! encoded ShortMsgNpdu, {} bytes {} bits",
                    enc_rval.encoded / 8,
                    enc_rval.encoded % 8,
                );
                let num_bytes = enc_rval.encoded / 8;
                encoded_data.resize(num_bytes as usize, 0);
            } else {
                panic!("Encode ShortMsgNpdu failed,  {}", enc_rval.encoded);
            }
        }
    }
}
