//! Windows TPM 2.0 integration via TBS (TPM Base Services).
//!
//! This backend talks to TPM directly through TBS command submission.
//! No software mock/fallback path is used.

#![cfg(target_os = "windows")]

use crate::HardwareEnclave;
use scb_vka_common::error::{VaultError, VaultErrorKind};
use scb_vka_memory::SecureBuffer;
use sha3::{Digest, Sha3_512};
use std::ffi::c_void;
use tracing::{error, info, warn};
use windows_sys::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsi_Is_Tpm_Present, Tbsip_Context_Close, Tbsip_Submit_Command,
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_VERSION_ONE, TBS_SUCCESS,
};
use zeroize::Zeroize;

// =============================================================================
// TPM CONSTANTS
// =============================================================================

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;

const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_HMAC: u32 = 0x0000_0155;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RS_PW: u32 = 0x4000_0009;

const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_HMAC: u16 = 0x0005;

const TPM_RC_SUCCESS: u32 = 0;
const TPM_RC_BAD_AUTH: u32 = 0x0000_009A2;
const TPM_RC_AUTH_FAIL: u32 = 0x0000_0098E;

const TPM_HMAC_LEN: usize = 32;
const TBS_MAX_RESPONSE_SIZE: usize = 8192;
const TPM_MAX_COMMAND_SIZE: usize = 1024;

/// Domain separator for TPM HMAC operations (16 bytes, null-terminated)
const DOMAIN_SEPARATOR: &[u8; 16] = b"BLACKBOX_TPM_V1\0";

/// Domain separator for MR expansion
const MR_EXPANDER_DOMAIN: &[u8] = b"BLACKBOX_MR_EXPANDER";

/// TPMA_OBJECT flags for an HMAC signing key.
const OBJECT_ATTR_FIXED_TPM: u32 = 1 << 1;
const OBJECT_ATTR_FIXED_PARENT: u32 = 1 << 4;
const OBJECT_ATTR_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const OBJECT_ATTR_USER_WITH_AUTH: u32 = 1 << 6;
const OBJECT_ATTR_SIGN_ENCRYPT: u32 = 1 << 18;
const HMAC_OBJECT_ATTRIBUTES: u32 = OBJECT_ATTR_FIXED_TPM
    | OBJECT_ATTR_FIXED_PARENT
    | OBJECT_ATTR_SENSITIVE_DATA_ORIGIN
    | OBJECT_ATTR_USER_WITH_AUTH
    | OBJECT_ATTR_SIGN_ENCRYPT;

// =============================================================================
// TBS CONTEXT
// =============================================================================

struct TbsContext {
    handle: *mut c_void,
}

/// Memory-locked byte buffer with explicit logical length.
/// Backed by `SecureBuffer` to reduce swap exposure of sensitive payloads.
struct LockedBytes {
    inner: SecureBuffer,
    len: usize,
}

impl LockedBytes {
    fn new(capacity: usize) -> Result<Self, VaultError> {
        Ok(Self {
            inner: SecureBuffer::new(capacity)?,
            len: 0,
        })
    }

    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        &self.inner[..self.len]
    }

    fn as_mut_full(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }

    fn set_len(&mut self, len: usize) -> Result<(), VaultError> {
        if len > self.inner.len() {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        self.len = len;
        Ok(())
    }

    fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), VaultError> {
        let end = self
            .len
            .checked_add(data.len())
            .ok_or_else(|| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
        if end > self.inner.len() {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        self.inner.as_mut_slice()[self.len..end].copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), VaultError> {
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
        if end > self.len {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        self.inner.as_mut_slice()[offset..end].copy_from_slice(data);
        Ok(())
    }
}

impl TbsContext {
    fn new() -> Result<Self, VaultError> {
        let params = TBS_CONTEXT_PARAMS {
            // Version one avoids requiring TBS_CONTEXT_PARAMS2 packing.
            version: TBS_CONTEXT_VERSION_ONE,
        };
        let mut handle: *mut c_void = std::ptr::null_mut();

        let status = unsafe {
            // SAFETY: `params` and `handle` are valid pointers for this call.
            Tbsi_Context_Create(&params as *const TBS_CONTEXT_PARAMS, &mut handle as *mut _)
        };
        if status != TBS_SUCCESS || handle.is_null() {
            error!("Tbsi_Context_Create failed with status: {status:#010x}");
            return Err(VaultError::new(VaultErrorKind::HardwareUnavailable));
        }

        Ok(Self { handle })
    }

    fn submit_command(&self, command: &[u8]) -> Result<LockedBytes, VaultError> {
        let command_size = u32::try_from(command.len())
            .map_err(|_| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
        let mut response = LockedBytes::new(TBS_MAX_RESPONSE_SIZE)?;
        let mut response_len = u32::try_from(response.as_mut_full().len())
            .map_err(|_| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

        let status = unsafe {
            // SAFETY: `self.handle` is a valid context created by TBS, input/output buffers
            // are valid and sized per provided lengths.
            Tbsip_Submit_Command(
                self.handle as *const c_void,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command_size,
                response.as_mut_full().as_mut_ptr(),
                &mut response_len as *mut u32,
            )
        };

        if status != TBS_SUCCESS {
            error!("Tbsip_Submit_Command failed with status: {status:#010x}");
            return Err(VaultError::new(VaultErrorKind::HardwareUnavailable));
        }

        let response_len_usize = usize::try_from(response_len)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        if response_len_usize > response.as_mut_full().len() || response_len_usize < 10 {
            return Err(VaultError::new(VaultErrorKind::OperationFailed));
        }
        response.set_len(response_len_usize)?;

        Ok(response)
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let _ = unsafe {
                // SAFETY: `handle` was created by TBS and is closed exactly once here.
                Tbsip_Context_Close(self.handle as *const c_void)
            };
            self.handle = std::ptr::null_mut();
        }
    }
}

// =============================================================================
// WINDOWS TPM ENCLAVE
// =============================================================================

pub struct WindowsTpmEnclave;

impl WindowsTpmEnclave {
    pub fn new() -> Self {
        Self
    }

    fn is_tpm_present() -> bool {
        let present = unsafe {
            // SAFETY: TBS performs its own internal checks and this call has no pointer args.
            Tbsi_Is_Tpm_Present()
        };
        present != 0
    }

    fn execute_tpm_hmac(&self, ur: &[u8; 64]) -> Result<[u8; 64], VaultError> {
        if !Self::is_tpm_present() {
            return Err(VaultError::new(VaultErrorKind::HardwareUnavailable));
        }

        let context = TbsContext::new()?;
        let key_handle = self.create_primary_hmac_key(&context)?;
        let result = self.do_hmac_operation(&context, key_handle, ur);

        if let Err(e) = self.flush_context(&context, key_handle) {
            warn!("Failed to flush TPM key handle (non-fatal): {:?}", e.kind);
        }

        result
    }

    fn create_primary_hmac_key(&self, context: &TbsContext) -> Result<u32, VaultError> {
        let command = build_create_primary_command()?;
        let response = context.submit_command(command.as_slice())?;
        parse_create_primary_response(response.as_slice())
    }

    fn do_hmac_operation(
        &self,
        context: &TbsContext,
        key_handle: u32,
        ur: &[u8; 64],
    ) -> Result<[u8; 64], VaultError> {
        let command = build_hmac_command(key_handle, ur)?;
        let response = context.submit_command(command.as_slice())?;
        let hmac = parse_hmac_response(response.as_slice())?;

        let mut expander = Sha3_512::new();
        expander.update(MR_EXPANDER_DOMAIN);
        expander.update(hmac);
        let mut expanded = expander.finalize();

        let mut mr = [0u8; 64];
        mr.copy_from_slice(&expanded);
        expanded.zeroize();
        Ok(mr)
    }

    fn flush_context(&self, context: &TbsContext, handle: u32) -> Result<(), VaultError> {
        let command = build_flush_context_command(handle)?;
        let response = context.submit_command(command.as_slice())?;
        parse_generic_success(response.as_slice())
    }

    fn probe_tpm(&self) -> Result<(), VaultError> {
        if !Self::is_tpm_present() {
            return Err(VaultError::new(VaultErrorKind::HardwareUnavailable));
        }
        let context = TbsContext::new()?;
        let handle = self.create_primary_hmac_key(&context)?;
        self.flush_context(&context, handle)?;
        Ok(())
    }
}

impl Default for WindowsTpmEnclave {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareEnclave for WindowsTpmEnclave {
    fn sign_with_hardware_key(&self, ur: &[u8; 64]) -> Result<[u8; 64], VaultError> {
        self.execute_tpm_hmac(ur)
    }

    fn provider_name(&self) -> &'static str {
        "TPM 2.0 (Windows TBS)"
    }

    fn init_hardware_keys(&self) -> Result<(), VaultError> {
        self.probe_tpm()
    }

    fn has_hardware_key(&self) -> bool {
        self.probe_tpm().is_ok()
    }

    fn clear_hardware_keys(&self) -> Result<(), VaultError> {
        info!("Windows TPM primary keys are transient; no app-persistent key to delete.");
        Ok(())
    }
}

static_assertions::assert_impl_all!(WindowsTpmEnclave: Send, Sync);

// =============================================================================
// TPM COMMAND ENCODING
// =============================================================================

fn build_create_primary_command() -> Result<LockedBytes, VaultError> {
    let mut command = LockedBytes::new(TPM_MAX_COMMAND_SIZE)?;
    command.extend_from_slice(&[0u8; 10])?;

    push_u32(&mut command, TPM_RH_OWNER)?;
    append_empty_pw_auth_area(&mut command)?;

    // inSensitive: TPM2B_SENSITIVE_CREATE with empty userAuth and data
    push_u16(&mut command, 4)?;
    push_u16(&mut command, 0)?;
    push_u16(&mut command, 0)?;

    // inPublic: TPM2B_PUBLIC for keyed-hash HMAC key
    // public area length: 16 bytes
    push_u16(&mut command, 16)?;
    push_u16(&mut command, TPM_ALG_KEYEDHASH)?;
    push_u16(&mut command, TPM_ALG_SHA256)?;
    push_u32(&mut command, HMAC_OBJECT_ATTRIBUTES)?;
    push_u16(&mut command, 0)?; // authPolicy: TPM2B_DIGEST empty
    push_u16(&mut command, TPM_ALG_HMAC)?;
    push_u16(&mut command, TPM_ALG_SHA256)?;
    push_u16(&mut command, 0)?; // unique: TPM2B_DIGEST empty

    // outsideInfo: empty TPM2B_DATA
    push_u16(&mut command, 0)?;
    // creationPCR: TPML_PCR_SELECTION count = 0
    push_u32(&mut command, 0)?;

    finalize_command_header(&mut command, TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY)?;
    Ok(command)
}

fn build_hmac_command(key_handle: u32, ur: &[u8; 64]) -> Result<LockedBytes, VaultError> {
    let mut command = LockedBytes::new(TPM_MAX_COMMAND_SIZE)?;
    command.extend_from_slice(&[0u8; 10])?;

    push_u32(&mut command, key_handle)?;
    append_empty_pw_auth_area(&mut command)?;

    let input_len = u16::try_from(DOMAIN_SEPARATOR.len() + ur.len())
        .map_err(|_| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
    push_u16(&mut command, input_len)?;
    command.extend_from_slice(DOMAIN_SEPARATOR)?;
    command.extend_from_slice(ur)?;

    // hashAlg
    push_u16(&mut command, TPM_ALG_SHA256)?;

    finalize_command_header(&mut command, TPM_ST_SESSIONS, TPM_CC_HMAC)?;
    Ok(command)
}

fn build_flush_context_command(handle: u32) -> Result<LockedBytes, VaultError> {
    let mut command = LockedBytes::new(32)?;
    command.extend_from_slice(&[0u8; 10])?;
    push_u32(&mut command, handle)?;
    finalize_command_header(&mut command, TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT)?;
    Ok(command)
}

fn append_empty_pw_auth_area(command: &mut LockedBytes) -> Result<(), VaultError> {
    // authorizationSize (u32): TPMS_AUTH_COMMAND length for password session.
    // TPMS_AUTH_COMMAND = sessionHandle(4) + nonce(2) + sessionAttrs(1) + hmac(2) = 9 bytes.
    push_u32(command, 9)?;
    push_u32(command, TPM_RS_PW)?;
    push_u16(command, 0)?; // nonce size
    push_u8(command, 0)?; // session attributes
    push_u16(command, 0)?; // hmac size
    Ok(())
}

fn finalize_command_header(
    command: &mut LockedBytes,
    tag: u16,
    command_code: u32,
) -> Result<(), VaultError> {
    let total_size = u32::try_from(command.len())
        .map_err(|_| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
    command.write_at(0, &tag.to_be_bytes())?;
    command.write_at(2, &total_size.to_be_bytes())?;
    command.write_at(6, &command_code.to_be_bytes())?;
    Ok(())
}

fn parse_create_primary_response(response: &[u8]) -> Result<u32, VaultError> {
    let (_tag, _size, rc) = parse_response_header(response)?;
    if rc != TPM_RC_SUCCESS {
        return Err(VaultError::new(map_tpm_rc(rc)));
    }
    if response.len() < 14 {
        return Err(VaultError::new(VaultErrorKind::OperationFailed));
    }
    let handle = read_u32(response, 10)?;
    if handle == 0 {
        return Err(VaultError::new(VaultErrorKind::OperationFailed));
    }
    Ok(handle)
}

fn parse_hmac_response(response: &[u8]) -> Result<[u8; TPM_HMAC_LEN], VaultError> {
    let (tag, _size, rc) = parse_response_header(response)?;
    if rc != TPM_RC_SUCCESS {
        return Err(VaultError::new(map_tpm_rc(rc)));
    }

    let mut offset = 10usize;
    if tag == TPM_ST_SESSIONS {
        let _param_size = read_u32(response, offset)?;
        offset += 4;
    }

    let digest_len = usize::from(read_u16(response, offset)?);
    offset += 2;
    if digest_len != TPM_HMAC_LEN || response.len() < offset + digest_len {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    let mut digest = [0u8; TPM_HMAC_LEN];
    digest.copy_from_slice(&response[offset..offset + digest_len]);
    Ok(digest)
}

fn parse_generic_success(response: &[u8]) -> Result<(), VaultError> {
    let (_tag, _size, rc) = parse_response_header(response)?;
    if rc == TPM_RC_SUCCESS {
        Ok(())
    } else {
        Err(VaultError::new(map_tpm_rc(rc)))
    }
}

fn parse_response_header(response: &[u8]) -> Result<(u16, u32, u32), VaultError> {
    if response.len() < 10 {
        return Err(VaultError::new(VaultErrorKind::OperationFailed));
    }
    let tag = read_u16(response, 0)?;
    let size = read_u32(response, 2)?;
    let rc = read_u32(response, 6)?;
    if usize::try_from(size).unwrap_or(0) > response.len() {
        return Err(VaultError::new(VaultErrorKind::OperationFailed));
    }
    Ok((tag, size, rc))
}

fn map_tpm_rc(rc: u32) -> VaultErrorKind {
    match rc {
        TPM_RC_AUTH_FAIL | TPM_RC_BAD_AUTH => VaultErrorKind::AuthenticationFailed,
        _ => VaultErrorKind::OperationFailed,
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, VaultError> {
    if data.len() < offset + 2 {
        return Err(VaultError::new(VaultErrorKind::OperationFailed));
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, VaultError> {
    if data.len() < offset + 4 {
        return Err(VaultError::new(VaultErrorKind::OperationFailed));
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn push_u8(buf: &mut LockedBytes, v: u8) -> Result<(), VaultError> {
    buf.extend_from_slice(&[v])
}

fn push_u16(buf: &mut LockedBytes, v: u16) -> Result<(), VaultError> {
    buf.extend_from_slice(&v.to_be_bytes())
}

fn push_u32(buf: &mut LockedBytes, v: u32) -> Result<(), VaultError> {
    buf.extend_from_slice(&v.to_be_bytes())
}
