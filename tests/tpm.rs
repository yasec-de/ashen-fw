//! Drives the real wolfTPM fwTPM core, compiled for the host, through the
//! same `ashen_fw::tpm` entry points the firmware uses.

use ashen_fw::tpm;

const ST_NO_SESSIONS: u16 = 0x8001;

const CC_STARTUP: u32 = 0x0000_0144;
const CC_SELF_TEST: u32 = 0x0000_0143;
const CC_GET_CAPABILITY: u32 = 0x0000_017A;
const CC_GET_RANDOM: u32 = 0x0000_017B;
const CC_PCR_READ: u32 = 0x0000_017E;
const CC_CREATE_PRIMARY: u32 = 0x0000_0131;

const SU_CLEAR: u16 = 0x0000;
const RC_SUCCESS: u32 = 0x0000_0000;

/// Builds a TPM 2.0 command packet: tag, size, command code, then parameters.
fn command(tag: u16, cc: u32, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + params.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&((10 + params.len()) as u32).to_be_bytes());
    out.extend_from_slice(&cc.to_be_bytes());
    out.extend_from_slice(params);
    out
}

struct Response {
    size: u32,
    code: u32,
    body: Vec<u8>,
}

fn parse(rsp: &[u8]) -> Response {
    assert!(rsp.len() >= 10, "response shorter than a TPM header: {rsp:?}");
    let size = u32::from_be_bytes(rsp[2..6].try_into().unwrap());
    let code = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    assert_eq!(
        size as usize,
        rsp.len(),
        "header size disagrees with the delivered length"
    );
    Response {
        size,
        code,
        body: rsp[10..].to_vec(),
    }
}

fn run(cc: u32, params: &[u8]) -> Response {
    let cmd = command(ST_NO_SESSIONS, cc, params);
    let rsp = tpm::process(&cmd).expect("TPM refused to process the command");
    parse(&rsp)
}

fn boot() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tpm::init().expect("fwTPM failed to initialise");
        let startup = run(CC_STARTUP, &SU_CLEAR.to_be_bytes());
        assert_eq!(startup.code, RC_SUCCESS, "TPM2_Startup failed");
    });
}

#[test]
fn reports_a_version_and_a_sane_context_size() {
    boot();
    assert!(!tpm::version().is_empty());
    // If the FFI were mislinked this would be zero or absurd.
    assert!(tpm::ffi::context_size() > 4096);
    assert_eq!(tpm::ffi::max_command_size(), 8192, "V185 buffer lift missing");
}

#[test]
fn self_test_passes() {
    boot();
    // fullTest = NO: run only what has not been tested yet.
    let rsp = run(CC_SELF_TEST, &[0u8]);
    assert_eq!(rsp.code, RC_SUCCESS, "TPM2_SelfTest failed");
}

#[test]
fn get_random_returns_the_requested_length_and_varies() {
    boot();

    let first = run(CC_GET_RANDOM, &16u16.to_be_bytes());
    assert_eq!(first.code, RC_SUCCESS);
    // TPM2B_DIGEST: a 2-byte size followed by that many bytes.
    let len = u16::from_be_bytes(first.body[..2].try_into().unwrap());
    assert_eq!(len, 16);
    assert_eq!(first.body.len(), 2 + 16);

    let second = run(CC_GET_RANDOM, &16u16.to_be_bytes());
    assert_ne!(
        first.body, second.body,
        "two GetRandom calls returned identical bytes"
    );
}

#[test]
fn get_capability_lists_commands() {
    boot();

    let mut params = Vec::new();
    params.extend_from_slice(&0x0000_0002u32.to_be_bytes()); // TPM_CAP_COMMANDS
    params.extend_from_slice(&0x0000_011Fu32.to_be_bytes()); // first command code
    params.extend_from_slice(&64u32.to_be_bytes()); // property count

    let rsp = run(CC_GET_CAPABILITY, &params);
    assert_eq!(rsp.code, RC_SUCCESS, "TPM2_GetCapability failed");
    assert!(rsp.size > 10, "capability response carried no payload");
}

#[test]
fn pcr_read_succeeds() {
    boot();

    // TPML_PCR_SELECTION: one SHA-256 selection over PCRs 0-7.
    let mut params = Vec::new();
    params.extend_from_slice(&1u32.to_be_bytes());
    params.extend_from_slice(&0x000Bu16.to_be_bytes()); // TPM_ALG_SHA256
    params.push(3); // sizeofSelect
    params.extend_from_slice(&[0x01, 0x00, 0x00]); // PCR 0

    let rsp = run(CC_PCR_READ, &params);
    assert_eq!(rsp.code, RC_SUCCESS, "TPM2_PCR_Read failed");
}

/// TPMT_PUBLIC for an ECDSA P-256 signing primary, wrapped as a TPM2B.
fn ecc_signing_template() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&0x0023u16.to_be_bytes()); // TPM_ALG_ECC
    t.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg SHA-256
    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
    t.extend_from_slice(&0x0004_0072u32.to_be_bytes());
    t.extend_from_slice(&0u16.to_be_bytes()); // empty authPolicy
    t.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric: TPM_ALG_NULL
    t.extend_from_slice(&0x0018u16.to_be_bytes()); // scheme: TPM_ALG_ECDSA
    t.extend_from_slice(&0x000Bu16.to_be_bytes()); // ecdsa hashAlg SHA-256
    t.extend_from_slice(&0x0003u16.to_be_bytes()); // TPM_ECC_NIST_P256
    t.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf: TPM_ALG_NULL
    t.extend_from_slice(&0u16.to_be_bytes()); // unique.x
    t.extend_from_slice(&0u16.to_be_bytes()); // unique.y

    let mut out = Vec::new();
    out.extend_from_slice(&(t.len() as u16).to_be_bytes());
    out.extend_from_slice(&t);
    out
}

fn create_primary() -> Response {
    let mut params = Vec::new();
    params.extend_from_slice(&0x4000_0001u32.to_be_bytes()); // TPM_RH_OWNER

    // Password session with an empty password.
    let mut auth = Vec::new();
    auth.extend_from_slice(&0x4000_0009u32.to_be_bytes()); // TPM_RS_PW
    auth.extend_from_slice(&0u16.to_be_bytes()); // nonce
    auth.push(0); // sessionAttributes
    auth.extend_from_slice(&0u16.to_be_bytes()); // hmac
    params.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    params.extend_from_slice(&auth);

    // inSensitive: empty userAuth, empty data.
    params.extend_from_slice(&4u16.to_be_bytes());
    params.extend_from_slice(&0u16.to_be_bytes());
    params.extend_from_slice(&0u16.to_be_bytes());

    params.extend_from_slice(&ecc_signing_template());
    params.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo
    params.extend_from_slice(&0u32.to_be_bytes()); // creationPCR count

    let cmd = command(0x8002, CC_CREATE_PRIMARY, &params); // ST_SESSIONS
    let rsp = tpm::process(&cmd).expect("TPM refused CreatePrimary");
    parse(&rsp)
}

/// The real exercise: ECC key generation inside the TPM, on the C heap and
/// wolfCrypt SP math, end to end.
#[test]
fn ecc_create_primary_generates_a_key() {
    boot();

    let rsp = create_primary();
    assert_eq!(
        rsp.code, RC_SUCCESS,
        "TPM2_CreatePrimary(ECC P-256) failed with 0x{:08X}",
        rsp.code
    );

    // Response: handle, paramSize, then TPM2B_PUBLIC among the rest. The
    // handle must be a transient object.
    let handle = u32::from_be_bytes(rsp.body[..4].try_into().unwrap());
    assert_eq!(
        handle & 0xFF00_0000,
        0x8000_0000,
        "expected a transient handle, got 0x{handle:08X}"
    );
}

/// Same hierarchy seed must yield the same primary key; that is what makes an
/// endorsement key stable for as long as the firmware stays powered.
#[test]
fn create_primary_is_deterministic_within_a_boot() {
    boot();

    let first = create_primary();
    let second = create_primary();
    assert_eq!(first.code, RC_SUCCESS);
    assert_eq!(second.code, RC_SUCCESS);

    // Skip the 4-byte handle, which differs per load; the public area must not.
    assert_eq!(
        first.body[4..],
        second.body[4..],
        "primary key derivation is not deterministic for a fixed seed"
    );
}

#[test]
fn oversized_commands_are_rejected_not_truncated() {
    boot();
    let huge = vec![0u8; tpm::ffi::max_command_size() + 1];
    assert_eq!(tpm::process(&huge), Err(tpm::Error::Oversized));
}

#[test]
fn malformed_commands_get_a_tpm_error_rather_than_a_panic() {
    boot();
    // A well-formed header naming a command code that does not exist.
    let rsp = run(0x0000_FFFF, &[]);
    assert_ne!(rsp.code, RC_SUCCESS);
}
