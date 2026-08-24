//! Session teardown and erase, against the real TPM core.
//!
//! Runs as its own test binary so it gets a private TPM singleton: it
//! deliberately destroys and re-manufactures the TPM, which would break the
//! other TPM tests if they shared the process.

use ashen_fw::tpm;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;

const CC_STARTUP: u32 = 0x0000_0144;
const CC_READ_PUBLIC: u32 = 0x0000_0173;
const CC_CREATE_PRIMARY: u32 = 0x0000_0131;

const SU_CLEAR: u16 = 0x0000;
const RC_SUCCESS: u32 = 0x0000_0000;
const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;
const TPM_RS_PW: u32 = 0x4000_0009;

struct Response {
    code: u32,
    body: Vec<u8>,
}

fn run(tag: u16, cc: u32, params: &[u8]) -> Response {
    let mut cmd = Vec::with_capacity(10 + params.len());
    cmd.extend_from_slice(&tag.to_be_bytes());
    cmd.extend_from_slice(&((10 + params.len()) as u32).to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(params);

    let rsp = tpm::process(&cmd).expect("TPM refused to process the command");
    assert!(rsp.len() >= 10, "response shorter than a TPM header");
    assert_eq!(
        u32::from_be_bytes(rsp[2..6].try_into().unwrap()) as usize,
        rsp.len()
    );
    Response {
        code: u32::from_be_bytes(rsp[6..10].try_into().unwrap()),
        body: rsp[10..].to_vec(),
    }
}

fn startup() {
    let rsp = run(ST_NO_SESSIONS, CC_STARTUP, &SU_CLEAR.to_be_bytes());
    assert_eq!(rsp.code, RC_SUCCESS, "TPM2_Startup failed");
}

/// TPMT_PUBLIC for an ECDSA P-256 signing primary, wrapped as a TPM2B.
fn ecc_signing_template() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&0x0023u16.to_be_bytes()); // TPM_ALG_ECC
    t.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg SHA-256
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

/// Creates the endorsement-hierarchy primary. Returns its transient handle and
/// the rest of the response, which carries the public area.
fn create_endorsement_primary() -> (u32, Vec<u8>) {
    let mut params = Vec::new();
    params.extend_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes());

    let mut auth = Vec::new();
    auth.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes()); // nonce
    auth.push(0); // sessionAttributes
    auth.extend_from_slice(&0u16.to_be_bytes()); // hmac
    params.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    params.extend_from_slice(&auth);

    params.extend_from_slice(&4u16.to_be_bytes()); // inSensitive
    params.extend_from_slice(&0u16.to_be_bytes());
    params.extend_from_slice(&0u16.to_be_bytes());

    params.extend_from_slice(&ecc_signing_template());
    params.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo
    params.extend_from_slice(&0u32.to_be_bytes()); // creationPCR count

    let rsp = run(ST_SESSIONS, CC_CREATE_PRIMARY, &params);
    assert_eq!(
        rsp.code, RC_SUCCESS,
        "TPM2_CreatePrimary failed with 0x{:08X}",
        rsp.code
    );
    let handle = u32::from_be_bytes(rsp.body[..4].try_into().unwrap());
    (handle, rsp.body[4..].to_vec())
}

fn read_public(handle: u32) -> u32 {
    run(ST_NO_SESSIONS, CC_READ_PUBLIC, &handle.to_be_bytes()).code
}

/// One sequential test because it walks the TPM through a fixed lifecycle:
/// a session teardown must keep the identity while dropping transient state,
/// and an erase must replace the identity outright.
#[test]
fn teardown_keeps_the_identity_and_erase_replaces_it() {
    tpm::init().expect("fwTPM failed to initialise");
    startup();

    let (handle, ek) = create_endorsement_primary();
    assert_eq!(
        read_public(handle),
        RC_SUCCESS,
        "the freshly created primary is not loaded"
    );

    // Session teardown: transient handles go, the endorsement key stays.
    tpm::reset_client();
    assert_ne!(
        read_public(handle),
        RC_SUCCESS,
        "a transient handle survived FWTPM_ResetCommandClient"
    );

    let (_, ek_after_teardown) = create_endorsement_primary();
    assert_eq!(
        ek, ek_after_teardown,
        "the endorsement key changed across a session teardown"
    );

    // Erase: new hierarchy seeds, so a genuinely different endorsement key.
    tpm::reinit().expect("TPM re-manufacture failed");
    startup();

    let (_, ek_after_erase) = create_endorsement_primary();
    assert_ne!(
        ek, ek_after_erase,
        "the endorsement key survived an erase"
    );
}
