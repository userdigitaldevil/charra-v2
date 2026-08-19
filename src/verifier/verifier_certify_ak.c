/**
 * @file verifier_certify_ak.c
 * @brief See verifier_certify_ak.h.
 *
 * The pending-challenge table lives here rather than in verifier.c: it is
 * the one piece of state only this handshake touches, and keeping it next
 * to the two legs that read and clear it is what makes the single-use
 * property checkable by reading one file.
 */

#include "verifier_certify_ak.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_ak_state.h"
#include "../core/charra_dto.h"
#include "../core/charra_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "../util/crypto_util.h"
#include "../util/hex_util.h"
#include "../util/io_util.h"
#include "../util/tpm2_util.h"
#include "verifier_shared.h"
#include "verifier_util.h"

#define LOG_NAME "verifier"

/* --- /certify_ak pending challenges -------------------------------------
 *
 * What CHALLENGE handed out and CONFIRM must match. Kept in memory only:
 * a handshake spans seconds, and a Verifier restart mid-flight just makes
 * the requester retry. Small table rather than one slot because the RP's
 * own handshake and one relayed for the Attester can overlap. */
#define CERTIFY_AK_MAX_PENDING 8
#define CERTIFY_AK_PENDING_TTL_SECONDS 60

typedef struct {
    bool in_use;
    uint8_t ek_fingerprint[32];
    uint8_t secret[CHARRA_CERTIFY_AK_SECRET_LEN];
    /* The key/name bound into this challenge. CONFIRM certifies THESE, not
     * anything it re-supplies, so a leaked secret can't be redirected. */
    uint32_t ak_public_key_len;
    uint8_t ak_public_key[sizeof(TPM2B_PUBLIC)];
    uint32_t ak_name_len;
    uint8_t ak_name[sizeof(TPM2B_NAME)];
    /* CHARRA_CERTIFY_AK_SUBJECT_* -- which ledger CONFIRM records the
     * issuance in, bound at CHALLENGE time for the same reason as the key/
     * name above: CONFIRM re-sending a different subject can't redirect a
     * proven RP identity into the Attester's ledger or vice versa. */
    uint32_t subject;
    time_t expires_at;
} certify_ak_pending_challenge;

static certify_ak_pending_challenge
        certify_ak_pending[CERTIFY_AK_MAX_PENDING] = {0};

/** Maps a CHARRA_CERTIFY_AK_SUBJECT_* value to its ledger path. Returns NULL
 * for anything else -- callers must reject the request in that case rather
 * than guess which ledger was meant. */
static const char* certify_ak_state_path_for_subject(uint32_t subject) {
    switch (subject) {
    case CHARRA_CERTIFY_AK_SUBJECT_RP:
        return rp_ak_state_file_path;
    case CHARRA_CERTIFY_AK_SUBJECT_ATTESTER:
        return attester_ak_state_file_path;
    default:
        return NULL;
    }
}

/** Human-readable subject name for log lines -- shares the same switch as
 * certify_ak_state_path_for_subject() above so a new subject can't be added
 * to one without the other being noticed. */
static const char* certify_ak_subject_name(uint32_t subject) {
    switch (subject) {
    case CHARRA_CERTIFY_AK_SUBJECT_RP:
        return "RP";
    case CHARRA_CERTIFY_AK_SUBJECT_ATTESTER:
        return "Attester (relayed)";
    default:
        return "unknown";
    }
}

/** Constant-time equality -- the secret is a shared authenticator, so its
 * comparison must not leak how far it matched. */
static bool constant_time_equal(
        const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/** Stores a challenge, replacing any prior one for the same identity (a
 * fresh CHALLENGE abandons whatever the requester didn't finish). */
static void certify_ak_pending_store(
        const certify_ak_pending_challenge* challenge) {
    time_t now = time(NULL);
    int slot = -1;
    for (int i = 0; i < CERTIFY_AK_MAX_PENDING; i++) {
        if (certify_ak_pending[i].in_use &&
                memcmp(certify_ak_pending[i].ek_fingerprint,
                        challenge->ek_fingerprint, 32) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) { /* else a free or expired slot */
        for (int i = 0; i < CERTIFY_AK_MAX_PENDING; i++) {
            if (!certify_ak_pending[i].in_use ||
                    certify_ak_pending[i].expires_at <= now) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        slot = 0; /* table full of live challenges: evict the oldest */
        for (int i = 1; i < CERTIFY_AK_MAX_PENDING; i++) {
            if (certify_ak_pending[i].expires_at <
                    certify_ak_pending[slot].expires_at) {
                slot = i;
            }
        }
    }
    certify_ak_pending[slot] = *challenge;
    certify_ak_pending[slot].in_use = true;
}

/** Single-use lookup: a matching challenge is copied out and cleared, so
 * neither a replay nor a retry after a wrong guess can reuse it. */
static bool certify_ak_pending_take(
        const uint8_t ek_fingerprint[32], certify_ak_pending_challenge* out) {
    time_t now = time(NULL);
    for (int i = 0; i < CERTIFY_AK_MAX_PENDING; i++) {
        if (!certify_ak_pending[i].in_use ||
                memcmp(certify_ak_pending[i].ek_fingerprint, ek_fingerprint,
                        32) != 0) {
            continue;
        }
        bool expired = certify_ak_pending[i].expires_at <= now;
        *out = certify_ak_pending[i];
        memset(&certify_ak_pending[i], 0, sizeof(certify_ak_pending[i]));
        return !expired;
    }
    return false;
}

/**
 * @brief /certify_ak CHALLENGE leg: validate the requester's EK
 * certificate, then hand back a fresh random secret wrapped via
 * Esys_MakeCredential against that EK/AK pair. Deliberately signs nothing
 * and records nothing -- an unanswered challenge leaves no trace.
 */
static CHARRA_RC certify_ak_do_challenge(const msg_certify_ak_request_dto* req,
        uint8_t** marshaled_out, uint32_t* marshaled_len_out,
        coap_pdu_code_t* response_code_out) {
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    TSS2_RC tss_r = 0;

    char* manufacturer_root_der = NULL;
    size_t manufacturer_root_der_len = 0;
    mbedtls_x509_crt ek_leaf_cert;
    bool ek_leaf_cert_inited = false;

    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    TPM2B_ID_OBJECT* credential_blob = NULL;
    TPM2B_ENCRYPTED_SECRET* wrapped_secret = NULL;

    if (certify_ak_state_path_for_subject(req->subject) == NULL) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: unrecognized subject %u.",
                req->subject);
        *response_code_out = COAP_RESPONSE_CODE_BAD_REQUEST;
        return CHARRA_RC_BAD_ARGUMENT;
    }

    if ((charra_r = charra_io_read_file(manufacturer_root_cert_path,
                 &manufacturer_root_der, &manufacturer_root_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME
                         "] /certify_ak: could not read manufacturer root "
                         "certificate ('%s').",
                manufacturer_root_cert_path);
        goto cleanup;
    }

    if ((charra_r = charra_crypto_verify_x509_cert_chain(req->ek_certificate,
                 req->ek_certificate_len, (uint8_t*)manufacturer_root_der,
                 manufacturer_root_der_len, &ek_leaf_cert)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: EK certificate did "
                         "NOT verify against the manufacturer root.");
        *response_code_out = COAP_RESPONSE_CODE_UNAUTHORIZED;
        goto cleanup;
    }
    ek_leaf_cert_inited = true;
    charra_log_info("[" LOG_NAME "] /certify_ak: EK certificate verified.");
    charra_crypto_log_cert_summary("requester's EK cert", &ek_leaf_cert);

    /* Esys_MakeCredential needs more than the bare RSA key the cert carries */
    TPM2B_PUBLIC ek_public_key = {0};
    if ((charra_r = charra_crypto_build_ek_tpm2b_public_from_cert(
                 &ek_leaf_cert, &ek_public_key)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not "
                         "reconstruct EK TPM2B_PUBLIC from certificate.");
        *response_code_out = COAP_RESPONSE_CODE_UNAUTHORIZED;
        goto cleanup;
    }

    certify_ak_pending_challenge challenge = {0};
    if ((charra_r = charra_random_bytes(sizeof(challenge.secret),
                 challenge.secret)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not generate secret.");
        goto cleanup;
    }
    if ((charra_r = hash_sha256(req->ek_certificate_len, req->ek_certificate,
                 challenge.ek_fingerprint)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not hash EK certificate.");
        goto cleanup;
    }
    challenge.ak_public_key_len = req->ak_public_key_len;
    memcpy(challenge.ak_public_key, req->ak_public_key,
            req->ak_public_key_len);
    challenge.ak_name_len = req->ak_name_len;
    memcpy(challenge.ak_name, req->ak_name, req->ak_name_len);
    challenge.subject = req->subject;
    challenge.expires_at = time(NULL) + CERTIFY_AK_PENDING_TTL_SECONDS;

    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Tss2_TctiLdr_Initialize.");
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: Esys_Initialize.");
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }

    TPM2B_DIGEST credential = {0};
    credential.size = sizeof(challenge.secret);
    memcpy(credential.buffer, challenge.secret, sizeof(challenge.secret));

    if ((charra_r = charra_tpm_make_credential_for_ak(esys_ctx, &ek_public_key,
                 (TPM2B_NAME*)req->ak_name, &credential, &credential_blob,
                 &wrapped_secret)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Esys_MakeCredential failed.");
        goto cleanup;
    }

    msg_certify_ak_response_dto resp = {0};
    resp.credential_blob_len = sizeof(*credential_blob);
    memcpy(resp.credential_blob, credential_blob, resp.credential_blob_len);
    resp.wrapped_secret_len = sizeof(*wrapped_secret);
    memcpy(resp.wrapped_secret, wrapped_secret, resp.wrapped_secret_len);

    if ((charra_r = charra_marshal_certify_ak_response(
                 &resp, marshaled_len_out, marshaled_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME
                         "] /certify_ak: could not marshal CHALLENGE.");
        goto cleanup;
    }

    certify_ak_pending_store(&challenge);
    {
        char fingerprint_hex[17] = {0};
        charra_hex_encode_prefix(challenge.ek_fingerprint, sizeof(challenge.ek_fingerprint),
                fingerprint_hex, sizeof(fingerprint_hex));
        charra_log_info("[" LOG_NAME "] /certify_ak: CHALLENGE issued to "
                        "identity %s... (subject=%s, valid %ds); awaiting "
                        "CONFIRM.",
                fingerprint_hex, certify_ak_subject_name(req->subject),
                CERTIFY_AK_PENDING_TTL_SECONDS);
    }
    *response_code_out = COAP_RESPONSE_CODE_CONTENT;
    charra_r = CHARRA_RC_SUCCESS;

cleanup:
    if (credential_blob != NULL) {
        Esys_Free(credential_blob);
    }
    if (wrapped_secret != NULL) {
        Esys_Free(wrapped_secret);
    }
    if (esys_ctx != NULL) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }
    if (ek_leaf_cert_inited) {
        mbedtls_x509_crt_free(&ek_leaf_cert);
    }
    charra_io_free_file_buffer(&manufacturer_root_der);
    return charra_r;
}

/**
 * @brief /certify_ak CONFIRM leg: match the echoed secret against the
 * pending challenge and only then sign, record, and release the
 * certificate. Needs no TPM -- the proof was produced by the requester's.
 */
static CHARRA_RC certify_ak_do_confirm(const msg_certify_ak_request_dto* req,
        uint8_t** marshaled_out, uint32_t* marshaled_len_out,
        coap_pdu_code_t* response_code_out) {
    CHARRA_RC charra_r = CHARRA_RC_ERROR;

    char* verifier_ca_cert_der = NULL;
    size_t verifier_ca_cert_der_len = 0;
    mbedtls_x509_crt verifier_ca_cert;
    bool verifier_ca_cert_inited = false;
    uint8_t* ak_cert_der = NULL;
    uint32_t ak_cert_der_len = 0;

    uint8_t ek_fingerprint[32] = {0};
    if ((charra_r = hash_sha256(req->ek_certificate_len, req->ek_certificate,
                 ek_fingerprint)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not hash EK certificate.");
        goto cleanup;
    }
    char ek_fingerprint_hex[17] = {0};
    charra_hex_encode_prefix(ek_fingerprint, sizeof(ek_fingerprint), ek_fingerprint_hex,
            sizeof(ek_fingerprint_hex));

    certify_ak_pending_challenge challenge = {0};
    if (!certify_ak_pending_take(ek_fingerprint, &challenge)) {
        charra_log_error("[" LOG_NAME "] /certify_ak: CONFIRM from identity "
                         "%s... has no live challenge (never issued, already "
                         "used, or expired).",
                ek_fingerprint_hex);
        *response_code_out = COAP_RESPONSE_CODE_UNAUTHORIZED;
        charra_r = CHARRA_RC_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (req->secret_len != sizeof(challenge.secret) ||
            !constant_time_equal(
                    req->secret, challenge.secret, sizeof(challenge.secret))) {
        charra_log_error("[" LOG_NAME "] /certify_ak: CONFIRM from identity "
                         "%s... did NOT echo the challenge secret -- this "
                         "requester does not hold the EK/AK it claims. "
                         "Nothing signed, nothing revoked.",
                ek_fingerprint_hex);
        *response_code_out = COAP_RESPONSE_CODE_UNAUTHORIZED;
        charra_r = CHARRA_RC_VERIFICATION_FAILED;
        goto cleanup;
    }
    charra_log_info("[" LOG_NAME "] /certify_ak: CONFIRM from identity %s... "
                    "echoed the correct secret (ActivateCredential proves "
                    "TPM possession); issuing certificate (subject=%s).",
            ek_fingerprint_hex, certify_ak_subject_name(challenge.subject));

    /* Ledger this issuance belongs in -- taken from the CHALLENGE-time
     * binding above, not anything req (CONFIRM) itself carries. Already
     * validated at CHALLENGE time, so NULL here would mean state corruption
     * (or a pending-challenge struct that predates this field), not
     * attacker input -- checked anyway, since silently falling back to
     * either ledger would be exactly the kind of cross-identity mixup this
     * whole change exists to prevent. */
    const char* subject_ak_state_file_path =
            certify_ak_state_path_for_subject(challenge.subject);
    if (subject_ak_state_file_path == NULL) {
        charra_log_error("[" LOG_NAME "] /certify_ak: CONFIRM from identity "
                         "%s... has an unrecognized subject %u bound into "
                         "its pending challenge -- refusing to guess which "
                         "ledger to use.",
                ek_fingerprint_hex, challenge.subject);
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* --- sign, for the key bound into the challenge --- */
    if ((charra_r = charra_io_read_file(verifier_ca_cert_path,
                 &verifier_ca_cert_der, &verifier_ca_cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not read "
                         "Verifier CA certificate ('%s').",
                verifier_ca_cert_path);
        goto cleanup;
    }
    mbedtls_x509_crt_init(&verifier_ca_cert);
    verifier_ca_cert_inited = true;
    if (mbedtls_x509_crt_parse(&verifier_ca_cert,
                (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len) !=
            0) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not parse "
                         "Verifier CA certificate.");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    char verifier_ca_subject_name[256] = {0};
    if (mbedtls_x509_dn_gets(verifier_ca_subject_name,
                sizeof(verifier_ca_subject_name),
                &verifier_ca_cert.subject) <= 0) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not read "
                         "Verifier CA subject name.");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    /* Validity runs from now, so every issuance gets the full window. */
    time_t ak_cert_issued_at = time(NULL);
    time_t ak_cert_expires_at = ak_cert_issued_at + ak_cert_validity_seconds;
    char ak_cert_not_before_utc[15] = {0};
    char ak_cert_not_after_utc[15] = {0};
    if (!charra_crypto_format_utc_yyyymmddhhmmss(
                ak_cert_issued_at, ak_cert_not_before_utc) ||
            !charra_crypto_format_utc_yyyymmddhhmmss(
                    ak_cert_expires_at, ak_cert_not_after_utc)) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not format AK "
                         "certificate validity window.");
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }

    uint8_t ak_cert_serial[CHARRA_AK_STATE_SERIAL_LEN] = {0};
    if ((charra_r = charra_crypto_sign_ak_certificate(
                 (TPM2B_PUBLIC*)challenge.ak_public_key, "CN=CHARRA AK",
                 verifier_ca_subject_name, ak_cert_not_before_utc,
                 ak_cert_not_after_utc, verifier_ca_key_path, &ak_cert_der,
                 &ak_cert_der_len, ak_cert_serial)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not sign AK certificate.");
        goto cleanup;
    }
    charra_log_info(
            "[" LOG_NAME "] /certify_ak: AK certificate signed (%u bytes).",
            ak_cert_der_len);

    msg_certify_ak_response_dto resp = {0};
    resp.ak_certificate_len = ak_cert_der_len;
    resp.ak_certificate = ak_cert_der;
    if ((charra_r = charra_marshal_certify_ak_response(
                 &resp, marshaled_len_out, marshaled_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not marshal CONFIRM.");
        goto cleanup;
    }

    /* --- record the issuance, revoking any prior one for this identity.
     * Only reachable past the proof above, so a request that can't answer
     * the challenge can no longer revoke a working certificate. */
    /* ak_cert_expires_at is already the exact value stamped into the
     * certificate above -- no need to parse the string back out. */
    {
        charra_ak_state_record* existing_records = NULL;
        uint32_t existing_count = 0;
        if (charra_ak_state_load(subject_ak_state_file_path, &existing_records,
                    &existing_count) == CHARRA_RC_SUCCESS) {
            uint32_t existing_index = 0;
            if (charra_ak_state_find_by_ek_fingerprint(existing_records,
                        existing_count, ek_fingerprint, &existing_index)) {
                char prev_serial_hex[33] = {0};
                charra_hex_encode_prefix(existing_records[existing_index].serial,
                        sizeof(existing_records[existing_index].serial),
                        prev_serial_hex, sizeof(prev_serial_hex));
                bool prev_was_valid = charra_ak_state_is_valid(
                        &existing_records[existing_index], time(NULL));
                charra_log_info(
                        "[" LOG_NAME "] /certify_ak: identity %s... has a "
                        "prior AK certificate on record (serial %s..., "
                        "%s) -- it will now be revoked in favor of the "
                        "fresh one.",
                        ek_fingerprint_hex, prev_serial_hex,
                        prev_was_valid ? "currently valid"
                                       : "already revoked/expired");
            } else {
                charra_log_info(
                        "[" LOG_NAME "] /certify_ak: identity %s... has no "
                        "prior AK certificate on record -- provisioning a "
                        "new identity.",
                        ek_fingerprint_hex);
            }
            free(existing_records);
        }
    }

    charra_ak_state_record ak_record = {0};
    memcpy(ak_record.ek_fingerprint, ek_fingerprint,
            sizeof(ak_record.ek_fingerprint));
    ak_record.ak_name_len = challenge.ak_name_len;
    memcpy(ak_record.ak_name, challenge.ak_name, challenge.ak_name_len);
    memcpy(ak_record.serial, ak_cert_serial, sizeof(ak_record.serial));
    ak_record.issued_at = time(NULL);
    ak_record.expires_at = ak_cert_expires_at;
    if ((charra_r = charra_ak_state_renew(subject_ak_state_file_path,
                 ek_fingerprint, &ak_record)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not record "
                         "issuance in AK-provisioning state.");
        goto cleanup;
    }
    {
        char new_serial_hex[33] = {0};
        charra_hex_encode_prefix(ak_cert_serial, sizeof(ak_cert_serial), new_serial_hex,
                sizeof(new_serial_hex));
        charra_log_info(
                "[" LOG_NAME "] /certify_ak: identity %s...: new AK "
                "certificate recorded (serial %s..., expires at %ld).",
                ek_fingerprint_hex, new_serial_hex, (long)ak_cert_expires_at);
    }

    *response_code_out = COAP_RESPONSE_CODE_CONTENT;
    charra_r = CHARRA_RC_SUCCESS;

cleanup:
    if (charra_r != CHARRA_RC_SUCCESS) {
        free(*marshaled_out);
        *marshaled_out = NULL;
        *marshaled_len_out = 0;
    }
    free(ak_cert_der);
    if (verifier_ca_cert_inited) {
        mbedtls_x509_crt_free(&verifier_ca_cert);
    }
    charra_io_free_file_buffer(&verifier_ca_cert_der);
    return charra_r;
}

/**
 * @brief /certify_ak: dispatches the two legs of the credential-activation
 * handshake (see CHARRA_CERTIFY_AK_* in charra_dto.h). Unmarshals, routes
 * on `kind`, and sends whatever response the leg produced.
 */
void coap_certify_ak_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;

    charra_coap_log_peer_address(LOG_NAME, "/certify_ak", session);

    msg_certify_ak_request_dto req = {0};
    bool req_unmarshaled = false;
    uint8_t* marshaled_response = NULL;
    uint32_t marshaled_response_len = 0;

    size_t data_len = 0;
    const uint8_t* data = NULL;
    if (!charra_coap_get_payload(
                request, LOG_NAME, "/certify_ak", &data, &data_len, NULL)) {
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }
    charra_log_info(
            "[" LOG_NAME "] /certify_ak: received request of length %zu.",
            data_len);

    if ((charra_r = charra_unmarshal_certify_ak_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not parse CBOR request.");
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }
    req_unmarshaled = true;

    switch (req.kind) {
    case CHARRA_CERTIFY_AK_CHALLENGE:
        charra_r = certify_ak_do_challenge(
                &req, &marshaled_response, &marshaled_response_len,
                &response_code);
        break;
    case CHARRA_CERTIFY_AK_CONFIRM:
        charra_r = certify_ak_do_confirm(
                &req, &marshaled_response, &marshaled_response_len,
                &response_code);
        break;
    default:
        charra_log_error("[" LOG_NAME "] /certify_ak: unknown kind %u.",
                req.kind);
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        charra_r = CHARRA_RC_BAD_ARGUMENT;
        break;
    }
    if (charra_r != CHARRA_RC_SUCCESS) {
        goto cleanup;
    }

    coap_pdu_set_code(response, response_code);
    if ((coap_r = coap_add_data_large_response(resource, session, request,
                 response, query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                 marshaled_response_len, marshaled_response,
                 release_response_data, marshaled_response)) == 0) {
        charra_log_error("[" LOG_NAME "] /certify_ak: Error invoking "
                         "coap_add_data_large_response().");
        /* libcoap did not accept ownership -- still ours to free */
        free(marshaled_response);
    }
    marshaled_response = NULL;
    goto cleanup_success;

cleanup:
    coap_pdu_set_code(response, response_code);

cleanup_success:
    /* NULL on the success path (ownership transferred above). */
    free(marshaled_response);
    if (req_unmarshaled) {
        charra_free_if_not_null(req.ek_certificate);
    }
}
