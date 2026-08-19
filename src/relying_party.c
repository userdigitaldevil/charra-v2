#include <coap3/coap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <tss2/tss2_tpm2_types.h>
#include <pthread.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "util/coap_util.h"
#include "util/crypto_util.h"
#include "util/io_util.h"
#include "rp/rp_attestation.h"
#include "rp/rp_attester_identity.h"
#include "rp/rp_identity.h"
#include "rp/rp_config.h"
#include "rp/rp_evidence.h"
#include "rp/rp_shared.h"

time_t rp_ak_renew_margin_s = RP_DEFAULT_AK_RENEW_MARGIN_S;
int rp_num_verifiers = RP_DEFAULT_NUM_VERIFIERS;

/* logging and coap config */
#define LOG_NAME "relying party"
coap_log_t coap_log_level = LOG_INFO;
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* trust manager config */
char trust_manager_host[16] = "127.0.0.1"; 
unsigned int trust_manager_port = 6000;
uint16_t trust_manager_response_timeout = 30;  
bool processing_trust_manager_response = false;

/* Sized to MAX_VERIFIERS -- the hard cap --verifiers is validated against
 * -- not to rp_num_verifiers, so a smaller run never risks overflowing this
 * array. Every per-Verifier array below is sized the same way for the same
 * reason. */
int verifier_list[MAX_VERIFIERS];
bool attestation_results[MAX_VERIFIERS];
/* Summary-report only: was_cached (cert reused vs. freshly /certify_ak'd)
 * and appraisal round-trip latency. */
bool rp_ak_cert_was_cached[MAX_VERIFIERS];
long verifier_latency_ms[MAX_VERIFIERS];
verifier_info verifiers[MAX_VERIFIERS];
/* Was 6000 -- 1000x too large: this feeds libcoap's ack_timeout (seconds),
 * so a stray retransmission could take tens of real seconds to resolve. */
uint16_t verifier_response_timeout = RP_DEFAULT_VERIFIER_TIMEOUT_S;
bool processing_appraisal_response[MAX_VERIFIERS] = {false};

/* attester config */
bool processing_attestation_response = false;
CHARRA_RC attestation_rc = CHARRA_RC_ERROR;
const bool USE_TPM_FOR_RANDOM_NONCE_GENERATION = false;
uint8_t tpm_pcr_selection[TPM2_MAX_PCRS] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
uint32_t tpm_pcr_selection_len = 9;
/* Same 1000x-too-large bug as verifier_response_timeout above, fixed the
 * same way; a real get_evidence round trip in this dev environment takes
 * ~0.2s, so 6s is generous, not tight. */
uint16_t attester_response_timeout = RP_DEFAULT_ATTESTER_TIMEOUT_S;
bool use_ima_event_log = false;
char* ima_event_log_path = "/sys/kernel/security/ima/binary_runtime_measurements";
bool use_ima_test_log = true;
char* ima_test_log_path = "ima_test_logs.txt";  // path to the IMA test log file for testing purposes

/* RP appraisal config */
char* whitelist_hashes_path = "whitelist-hashes.txt";
char* blacklist_hashes_path = "blacklist-hashes.txt";

/* --- privacy-cleaning state, produced once per attestation -------------- */
/* log_r: the redacted log, and PCR_r: the composite digest over a replay of
 * it. Shared by every verifier thread -- the redaction is randomised, so
 * redacting once per verifier would hand each of them a different log_r for
 * the same attestation. */
uint8_t* rp_log_r = NULL;
uint32_t rp_log_r_len = 0;
uint8_t rp_pcr_r[TPM2_SHA256_DIGEST_SIZE] = {0};
/* Quote_r's signing key is RP's TPM-resident AK (see ensure_rp_ak_keypair()
 * / charra_identity_key_mgr.h) -- created once and reused for the process's
 * lifetime, unlike the throwaway software key this used to be. Verifier-
 * agnostic: the same keypair signs Quote_r for every Verifier -- only its
 * CERTIFICATE differs per Verifier, see rp_ak_cert_der below. */
uint8_t rp_public_key_der[CHARRA_RSA_PUB_KEY_DER_MAX] = {0};
uint32_t rp_public_key_der_len = 0;

/* --- RP TPM identity / /certify_ak config -------------------------------- */
/* Same synthetic test PKI keys/gen-ak-pki.sh generates. manufacturer_root_key
 * is only ever touched here, once, to mint RP's own EK certificate the first
 * time this binary runs against a fresh TPM -- a real device would never
 * hold this key itself (it's normally burned in by the manufacturer at
 * TPM-manufacture time), but there is no real manufacturer in this
 * synthetic PKI, same simplification /certify_ak's own EK-check already
 * documents. */
char* manufacturer_root_cert_path = "keys/manufacturer-root.crt";
char* manufacturer_root_key_path = "keys/manufacturer-root.key";
const char* rp_ek_cert_not_before_utc = "20240101000000";
const char* rp_ek_cert_not_after_utc = "20340101000000";
/* Cache files -- written on first successful provisioning, reused (skipping
 * the /certify_ak round trip) on every later run. All of RP's runtime state
 * lives under state/relying-party/, created by main() and split by purpose
 * the same way verifier.c splits state/verifier/:
 *   identity/            the one TPM-resident EK/AK keypair (Verifier-agnostic)
 *   ak-certificates/     per-Verifier AK certificates for that keypair, named
 *                        rp-ak-certificate-<port>.der by
 *                        ensure_rp_ak_certificate() */
char* rp_ek_cert_cache_path =
        "state/relying-party/identity/rp-ek-certificate.der";
char* rp_ak_public_path =
        "state/relying-party/identity/rp-ak-public.bin";
char* rp_ak_private_path =
        "state/relying-party/identity/rp-ak-private.bin";

/* True once the TPM-resident EK+AK keypair exists and rp_public_key_der is
 * populated -- set once by ensure_rp_ak_keypair(), never per-Verifier. */
bool rp_ak_keypair_ready = false;
/* Per-Verifier AK certificate state: each Verifier independently issues
 * (and tracks the validity/revocation of) its own certificate for RP's one
 * AK public key -- since Verifiers are independent, RP's AK certification
 * has to be too, not a single certificate obtained from verifiers[0] and
 * assumed good everywhere (see CHARRA_V2_NOTES.md). */
bool rp_ak_cert_ready[MAX_VERIFIERS] = {false};
/* When each cached certificate expires, re-checked every call. */
time_t rp_ak_cert_expires_at[MAX_VERIFIERS] = {0};
uint8_t* rp_ak_cert_der[MAX_VERIFIERS] = {NULL};
uint32_t rp_ak_cert_der_len[MAX_VERIFIERS] = {0};
bool processing_certify_ak_response = false;
CHARRA_RC certify_ak_rc = CHARRA_RC_ERROR;

/* --- Attester identity provisioning (/certify_ak_of_attester) -----------
 * Two kinds of CA certify the Attester's AK identity, neither trusting the
 * other's issuance -- see CHARRA_V2_NOTES.md. RP acts as the sole initiator
 * throughout (Attester and every Verifier stay fully passive):
 *   - RP's own CA: one relationship, one certificate, provisioned once per
 *     process by ensure_attester_identity_provisioned() -- the same
 *     one-time shape as ensure_rp_ak_keypair().
 *   - Each Verifier's own CA: a SEPARATE certificate per Verifier, since
 *     Verifiers hold independent CA keys (see verifier.c's
 *     verifier_ca_key_path). ensure_attester_identity_certified_by_verifier()
 *     runs once per Verifier, from that Verifier's own thread.
 * Both live in rp/rp_attester_identity.c. */
char* rp_ca_cert_path = "keys/rp-ca.crt";
char* rp_ca_key_path = "keys/rp-ca.key";
/* Lifetime of the Attester AK certificate RP issues under its own CA,
 * as a duration from issuance rather than a fixed absolute window (see
 * verifier.c's ak_cert_validity_seconds for why). Settable with
 * --attester-ak-validity. Five minutes by default, same reasoning as the
 * Verifier's --ak-validity.
 * Independent of the Verifier's own --ak-validity: that one covers the
 * certificates the Verifier issues, this one only the Attester
 * certificate RP signs itself. Each certificate carries its own
 * notAfter, so the two never need to agree. */
#define RP_AK_CERT_VALIDITY_SECONDS_DEFAULT (5 * 60)
time_t attester_ak_cert_validity_seconds =
        RP_AK_CERT_VALIDITY_SECONDS_DEFAULT;
char* attester_ak_state_file_path =
        "state/relying-party/ak-provisioning/attester-ak-state.txt";
/* The RP-issued leg's cache. Every Verifier-issued leg is cached too, in
 * the same directory as attester-ak-certificate-verifier-<port>.der (see
 * ensure_attester_identity_certified_by_verifier()) -- certificates are
 * public, so RP holds all of them in the clear. What only the Attester's
 * TPM can decrypt is the credential-activation *secret*, not any of these.
 * This file's presence gates ensure_attester_identity_provisioned() (the
 * FETCH + RP-CA leg only); the Verifier legs gate per-Verifier. */
char* attester_ak_cert_rp_cache_path =
        "state/relying-party/attester-ak-certificates/"
        "attester-ak-certificate-rp.der";
bool attester_identity_provisioned = false;
time_t attester_ak_cert_rp_expires_at = 0;
/* ensure_attester_identity_provisioned() used to run exactly once,
 * before any Verifier thread existed, which is why its FETCH globals
 * need no lock of their own. Expiry-driven renewal means a thread can
 * now reach it mid-cycle, so the work is serialised here. Taken before
 * attester_identity_relay_mutex and released before the relay starts,
 * so the two never nest. */
pthread_mutex_t attester_identity_provision_mutex =
        PTHREAD_MUTEX_INITIALIZER;

msg_ak_identity_response_dto ak_identity_response = {0};
CHARRA_RC ak_identity_rc = CHARRA_RC_ERROR;
bool processing_ak_identity_response = false;

/* The Attester's EK certificate + AK public key + AK name, as FETCHed once
 * by ensure_attester_identity_provisioned() -- doesn't vary per Verifier,
 * so every ensure_attester_identity_certified_by_verifier() call reuses
 * this rather than re-FETCHing. Populated once; ek_certificate is this
 * struct's own heap copy, independent of ak_identity_response above. */
msg_ak_identity_response_dto attester_identity_cached = {0};

/* No payload to parse on the DELIVER_RP/DELIVER_VERIFIER leg -- this
 * handler only needs to know the round trip completed. */
bool processing_certify_ak_of_attester_deliver_response = false;

/* ACTIVATE leg: the secret the Attester recovered, relayed onward as that
 * Verifier's CONFIRM. */
msg_activate_credential_response_dto activate_credential_response = {0};
CHARRA_RC activate_credential_rc = CHARRA_RC_ERROR;
bool processing_activate_credential_response = false;

/* Per-Verifier Attester AK certificate -- mirrors rp_ak_cert_der/_len/_ready
 * above, same reason: each Verifier issues, and must be sent back, its OWN
 * certificate. charra_rp_build_evidence_message() substitutes it directly
 * rather than relaying whatever the Attester reports, since only RP knows
 * which certificate belongs to which Verifier. Not a trust shortcut: a
 * certificate's validity rests on its CA signature, not on who carried it. */
bool attester_ak_cert_by_verifier_ready[MAX_VERIFIERS] = {false};
time_t attester_ak_cert_by_verifier_expires_at[MAX_VERIFIERS] = {0};
uint8_t* attester_ak_cert_by_verifier_der[MAX_VERIFIERS] = {NULL};
uint32_t attester_ak_cert_by_verifier_der_len[MAX_VERIFIERS] = {0};
/* Guards the Attester-relay round trips in ensure_attester_identity_
 * certified_by_verifier() (ACTIVATE, DELIVER_VERIFIER) against concurrent
 * Verifier threads: both use the shared response globals above, just as
 * /certify_ak's globals need rp_ak_reprovision_mutex. Held for the whole
 * function body rather than per-exchange, because the Attester is
 * single-threaded and serializes these anyway (see attester.c) -- there is
 * no concurrency to preserve here, only correctness to add. */
pthread_mutex_t attester_identity_relay_mutex =
        PTHREAD_MUTEX_INITIALIZER;

/* Guards every TPM connection RP opens (provisioning and, later, each
 * Quote_r signing operation): the TPM simulator this dev environment uses
 * accepts only one client connection at a time, and every other binary
 * (attester.c, verifier.c) already follows an open-do-one-thing-close
 * pattern per request rather than holding a connection for a whole
 * process's lifetime. A connection RP held open for its entire run once
 * starved the Verifier's own /certify_ak TPM work indefinitely -- observed
 * directly (killing the RP process immediately unblocked the Verifier).
 * This mutex keeps RP's own accesses serialized and, just as importantly,
 * keeps each one short-lived so other processes get a turn. */
pthread_mutex_t rp_tpm_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Guards /certify_ak's shared response globals (certify_ak_response/_rc/
 * processing_, above) against concurrent Verifier threads: each thread
 * certifies RP's AK with its own Verifier, so several can legitimately be
 * mid-/certify_ak at once and would otherwise read each other's response.
 * It no longer guards the thundering herd it was written for -- threads
 * each own their rp_ak_cert_der[i] slot now, so that race is gone. */
pthread_mutex_t rp_ak_reprovision_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Nonces received from each Verifier, indexed by verifier slot. */
uint8_t verifier_nonces[MAX_VERIFIERS][sizeof(TPMU_HA)] = {{0}};
uint32_t verifier_nonce_lens[MAX_VERIFIERS] = {0};
bool processing_nonce_response[MAX_VERIFIERS] = {false};
char attester_host[16] = "127.0.0.1";      // 15 characters for IPv4 plus \0
unsigned int attester_port = 5683;         // default port

/* No CLI reaches these yet -- relying_party has no --psk/--rpk options, so
 * use_psk/use_rpk stay false and rp_coap.c always opens plain UDP. The
 * plumbing below and in rp_coap.c is complete; only the options are missing. */
charra_dtls_config dtls_config = {
        .psk_key = "Charra DTLS Key",
        .psk_identity = "Charra Relying Party",
        .rpk_private_key_path = "keys/relying_party.der",
        .rpk_public_key_path = "keys/relying_party.pub.der",
        .rpk_verify_peer_public_key = true,
};

/* Per-peer, not per-role: the RP is a client to two different servers, so
 * it names both rather than filling in rpk_peer_public_key_path. */
char* dtls_rpk_attester_public_key_path = "keys/attester.pub.der";
char* dtls_rpk_verifier_public_key_path = "keys/verifier.pub.der";

/* --- in-flight message state -------------------------------------------
 * Declared in rp_shared.h; the pipeline modules in src/rp/ fill these in
 * from their CoAP response handlers, which cannot return data. */

msg_attestation_request_dto last_request = {0};
msg_attestation_response_dto last_response = {0};
msg_certify_ak_response_dto certify_ak_response = {0};

/* --- attestation cycle -------------------------------------------------- */

/**
 * @brief One complete attestation cycle: resolve Verifiers, ensure the
 * Attester's identity, fetch and locally appraise its evidence, then
 * privacy-clean and submit to every Verifier.
 *
 * Everything expensive inside (RP AK keypair/certificates, Attester
 * identity) is cached by its own ensure_* or cache check, so a rebuilt
 * binary run again against still-valid credentials skips straight to
 * /attest -> /nonce -> /appraise.
 */
static CHARRA_RC run_one_attestation_cycle(
        int num_verifiers, const char* label) {
    CHARRA_RC result = CHARRA_RC_SUCCESS;
    struct timespec start_time, end_time;
    double duration = 0.0;

    for (int i = 0; i < num_verifiers; i++) {
        verifier_list[i] = i + 1;
    }

    /* Clear delimiter between cycles -- without it every cycle's log lines
     * run together with no way to tell where one attempt ends and the next
     * begins. */
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME
                    "] Starting new attestation run with %d verifier(s) (%s).",
            num_verifiers, label);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");

    /* Getting verifiers */
    charra_log_info("[" LOG_NAME "] Getting verifiers.");
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    if ((result = get_verifiers(verifier_list, num_verifiers)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error getting verifiers.");
        return result;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    duration = (end_time.tv_sec - start_time.tv_sec) +
               (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] Phase timing: get_verifiers took %.3fs.",
            duration);

    /* Only the RP-CA leg of the Attester's identity is ensured here: it is
     * one relationship, FETCHed and signed once per process, and the call
     * no-ops thereafter. Fail-closed -- this is RP's own gate on the
     * Attester's identity, so a failure aborts the cycle rather than
     * appraising unverified evidence.
     *
     * Everything per-Verifier (RP's own AK certificate, and the Attester's
     * certificate from that Verifier's CA) is ensured inside
     * get_attestation_results_thread() instead, since Verifiers hold
     * independent CA keys -- one certificate from verifiers[0] cannot be
     * assumed good everywhere. */
    if ((result = ensure_attester_identity_provisioned()) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not provision the Attester's identity.");
        return result;
    }

    /* Getting evidence */
    charra_log_info("[" LOG_NAME "] Getting evidence.");
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    if ((result = get_evidence()) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error getting evidence.");
        return result;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    duration = (end_time.tv_sec - start_time.tv_sec) +
               (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] Phase timing: get_evidence (Attester "
                    "round trip + local appraisal) took %.3fs.",
            duration);

    /* Getting attestation results */
    charra_log_info("[" LOG_NAME "] Getting attestation results.");
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    if ((result = get_attestation_results(num_verifiers)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error getting attestation results.");
        return result;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    duration = (end_time.tv_sec - start_time.tv_sec) +
               (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] Phase timing: get_attestation_results "
                    "(all Verifiers) took %.3fs.",
            duration);

    return CHARRA_RC_SUCCESS;
}

/* --- main --------------------------------------------------------------- */

int main(int argc, char** argv) {
    /* Environment first, so an explicit --log-level/-v on the command line
     * overrides it rather than the other way round. */
    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);

    int parse_result = parse_rp_command_line(argc, argv);
    if (parse_result != 0) {
        return (parse_result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    charra_log_set_level(charra_log_level);

    /* Before any setup output, so the top of a log file always states every
     * value this run will use. */
    rp_log_effective_configuration();

    /* RP's own runtime state (TPM identity, per-Verifier AK certificates)
     * lives under state/relying-party/. All of it is shared mutable state
     * keyed by nothing but the path, so exactly one RP may own it at a
     * time. */
    static const char* const state_dirs[] = {
            "state/relying-party/identity",
            "state/relying-party/ak-certificates",
            "state/relying-party/attester-ak-certificates",
            "state/relying-party/ak-provisioning", NULL};
    if (charra_io_claim_state_dir(state_dirs,
                "state/relying-party/relying-party.lock",
                "relying_party") != CHARRA_RC_SUCCESS) {
        return EXIT_FAILURE;
    }

    CHARRA_RC result = run_one_attestation_cycle(rp_num_verifiers, "run");

    /* Release this cycle's evidence buffers so a clean shutdown really is
     * clean -- makes "still reachable" bytes at exit meaningful under
     * valgrind rather than noise. */
    charra_free_attestation_response(&last_response);
    charra_rp_release_evidence();
    coap_cleanup();

    return (result == CHARRA_RC_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
