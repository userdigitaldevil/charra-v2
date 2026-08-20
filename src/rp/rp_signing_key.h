/**
 * @file rp_signing_key.h
 * @brief AK_r -- the RP's attestation key, and the thing that signs
 * Quote_r. Physically, its TPM's unrestricted signing primary.
 *
 * It is an AK by assertion, not by certification: this PoC has no EK and
 * no CA, so nothing proves the key into that role at runtime. What makes
 * it AK_r is that keys/trusted_keys.txt names it as such (see
 * charra_trusted_keys.h).
 *
 * There is no provisioning here, nothing on disk, and nothing held in
 * memory between uses. The key is derived from the TPM's owner-hierarchy
 * seed by tpm2_create_primary_key_rsa2048_unrestricted(), which reproduces
 * it identically on every call, and its public half was written into
 * keys/trusted_keys.txt long before this process started (see
 * charra_trusted_keys.h). The RP's whole identity story is therefore
 * "derive AK_r, sign with it, send its public half, let the Verifier
 * decide whether it recognises it" -- every time, from scratch.
 *
 * Unrestricted rather than restricted because Quote_r signs
 * (PCR_r || nonce) -- a buffer the RP assembled in software from a log
 * replay. A restricted key would refuse it for want of a TPM-produced
 * validation ticket.
 *
 * Every entry point here opens its own short-lived TPM connection and
 * closes it before returning, rather than holding one for the process's
 * lifetime. That is not tidiness: the dev environment's TPM simulator
 * serves one client at a time, and an RP that kept a connection open
 * across a CoAP wait once starved every other role outright.
 */

#ifndef CHARRA_RP_SIGNING_KEY_H
#define CHARRA_RP_SIGNING_KEY_H

#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/**
 * @brief Sign data with AK_r, and hand back the public half of the very
 * key that signed it.
 *
 * The two outputs come from one derivation on purpose. Nothing is cached:
 * the key is derived here, used, and discarded, so the public key the RP
 * puts on the wire is by construction the one its signature verifies
 * under. Caching the public half and re-deriving the private half for each
 * signature would let the two drift apart -- silently, and only under a
 * TPM reset, which is the worst possible way to find out.
 *
 * SHA-256(data), then TPM2_Sign under an RSA-PSS scheme with a null
 * validation ticket -- the ticket that tells the TPM "this digest did not
 * come from me", which only an unrestricted key may sign.
 *
 * Serialized against every other TPM user in this process via
 * rp_tpm_mutex, which the caller must NOT already hold.
 *
 * @param[out] signature_out at least CHARRA_RSA_SIGNATURE_LEN bytes; raw
 * RSA-PSS signature bytes, not a TPMT_SIGNATURE wrapper, so the Verifier's
 * existing mbedTLS check reads it unchanged.
 * @param[out] ak_public_key_out AK_r's public half, in the shape it
 * travels the wire in. NULL if the caller only needs the signature.
 */
CHARRA_RC rp_sign_with_ak(const uint8_t* data, size_t data_len,
        uint8_t* signature_out, TPM2B_PUBLIC* ak_public_key_out);

#endif /* CHARRA_RP_SIGNING_KEY_H */
