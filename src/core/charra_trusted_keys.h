/**
 * @file charra_trusted_keys.h
 * @brief The trust anchor: a flat file of public keys that every role
 * reads to decide whether a signing key it just saw is one it should
 * trust.
 *
 * These keys ARE the AKs -- the attestation keys of the Attester and of
 * the RP. What this PoC drops is not the concept but the ceremony: there
 * is no EK, no credential activation and no CA, so nothing *certifies* a
 * key into being an AK at runtime. It is an AK because this file says so.
 *
 * Both roles sign with a TPM-resident AK, both send its public half with
 * whatever they signed, and the receiver's entire identity check is:
 *
 *   a signing key is trusted if, and only if, it appears in this file.
 *
 * That is the whole of it. No chain to walk, no validity dates, no
 * revocation list, no serial numbers -- and correspondingly nothing to
 * provision, renew or expire at runtime. The AK/EK binding a real
 * deployment would prove with TPM2_MakeCredential is asserted here by the
 * file's existence instead. Anyone who can write the file can
 * add a trusted key, which is precisely what "assume the key was already
 * vouched for out of band" buys us, and precisely why this shape belongs
 * in a PoC and not in a deployment.
 *
 * The file holds the AKs' PEM public keys (`-----BEGIN PUBLIC KEY-----`),
 * one per identity, each preceded by a `# name` comment. PEM because it is the
 * ordinary text encoding for a public key: the file stays readable, and
 * any entry can be inspected with `openssl rsa -pubin -in ... -text`.
 * keys/gen-trusted-keys.sh writes it from the TPM's own keys.
 *
 * The file is re-read on every lookup rather than cached. Lookups happen a
 * handful of times per attestation cycle against a file of two keys, so
 * the cost is irrelevant next to the TPM round trips around it -- and
 * re-reading means a regenerated trust anchor takes effect without
 * restarting every daemon.
 */

#ifndef CHARRA_TRUSTED_KEYS_H
#define CHARRA_TRUSTED_KEYS_H

#include <stddef.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/** Default location, relative to the working directory every role is
 * started from. */
#define CHARRA_TRUSTED_KEYS_DEFAULT_PATH "keys/trusted_keys.txt"

/* The two identity labels, defined once because three separate things have
 * to spell them identically or the system breaks in ways that are hard to
 * see: bin/provision_trusted_keys --role, the `# name` comment it writes
 * above each key, and the name_out this file's lookup reports. The
 * Attester's label doubles as the signing-key name on the /attest wire --
 * see CHARRA_AK_A_KEY_ID in charra_key_mgr.h. */
#define CHARRA_ROLE_ATTESTER "attester"
#define CHARRA_ROLE_RELYING_PARTY "relying-party"

/**
 * @brief Is this AK's public key one we trust?
 *
 * One entry point, because every role checks the same thing in the same
 * shape: AK_a (the Attester's quoting key) and AK_r (the RP's Quote_r
 * signing key) both travel the wire as a TPM2B_PUBLIC.
 *
 * @param[in] path trust anchor file, or NULL for
 * CHARRA_TRUSTED_KEYS_DEFAULT_PATH.
 * @param[out] name_out if non-NULL, receives the `# name` label of the
 * matching entry -- for logging which identity was recognised.
 * @returns CHARRA_RC_SUCCESS on a match, CHARRA_RC_VERIFICATION_FAILED if
 * the file parsed but held no such key, CHARRA_RC_ERROR if the file could
 * not be read or contained no key at all.
 */
CHARRA_RC charra_trusted_keys_check(const char* path,
        const TPM2B_PUBLIC* public_key, char* name_out, size_t name_out_size);

#endif /* CHARRA_TRUSTED_KEYS_H */
