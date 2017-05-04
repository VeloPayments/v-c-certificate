/**
 * \file builder.h
 *
 * Certificate Builder.  The Certificate Builder provides a directed mechanism
 * for building a certificate.  It supports raw mode, which allows a freeform
 * certificate to be built, and contract mode, in which a certificate must be
 * strictly built following a contract.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_BUILDER_HEADER_GUARD
#define VCCERT_BUILDER_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <vccert/parser.h>
#include <vccrypt/suite.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

#define BUILDER_SIGN_SUCCESS 0x0000
#define BUILDER_SIGN_ERROR_GENERAL 0x1101
#define BUILDER_SIGN_ERROR_UNKNOWN 0x1111

/**
 * The builder options structure is used to manage options needed to build a
 * certificate.
 */
typedef struct vccert_builder_options
{
    /* this options structure inherits from disposable. */
    disposable_t hdr;

    /* the allocator options to use for this parser. */
    allocator_options_t* alloc_opts;

    /* the crypto suite to use for this parser. */
    vccrypt_suite_options_t* crypto_suite;

} vccert_builder_options_t;

/**
 * The builder context manages building and signing a certificate.
 */
typedef struct vccert_builder_context
{
    /* this is a disposable structure */
    disposable_t hdr;

    /* options structure for this parser */
    vccert_builder_options_t* options;

    /* certificate buffer */
    vccrypt_buffer_t buffer;
    /* current offset */
    size_t offset;

} vccert_builder_context_t;

/**
 * Initialize a builder options structure using the given allocator, and crypto
 * suite.
 * and must be disposed of when no longer needed by calling dispose().
 *
 * \param options           The options structure to initialize.
 * \param alloc_opts        The allocator options to use for this structure.
 * \param crypto_suite      The crypto suite to use for this structure.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_options_init(
    vccert_builder_options_t* options, allocator_options_t* alloc_opts,
    vccrypt_suite_options_t* crypto_suite);

/**
 * Initialize a builder context structure using the given options and maximum
 * size.
 *
 * \param options           The options structure to initialize.
 * \param context           The builder context structure to initialize.
 * \param size              The maximum size of the certificate.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_init(
    vccert_builder_options_t* options, vccert_builder_context_t* context,
    size_t size);

/**
 * Add an int8_t field to the certificate with a short field ID.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The int8_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_int8(
    vccert_builder_context_t* context, uint16_t field, int8_t value);

/**
 * Add a uint8_t field to the certificate with a short field ID.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The uint8_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_uint8(
    vccert_builder_context_t* context, uint16_t field, uint8_t value);

/**
 * Add an int16_t field to the certificate with a short field ID.
 *
 * Note that this value will be written as a Big Endian integer value.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The uint16_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_int16(
    vccert_builder_context_t* context, uint16_t field, int16_t value);

/**
 * Add a uint16_t field to the certificate with a short field ID.
 *
 * Note that this value will be written as a Big Endian integer value.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The uint16_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_uint16(
    vccert_builder_context_t* context, uint16_t field, uint16_t value);

/**
 * Add an int32_t field to the certificate with a short field ID.
 *
 * Note that this value will be written as a Big Endian integer value.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The int32_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_int32(
    vccert_builder_context_t* context, uint16_t field, int32_t value);

/**
 * Add a uint32_t field to the certificate with a short field ID.
 *
 * Note that this value will be written as a Big Endian integer value.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The uint32_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_uint32(
    vccert_builder_context_t* context, uint16_t field, uint32_t value);

/**
 * Add an int64_t field to the certificate with a short field ID.
 *
 * Note that this value will be written as a Big Endian integer value.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The int64_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_int64(
    vccert_builder_context_t* context, uint16_t field, int64_t value);

/**
 * Add a uint64_t field to the certificate with a short field ID.
 *
 * Note that this value will be written as a Big Endian integer value.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The uint64_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_uint64(
    vccert_builder_context_t* context, uint16_t field, uint64_t value);

/**
 * Add a byte buffer field to the certificate with a short field ID.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The byte buffer value to encode as this field.
 * \param size              The size of this field in bytes.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_buffer(
    vccert_builder_context_t* context, uint16_t field, const uint8_t* value,
    size_t size);

/**
 * Add a UUID field to the certificate with a short field ID.
 *
 * Note that this value is expected as a Big Endian representation of a UUID.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The 128-bit UUID.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_UUID(
    vccert_builder_context_t* context, uint16_t field,
    const uint8_t* value);

/**
 * Sign the certificate using the given signer UUID and private key.
 *
 * Note that the signer_id is expected as a Big Endian representation of a UUID.
 *
 * \param context           The builder context to use for this operation.
 * \param signer_id         The 128-bit signer UUID.
 * \param private_key       The private key buffer to use to sign the
 *                          certificate.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_sign(
    vccert_builder_context_t* context, const uint8_t* signer_id,
    const vccrypt_buffer_t* private_key);

/**
 * Get a pointer to the current certificate and its size.  The certificate
 * pointer is owned by the builder context structure and will be disposed when
 * the structure is disposed.  If the caller wishes to keep the certificate
 * beyond the scope of the builder context, it should copy this certificate
 * data.
 *
 * \param context           The builder context to use for this operation.
 * \param size              A pointer to a size_t field to receive the current
 *                          size of the certificate.
 *
 * \returns a pointer to the raw certificate.
 */
const uint8_t* vccert_builder_emit(
    vccert_builder_context_t* context, size_t* size);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_BUILDER_HEADER_GUARD
