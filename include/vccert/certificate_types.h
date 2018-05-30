/**
 * \file certificate_types.h
 *
 * \brief This header defines built-in certificate types needed for the base
 * Velo Certificate library.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_CERTIFICATE_TYPES_HEADER_GUARD
#define VCCERT_CERTIFICATE_TYPES_HEADER_GUARD

#include <stdint.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \brief The Root Block Identifier.
 */
extern const uint8_t vccert_certificate_type_uuid_root_block[16];

/**
 * \brief The Root Entity Create Transation Type.
 */
extern const uint8_t vccert_certificate_type_uuid_txn_root_entity_create[16];

/**
 * \brief The Root Entity Destroy Transation Type.
 */
extern const uint8_t vccert_certificate_type_uuid_txn_root_entity_destroy[16];

/**
 * \brief The Block Transaction Certificate Type Identifier.
 */
extern const uint8_t vccert_certificate_type_uuid_txn_block[16];

/**
 * \brief The Transaction Certificate Type Identifier.
 */
extern const uint8_t vccert_certificate_type_uuid_txn[16];

/**
 * \brief The Private Entity Certificate Type Identifier.
 */
extern const uint8_t vccert_certificate_type_uuid_private_entity[16];

/**
 * \brief The Agent Subtype Identifier.
 */
extern const uint8_t vccert_certificate_type_uuid_agent_subtype[16];

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_CERTIFICATE_TYPES_HEADER_GUARD
