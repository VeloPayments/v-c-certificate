/**
 * \file certificate_types.h
 *
 * This header defines built-in certificate types needed for the base Velo
 * Certificate library.
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

extern const uint8_t vccert_certificate_type_uuid_artifact[16];
extern const uint8_t vccert_certificate_type_uuid_entity[16];

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_CERTIFICATE_TYPES_HEADER_GUARD
