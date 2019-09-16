/**
 * \file type.h
 *
 * \brief This header defines the types of fields in a certificate
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_TYPE_HEADER_GUARD
#define VCCERT_TYPE_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

typedef struct field_mapping
{
    uint8_t longcode[16];
    uint16_t shortcode;
    uint8_t type;
} field_mapping_t;

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_FIELD_MAPPING_HEADER_GUARD
