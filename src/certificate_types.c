/**
 * \file certificate_types.c
 *
 * This header defines built-in certificate types needed for the base Velo
 * Certificate library.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <vccert/certificate_types.h>

/**
 * Certificate Type Artifact 7f43cd35-1e5e-4703-99f5-43b0ca590d33
 */
uint8_t vccert_certificate_type_uuid_artifact[16] = { 0x7f, 0x43, 0xcd, 0x35, 0x1e, 0x5e, 0x47, 0x03,
    0x99, 0xf5, 0x43, 0xb0, 0xca, 0x59, 0x0d, 0x33 };

/**
 * Certificate Type Entity c1e0339d-546d-4066-8a20-9b7939915991
 */
uint8_t vccert_certificate_type_uuid_entity[16] = { 0xc1, 0xe0, 0x33, 0x9d, 0x54, 0x6d, 0x40, 0x66,
    0x8a, 0x20, 0x9b, 0x79, 0x39, 0x91, 0x59, 0x91 };
