/**
 * \file test_vccert_parser_field.cpp
 *
 * Test the internal vccert_parser_field function.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include "../../src/parser/parser_internal.h"

/**
 * Test that the field parser method returns an error if any of the parameters
 * are invalid.
 */
TEST(vccert_parser_field_test, parameter_sanity)
{
    const uint8_t* cert = (const uint8_t*)"\x00\x00\x00\x01\xFF";
    const size_t CERT_SIZE = 5;
    size_t OFFSET = 0;
    uint16_t field_type;
    size_t field_size;
    const uint8_t* field;
    size_t next_offset;

    //the certificate must be non-null
    ASSERT_NE(0,
        vccert_parser_field(NULL, CERT_SIZE, OFFSET, &field_type, &field_size,
            &field, &next_offset));

    //the certificate size must be non-zero
    ASSERT_NE(0,
        vccert_parser_field(cert, 0, OFFSET, &field_type, &field_size,
            &field, &next_offset));

    //the offset must leave enough space for parsing a certificate
    ASSERT_NE(0,
        vccert_parser_field(cert, CERT_SIZE, 10, &field_type, &field_size,
            &field, &next_offset));

    //the field type pointer cannot be NULL
    ASSERT_NE(0,
        vccert_parser_field(cert, CERT_SIZE, OFFSET, NULL, &field_size,
            &field, &next_offset));

    //the field size pointer cannot be NULL
    ASSERT_NE(0,
        vccert_parser_field(cert, CERT_SIZE, OFFSET, &field_type, NULL,
            &field, &next_offset));

    //the field pointer cannot be NULL
    ASSERT_NE(0,
        vccert_parser_field(cert, CERT_SIZE, OFFSET, &field_type, &field_size,
            NULL, &next_offset));

    //the next offset pointer cannot be NULL
    ASSERT_NE(0,
        vccert_parser_field(cert, CERT_SIZE, OFFSET, &field_type, &field_size,
            &field, NULL));
}

/**
 * Test that the field size cannot exceed the size of the certificate.
 */
TEST(vccert_parser_field_test, field_size_sanity)
{
    const uint8_t* cert = (const uint8_t*)"\x00\x00\x00\x0F\xFF";
    const size_t CERT_SIZE = 5;
    size_t OFFSET = 0;
    uint16_t field_type;
    size_t field_size;
    const uint8_t* field;
    size_t next_offset;

    //this should fail to parse, because the field size embedded in the
    //certificate is too large
    ASSERT_NE(0,
        vccert_parser_field(cert, CERT_SIZE, OFFSET, &field_type, &field_size,
            &field, &next_offset));
}

/**
 * Test that we can parse a 32-bit value field from a certificate.
 */
TEST(vccert_parser_field_test, simple_parse)
{
    const uint8_t* cert = (const uint8_t*)"\x01\x00\x00\x04\x00\x00\x00\x07";
    const size_t CERT_SIZE = 8;
    size_t OFFSET = 0;
    uint16_t field_type;
    size_t field_size;
    const uint8_t* field;
    size_t next_offset;

    //the parse should succeed
    ASSERT_EQ(0,
        vccert_parser_field(cert, CERT_SIZE, OFFSET, &field_type, &field_size,
            &field, &next_offset));

    //the field type should be 0x100 hex
    ASSERT_EQ(0x100U, field_type);

    //the field size should be 4
    ASSERT_EQ(4U, field_size);

    //parse the field value
    uint32_t value = (((uint32_t)field[0]) << 24) | (((uint32_t)field[1]) << 16) | (((uint32_t)field[2]) << 8) | (((uint32_t)field[3]));
    ASSERT_EQ(7U, value);

    //this should be the only field
    ASSERT_GE(next_offset, CERT_SIZE);
}
