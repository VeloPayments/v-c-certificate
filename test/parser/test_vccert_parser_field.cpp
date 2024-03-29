/**
 * \file test_vccert_parser_field.cpp
 *
 * Test the internal vccert_parser_field function.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include "../../src/parser/parser_internal.h"

TEST_SUITE(vccert_parser_field_test);

/**
 * Test that the field parser method returns an error if any of the parameters
 * are invalid.
 */
TEST(parameter_sanity)
{
    const uint8_t* cert = (const uint8_t*)"\x00\x00\x00\x01\xFF";
    const size_t CERT_SIZE = 5;
    size_t OFFSET = 0;
    uint16_t field_type;
    size_t field_size;
    const uint8_t* field;
    size_t next_offset;

    //the certificate must be non-null
    TEST_ASSERT(
        0
            != vccert_parser_field(
                    NULL, CERT_SIZE, OFFSET, &field_type, &field_size, &field,
                    &next_offset));

    //the certificate size must be non-zero
    TEST_ASSERT(
        0
            != vccert_parser_field(
                    cert, 0, OFFSET, &field_type, &field_size, &field,
                    &next_offset));

    //the offset must leave enough space for parsing a certificate
    TEST_ASSERT(
        0
            != vccert_parser_field(
                    cert, CERT_SIZE, 10, &field_type, &field_size, &field,
                    &next_offset));

    //the field type pointer cannot be NULL
    TEST_ASSERT(
        0
            != vccert_parser_field(
                    cert, CERT_SIZE, OFFSET, NULL, &field_size, &field,
                    &next_offset));

    //the field size pointer cannot be NULL
    TEST_ASSERT(
        0
            != vccert_parser_field(
                    cert, CERT_SIZE, OFFSET, &field_type, NULL, &field,
                    &next_offset));

    //the field pointer cannot be NULL
    TEST_ASSERT(
        0
            != vccert_parser_field(
                    cert, CERT_SIZE, OFFSET, &field_type, &field_size, NULL,
                    &next_offset));

    //the next offset pointer cannot be NULL
    TEST_ASSERT(
        0
            != vccert_parser_field(
                    cert, CERT_SIZE, OFFSET, &field_type, &field_size, &field,
                    NULL));
}

/**
 * Test that the field size cannot exceed the size of the certificate.
 */
TEST(field_size_sanity)
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
    TEST_ASSERT(
        0
            != vccert_parser_field(
                    cert, CERT_SIZE, OFFSET, &field_type, &field_size, &field,
                    &next_offset));
}

/**
 * Test that we can parse a 32-bit value field from a certificate.
 */
TEST(simple_parse)
{
    const uint8_t* cert = (const uint8_t*)"\x01\x00\x00\x04\x00\x00\x00\x07";
    const size_t CERT_SIZE = 8;
    size_t OFFSET = 0;
    uint16_t field_type;
    size_t field_size;
    const uint8_t* field;
    size_t next_offset;

    //the parse should succeed
    TEST_ASSERT(
        0
            == vccert_parser_field(
                    cert, CERT_SIZE, OFFSET, &field_type, &field_size, &field,
                    &next_offset));

    //the field type should be 0x100 hex
    TEST_ASSERT(0x100U == field_type);

    //the field size should be 4
    TEST_ASSERT(4U == field_size);

    //parse the field value
    uint32_t value =
        (   ((uint32_t)field[0]) << 24)
         | (((uint32_t)field[1]) << 16)
         | (((uint32_t)field[2]) <<  8)
         | (((uint32_t)field[3]));
    TEST_ASSERT(7U == value);

    //this should be the only field
    TEST_ASSERT(next_offset >= CERT_SIZE);
}
