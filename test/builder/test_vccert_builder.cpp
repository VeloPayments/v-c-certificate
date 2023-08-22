/**
 * \file test_vccert_builder.cpp
 *
 * Test the vccert builder methods.
 *
 * \copyright 2017-2021 Velo-Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <iomanip>
#include <iostream>
#include <vccert/builder.h>
#include <vccert/fields.h>
#include <vccert/parser.h>
#include <vccrypt/suite.h>
#include <vpr/allocator/malloc_allocator.h>

/* DISABLED GTEST */
#if 0

using namespace std;

//forward declarations for dummy certificate delegate methods
static bool dummy_txn_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccrypt_buffer_t*, bool*);
static int32_t dummy_artifact_state_resolver(
    void*, void*, const uint8_t*, vccrypt_buffer_t*);
static bool dummy_entity_key_resolver(
    void*, void*, uint64_t, const uint8_t*, vccrypt_buffer_t*,
    vccrypt_buffer_t*);
static int dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccert_contract_closure_t* closure);

const size_t CERT_MAX_SIZE = 65536;

class vccert_builder_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        vccrypt_suite_register_velo_v1();

        malloc_allocator_options_init(&alloc_opts);

        suite_init_result =
            vccrypt_suite_options_init(&crypto_suite, &alloc_opts,
                VCCRYPT_SUITE_VELO_V1);

        parser_opts_init_result =
            vccert_parser_options_init(
                &parser_opts, &alloc_opts, &crypto_suite, &dummy_txn_resolver,
                &dummy_artifact_state_resolver, &dummy_contract_resolver,
                &dummy_entity_key_resolver, &dummy_context);

        builder_opts_init_result =
            vccert_builder_options_init(
                &builder_opts, &alloc_opts, &crypto_suite);

        builder_init_result =
            vccert_builder_init(&builder_opts, &builder, CERT_MAX_SIZE);

        private_key_buffer_result =
            vccrypt_suite_buffer_init_for_signature_private_key(
                &crypto_suite, &private_key_buffer);
    }

    void TearDown() override
    {
        if (private_key_buffer_result == 0)
        {
            dispose((disposable_t*)&private_key_buffer);
        }

        if (builder_init_result == 0)
        {
            dispose((disposable_t*)&builder);
        }

        if (builder_opts_init_result == 0)
        {
            dispose((disposable_t*)&builder_opts);
        }

        if (parser_opts_init_result == 0)
        {
            dispose((disposable_t*)&parser_opts);
        }

        if (suite_init_result == 0)
        {
            dispose((disposable_t*)&crypto_suite);
        }

        dispose((disposable_t*)&alloc_opts);
    }

    int suite_init_result, parser_opts_init_result, builder_opts_init_result;
    int builder_init_result;
    int dummy_context;
    int private_key_buffer_result;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t crypto_suite;
    vccert_parser_options_t parser_opts;
    vccert_builder_options_t builder_opts;
    vccert_builder_context_t builder;
    vccrypt_buffer_t private_key_buffer;
};

/**
 * Sanity test of external dependencies.
 */
TEST_F(vccert_builder_test, external_dependencies)
{
    ASSERT_EQ(0, builder_opts_init_result);
    ASSERT_EQ(0, parser_opts_init_result);
    ASSERT_EQ(0, suite_init_result);
}

/**
 * Happy path test for vcert_builder_init.
 */
TEST_F(vccert_builder_test, vccert_builder_init)
{
    ASSERT_EQ(0, builder_init_result);

    EXPECT_EQ(&builder_opts, builder.options);
    EXPECT_NE(nullptr, builder.buffer.data);
    EXPECT_EQ(CERT_MAX_SIZE, builder.buffer.size);
    EXPECT_EQ(0UL, builder.offset);
}

/**
 * Test that we can add an int8_t field to a certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_short_int8)
{
    const uint16_t FIELD = 0x1068;
    const int8_t VALUE = -27;

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add an int8_t value
    ASSERT_EQ(0, vccert_builder_add_short_int8(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    EXPECT_EQ(VALUE, (int8_t)buf[0]);
}

/**
 * Test that we can add a uint8_t field to a certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_short_uint8)
{
    const uint16_t FIELD = 0x1068;
    const uint8_t VALUE = -27;

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add a uint8_t value
    ASSERT_EQ(0, vccert_builder_add_short_uint8(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    EXPECT_EQ(VALUE, buf[0]);
}

/**
 * Test that we can add an int16_t field to a certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_short_int16)
{
    const uint16_t FIELD = 0x1068;
    const int16_t VALUE = -768;

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add an int16_t value
    ASSERT_EQ(0, vccert_builder_add_short_int16(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    int16_t field_value;
    memcpy(&field_value, buf, sizeof(int16_t));
    EXPECT_EQ(VALUE, (int16_t)ntohs(field_value));
}

/**
 * Test that we can add a uint16_t field to a certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_short_uint16)
{
    const uint16_t FIELD = 0x1068;
    const uint16_t VALUE = 1027;

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add a uint16_t value
    ASSERT_EQ(0, vccert_builder_add_short_uint16(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    uint16_t field_value;
    memcpy(&field_value, buf, sizeof(uint16_t));
    EXPECT_EQ(VALUE, ntohs(field_value));
}

/**
 * Test that we can add an int32_t field to a certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_short_int32)
{
    const uint16_t FIELD = 0x1068;
    const int32_t VALUE = -127877;

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add an int32_t value
    ASSERT_EQ(0, vccert_builder_add_short_int32(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    int32_t field_value;
    memcpy(&field_value, buf, sizeof(int32_t));
    EXPECT_EQ(VALUE, (int32_t)ntohl(field_value));
}

/**
 * Test that we can add a uint32_t field to a certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_short_uint32)
{
    const uint16_t FIELD = 0x1068;
    const uint32_t VALUE = 1024 * 1023 * 1022;

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add a uint32_t value
    ASSERT_EQ(0, vccert_builder_add_short_uint32(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    uint32_t field_value;
    memcpy(&field_value, buf, sizeof(uint32_t));
    EXPECT_EQ(VALUE, ntohl(field_value));
}

/**
 * Test that we can add an int64_t field to a certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_short_int64)
{
    const uint16_t FIELD = 0x1068;
    const int64_t VALUE = -7149262036854774901;

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add an int64_t value
    ASSERT_EQ(0, vccert_builder_add_short_int64(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    uint8_t val_buf[8];
    memcpy(val_buf, &VALUE, sizeof(VALUE));
    EXPECT_EQ(val_buf[7], buf[0]);
    EXPECT_EQ(val_buf[6], buf[1]);
    EXPECT_EQ(val_buf[5], buf[2]);
    EXPECT_EQ(val_buf[4], buf[3]);
    EXPECT_EQ(val_buf[3], buf[4]);
    EXPECT_EQ(val_buf[2], buf[5]);
    EXPECT_EQ(val_buf[1], buf[6]);
    EXPECT_EQ(val_buf[0], buf[7]);
}

/**
 * Test that we can add a uint64_t field to a certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_short_uint64)
{
    const uint16_t FIELD = 0x1068;
    const uint64_t VALUE = 7149262036854774907;

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add an uint64_t value
    ASSERT_EQ(0, vccert_builder_add_short_uint64(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    uint8_t val_buf[8];
    memcpy(val_buf, &VALUE, sizeof(VALUE));
    EXPECT_EQ(val_buf[7], buf[0]);
    EXPECT_EQ(val_buf[6], buf[1]);
    EXPECT_EQ(val_buf[5], buf[2]);
    EXPECT_EQ(val_buf[4], buf[3]);
    EXPECT_EQ(val_buf[3], buf[4]);
    EXPECT_EQ(val_buf[2], buf[5]);
    EXPECT_EQ(val_buf[1], buf[6]);
    EXPECT_EQ(val_buf[0], buf[7]);
}

/**
 * Test that we can add a buffer field to the certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_buffer)
{
    const uint16_t FIELD = 0x1068;
    const uint8_t VALUE[] = { 0x23, 0x46, 0x77, 0x12, 0x01 };

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add a buffer value
    ASSERT_EQ(0,
        vccert_builder_add_short_buffer(&builder, FIELD, VALUE, sizeof(VALUE)));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    EXPECT_EQ(0, memcmp(buf, VALUE, sizeof(VALUE)));
}

/**
 * Test that a buffer larger than 32k can't be added... yet.
 */
TEST_F(vccert_builder_test, vccert_builder_add_buffer_too_big)
{
    const uint16_t FIELD = 0x1068;
    uint8_t VALUE[VCCERT_MAX_FIELD_SIZE + 1];

    /* Set value in buffer. */
    memset(VALUE, 'a', sizeof(VALUE));

    /* Attempt to add the buffer value.  It should fail with
     * VCCERT_ERROR_BUILDER_ADD_TOO_BIG. */
    EXPECT_EQ(
        VCCERT_ERROR_BUILDER_ADD_TOO_BIG,
        vccert_builder_add_short_buffer(&builder, FIELD, VALUE, sizeof(VALUE)));
}

/**
 * Test that we can add a UUID field to the certificate.
 */
TEST_F(vccert_builder_test, vccert_builder_add_UUID)
{
    const uint16_t FIELD = 0x1068;
    const uint8_t VALUE[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add a UUID value
    ASSERT_EQ(0,
        vccert_builder_add_short_UUID(&builder, FIELD, VALUE));

    //postconditions
    const uint8_t* buf = (const uint8_t*)builder.buffer.data;

    //verify that the buffer offset has been updated correctly
    EXPECT_EQ(FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(VALUE),
        builder.offset);

    //verify that the field was written as a Big Endian value
    uint16_t field_type;
    memcpy(&field_type, buf, sizeof(uint16_t));
    EXPECT_EQ(FIELD, ntohs(field_type));
    buf += FIELD_TYPE_SIZE;

    //verify that the size was written as a Big Endian value
    uint16_t field_size;
    memcpy(&field_size, buf, sizeof(uint16_t));
    EXPECT_EQ(sizeof(VALUE), ntohs(field_size));
    buf += FIELD_SIZE_SIZE;

    //verify that the field value was written correctly
    EXPECT_EQ(0, memcmp(buf, VALUE, sizeof(VALUE)));
}

/**
 * Test that we can emit a certificate as a buffer.
 */
TEST_F(vccert_builder_test, vccert_builder_emit)
{
    const uint16_t FIELD = 0x1068;
    const uint8_t VALUE[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    //precondition - offset is 0
    ASSERT_EQ(0UL, builder.offset);

    //add a UUID value
    ASSERT_EQ(0,
        vccert_builder_add_short_UUID(&builder, FIELD, VALUE));

    //emit should return the certificate buffer
    size_t size;
    ASSERT_EQ((const uint8_t*)builder.buffer.data,
        vccert_builder_emit(&builder, &size));
    EXPECT_EQ(builder.offset, size);
}

static const uint8_t* PRIVATE_KEY = (const uint8_t*)"\x65\x93\x21\xd0\x35\xa9\xf8\xcf"
                                                    "\x35\x37\xd1\xd1\x82\xfd\xee\xf8"
                                                    "\x92\x8e\x0c\xfe\xb4\x56\x4b\x2d"
                                                    "\xb5\x11\x60\x6d\xc6\xf6\x13\xbd"
                                                    "\x47\x83\xe9\xf6\x78\xd1\x49\xac"
                                                    "\xd2\x09\x66\xb0\xab\x88\xf7\xd0"
                                                    "\x5d\x6d\x4f\x54\x0f\x1f\x23\x82"
                                                    "\x86\x00\x3a\xda\x0c\x27\xcc\x35";

static const uint8_t* SIGNER_ID = (const uint8_t*)"\x71\x1f\x22\x65\xb6\x50\x46\x12"
                                                  "\xa7\x3a\xad\x82\x7f\xb2\x71\x18";

/**
 * Test that we can create a signed certificate.
 */
TEST_F(vccert_builder_test, vccert_build_signed)
{
    /* certificate version */
    ASSERT_EQ(0,
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_VERSION, 0x00010000UL));
    /* transaction timestamp */
    ASSERT_EQ(0,
        vccert_builder_add_short_uint64(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_VALID_FROM, 1515987826));
    /* crypto suite */
    ASSERT_EQ(0,
        vccert_builder_add_short_uint16(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_CRYPTO_SUITE, 0x0001));
    /* certificate type */
    ASSERT_EQ(0,
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_TYPE,
            (const uint8_t*)"\x52\xa7\xf0\xfb\x8a\x6b\x4d\x03\x86\xa5\x7f\x61\x2f\xcf\x7e\xff"));
    /* transaction id */
    ASSERT_EQ(0,
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_ID,
            (const uint8_t*)"\x1d\x6e\x32\xfa\x1f\x23\x49\xf4\xa5\xaa\x57\x05\x48\x93\xc5\xf6"));
    /* transaction link */
    ASSERT_EQ(0,
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_PREVIOUS_CERTIFICATE_ID,
            (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"));
    /* transaction type */
    ASSERT_EQ(0,
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_TRANSACTION_TYPE,
            (const uint8_t*)"\x17\xe1\xfc\x1f\x5d\xd9\x44\xa9\xb4\x9d\x1b\x6c\x1e\xb6\xd0\x11"));
    /* artifact type */
    ASSERT_EQ(0,
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_ARTIFACT_TYPE,
            (const uint8_t*)"\x6d\x34\x1a\x9b\x42\xaf\x45\x3d\xac\xdb\x4a\x99\x63\xd9\xd1\x4e"));
    /* artifact id */
    ASSERT_EQ(0,
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_ARTIFACT_ID,
            (const uint8_t*)"\x3e\xe2\x99\x7b\x2d\x4f\x48\x2e\x86\x58\x88\x86\x06\xd1\x35\x03"));
    /* previous state */
    ASSERT_EQ(0,
        vccert_builder_add_short_uint16(
            &builder, VCCERT_FIELD_TYPE_PREVIOUS_ARTIFACT_STATE, 0x0002));
    /* next state */
    ASSERT_EQ(0,
        vccert_builder_add_short_uint16(
            &builder, VCCERT_FIELD_TYPE_NEW_ARTIFACT_STATE, 0x0003));
    /* read the private key into a buffer */
    ASSERT_EQ(0,
        vccrypt_buffer_read_data(
            &private_key_buffer, PRIVATE_KEY, 64));
    /* sign the certificate */
    ASSERT_EQ(0,
        vccert_builder_sign(
            &builder, SIGNER_ID, &private_key_buffer));

    size_t size = 0;
    auto cert = vccert_builder_emit(&builder, &size);
    ASSERT_NE(nullptr, cert);
    ASSERT_NE(0U, size);

#if 0
    cout << "Size: " << size << endl << endl;

    for (size_t i = 0; i < size; ++i)
    {
        if (i % 16 == 0)
            cout << endl;

        cout << "0x";
        auto f = cout.flags();
        cout << hex << setw(2) << setfill('0') << (int)cert[i];
        cout.flags(f);
        cout << ", ";
    }
#endif
}

/**
 * Dummy transaction resolver.
 */
static bool dummy_txn_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccrypt_buffer_t*, bool*)
{
    return false;
}

/**
 * Dummy artifact state resolver.
 */
static int32_t dummy_artifact_state_resolver(
    void*, void*, const uint8_t*, vccrypt_buffer_t*)
{
    return -1;
}

/**
 * Dummy entity key resolver.
 */
static bool dummy_entity_key_resolver(
    void*, void*, uint64_t, const uint8_t*, vccrypt_buffer_t*,
    vccrypt_buffer_t*)
{
    return false;
}

/**
 * Dummy contract resolver.
 */
static int dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccert_contract_closure_t*)
{
    return VCCERT_ERROR_PARSER_ATTEST_MISSING_CONTRACT;
}
#endif
