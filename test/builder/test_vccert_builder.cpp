/**
 * \file test_vccert_builder.cpp
 *
 * Test the vccert builder methods.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vccert/builder.h>
#include <vccert/parser.h>
#include <vccrypt/suite.h>
#include <vpr/allocator/malloc_allocator.h>

//forward declarations for dummy certificate delegate methods
static bool dummy_entity_resolver(
    void*, void*, const uint8_t*, vccrypt_buffer_t*, bool*);
static int32_t dummy_state_resolver(
    void*, void*, const uint8_t*);
static vccert_contract_fn_t dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*);

const size_t CERT_MAX_SIZE = 1024;

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
                &parser_opts, &alloc_opts, &crypto_suite, &dummy_entity_resolver,
                &dummy_state_resolver, &dummy_contract_resolver,
                &dummy_context);

        builder_opts_init_result =
            vccert_builder_options_init(
                &builder_opts, &alloc_opts, &crypto_suite);

        builder_init_result =
            vccert_builder_init(&builder_opts, &builder, CERT_MAX_SIZE);
    }

    void TearDown() override
    {
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
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t crypto_suite;
    vccert_parser_options_t parser_opts;
    vccert_builder_options_t builder_opts;
    vccert_builder_context_t builder;
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

/**
 * Dummy entity resolver.
 */
static bool dummy_entity_resolver(
    void*, void*, const uint8_t*, vccrypt_buffer_t*, bool*)
{
    return false;
}

/**
 * Dummy entity state resolver.
 */
static int32_t dummy_state_resolver(
    void*, void*, const uint8_t*)
{
    return 0;
}

/**
 * Dummy contract resolver.
 */
static vccert_contract_fn_t dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*)
{
    return NULL;
}
