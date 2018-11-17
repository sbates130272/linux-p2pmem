/* SPDX-License-Identifier: GPL-2.0 */
/*
 * C++ stream style string formatter and printer used in KUnit for outputting
 * KUnit messages.
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#ifndef _KUNIT_KUNIT_STREAM_H
#define _KUNIT_KUNIT_STREAM_H

#include <linux/types.h>
#include <kunit/string-stream.h>

struct kunit;

/**
 * struct kunit_stream - a std::stream style string builder.
 * @set_level: sets the level that this string should be printed at.
 * @add: adds the formatted input to the internal buffer.
 * @append: adds the contents of other to this.
 * @commit: prints out the internal buffer to the user.
 * @clear: clears the internal buffer.
 *
 * A std::stream style string builder. Allows messages to be built up and
 * printed all at once.
 */
struct kunit_stream {
	void (*set_level)(struct kunit_stream *this, const char *level);
	void (*add)(struct kunit_stream *this, const char *fmt, ...);
	void (*append)(struct kunit_stream *this, struct kunit_stream *other);
	void (*commit)(struct kunit_stream *this);
	void (*clear)(struct kunit_stream *this);
	/* private: internal use only. */
	struct kunit *test;
	spinlock_t lock; /* Guards level. */
	const char *level;
	struct string_stream *internal_stream;
};

/**
 * kunit_new_stream() - constructs a new &struct kunit_stream.
 * @test: The test context object.
 *
 * Constructs a new test managed &struct kunit_stream.
 */
struct kunit_stream *kunit_new_stream(struct kunit *test);

#endif /* _KUNIT_KUNIT_STREAM_H */
