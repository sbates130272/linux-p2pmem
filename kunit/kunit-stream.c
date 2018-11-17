// SPDX-License-Identifier: GPL-2.0
/*
 * C++ stream style string formatter and printer used in KUnit for outputting
 * KUnit messages.
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#include <kunit/test.h>
#include <kunit/kunit-stream.h>
#include <kunit/string-stream.h>

static const char *kunit_stream_get_level(struct kunit_stream *this)
{
	unsigned long flags;
	const char *level;

	spin_lock_irqsave(&this->lock, flags);
	level = this->level;
	spin_unlock_irqrestore(&this->lock, flags);

	return level;
}

static void kunit_stream_set_level(struct kunit_stream *this, const char *level)
{
	unsigned long flags;

	spin_lock_irqsave(&this->lock, flags);
	this->level = level;
	spin_unlock_irqrestore(&this->lock, flags);
}

static void kunit_stream_add(struct kunit_stream *this, const char *fmt, ...)
{
	va_list args;
	struct string_stream *stream = this->internal_stream;

	va_start(args, fmt);
	if (stream->vadd(stream, fmt, args) < 0)
		kunit_err(this->test, "Failed to allocate fragment: %s", fmt);

	va_end(args);
}

static void kunit_stream_append(struct kunit_stream *this,
				struct kunit_stream *other)
{
	struct string_stream *other_stream = other->internal_stream;
	const char *other_content;

	other_content = other_stream->get_string(other_stream);

	if (!other_content) {
		kunit_err(this->test,
			  "Failed to get string from second argument for appending.");
		return;
	}

	this->add(this, other_content);
}

static void kunit_stream_clear(struct kunit_stream *this)
{
	this->internal_stream->clear(this->internal_stream);
}

static void kunit_stream_commit(struct kunit_stream *this)
{
	struct string_stream *stream = this->internal_stream;
	struct string_stream_fragment *fragment;
	const char *level;
	char *buf;

	level = kunit_stream_get_level(this);
	if (!level) {
		kunit_err(this->test,
			  "Stream was committed without a specified log level.");
		level = KERN_ERR;
		this->set_level(this, level);
	}

	buf = stream->get_string(stream);
	if (!buf) {
		kunit_err(this->test,
			 "Could not allocate buffer, dumping stream:");
		list_for_each_entry(fragment, &stream->fragments, node) {
			kunit_err(this->test, fragment->fragment);
		}
		goto cleanup;
	}

	kunit_printk(level, this->test, buf);
	kfree(buf);

cleanup:
	this->clear(this);
}

static int kunit_stream_init(struct kunit_resource *res, void *context)
{
	struct kunit *test = context;
	struct kunit_stream *stream;

	stream = kzalloc(sizeof(*stream), GFP_KERNEL);
	if (!stream)
		return -ENOMEM;
	res->allocation = stream;
	stream->test = test;
	spin_lock_init(&stream->lock);
	stream->internal_stream = new_string_stream();

	if (!stream->internal_stream)
		return -ENOMEM;

	stream->set_level = kunit_stream_set_level;
	stream->add = kunit_stream_add;
	stream->append = kunit_stream_append;
	stream->commit = kunit_stream_commit;
	stream->clear = kunit_stream_clear;

	return 0;
}

static void kunit_stream_free(struct kunit_resource *res)
{
	struct kunit_stream *stream = res->allocation;

	if (!stream->internal_stream->is_empty(stream->internal_stream)) {
		kunit_err(stream->test,
			 "End of test case reached with uncommitted stream entries.");
		stream->commit(stream);
	}

	destroy_string_stream(stream->internal_stream);
	kfree(stream);
}

struct kunit_stream *kunit_new_stream(struct kunit *test)
{
	struct kunit_resource *res;

	res = kunit_alloc_resource(test,
				   kunit_stream_init,
				   kunit_stream_free,
				   test);

	if (res)
		return res->allocation;
	else
		return NULL;
}
