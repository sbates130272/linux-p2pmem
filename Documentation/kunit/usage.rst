.. SPDX-License-Identifier: GPL-2.0

=============
Using KUnit
=============

The purpose of this document is to describe what KUnit is, how it works, how it
is intended to be used, and all the concepts and terminology that are needed to
understand it. This guide assumes a working knowledge of the Linux kernel and
some basic knowledge of testing.

For a high level introduction to KUnit, including setting up KUnit for your
project, see :doc:`start`.

Organization of this document
=================================

This document is organized into two main sections: Testing and Isolating
Behavior. The first covers what a unit test is and how to use KUnit to write
them. The second covers how to use KUnit to isolate code and make it possible
to unit test code that was otherwise un-unit-testable.

Testing
==========

What is KUnit?
------------------

"K" is short for "kernel" so "KUnit" is the "(Linux) Kernel Unit Testing
Framework." KUnit is intended first and foremost for writing unit tests; it is
general enough that it can be used to write integration tests; however, this is
a secondary goal. KUnit has no ambition of being the only testing framework for
the kernel; for example, it does not intend to be an end-to-end testing
framework.

What is Unit Testing?
-------------------------

A `unit test <https://martinfowler.com/bliki/UnitTest.html>`_ is a test that
tests code at the smallest possible scope, a *unit* of code. In the C
programming language that's a function.

Unit tests should be written for all the publicly exposed functions in a
compilation unit; so that is all the functions that are exported in either a
*class* (defined below) or all functions which are **not** static.

Writing Tests
-------------

Test Cases
~~~~~~~~~~

The fundamental unit in KUnit is the test case. A test case is a function with
the signature ``void (*)(struct kunit *test)``. It calls a function to be tested
and then sets *expectations* for what should happen. For example:

.. code-block:: c

	void example_test_success(struct kunit *test)
	{
	}

	void example_test_failure(struct kunit *test)
	{
		KUNIT_FAIL(test, "This test never passes.");
	}

In the above example ``example_test_success`` always passes because it does
nothing; no expectations are set, so all expectations pass. On the other hand
``example_test_failure`` always fails because it calls ``KUNIT_FAIL``, which is
a special expectation that logs a message and causes the test case to fail.

Expectations
~~~~~~~~~~~~
An *expectation* is a way to specify that you expect a piece of code to do
something in a test. An expectation is called like a function. A test is made
by setting expectations about the behavior of a piece of code under test; when
one or more of the expectations fail, the test case fails and information about
the failure is logged. For example:

.. code-block:: c

	void add_test_basic(struct kunit *test)
	{
		KUNIT_EXPECT_EQ(test, 1, add(1, 0));
		KUNIT_EXPECT_EQ(test, 2, add(1, 1));
	}

In the above example ``add_test_basic`` makes a number of assertions about the
behavior of a function called ``add``; the first parameter is always of type
``struct kunit *``, which contains information about the current test context;
the second parameter, in this case, is what the value is expected to be; the
last value is what the value actually is. If ``add`` passes all of these
expectations, the test case, ``add_test_basic`` will pass; if any one of these
expectations fail, the test case will fail.

It is important to understand that a test case *fails* when any expectation is
violated; however, the test will continue running, potentially trying other
expectations until the test case ends or is otherwise terminated. This is as
opposed to *assertions* which are discussed later.

To learn about more expectations supported by KUnit, see :doc:`api/test`.

.. note::
   A single test case should be pretty short, pretty easy to understand,
   focused on a single behavior.

For example, if we wanted to properly test the add function above, we would
create additional tests cases which would each test a different property that an
add function should have like this:

.. code-block:: c

	void add_test_basic(struct kunit *test)
	{
		KUNIT_EXPECT_EQ(test, 1, add(1, 0));
		KUNIT_EXPECT_EQ(test, 2, add(1, 1));
	}

	void add_test_negative(struct kunit *test)
	{
		KUNIT_EXPECT_EQ(test, 0, add(-1, 1));
	}

	void add_test_max(struct kunit *test)
	{
		KUNIT_EXPECT_EQ(test, INT_MAX, add(0, INT_MAX));
		KUNIT_EXPECT_EQ(test, -1, add(INT_MAX, INT_MIN));
	}

	void add_test_overflow(struct kunit *test)
	{
		KUNIT_EXPECT_EQ(test, INT_MIN, add(INT_MAX, 1));
	}

Notice how it is immediately obvious what all the properties that we are testing
for are.

Assertions
~~~~~~~~~~

KUnit also has the concept of an *assertion*. An assertion is just like an
expectation except the assertion immediately terminates the test case if it is
not satisfied.

For example:

.. code-block:: c

	static void mock_test_do_expect_default_return(struct kunit *test)
	{
		struct mock_test_context *ctx = test->priv;
		struct mock *mock = ctx->mock;
		int param0 = 5, param1 = -5;
		const char *two_param_types[] = {"int", "int"};
		const void *two_params[] = {&param0, &param1};
		const void *ret;

		ret = mock->do_expect(mock,
				      "test_printk", test_printk,
				      two_param_types, two_params,
				      ARRAY_SIZE(two_params));
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ret);
		KUNIT_EXPECT_EQ(test, -4, *((int *) ret));
	}

In this example, the method under test should return a pointer to a value, so
if the pointer returned by the method is null or an errno, we don't want to
bother continuing the test since the following expectation could crash the test
case. `ASSERT_NOT_ERR_OR_NULL(...)` allows us to bail out of the test case if
the appropriate conditions have not been satisfied to complete the test.

Modules / Test Suites
~~~~~~~~~~~~~~~~~~~~~

Now obviously one unit test isn't very helpful; the power comes from having
many test cases covering all of your behaviors. Consequently it is common to
have many *similar* tests; in order to reduce duplication in these closely
related tests most unit testing frameworks provide the concept of a *test
suite*, in KUnit we call it a *test module*; all it is is just a collection of
test cases for a unit of code with a set up function that gets invoked before
every test cases and then a tear down function that gets invoked after every
test case completes.

Example:

.. code-block:: c

	static struct kunit_case example_test_cases[] = {
		KUNIT_CASE(example_test_foo),
		KUNIT_CASE(example_test_bar),
		KUNIT_CASE(example_test_baz),
		{},
	};

	static struct kunit_module example_test_module[] = {
		.name = "example",
		.init = example_test_init,
		.exit = example_test_exit,
		.test_cases = example_test_cases,
	};
	module_test(example_test_module);

In the above example the test suite, ``example_test_module``, would run the test
cases ``example_test_foo``, ``example_test_bar``, and ``example_test_baz``, each
would have ``example_test_init`` called immediately before it and would have
``example_test_exit`` called immediately after it.
``module_test(example_test_module)`` registers the test suite with the KUnit
test framework.

.. note::
   A test case will only be run if it is associated with a test suite.

For a more information on these types of things see the :doc:`api/test`.

Isolating Behavior
==================

The most important aspect of unit testing that other forms of testing do not
provide is the ability to limit the amount of code under test to a single unit.
In practice, this is only possible by being able to control what code gets run
when the unit under test calls a function and this is usually accomplished
through some sort of indirection where a function is exposed as part of an API
such that the definition of that function can be changed without affecting the
rest of the code base. In the kernel this primarily comes from two constructs,
classes, structs that contain function pointers that are provided by the
implementer, and architecture specific functions which have definitions selected
at compile time.

Classes
-------

Classes are not a construct that is built into the C programming language;
however, it is an easily derived concept. Accordingly, pretty much every project
that does not use a standardized object oriented library (like GNOME's GObject)
has their own slightly different way of doing object oriented programming; the
Linux kernel is no exception.

The central concept in kernel object oriented programming is the class. In the
kernel, a *class* is a struct that contains function pointers. This creates a
contract between *implementers* and *users* since it forces them to use the
same function signature without having to call the function directly. In order
for it to truly be a class, the function pointers must specify that a pointer
to the class, known as a *class handle*, be one of the parameters; this makes
it possible for the member functions (also known as *methods*) to have access
to member variables (more commonly known as *fields*) allowing the same
implementation to have multiple *instances*.

Typically a class can be *overridden* by *child classes* by embedding the
*parent class* in the child class. Then when a method provided by the child
class is called, the child implementation knows that the pointer passed to it is
of a parent contained within the child; because of this, the child can compute
the pointer to itself because the pointer to the parent is always a fixed offset
from the pointer to the child; this offset is the offset of the parent contained
in the child struct. For example:

.. code-block:: c

	struct shape {
		int (*area)(struct shape *this);
	};

	struct rectangle {
		struct shape parent;
		int length;
		int width;
	};

	int rectangle_area(struct shape *this)
	{
		struct rectangle *self = container_of(this, struct shape, parent);

		return self->length * self->width;
	};

	void rectangle_new(struct rectangle *self, int length, int width)
	{
		self->parent.area = rectangle_area;
		self->length = length;
		self->width = width;
	}

In this example (as in most kernel code) the operation of computing the pointer
to the child from the pointer to the parent is done by ``container_of``.

Faking Classes
~~~~~~~~~~~~~~

In order to unit test a piece of code that calls a method in a class, the
behavior of the method must be controllable, otherwise the test ceases to be a
unit test and becomes an integration test.

A fake just provides an implementation of a piece of code that is different than
what runs in a production instance, but behaves identically from the standpoint
of the callers; this is usually done to replace a dependency that is hard to
deal with, or is slow.

A good example for this might be implementing a fake EEPROM that just stores the
"contents" in an internal buffer. For example, let's assume we have a class that
represents an EEPROM:

.. code-block:: c

	struct eeprom {
		ssize_t (*read)(struct eeprom *this, size_t offset, char *buffer, size_t count);
		ssize_t (*write)(struct eeprom *this, size_t offset, const char *buffer, size_t count);
	};

And we want to test some code that buffers writes to the EEPROM:

.. code-block:: c

	struct eeprom_buffer {
		ssize_t (*write)(struct eeprom_buffer *this, const char *buffer, size_t count);
		int flush(struct eeprom_buffer *this);
		size_t flush_count; /* Flushes when buffer exceeds flush_count. */
	};

	struct eeprom_buffer *new_eeprom_buffer(struct eeprom *eeprom);
	void destroy_eeprom_buffer(struct eeprom *eeprom);

We can easily test this code by *faking out* the underlying EEPROM:

.. code-block:: c

	struct fake_eeprom {
		struct eeprom parent;
		char contents[FAKE_EEPROM_CONTENTS_SIZE];
	};

	ssize_t fake_eeprom_read(struct eeprom *parent, size_t offset, char *buffer, size_t count)
	{
		struct fake_eeprom *this = container_of(parent, struct fake_eeprom, parent);

		count = min(count, FAKE_EEPROM_CONTENTS_SIZE - offset);
		memcpy(buffer, this->contents + offset, count);

		return count;
	}

	ssize_t fake_eeprom_write(struct eeprom *this, size_t offset, const char *buffer, size_t count)
	{
		struct fake_eeprom *this = container_of(parent, struct fake_eeprom, parent);

		count = min(count, FAKE_EEPROM_CONTENTS_SIZE - offset);
		memcpy(this->contents + offset, buffer, count);

		return count;
	}

	void fake_eeprom_init(struct fake_eeprom *this)
	{
		this->parent.read = fake_eeprom_read;
		this->parent.write = fake_eeprom_write;
		memset(this->contents, 0, FAKE_EEPROM_CONTENTS_SIZE);
	}

We can now use it to test ``struct eeprom_buffer``:

.. code-block:: c

	struct eeprom_buffer_test {
		struct fake_eeprom *fake_eeprom;
		struct eeprom_buffer *eeprom_buffer;
	};

	static void eeprom_buffer_test_does_not_write_until_flush(struct kunit *test)
	{
		struct eeprom_buffer_test *ctx = test->priv;
		struct eeprom_buffer *eeprom_buffer = ctx->eeprom_buffer;
		struct fake_eeprom *fake_eeprom = ctx->fake_eeprom;
		char buffer[] = {0xff};

		eeprom_buffer->flush_count = SIZE_MAX;

		eeprom_buffer->write(eeprom_buffer, buffer, 1);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[0], 0);

		eeprom_buffer->write(eeprom_buffer, buffer, 1);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[1], 0);

		eeprom_buffer->flush(eeprom_buffer);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[0], 0xff);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[1], 0xff);
	}

	static void eeprom_buffer_test_flushes_after_flush_count_met(struct kunit *test)
	{
		struct eeprom_buffer_test *ctx = test->priv;
		struct eeprom_buffer *eeprom_buffer = ctx->eeprom_buffer;
		struct fake_eeprom *fake_eeprom = ctx->fake_eeprom;
		char buffer[] = {0xff};

		eeprom_buffer->flush_count = 2;

		eeprom_buffer->write(eeprom_buffer, buffer, 1);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[0], 0);

		eeprom_buffer->write(eeprom_buffer, buffer, 1);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[0], 0xff);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[1], 0xff);
	}

	static void eeprom_buffer_test_flushes_increments_of_flush_count(struct kunit *test)
	{
		struct eeprom_buffer_test *ctx = test->priv;
		struct eeprom_buffer *eeprom_buffer = ctx->eeprom_buffer;
		struct fake_eeprom *fake_eeprom = ctx->fake_eeprom;
		char buffer[] = {0xff, 0xff};

		eeprom_buffer->flush_count = 2;

		eeprom_buffer->write(eeprom_buffer, buffer, 1);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[0], 0);

		eeprom_buffer->write(eeprom_buffer, buffer, 2);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[0], 0xff);
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[1], 0xff);
		/* Should have only flushed the first two bytes. */
		KUNIT_EXPECT_EQ(test, fake_eeprom->contents[2], 0);
	}

	static int eeprom_buffer_test_init(struct kunit *test)
	{
		struct eeprom_buffer_test *ctx;

		ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
		ASSERT_NOT_ERR_OR_NULL(test, ctx);

		ctx->fake_eeprom = kunit_kzalloc(test, sizeof(*ctx->fake_eeprom), GFP_KERNEL);
		ASSERT_NOT_ERR_OR_NULL(test, ctx->fake_eeprom);

		ctx->eeprom_buffer = new_eeprom_buffer(&ctx->fake_eeprom->parent);
		ASSERT_NOT_ERR_OR_NULL(test, ctx->eeprom_buffer);

		test->priv = ctx;

		return 0;
	}

	static void eeprom_buffer_test_exit(struct kunit *test)
	{
		struct eeprom_buffer_test *ctx = test->priv;

		destroy_eeprom_buffer(ctx->eeprom_buffer);
	}

