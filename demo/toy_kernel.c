/* A tiny program with kernel-style types, built with BTF only (gcc -gbtf), for trying btf2ida in seconds. */
#include <stddef.h>

enum demo_state { DEMO_IDLE, DEMO_RUNNING = 5, DEMO_DONE };

struct demo_device;

struct demo_ops {
	int (*open)(struct demo_device *dev, unsigned int flags);
	void (*close)(struct demo_device *dev);
};

struct demo_device {
	unsigned long id;
	unsigned int ready : 1;
	unsigned int mode : 3;
	unsigned int refs : 12;
	enum demo_state state;
	union {
		void *ptr;
		unsigned long long raw;
	} cookie;
	struct {
		short x, y;
	};
	const struct demo_ops *ops;
	int private;
	unsigned char payload[];
};

__attribute__((noinline)) int demo_open(struct demo_device *dev, unsigned int flags)
{
	dev->state = DEMO_RUNNING;
	dev->mode = flags & 7;
	return dev->refs++;
}

__attribute__((noinline)) void demo_close(struct demo_device *dev)
{
	dev->state = DEMO_DONE;
}

const struct demo_ops demo_default_ops = { demo_open, demo_close };

__attribute__((noinline)) long demo_checksum(const struct demo_device *dev, size_t len)
{
	long sum = (long)dev->id + dev->x + dev->y + dev->private;
	for (size_t i = 0; i < len; i++)
		sum += dev->payload[i];
	return sum;
}

__attribute__((noinline)) int demo_dispatch(struct demo_device *dev, unsigned int flags)
{
	return dev->ops->open(dev, flags);
}

int main(void)
{
	static struct demo_device dev = { .id = 42, .ops = &demo_default_ops };
	return demo_dispatch(&dev, 3) + (int)demo_checksum(&dev, 0);
}
