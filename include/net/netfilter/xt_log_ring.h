#ifndef XT_LOG_RING_H
#define XT_LOG_RING_H

struct xt_LOG_ring_ctx;
struct xt_LOG_ring_ctx *xt_LOG_ring_new_ctx(const char *name, size_t rb_size);
int xt_LOG_ring_add_record(const struct xt_LOG_ring_ctx *rctx, const char *buf, unsigned int len);
void xt_LOG_ring_get(struct xt_LOG_ring_ctx *ctx);
void xt_LOG_ring_put(struct xt_LOG_ring_ctx *ctx);
struct xt_LOG_ring_ctx *xt_LOG_ring_find_ctx(const char *name);

#ifdef CONFIG_NETFILTER_XT_TARGET_LOG_RING
void xt_LOG_ring_exit(void);
int xt_LOG_ring_init(void);
#else
static inline void xt_LOG_ring_exit(void)
{
}

static inline int xt_LOG_ring_init(void)
{
	return 0;
}
#endif
#endif
