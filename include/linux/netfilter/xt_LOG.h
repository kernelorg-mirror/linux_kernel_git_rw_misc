#ifndef _XT_LOG_H
#define _XT_LOG_H

/* make sure not to change this without changing nf_log.h:NF_LOG_* (!) */
#define XT_LOG_TCPSEQ		0x01	/* Log TCP sequence numbers */
#define XT_LOG_TCPOPT		0x02	/* Log TCP options */
#define XT_LOG_IPOPT		0x04	/* Log IP options */
#define XT_LOG_UID		0x08	/* Log UID owning local socket */
#define XT_LOG_NFLOG		0x10	/* Unsupported, don't reuse */
#define XT_LOG_MACDECODE	0x20	/* Decode MAC header */
#define XT_LOG_ADD_TIMESTAMP	0x40	/* Add a timestamp */
#define XT_LOG_MASK		0x6f

struct xt_log_info {
	unsigned char level;
	unsigned char logflags;
	char prefix[30];
};

struct xt_log_info_v1 {
	unsigned char level;
	unsigned char logflags;
	char prefix[30];

	char ring_name[30];
	__aligned_u64 ring_size;
	struct xt_LOG_ring_ctx *rctx __attribute__((aligned(8)));
};

#endif /* _XT_LOG_H */
