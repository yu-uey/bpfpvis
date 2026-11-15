struct pd_key {
	__u32 tgid;
};

struct pd_value {
	__u64 cycles;
};

struct pd_extra {
	struct pd_key parent;
	char comm[16];
	__u32 uid;
	__u32 gid;
};
