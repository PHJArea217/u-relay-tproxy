static int xcapset(const uint64_t caps[3]) {
	struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3, pid = 0};
	struct __user_cap_data_struct d[2] = {};
	d[0].effective = caps[0] & 0xffffffffU;
	d[0].permitted = caps[1] & 0xffffffffU;
	d[0].inheritable = caps[2] & 0xffffffffU;
	d[1].effective = caps[0] >> 32;
	d[1].permitted = caps[1] >> 32;
	d[1].inheritable = caps[2] >> 32;
	return syscall(SYS_capset, &h, d);
}
static int xcapget(uint64_t caps[3]) {
	struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3, pid = 0};
	struct __user_cap_data_struct d[2] = {};
	int rv = syscall(SYS_capget, &h, d);
	if (rv) return rv;
	caps[0] = (((uint64_t)d[0].effective) << 32) | d[1].effective;
	caps[1] = (((uint64_t)d[0].permitted) << 32) | d[1].permitted;
	caps[2] = (((uint64_t)d[0].inheritable) << 32) | d[1].inheritable;
	return 0;
}
static int set_noroot(int noroot) {
	int securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
	if (securebits < 0) return -1;
	if (noroot) {
		if (securebits & SECBIT_NOROOT) return 0;
		return prctl(PR_SET_SECUREBITS, securebits | SECBIT_NOROOT, 0, 0, 0);
	} else {
		return prctl(PR_SET_SECUREBITS, securebits & ~(SECBIT_NOROOT), 0, 0, 0);
	}
int i_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	uid_t olduids[3] = {1, 1, 1};
	if (i_getresuid(olduids)) goto fail;
	if (ruid == (uid_t)-1) ruid = olduids[0];
	if (euid == (uid_t)-1) euid = olduids[1];
	if (suid == (uid_t)-1) suid = olduids[2];
	if (euid) {
		/* only EUID 0 -> 1, keep caps in permitted, clear effective (except CAP_SETFCAP) */
		if (!ruid) { /* EUID != 0, RUID = 0. simple temporary privilege drop */
			if (set_noroot(1)) goto fail;
			uint64_t caps[3] = {0, 0, 0};
			if (xcapget(caps)) goto fail;
			caps[0] &= (1<<CAP_SETFCAP);
			if (xcapset(caps)) goto fail;
		}
		/* both EUID & RUID 0 -> 1, permanent drop */
		else {
			if (set_noroot(1)) goto fail;
			uint64_t caps[3] = {0, 0, 0};
			if (xcapget(caps)) goto fail;
			caps[0] = 0;
			caps[1] = 0;
			if (xcapset(caps)) goto fail;
		}
	} else {
#if 0
		if (ruid) { /* EUID = 0, RUID != 0, does nothing. */
		} else {
#endif
			/* EUID = 0, RUID = 0, revert temporary drop */
			if (set_noroot(0)) goto fail;
			uint64_t caps[3] = {0, 0, 0};
			if (xcapget(caps)) goto fail;
			caps[0] = caps[1];
			if (xcapset(caps)) goto fail;
		// }
	}
	return 0;
}
int i_getresuid(uid_t *uids) {
	uint64_t caps[3] = {0, 0, 0};
	if (xcapget(caps)) return -1;
	uids[0] = !(caps[1] & (1<<CAP_SYS_MODULE));
	uids[1] = !(caps[0] & (1<<CAP_SYS_MODULE));
	uids[2] = uids[0];
	return 0;
}
/* getresgid is the same as getresuid, setresgid and setgroups are successful no-ops. */
/* TODO: transparent chroot on setuid, block all uid/gid change in multithreaded app (determined by intercepting pthread_create) */
