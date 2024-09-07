#define _GNU_SOURCE
#include <string.h>
#include "preload.h"
#define globals urtp_preload_globals
static void sockaddr_un_subst(const struct sockaddr_in6 *sockaddr, struct sockaddr_un *resultant, uint32_t length) {
	char *subst_val = memmem(resultant->sun_path, length, "#//0_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[0]), subst_val);
	subst_val = memmem(resultant->sun_path, length, "#//1_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[1]), subst_val);
	subst_val = memmem(resultant->sun_path, length, "#//2_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[2]), subst_val);
	subst_val = memmem(resultant->sun_path, length, "#//3_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[3]), subst_val);
	subst_val = memmem(resultant->sun_path, length, "#//4_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[4]), subst_val);
	subst_val = memmem(resultant->sun_path, length, "#//5_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[5]), subst_val);
	subst_val = memmem(resultant->sun_path, length, "#//6_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[6]), subst_val);
	subst_val = memmem(resultant->sun_path, length, "#//7_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[7]), subst_val);
	subst_val = memmem(resultant->sun_path, length, "#//P_", 5);
	if (subst_val) globals->int16tonum(ntohs(sockaddr->sin6_port), subst_val);
}
struct urtp_t1_globals t1_globals_m = {
	.sockaddr_un_subst = sockaddr_un_subst
};
struct urtp_t1_globals *urtp_preload_t1_globals = &t1_globals_m;
