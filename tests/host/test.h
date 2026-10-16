/**
 * @file test.h — shared host-test harness: assertions + suite registry.
 *
 * Self-validating helpers first (no golden needed): T_OK/T_EQ for booleans and
 * integers, t_vec round-trip compares. For exact-byte pins use t_vec/t_u32 with
 * an empty expect string to RECORD the value, then bake it in (behavior-lock).
 * Each module under test exposes one void test_<module>(void) suite; test_main.c
 * runs them all and prints an aggregate PASS/FAIL/RECORD.
 */
#ifndef TINYTALK_HOST_TEST_H
#define TINYTALK_HOST_TEST_H

#include <stddef.h>
#include <stdint.h>

/* Reporting counters (defined in test.c). */
extern int t_fail;
extern int t_pending;
extern int t_pass;

/* hex helpers */
void t_hex(char *dst, const uint8_t *b, size_t n);
int t_unhex(uint8_t *dst, const char *hex, size_t cap);

/* Group header inside a suite. */
void t_group(const char *name);

/* Silence stdout across a call that prints firmware diagnostics by the
 * thousand-line (the CIR ring drain, the accumulator probe). Those are driven
 * for their state changes, not their text, and printing them buries the suite's
 * own output. Keep assertions OUTSIDE the muted region: t_ok_/t_eqi_ print only
 * on failure, so a muted assertion fails invisibly. Nesting is a no-op. */
void t_mute(void);
void t_unmute(void);

/* Byte-vector check. expect==NULL or "" => RECORD (print value, mark pending). */
void t_vec(const char *name, const uint8_t *got, size_t len, const char *expect);
void t_u32(const char *name, uint32_t v, const char *expect);
void t_u16(const char *name, uint16_t v, const char *expect);

/* Self-validating assertions (no golden). */
void t_ok_(const char *name, int cond, const char *file, int line);
void t_eqi_(const char *name, long got, long want, const char *file, int line);
#define T_OK(name, cond)      t_ok_((name), (cond), __FILE__, __LINE__)
#define T_EQ(name, got, want) t_eqi_((name), (long)(got), (long)(want), __FILE__, __LINE__)

/* Module suites — one per file under test. */
void test_tm_hash(void);
void test_matter_tlv(void);
void test_matter_msg(void);
void test_matter_mrp(void);
void test_matter_crypto(void);
void test_matter_btp(void);
void test_matter_pase(void);
void test_matter_spake2p(void);
void test_matter_pase_sm(void);
void test_matter_exchange(void);
void test_matter_im(void);
void test_matter_im_invoke(void);
void test_matter_im_write(void);
void test_matter_im_events(void);
void test_matter_attest(void);
void test_matter_fabric(void);
void test_matter_addnoc(void);
void test_matter_network(void);
void test_matter_case(void);
void test_matter_clusters(void);
void test_matter_commission(void);
void test_tm_app(void);
void test_root_clusters(void);
/* Only with the real curve; see the Makefile's SPAKE. */
void test_spake2p_mbedtls(void);

#endif /* TINYTALK_HOST_TEST_H */
