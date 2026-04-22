/*
 * PoC: Kernel Information Disclosure via mbuf Length Desynchronization
 *      in IPv6 Neighbor Discovery Proxy (nd6_prproxy_ns_output)
 *
 * Title:      Kernel Information Disclosure via mbuf Length Desynchronization
 *             in IPv6 Neighbor Discovery Proxy (nd6_prproxy_ns_output)
 * Researcher: Ruwanpurage Pawan Nimesh Ranasinghe ("proudlion")
 * Target:     XNU Kernel -- bsd/netinet6/nd6_prproxy.c
 * CWE:        CWE-908 (Use of Uninitialized Resource)
 *             CWE-200 (Exposure of Sensitive Information)
 *
 * Build:
 *   gcc -Wall -o poc_nd6_mbuf_desync poc_nd6_mbuf_desync.c
 *   ./poc_nd6_mbuf_desync
 *
 * Notes on region classification:
 *   Bytes [0..39]  = IPv6 header -- NOT written by nd6_prproxy_ns_output.
 *                    This is EXPECTED: ip6_output fills this region later.
 *                    Both vulnerable and fixed paths leave this uninit.
 *                    NOT counted as a leak.
 *
 *   Bytes [40..63] = NS header -- written correctly in both paths.
 *
 *   Bytes [64..71] = Options region -- written in both paths (Nonce wins
 *                    due to pointer reset in vulnerable path).
 *
 *   Bytes [72..79] = ONLY present in vulnerable path's m_len accounting.
 *                    Never written. Contains heap residue.
 *                    THIS is the actual leak (8 bytes).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* -----------------------------------------------------------------------
 * Region classification -- used to separate "expected uninit" (IPv6 hdr,
 * filled by ip6_output) from "unexpected uninit" (the actual leak).
 * ---------------------------------------------------------------------- */
typedef enum {
    REGION_IPV6_HDR  = 0,   /* [0..39]  -- expected uninit, ip6_output fills */
    REGION_NS_HDR    = 1,   /* [40..63] -- should always be written          */
    REGION_OPTIONS   = 2,   /* [64..71] -- should be written by prproxy      */
    REGION_LEAK      = 3,   /* [72..79] -- only in vuln path, never written  */
} region_t;

#define MHLEN          256
#define IPV6_HDR_SIZE  40
#define NS_HDR_SIZE    24   /* sizeof(struct nd_neighbor_solicit)             */
#define OPTIONS_START  (IPV6_HDR_SIZE + NS_HDR_SIZE)   /* 64 */
#define OPTIONS_END    (OPTIONS_START + 8)              /* 72 */
#define FULL_PKT_LEN   (OPTIONS_END + 8)                /* 80 -- vuln m_len  */

typedef struct { int len; int rcvif; } pkthdr_t;

typedef struct {
    pkthdr_t m_pkthdr;
    int      m_len;
    uint8_t  m_data[MHLEN];
    bool     m_init[MHLEN];   /* shadow: tracks explicit writes            */
} mbuf_t;

/* ICMPv6 NS header (RFC 4861 s4.3) */
typedef struct {
    uint8_t  nd_ns_type;
    uint8_t  nd_ns_code;
    uint16_t nd_ns_cksum;
    uint32_t nd_ns_reserved;
    uint8_t  nd_ns_target[16];
} nd_ns_t;

typedef struct { uint8_t nd_opt_type; uint8_t nd_opt_len; } nd_opt_hdr_t;
typedef struct { nd_opt_hdr_t hdr; uint8_t addr[6];  } nd_opt_sllao_t;
typedef struct { nd_opt_hdr_t hdr; uint8_t nonce[6]; } nd_opt_nonce_t;

/* -----------------------------------------------------------------------
 * Simulated m_gethdr()
 *
 * XNU's m_gethdr does NOT zero the data region.
 * Fill with 0xAB to represent uninitialized heap slab content.
 * ---------------------------------------------------------------------- */
static mbuf_t *sim_m_gethdr(void)
{
    mbuf_t *m = malloc(sizeof(mbuf_t));
    if (!m) { perror("malloc"); exit(1); }
    memset(m->m_data, 0xAB, MHLEN);  /* uninitialized heap residue         */
    memset(m->m_init, 0,    MHLEN);  /* nothing written yet                */
    m->m_len = 0;
    m->m_pkthdr.len = 0;
    return m;
}

static void mark_init(mbuf_t *m, int off, int len)
{
    for (int i = off; i < off + len && i < MHLEN; i++)
        m->m_init[i] = true;
}

static region_t classify(int offset)
{
    if (offset < IPV6_HDR_SIZE)     return REGION_IPV6_HDR;
    if (offset < OPTIONS_START)     return REGION_NS_HDR;
    if (offset < OPTIONS_END)       return REGION_OPTIONS;
    return REGION_LEAK;
}

/* -----------------------------------------------------------------------
 * VULNERABLE construction
 *
 * Mirrors nd6_prproxy_ns_output() logic where the Nonce option write
 * pointer is re-derived from a fixed (ip6_hdr + nd_ns) offset instead
 * of advancing past the previously appended SLLAO option.
 *
 * Result:
 *   - SLLAO bytes [64..71] are overwritten by Nonce
 *   - m_len counts 8 bytes for SLLAO + 8 for Nonce = 80
 *   - bytes [72..79] are never written
 *   - ip6_output transmits all 80 bytes, leaking bytes [72..79]
 * ---------------------------------------------------------------------- */
static mbuf_t *sim_vuln(void)
{
    mbuf_t  *m    = sim_m_gethdr();
    uint8_t *base = m->m_data;
    int      off;

    /* Step 1: account for IPv6 + NS headers (IPv6 hdr written by ip6_output) */
    m->m_len        = IPV6_HDR_SIZE + NS_HDR_SIZE;
    m->m_pkthdr.len = m->m_len;

    /* Step 2: write NS header */
    nd_ns_t *ns = (nd_ns_t *)(base + IPV6_HDR_SIZE);
    ns->nd_ns_type     = 135;
    ns->nd_ns_code     = 0;
    ns->nd_ns_cksum    = 0;
    ns->nd_ns_reserved = 0;
    memset(ns->nd_ns_target, 0, 15);
    ns->nd_ns_target[15] = 1;
    mark_init(m, IPV6_HDR_SIZE, NS_HDR_SIZE);

    off = IPV6_HDR_SIZE + NS_HDR_SIZE;   /* = 64 */

    /* Step 3: SLLAO append */
    nd_opt_sllao_t *sllao = (nd_opt_sllao_t *)(base + off);
    sllao->hdr.nd_opt_type = 1;
    sllao->hdr.nd_opt_len  = 1;
    uint8_t mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    memcpy(sllao->addr, mac, 6);
    m->m_len        += 8;
    m->m_pkthdr.len += 8;
    mark_init(m, off, 8);
    printf("  [WRITE] SLLAO at offset %-3d  bytes [%d..%d]\n", off, off, off+7);

    /*
     * Step 4: Nonce append
     *
     * BUG: pointer reset to fixed offset (IPV6_HDR_SIZE + NS_HDR_SIZE = 64)
     *      instead of advancing to current m->m_len (= 72).
     *
     * XNU source pattern:
     *   optp = (struct nd_opt_hdr *)(mtod(m, caddr_t)
     *            + sizeof(struct ip6_hdr)
     *            + sizeof(struct nd_neighbor_solicit));   <-- hardcoded 64
     */
    nd_opt_nonce_t *nopt = (nd_opt_nonce_t *)(base + off);  /* off still 64 */
    nopt->hdr.nd_opt_type = 14;
    nopt->hdr.nd_opt_len  = 1;
    uint8_t nonce[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(nopt->nonce, nonce, 6);
    m->m_len        += 8;   /* m_len = 80 -- claims slot [72..79] */
    m->m_pkthdr.len += 8;
    mark_init(m, off, 8);   /* marks [64..71] again -- [72..79] never touched */
    printf("  [WRITE] Nonce  at offset %-3d  bytes [%d..%d]"
           "  <-- BUG: same offset as SLLAO\n", off, off, off+7);
    printf("          Bytes [72..79] counted in m_len but NEVER written.\n");

    return m;
}

/* -----------------------------------------------------------------------
 * FIXED construction
 *
 * Fix: derive option write pointer from current m->m_len after each
 * append, not from a fixed header offset.
 * ---------------------------------------------------------------------- */
static mbuf_t *sim_fixed(void)
{
    mbuf_t  *m    = sim_m_gethdr();
    uint8_t *base = m->m_data;
    int      off;

    m->m_len        = IPV6_HDR_SIZE + NS_HDR_SIZE;
    m->m_pkthdr.len = m->m_len;

    nd_ns_t *ns = (nd_ns_t *)(base + IPV6_HDR_SIZE);
    ns->nd_ns_type     = 135;
    ns->nd_ns_code     = 0;
    ns->nd_ns_cksum    = 0;
    ns->nd_ns_reserved = 0;
    memset(ns->nd_ns_target, 0, 15);
    ns->nd_ns_target[15] = 1;
    mark_init(m, IPV6_HDR_SIZE, NS_HDR_SIZE);

    off = IPV6_HDR_SIZE + NS_HDR_SIZE;   /* = 64 */

    /* SLLAO */
    nd_opt_sllao_t *sllao = (nd_opt_sllao_t *)(base + off);
    sllao->hdr.nd_opt_type = 1;
    sllao->hdr.nd_opt_len  = 1;
    uint8_t mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    memcpy(sllao->addr, mac, 6);
    mark_init(m, off, 8);
    m->m_len        += 8;
    m->m_pkthdr.len += 8;
    off             += 8;   /* <-- FIXED: advance past SLLAO (off = 72)    */

    /* Nonce -- pointer now at correct offset 72 */
    nd_opt_nonce_t *nopt = (nd_opt_nonce_t *)(base + off);
    nopt->hdr.nd_opt_type = 14;
    nopt->hdr.nd_opt_len  = 1;
    uint8_t nonce[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(nopt->nonce, nonce, 6);
    mark_init(m, off, 8);
    m->m_len        += 8;
    m->m_pkthdr.len += 8;

    return m;
}

/* -----------------------------------------------------------------------
 * Annotated hex dump
 *
 * Distinguishes three init states per byte:
 *   OK             -- explicitly written by this function
 *   EXPECTED-UNINIT -- IPv6 header region, filled later by ip6_output
 *   *** LEAK ***   -- NOT OK and NOT in IPv6 hdr region = actual bug
 * ---------------------------------------------------------------------- */
static void dump(const char *label, mbuf_t *m)
{
    printf("\n");
    printf("=================================================================\n");
    printf(" %s\n", label);
    printf(" m_len = %d bytes  (ip6_output will transmit exactly this many)\n",
           m->m_len);
    printf("=================================================================\n");
    printf(" Offset | Hex (16 bytes/row)                | Status\n");
    printf("--------|-----------------------------------|-----------------------\n");

    for (int i = 0; i < m->m_len; i++) {
        if (i % 16 == 0) printf(" %04d   | ", i);
        printf("%02X ", m->m_data[i]);

        if (i % 16 == 15 || i == m->m_len - 1) {
            int pad = 15 - (i % 16);
            for (int p = 0; p < pad; p++) printf("   ");
            printf("| ");

            int row_start = i - (i % 16);
            bool any_leak     = false;
            bool any_expected = false;
            bool all_ok       = true;

            for (int j = row_start; j <= i; j++) {
                region_t r = classify(j);
                if (!m->m_init[j]) {
                    all_ok = false;
                    if (r == REGION_IPV6_HDR) any_expected = true;
                    else                      any_leak     = true;
                }
            }

            if (all_ok)                          printf("OK");
            else if (any_leak && any_expected)   printf("*** LEAK *** + ipv6-hdr");
            else if (any_leak)                   printf("*** LEAK (heap residue) ***");
            else if (any_expected)               printf("expected-uninit (ip6_output fills)");
            printf("\n");
        }
    }
}

/* -----------------------------------------------------------------------
 * Summary: count only the bytes that are genuinely unexpected leaks
 * (i.e. uninit AND not in the IPv6 header region).
 * ---------------------------------------------------------------------- */
static int count_leaks(mbuf_t *m)
{
    int n = 0;
    for (int i = 0; i < m->m_len; i++)
        if (!m->m_init[i] && classify(i) != REGION_IPV6_HDR)
            n++;
    return n;
}

/* -----------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------- */
int main(void)
{
    printf("\n");
    printf("#################################################################\n");
    printf("##  XNU nd6_prproxy_ns_output -- mbuf Desync PoC              ##\n");
    printf("##  CWE-908: Use of Uninitialized Resource                    ##\n");
    printf("##  Researcher: proudlion                                     ##\n");
    printf("#################################################################\n");
    printf("\n");
    printf(" Packet layout under test:\n");
    printf("   [0..39]  IPv6 hdr      (ip6_output fills -- expected uninit here)\n");
    printf("   [40..63] NS header     (nd6_prproxy_ns_output writes)\n");
    printf("   [64..71] Options slot  (SLLAO + Nonce -- prproxy writes)\n");
    printf("   [72..79] *** LEAK ***  (only in vuln path m_len; never written)\n");
    printf("\n");

    printf("[*] VULNERABLE construction (pointer reset bug):\n");
    mbuf_t *mv = sim_vuln();
    dump("VULNERABLE -- outgoing NS packet as seen by ip6_output", mv);

    printf("\n[*] FIXED construction (pointer advances after each option):\n");
    mbuf_t *mf = sim_fixed();
    dump("FIXED -- outgoing NS packet as seen by ip6_output", mf);

    int lv = count_leaks(mv);
    int lf = count_leaks(mf);

    printf("\n");
    printf("=================================================================\n");
    printf(" RESULT SUMMARY\n");
    printf("=================================================================\n");
    printf(" Path        m_len   Unexpected uninit bytes in transmitted range\n");
    printf(" ----------  -----   -------------------------------------------\n");
    printf(" Vulnerable   %3d    %d byte(s) at offsets [72..79]  <-- LEAK\n",
           mv->m_len, lv);
    printf(" Fixed        %3d    %d byte(s)                       <-- CLEAN\n",
           mf->m_len, lf);
    printf("\n");
    printf(" NOTE: Both paths leave bytes [0..39] uninit. This is EXPECTED\n");
    printf(" behavior -- ip6_output fills the IPv6 header before transmission.\n");
    printf(" That region is excluded from the leak count above.\n");
    printf("\n");
    printf(" ROOT CAUSE:\n");
    printf("   In nd6_prproxy_ns_output(), the Nonce option write pointer is\n");
    printf("   re-derived from a fixed offset:\n");
    printf("     (mtod(m,caddr_t) + sizeof(ip6_hdr) + sizeof(nd_ns))  = 64\n");
    printf("   instead of advancing from the current end of data:\n");
    printf("     (mtod(m,caddr_t) + m->m_len)                         = 72\n");
    printf("\n");
    printf("   This causes Nonce to overwrite SLLAO bytes [64..71].\n");
    printf("   m_len is incremented twice (+8 SLLAO, +8 Nonce) = 80.\n");
    printf("   But bytes [72..79] are never written.\n");
    printf("   ip6_output transmits all 80 bytes, leaking [72..79].\n");
    printf("\n");
    printf(" FIX:\n");
    printf("   Advance 'off' by option size after each append:\n");
    printf("     off += 8;\n");
    printf("   OR always derive write pointer from current m->m_len.\n");
    printf("=================================================================\n\n");

    free(mv);
    free(mf);
    return 0;
}
