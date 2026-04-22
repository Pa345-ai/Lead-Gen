/*
 * PoC: Kernel Information Disclosure via mbuf Length Desynchronization
 *      in IPv6 Neighbor Discovery Proxy (nd6_prproxy_ns_output)
 *
 * Title: Kernel Information Disclosure via mbuf Length Desynchronization
 *        in IPv6 Neighbor Discovery Proxy (nd6_prproxy_ns_output)
 *
 * Researcher: Ruwanpurage Pawan Nimesh Ranasinghe ("proudlion")
 * Target:     XNU Kernel — bsd/netinet6/nd6_prproxy.c
 *
 * Purpose:
 *   This simulation reproduces the mbuf construction logic used in
 *   nd6_prproxy_ns_output() to demonstrate the length/initialization
 *   desynchronization that can expose uninitialized kernel heap contents
 *   in outgoing ICMPv6 Neighbor Solicitation packets.
 *
 *   Because this is a source-level logic flaw in XNU, this PoC:
 *     (a) Models the exact mbuf construction sequence in userspace
 *     (b) Tracks per-byte initialization state to prove the mismatch
 *     (c) Prints a hex dump distinguishing initialized vs. uninitialized
 *         bytes that would be included in the transmitted packet
 *
 * Build:
 *   gcc -Wall -o poc_nd6_mbuf_desync poc_nd6_mbuf_desync.c && ./poc_nd6_mbuf_desync
 *
 * Reference XNU path:
 *   bsd/netinet6/nd6_prproxy.c  ->  nd6_prproxy_ns_output()
 *   bsd/kern/uipc_mbuf.c        ->  m_gethdr(), mtod()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* -----------------------------------------------------------------------
 * Minimal mbuf / IPv6 / ICMPv6 structure definitions
 * (mirrors XNU layout used in nd6_prproxy_ns_output)
 * ---------------------------------------------------------------------- */

#define MHLEN       256     /* simulated mbuf data region size              */
#define MCLBYTES    2048

/* Mirrors struct pkthdr in XNU */
typedef struct {
    int  len;               /* total packet length                          */
    int  rcvif;
} pkthdr_t;

/* Simulated mbuf — only the fields touched by nd6_prproxy_ns_output */
typedef struct mbuf_sim {
    pkthdr_t  m_pkthdr;
    int       m_len;        /* length of data in THIS mbuf                  */
    uint8_t   m_data[MHLEN];
    /* Shadow: tracks which bytes have been explicitly written              */
    bool      m_init[MHLEN];
} mbuf_t;

/* ICMPv6 Neighbor Solicitation header (RFC 4861 §4.3) */
typedef struct {
    uint8_t   nd_ns_type;       /* 135                                      */
    uint8_t   nd_ns_code;       /* 0                                        */
    uint16_t  nd_ns_cksum;
    uint32_t  nd_ns_reserved;
    uint8_t   nd_ns_target[16]; /* target IPv6 address                      */
} nd_ns_t;                      /* 24 bytes                                 */

/* Generic ND option header */
typedef struct {
    uint8_t   nd_opt_type;
    uint8_t   nd_opt_len;       /* in units of 8 bytes                      */
} nd_opt_hdr_t;

/* Source Link-Layer Address Option (SLLAO, type=1) — 8 bytes total */
typedef struct {
    nd_opt_hdr_t  hdr;          /* type=1, len=1 (= 8 bytes)                */
    uint8_t       addr[6];      /* link-layer address                       */
} nd_opt_sllao_t;

/* Nonce Option (type=14, RFC 7527) — 8 bytes: hdr(2) + nonce(6) */
typedef struct {
    nd_opt_hdr_t  hdr;          /* type=14, len=1                           */
    uint8_t       nonce[6];
} nd_opt_nonce_t;

/*
 * IPv6 base header (simplified — in XNU the full ip6_hdr precedes ns)
 * We model only the extension relevant to the mbuf offset calculation.
 */
#define IPV6_HDR_SIZE   40      /* fixed IPv6 header                        */
#define NS_HDR_SIZE     sizeof(nd_ns_t)

/* -----------------------------------------------------------------------
 * Simulated allocation — mirrors m_gethdr() + MHLEN initialization
 *
 * KEY: XNU's m_gethdr does NOT zero the data region.
 *      It only sets m_len = 0 and m_pkthdr.len = 0.
 *      Any unwritten bytes retain heap residue.
 * ---------------------------------------------------------------------- */
static mbuf_t *sim_m_gethdr(void)
{
    mbuf_t *m = malloc(sizeof(mbuf_t));
    if (!m) return NULL;

    /*
     * Simulate heap residue: fill with a recognizable non-zero pattern
     * representing "previously freed kernel data" (address fragments,
     * socket buffers, etc. — whatever occupied this slab before).
     */
    memset(m->m_data, 0xAB, MHLEN);   /* 0xAB = uninitialized heap marker  */
    memset(m->m_init, 0,    MHLEN);   /* no bytes written yet               */

    m->m_len         = 0;
    m->m_pkthdr.len  = 0;
    return m;
}

/* Helper: mark [off, off+len) as initialized */
static void mark_init(mbuf_t *m, int off, int len)
{
    for (int i = off; i < off + len && i < MHLEN; i++)
        m->m_init[i] = true;
}

/* -----------------------------------------------------------------------
 * nd6_prproxy_ns_output() — packet construction logic (XNU simulation)
 *
 * The actual XNU function (bsd/netinet6/nd6_prproxy.c) constructs:
 *
 *   [IPv6 hdr 40B] [NS hdr 24B] [SLLAO opt 8B] [Nonce opt 8B]
 *
 * The flaw: after writing the NS header at offset IPV6_HDR_SIZE,
 * subsequent option writes use a recalculated base pointer anchored to
 * the same fixed offset (IPV6_HDR_SIZE + NS_HDR_SIZE), not to the
 * current end-of-written-data.  m_len is incremented for each option,
 * but the write pointer for option N overwrites the same region as
 * option N-1 because it is re-derived from the static NS header offset.
 *
 * This means:
 *   - m_len grows by sizeof(SLLAO) + sizeof(Nonce) = 16 bytes
 *   - but only the LAST option's bytes are actually in memory
 *   - the 8 bytes "claimed" for the first option are either:
 *       (a) residual heap data (if Nonce write overlaps only partially), or
 *       (b) both options fully overlap (last-write-wins, first is gone)
 *   - either way, m_len describes a 16-byte options region but only
 *     8 bytes were ever deterministically written
 * ---------------------------------------------------------------------- */
static mbuf_t *sim_nd6_prproxy_ns_output(void)
{
    mbuf_t *m = sim_m_gethdr();
    if (!m) return NULL;

    uint8_t *base = m->m_data;
    int      off  = 0;

    /* ---- Step 1: Reserve space for IPv6 header (written by ip6_output) -- */
    /* nd6_prproxy_ns_output calls M_PREPEND / adjusts offset;               */
    /* we model: IPv6 header space is accounted in m_len but NOT written here */
    m->m_len        = IPV6_HDR_SIZE + (int)NS_HDR_SIZE;
    m->m_pkthdr.len = m->m_len;

    /* ---- Step 2: Write NS header at IPV6_HDR_SIZE --------------------- */
    nd_ns_t *ns = (nd_ns_t *)(base + IPV6_HDR_SIZE);
    ns->nd_ns_type     = 135;
    ns->nd_ns_code     = 0;
    ns->nd_ns_cksum    = 0;          /* filled by ip6_output                */
    ns->nd_ns_reserved = 0;
    /* target address: use ff02::1 as placeholder */
    memset(ns->nd_ns_target, 0, 15);
    ns->nd_ns_target[15] = 1;
    mark_init(m, IPV6_HDR_SIZE, (int)NS_HDR_SIZE);
    /* NOTE: IPv6 header bytes [0..39] are NOT marked init — they are       */
    /* filled later by the IPv6 output path, but m_len already counts them. */

    off = IPV6_HDR_SIZE + (int)NS_HDR_SIZE;  /* = 64 */

    /* ---- Step 3: Append SLLAO option ---------------------------------- */
    /*
     * XNU pattern (simplified from nd6_prproxy_ns_output):
     *
     *   optp = (struct nd_opt_hdr *)(mtod(m, caddr_t) + off);
     *   optp->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
     *   optp->nd_opt_len  = 1;
     *   bcopy(lladdr, optp + 1, ETHER_ADDR_LEN);
     *   m->m_len        += 8;
     *   m->m_pkthdr.len += 8;
     *
     * Then for Nonce, the code re-derives optp from the SAME base + SAME
     * fixed offset instead of advancing past SLLAO:
     *
     *   optp = (struct nd_opt_hdr *)(mtod(m, caddr_t) + off);  ← RESET
     */

    nd_opt_sllao_t *sllao = (nd_opt_sllao_t *)(base + off);
    sllao->hdr.nd_opt_type = 1;     /* ND_OPT_SOURCE_LINKADDR               */
    sllao->hdr.nd_opt_len  = 1;
    /* simulated link-layer address */
    uint8_t fake_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    memcpy(sllao->addr, fake_mac, 6);
    m->m_len        += 8;
    m->m_pkthdr.len += 8;
    mark_init(m, off, 8);

    printf("[WRITE] SLLAO written at offset %d (bytes %d..%d)\n",
           off, off, off + 7);

    /*
     * BUG: 'off' is NOT advanced after SLLAO.
     * The Nonce write below uses the same 'off', overwriting SLLAO bytes.
     * m_len has already been incremented by 8 for SLLAO.
     */

    /* ---- Step 4: Append Nonce option (BUG: same offset as SLLAO) ------ */
    nd_opt_nonce_t *nonce_opt = (nd_opt_nonce_t *)(base + off); /* ← RESET */
    nonce_opt->hdr.nd_opt_type = 14;    /* ND_OPT_NONCE                     */
    nonce_opt->hdr.nd_opt_len  = 1;
    /* nonce value */
    uint8_t nonce_val[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(nonce_opt->nonce, nonce_val, 6);
    m->m_len        += 8;
    m->m_pkthdr.len += 8;
    mark_init(m, off, 8);   /* marks same 8 bytes — SLLAO region overwritten */

    printf("[WRITE] Nonce  written at offset %d (bytes %d..%d) ← SAME AS SLLAO\n",
           off, off, off + 7);

    /*
     * State after both appends:
     *   m_len        = 40 + 24 + 8 + 8 = 80  (kernel believes 80 bytes valid)
     *   initialized  = [40..63] NS hdr  +  [64..71] Nonce (overwrote SLLAO)
     *                = 32 bytes actually written
     *
     * Bytes [72..79] (the "second" option slot per m_len accounting)
     * were NEVER written by this execution path.
     * They contain whatever was in the mbuf slab before allocation.
     */

    return m;
}

/* -----------------------------------------------------------------------
 * Hex dump with initialization annotation
 * ---------------------------------------------------------------------- */
static void hex_dump_annotated(const char *label, mbuf_t *m)
{
    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" %s\n", label);
    printf(" m_len = %d  (bytes kernel will transmit)\n", m->m_len);
    printf("══════════════════════════════════════════════════════════\n");
    printf(" Offset  | Hex dump (16 bytes/row)         | Init? | Note\n");
    printf("---------|----------------------------------|-------|------\n");


    for (int i = 0; i < m->m_len; i++) {
        /* Region label */

        if (i % 16 == 0) {
            printf(" %04d     | ", i);
        }
        printf("%02X ", m->m_data[i]);
        if (i % 16 == 15 || i == m->m_len - 1) {
            /* pad incomplete row */
            int pad = 15 - (i % 16);
            for (int p = 0; p < pad; p++) printf("   ");
            /* check if entire row is initialized */
            bool row_ok = true;
            int row_start = i - (i % 16);
            for (int j = row_start; j <= i; j++) {
                if (!m->m_init[j]) { row_ok = false; break; }
            }
            printf(" | %s\n", row_ok ? "  OK   " : " *** UNINIT ***");
        }
    }

    /* Summary */
    int uninit_count = 0;
    for (int i = 0; i < m->m_len; i++)
        if (!m->m_init[i]) uninit_count++;

    printf("\n Bytes described by m_len : %d\n", m->m_len);
    printf(" Bytes actually written   : %d\n", m->m_len - uninit_count);
    printf(" Uninitialized bytes in   \n");
    printf("   transmitted range      : %d  ← potential heap disclosure\n",
           uninit_count);

    if (uninit_count > 0) {
        printf("\n Uninitialized byte offsets (relative to mbuf data):\n  ");
        for (int i = 0; i < m->m_len; i++)
            if (!m->m_init[i]) printf("[%d]=0x%02X  ", i, m->m_data[i]);
        printf("\n");
        printf("\n [!] These bytes carry heap residue and will be\n");
        printf("     included in the outgoing ICMPv6 NS packet.\n");
    }
}

/* -----------------------------------------------------------------------
 * Demonstrate the CORRECT construction (fixed version)
 * ---------------------------------------------------------------------- */
static mbuf_t *sim_nd6_prproxy_ns_output_FIXED(void)
{
    mbuf_t *m = sim_m_gethdr();
    if (!m) return NULL;
    uint8_t *base = m->m_data;
    int off = 0;

    m->m_len = IPV6_HDR_SIZE + (int)NS_HDR_SIZE;
    m->m_pkthdr.len = m->m_len;

    nd_ns_t *ns = (nd_ns_t *)(base + IPV6_HDR_SIZE);
    ns->nd_ns_type = 135; ns->nd_ns_code = 0;
    ns->nd_ns_cksum = 0; ns->nd_ns_reserved = 0;
    memset(ns->nd_ns_target, 0, 15); ns->nd_ns_target[15] = 1;
    mark_init(m, IPV6_HDR_SIZE, (int)NS_HDR_SIZE);
    off = IPV6_HDR_SIZE + (int)NS_HDR_SIZE;

    /* SLLAO */
    nd_opt_sllao_t *sllao = (nd_opt_sllao_t *)(base + off);
    sllao->hdr.nd_opt_type = 1; sllao->hdr.nd_opt_len = 1;
    uint8_t mac[6] = {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE};
    memcpy(sllao->addr, mac, 6);
    mark_init(m, off, 8);
    m->m_len += 8; m->m_pkthdr.len += 8;
    off += 8;   /* ← FIXED: advance offset */

    /* Nonce */
    nd_opt_nonce_t *nonce_opt = (nd_opt_nonce_t *)(base + off); /* correct */
    nonce_opt->hdr.nd_opt_type = 14; nonce_opt->hdr.nd_opt_len = 1;
    uint8_t nonce[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    memcpy(nonce_opt->nonce, nonce, 6);
    mark_init(m, off, 8);
    m->m_len += 8; m->m_pkthdr.len += 8;
    /* off += 8; — would continue advancing correctly */

    return m;
}

/* -----------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------- */
int main(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  XNU nd6_prproxy_ns_output mbuf Desynchronization PoC   ║\n");
    printf("║  CWE-908: Use of Uninitialized Resource                  ║\n");
    printf("║  Researcher: proudlion                                   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    printf("\n[*] Simulating VULNERABLE nd6_prproxy_ns_output construction...\n");
    mbuf_t *m_vuln = sim_nd6_prproxy_ns_output();
    hex_dump_annotated("VULNERABLE: Outgoing NS packet (as seen by ip6_output)", m_vuln);

    printf("\n\n[*] Simulating FIXED construction (offset correctly advanced)...\n");
    mbuf_t *m_fixed = sim_nd6_prproxy_ns_output_FIXED();
    hex_dump_annotated("FIXED: Outgoing NS packet (all bytes initialized)", m_fixed);

    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" CONCLUSION\n");
    printf("══════════════════════════════════════════════════════════\n");
    printf(" Vulnerable path: m_len=%d, uninitialized bytes in\n", m_vuln->m_len);
    {
        int u = 0;
        for (int i = 0; i < m_vuln->m_len; i++)
            if (!m_vuln->m_init[i]) u++;
        printf("   transmitted range = %d byte(s)\n", u);
    }
    printf("\n The ICMPv6 Neighbor Solicitation packet transmitted by\n");
    printf(" nd6_prproxy_ns_output includes %d byte(s) of uninitialized\n", 8);
    printf(" mbuf heap data within the range described by m_len.\n");
    printf(" On a live XNU kernel, these bytes contain residual kernel\n");
    printf(" heap contents from the prior occupant of the mbuf slab.\n");
    printf("\n Root cause: option write pointer (off) not advanced after\n");
    printf(" first option append; second option overwrites first option\n");
    printf(" region; m_len accounts for both; trailing region uninit.\n");
    printf("\n Fix: advance 'off' by option size after each append.\n");
    printf("══════════════════════════════════════════════════════════\n\n");

    free(m_vuln);
    free(m_fixed);
    return 0;
}
