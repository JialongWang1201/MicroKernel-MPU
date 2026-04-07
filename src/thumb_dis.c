/* thumb_dis.c — Thumb/Thumb-2 disassembler (P1 + P2 + IT block)
 *
 * Coverage:
 *   P1: MOV/MOVW/MOVT, LDR/STR (T1-T4), PUSH/POP, BL/BLX, B (all conds)
 *   P2: ADD/SUB/MUL, CMP/TST/AND/ORR/EOR/BIC/MVN, LSL/LSR/ASR, IT block
 *   Unknown encodings → "<unknown 0xXXXX>" (never crashes)
 *
 * SPDX-License-Identifier: MIT
 */

#include "thumb_dis.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */

static const char *s_reg[16] = {
    "r0","r1","r2","r3","r4","r5","r6","r7",
    "r8","r9","r10","r11","r12","sp","lr","pc"
};

static const char *s_cc[16] = {
    "eq","ne","cs","cc","mi","pl","vs","vc",
    "hi","ls","ge","lt","gt","le","al","nv"
};

/* Sign-extend a value of <bits> width to int32_t. */
static int32_t sext(uint32_t v, int bits)
{
    uint32_t mask = 1u << (bits - 1);
    return (int32_t)((v ^ mask) - mask);
}

/* Build a register-list string like "{r4, r5, lr}".
 * bits[0..12] map to r0..r12; extra is a named reg (sp/lr/pc) or -1. */
static void fmt_reglist(char *buf, size_t sz, uint16_t list8, int extra_reg)
{
    char tmp[THUMB_DIS_OUT_MAX];
    int pos = 0;
    tmp[pos++] = '{';
    int first = 1;
    for (int i = 0; i < 8; i++) {
        if (list8 & (1u << i)) {
            if (!first) { tmp[pos++] = ','; tmp[pos++] = ' '; }
            const char *rn = s_reg[i];
            for (int k = 0; rn[k]; k++) tmp[pos++] = rn[k];
            first = 0;
        }
    }
    if (extra_reg >= 0) {
        if (!first) { tmp[pos++] = ','; tmp[pos++] = ' '; }
        const char *rn = s_reg[extra_reg];
        for (int k = 0; rn[k]; k++) tmp[pos++] = rn[k];
    }
    tmp[pos++] = '}';
    tmp[pos] = '\0';
    snprintf(buf, sz, "%s", tmp);
}

/* IT mnemonic: "it", "itt", "ite", "ittt", "itte", etc.
 * firstcond and mask from IT instruction. */
static void fmt_it_mnemonic(char *buf, size_t sz,
                             uint8_t firstcond, uint8_t mask)
{
    char tmp[8] = "it";
    int pos = 2;
    /* Number of extra slots: find lowest set bit position in mask (0-indexed from MSB of nibble) */
    /* trailing-1 at bit[3] → 1 slot total (just "it");
     * trailing-1 at bit[2] → 2 slots ("itt" or "ite");
     * etc. */
    /* Work from bit[3] downward: the bits ABOVE the trailing-1 are T/E bits. */
    for (int b = 3; b >= 0; b--) {
        if (!(mask & (1u << b))) {
            /* This is a T/E slot above the trailing-1. */
            uint8_t te = (mask >> (b + 1)) & 1; /* The actual T/E bit is one higher... */
            /* Simpler: bits[3:0] of mask, from MSB down, until we hit the trailing 1 */
            (void)te;
            break;
        }
    }
    /* Cleaner approach: iterate from bit[3] downward.
     * Stop when we see the lowest set bit (trailing 1). */
    /* The trailing 1 is at position ctz4 = position of lowest set bit in mask[3:0]. */
    int trailing_pos = -1;
    for (int b = 0; b <= 3; b++) {
        if (mask & (1u << b)) { trailing_pos = b; break; }
    }
    if (trailing_pos < 0) { snprintf(buf, sz, "it"); return; }

    /* Slots 2..N encoded in mask bits above trailing_pos (i.e., bits[3..trailing_pos+1]). */
    int n_extra = 3 - trailing_pos; /* number of T/E bits encoded above trailing */
    for (int k = 0; k < n_extra; k++) {
        /* bit for slot (k+2) is at mask[3-k] */
        uint8_t te_bit = (mask >> (3 - k)) & 1;
        tmp[pos++] = (te_bit == (firstcond & 1)) ? 't' : 'e';
    }
    tmp[pos] = '\0';
    snprintf(buf, sz, "%s", tmp);
}

/* Advance IT state after consuming one IT-conditioned instruction. */
static void it_advance(uint8_t *itstate)
{
    if (*itstate & 0x07)
        *itstate = (uint8_t)((*itstate & 0xe0u) | ((*itstate << 1) & 0x1fu));
    else
        *itstate = 0;
}

