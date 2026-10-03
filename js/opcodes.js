/* xdis — 6502 opcode table (NMOS, including undocumented opcodes).
 * Entries prefixed with "!" are undocumented; "jam" locks up the CPU.
 * Format: mnemonic[:mode], mode defaults to implied. */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) module.exports = factory();
    else root.XDisOpcodes = factory();
})(this, function () {
    'use strict';

    const TABLE = `
brk     ora:izx !jam    !slo:izx !nop:zp  ora:zp  asl:zp  !slo:zp  php ora:imm asl:acc !anc:imm !nop:abs ora:abs asl:abs !slo:abs
bpl:rel ora:izy !jam    !slo:izy !nop:zpx ora:zpx asl:zpx !slo:zpx clc ora:aby !nop   !slo:aby !nop:abx ora:abx asl:abx !slo:abx
jsr:abs and:izx !jam    !rla:izx bit:zp   and:zp  rol:zp  !rla:zp  plp and:imm rol:acc !anc:imm bit:abs  and:abs rol:abs !rla:abs
bmi:rel and:izy !jam    !rla:izy !nop:zpx and:zpx rol:zpx !rla:zpx sec and:aby !nop   !rla:aby !nop:abx and:abx rol:abx !rla:abx
rti     eor:izx !jam    !sre:izx !nop:zp  eor:zp  lsr:zp  !sre:zp  pha eor:imm lsr:acc !alr:imm jmp:abs  eor:abs lsr:abs !sre:abs
bvc:rel eor:izy !jam    !sre:izy !nop:zpx eor:zpx lsr:zpx !sre:zpx cli eor:aby !nop   !sre:aby !nop:abx eor:abx lsr:abx !sre:abx
rts     adc:izx !jam    !rra:izx !nop:zp  adc:zp  ror:zp  !rra:zp  pla adc:imm ror:acc !arr:imm jmp:ind  adc:abs ror:abs !rra:abs
bvs:rel adc:izy !jam    !rra:izy !nop:zpx adc:zpx ror:zpx !rra:zpx sei adc:aby !nop   !rra:aby !nop:abx adc:abx ror:abx !rra:abx
!nop:imm sta:izx !nop:imm !sax:izx sty:zp sta:zp  stx:zp  !sax:zp  dey !nop:imm txa  !ane:imm sty:abs  sta:abs stx:abs !sax:abs
bcc:rel sta:izy !jam    !sha:izy sty:zpx  sta:zpx stx:zpy !sax:zpy tya sta:aby txs    !tas:aby !shy:abx sta:abx !shx:aby !sha:aby
ldy:imm lda:izx ldx:imm !lax:izx ldy:zp   lda:zp  ldx:zp  !lax:zp  tay lda:imm tax    !lxa:imm ldy:abs  lda:abs ldx:abs !lax:abs
bcs:rel lda:izy !jam    !lax:izy ldy:zpx  lda:zpx ldx:zpy !lax:zpy clv lda:aby tsx    !las:aby ldy:abx  lda:abx ldx:aby !lax:aby
cpy:imm cmp:izx !nop:imm !dcp:izx cpy:zp  cmp:zp  dec:zp  !dcp:zp  iny cmp:imm dex    !sbx:imm cpy:abs  cmp:abs dec:abs !dcp:abs
bne:rel cmp:izy !jam    !dcp:izy !nop:zpx cmp:zpx dec:zpx !dcp:zpx cld cmp:aby !nop   !dcp:aby !nop:abx cmp:abx dec:abx !dcp:abx
cpx:imm sbc:izx !nop:imm !isb:izx cpx:zp  sbc:zp  inc:zp  !isb:zp  inx sbc:imm nop    !sbc:imm cpx:abs  sbc:abs inc:abs !isb:abs
beq:rel sbc:izy !jam    !isb:izy !nop:zpx sbc:zpx inc:zpx !isb:zpx sed sbc:aby !nop   !isb:aby !nop:abx sbc:abx inc:abx !isb:abx`;

    const LEN = {
        imp: 1, acc: 1, imm: 2, zp: 2, zpx: 2, zpy: 2, izx: 2, izy: 2, rel: 2,
        abs: 3, abx: 3, aby: 3, ind: 3,
    };

    const OPS = TABLE.trim().split(/\s+/).map(function (tok, code) {
        const illegal = tok[0] === '!';
        const [mn, mode = 'imp'] = (illegal ? tok.slice(1) : tok).split(':');
        return {
            code, mn, mode, len: LEN[mode],
            illegal, jam: mn === 'jam',
            branch: mode === 'rel',
        };
    });
    if (OPS.length !== 256) throw new Error('opcode table has ' + OPS.length + ' entries');

    return { OPS, LEN };
});
