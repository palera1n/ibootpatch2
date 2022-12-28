.text
.align 2

.globl start
.align 4

start:
ldr x16, _payload_base_address
ldr x16, [x16]
cmp x16, xzr
b.ne _two
ldr x16, _load_address
ldr x16, [x16]
cmp x16, xzr
b.ne _one
ret 

// 0x24
_one:
ldr x16, _load_address
br x16

// 0x2c
_two:
ldr x16, _payload_base_address
br x16

_pad:
.byte 0x00, 0x00, 0x00, 0x00
// To be filled in by ibootpatch2
// 0x38
_payload_base_address:
.ascii "AAAAAAAA"
// 0x40
_load_address:
.ascii "BBBBBBBB"
 