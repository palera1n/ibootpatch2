.text
.align 2

.globl start
.align 4

start:
ldr x16, _b_payload_entry_address
br x16

_b_payload_entry_address:
.ascii "DDDDDDDD"
