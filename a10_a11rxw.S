.text
.align 2

.globl start
.align 4

start:
mov x5, x30
mov x0, #0x800000000
bl _cache_clean_and_invalidate_page
mov x0, #0
svc #0
ic iallu


mrs x4, sctlr_el1
mov x0, #0
msr sctlr_el1, x0
ldr x0, SDRAM_PAGE1
ldr x0, [x0]
and x0, x0, #0xff9fffffffffffff
ldr x1, SDRAM_PAGE1
str x0, [x1]
mov x0, x4
and x0, x0, #0xfffffffffff7ffff
msr sctlr_el1, x0
dsb sy
tlbi vmalle1
dsb sy
isb 
mrs x0, spsr_el1
and x0, x0, #0xfffffffffffffff3
msr spsr_el1, x0
mov x0, x5
msr elr_el1, x0
eret

_cache_clean_and_invalidate_page:
mov x1, #0x80000
mov x2, #0

_one:
cmp x1, x2
b.eq _two
dc civac, x0
add x0, x0, #0x40
add x2, x2, #0x40
b _one

_two:
ret 

// To be filled in by ibootpatch2
SDRAM_PAGE1:
.ascii "AAAAAAAA"
