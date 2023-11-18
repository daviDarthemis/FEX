.text
.balign 16
.globl ExitToX64
ExitToX64:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr
  ldr x16, [x18, #0x1788]
  // Load arm64ec context pointer
  ldr x16, [x16, #0x18]
  // When context is observed after an arm64ec call, all of the below registers are up to date (why?)
  stp x0, x1, [x16, #0x80]
  stp x2, x3, [x16, #0xb8]
  str x9, [x16, #0xf8]

enter_jit:
  stp x19, x20, [x16, #0xd8]
  stp x21, x22, [x16, #0xe8]
  stp x25, x26, [x16, #0xa8]
  str x27, [x16, #0x90]
  stp q0, q1, [x16, #0x1a0]
  stp q2, q3, [x16, #0x1c0]
  stp q4, q5, [x16, #0x1e0]
  stp q6, q7, [x16, #0x200]
  stp q8, q9, [x16, #0x220]
  stp q10, q11, [x16, #0x240]
  stp q12, q13, [x16, #0x260]
  stp q14, q15, [x16, #0x280]
  mov x17, sp
  stp x17, fp, [x16, #0x98]
  // Switch to emulator stack
  ldr x16, [x18, #0x1788]
  ldr x16, [x16, #8]
  mov sp, x16
  // Run the JIT
  bl #RunJIT
  
  ldr x16, [x18, #0x1788]
  // Load arm64ec context pointer
  ldr x16, [x16, #0x18]
  // Switch to normal stack
  ldp x8, fp, [x16, #0x98]
  mov sp, x8
  ldr x8, [x16, #0x78]
  ldr x9, [x16, #0xf8]
  mov x17, x9
  
  // Check whether to return to an exit thunk or call an entry thunk
  mov w0, #0x200
  movk w0, #0xd63f, lsl 16
  ldursw x1, [x17, #-0x4]
  cmp w0, w1
  beq 1f
  
  // Setup for entry thunk
  and x1, x1, #-0x4
  add x17, x17, x1
  
  mov x4, sp
  ldr lr, [x4], #0x8
  mov sp, x4

  
  // TODO: misaligned sp?
  
  1: ldp x0, x1, [x16, #0x80]
  ldp x2, x3, [x16, #0xb8]
  ldp x19, x20, [x16, #0xd8]
  ldp x21, x22, [x16, #0xe8]
  ldp x25, x26, [x16, #0xa8]
  ldr x27, [x16, #0x90]
  ldp q0, q1, [x16, #0x1a0]
  ldp q2, q3, [x16, #0x1c0]
  ldp q4, q5, [x16, #0x1e0]
  ldp q6, q7, [x16, #0x200]
  ldp q8, q9, [x16, #0x220]
  ldp q10, q11, [x16, #0x240]
  ldp q12, q13, [x16, #0x260]
  ldp q14, q15, [x16, #0x280]
  br x17
.globl RetToEntryThunk
RetToEntryThunk:
  ldr x16, [x18, #0x1788]
  // Load arm64ec context pointer
  ldr x16, [x16, #0x18]
  str x8, [x16, #0x78]
  str lr, [x16, #0xf8]
  b enter_jit
 
