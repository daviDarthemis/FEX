.text
.balign 16
.globl ExitToX64
ExitToX64:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr

  // Expects RIP in x9
enter_jit:
  // Check if target is in-fact X86 code
  ldr x16, [x18, #0x60]
  ldr x16, [x16, #0x368]
  lsr x17, x9, #15
  and x17, x17, #0x1fffffffffff8
  ldr x16, [x16, x17]
  lsr x17, x9, #12
  lsr x16, x16, x17
  and x16, x16,#1
  tbnz x16, #0, 1f

  // TODO: floating point flag mapping
  ldr x17, [x18, #0x1788]
  // Per internal FEX SRA mapping
  mov x13, sp
  // Switch to emulator stack
  ldr x16, [x17, #8]
  mov sp, x16
  // Run the JIT
  ldr x17, [x17, #0x40] // EmulatorData[2]

  //  x9 = Dispatcher(x9 (RIP), x16 (SP))
  blr x17
  
  // Switch to normal stack
  mov sp, x13 // PER SRA MAPPING
  
1:
  // Check whether to return to an exit thunk or call an entry thunk
  mov x17, x9
  mov w16, #0x200
  movk w16, #0xd63f, lsl 16
  ldursw x13, [x17, #-0x4]
  cmp w13, w16
  beq 2f
  
  // Setup for entry thunk
  and x13, x13, #-0x4
  add x17, x17, x1
  
  mov x4, sp // TODO: needed for exit thunk?
  ldr lr, [x4], #0x8
  mov sp, x4

  
  // TODO: misaligned sp?
  
2:
  br x17
.globl RetToEntryThunk
RetToEntryThunk:
  mov x9, lr
  b enter_jit
 
