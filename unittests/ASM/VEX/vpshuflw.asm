%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0": ["0x4142434445464748", "0x5152535455565758", "0xAAAABBBBCCCCDDDD", "0xEEEEFFFF11112222"],
    "XMM1": ["0x6162636465666768", "0x7172737475767778", "0xFFFFCCCCDDDDEEEE", "0xAAAABBBB88889999"],
    "XMM2": ["0x4748474847484748", "0x5152535455565758", "0x0000000000000000", "0x0000000000000000"],
    "XMM3": ["0x6162616261626162", "0x7172737475767778", "0x0000000000000000", "0x0000000000000000"],
    "XMM4": ["0x4748474847484748", "0x5152535455565758", "0xDDDDDDDDDDDDDDDD", "0xEEEEFFFF11112222"],
    "XMM5": ["0x6162616261626162", "0x7172737475767778", "0xFFFFFFFFFFFFFFFF", "0xAAAABBBB88889999"],
    "XMM6": ["0x4142434445464748", "0x5152535455565758", "0xAAAABBBBCCCCDDDD", "0xEEEEFFFF11112222"],
    "XMM7": ["0x6162636465666768", "0x7172737475767778", "0x0000000000000000", "0x0000000000000000"],
    "XMM8": ["0x4344474843444748", "0x5152535455565758", "0xBBBBDDDDBBBBDDDD", "0xEEEEFFFF11112222"],
    "XMM9": ["0x6364676863646768", "0x7172737475767778", "0x0000000000000000", "0x0000000000000000"]
  }
}
%endif

lea rdx, [rel .data]

vmovapd ymm0, [rdx]
vmovapd ymm1, [rdx + 32]

vpshuflw xmm2, xmm0, 0x0
vpshuflw xmm3, xmm1, 0xFF

vpshuflw ymm4, ymm0, 0x0
vpshuflw ymm5, ymm1, 0xFF

; Shouldn't modify vector (selector is [3, 2, 1, 0])
; Which would effectively place elements in their
; same location
vpshuflw ymm6, ymm0, 0b11100100
vpshuflw xmm7, xmm1, 0b11100100

; [2, 0, 2, 0] shuffling
vpshuflw ymm8, ymm0, 0b10001000
vpshuflw xmm9, xmm1, 0b10001000

hlt

align 32
.data:
dq 0x4142434445464748
dq 0x5152535455565758
dq 0xAAAABBBBCCCCDDDD
dq 0xEEEEFFFF11112222

dq 0x6162636465666768
dq 0x7172737475767778
dq 0xFFFFCCCCDDDDEEEE
dq 0xAAAABBBB88889999
