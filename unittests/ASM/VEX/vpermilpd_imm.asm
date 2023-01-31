%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM1": ["0xAAAAAAAAAAAAAAAA", "0xAAAAAAAAAAAAAAAA", "0x0000000000000000", "0x0000000000000000"],
    "XMM2": ["0xBBBBBBBBBBBBBBBB", "0xBBBBBBBBBBBBBBBB", "0x0000000000000000", "0x0000000000000000"],
    "XMM3": ["0xAAAAAAAAAAAAAAAA", "0xBBBBBBBBBBBBBBBB", "0x0000000000000000", "0x0000000000000000"],
    "XMM4": ["0xBBBBBBBBBBBBBBBB", "0xAAAAAAAAAAAAAAAA", "0x0000000000000000", "0x0000000000000000"],
    "XMM5": ["0xAAAAAAAAAAAAAAAA", "0xAAAAAAAAAAAAAAAA", "0xCCCCCCCCCCCCCCCC", "0xCCCCCCCCCCCCCCCC"],
    "XMM6": ["0xBBBBBBBBBBBBBBBB", "0xBBBBBBBBBBBBBBBB", "0xDDDDDDDDDDDDDDDD", "0xDDDDDDDDDDDDDDDD"],
    "XMM7": ["0xAAAAAAAAAAAAAAAA", "0xBBBBBBBBBBBBBBBB", "0xCCCCCCCCCCCCCCCC", "0xDDDDDDDDDDDDDDDD"]

  }
}
%endif

lea rdx, [rel .data]

vmovaps ymm0, [rdx]

vpermilpd xmm1, xmm0, 0000b
vpermilpd xmm2, xmm0, 0011b
vpermilpd xmm3, xmm0, 0010b
vpermilpd xmm4, xmm0, 0001b

vpermilpd ymm5, ymm0, 0000b
vpermilpd ymm6, ymm0, 1111b
vpermilpd ymm7, ymm0, 1010b

hlt

align 32
.data:
dq 0xAAAAAAAAAAAAAAAA
dq 0xBBBBBBBBBBBBBBBB
dq 0xCCCCCCCCCCCCCCCC
dq 0xDDDDDDDDDDDDDDDD