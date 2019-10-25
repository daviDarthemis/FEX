#include "Interface/Core/X86Tables/X86Tables.h"

namespace FEXCore::X86Tables {
using namespace InstFlags;

void InitializeH0F3ATables() {
#define OPD(REX, prefix, opcode) ((REX << 9) | (prefix << 8) | opcode)
  constexpr uint16_t PF_3A_NONE = 0;
  constexpr uint16_t PF_3A_66   = 1;

  const U16U8InfoStruct H0F3ATable[] = {
    {OPD(0, PF_3A_NONE, 0x0F), 1, X86InstInfo{"PALIGNR",         TYPE_UNDEC, FLAGS_NONE, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x08), 1, X86InstInfo{"ROUNDPS",         TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x09), 1, X86InstInfo{"ROUNDPD",         TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x0A), 1, X86InstInfo{"ROUNDSS",         TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x0B), 1, X86InstInfo{"ROUNDSD",         TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x0C), 1, X86InstInfo{"BLENDPS",         TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x0D), 1, X86InstInfo{"BLENDPD",         TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x0E), 1, X86InstInfo{"PBLENDW",         TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x0F), 1, X86InstInfo{"PALIGNR",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(1, PF_3A_66,   0x0F), 1, X86InstInfo{"PALIGNR",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},

    {OPD(0, PF_3A_66,   0x14), 1, X86InstInfo{"PEXTRB",          TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x15), 1, X86InstInfo{"PEXTRW",          TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x16), 1, X86InstInfo{"PEXTRD",          TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(1, PF_3A_66,   0x16), 1, X86InstInfo{"PEXTRD",          TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x17), 1, X86InstInfo{"EXTRACTPS",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},

    {OPD(0, PF_3A_66,   0x20), 1, X86InstInfo{"PINSRB",          TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x21), 1, X86InstInfo{"INSERTPS",        TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x22), 1, X86InstInfo{"PINSRD",          TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(1, PF_3A_66,   0x22), 1, X86InstInfo{"PINSRQ",          TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},

    {OPD(0, PF_3A_66,   0x40), 1, X86InstInfo{"DPPS",            TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x41), 1, X86InstInfo{"DPPD",            TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x42), 1, X86InstInfo{"MPSADBW",         TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x44), 1, X86InstInfo{"PCLMULQDQ",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},

    {OPD(0, PF_3A_66,   0x60), 1, X86InstInfo{"PCMPESTRM",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x61), 1, X86InstInfo{"PCMPESTRI",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x62), 1, X86InstInfo{"PCMPISTRM",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x63), 1, X86InstInfo{"PCMPISTRI",       TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},

    {OPD(0, PF_3A_66,   0xDF), 1, X86InstInfo{"AESKEYGENASSIST", TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
  };
#undef OPD

  GenerateTable(H0F3ATableOps, H0F3ATable, sizeof(H0F3ATable) / sizeof(H0F3ATable[0]));
}
}
