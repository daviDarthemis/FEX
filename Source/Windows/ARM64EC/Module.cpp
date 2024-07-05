// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|ARM64EC
desc: Implements the ARM64EC BT module API using FEXCore
$end_info$
*/

#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>

#include "Common/Config.h"
#include "Common/InvalidationTracker.h"
#include "Common/TSOHandlerConfig.h"
#include "Common/CPUFeatures.h"
#include "DummyHandlers.h"
#include "BTInterface.h"

#include <cstdint>
#include <cstdio>
#include <type_traits>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
#include <wine/debug.h>
#include <wine/unixlib.h>


class ECSyscallHandler;
extern void* ExitFunctionEC;

struct ThreadCPUArea {
  static constexpr size_t TEBCPUAreaOffset = 0x1788;
  CHPE_V2_CPU_AREA_INFO* Area;

  explicit ThreadCPUArea(_TEB* TEB)
    : Area(*reinterpret_cast<CHPE_V2_CPU_AREA_INFO**>(reinterpret_cast<uintptr_t>(TEB) + TEBCPUAreaOffset)) {}

  uint64_t EmulatorStackLimit() const {
    return Area->EmulatorStackLimit;
  }

  uint64_t EmulatorStackBase() const {
    return Area->EmulatorStackBase;
  }

  FEXCore::Core::CpuStateFrame*& StateFrame() const {
    return reinterpret_cast<FEXCore::Core::CpuStateFrame*&>(Area->EmulatorData[0]);
  }

  FEXCore::Core::InternalThreadState*& ThreadState() const {
    return reinterpret_cast<FEXCore::Core::InternalThreadState*&>(Area->EmulatorData[1]);
  }

  uint64_t& DispatcherLoopTopEnterEC() const {
    return reinterpret_cast<uint64_t&>(Area->EmulatorData[2]);
  }

  uint64_t& DispatcherLoopTopEnterECFillSRA() const {
    return reinterpret_cast<uint64_t&>(Area->EmulatorData[3]);
  }
};

namespace {
fextl::unique_ptr<FEXCore::Context::Context> CTX;
fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
fextl::unique_ptr<ECSyscallHandler> SyscallHandler;
std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::CPUFeatures> CPUFeatures;
uint64_t KiUserExceptionDispatcher;


std::recursive_mutex ThreadCreationMutex;
// Map of TIDs to their FEX thread state, `ThreadCreationMutex` must be locked when accessing
std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;


std::pair<NTSTATUS, ThreadCPUArea> GetThreadCPUArea(HANDLE Thread) {
  THREAD_BASIC_INFORMATION Info;
  const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
  return {Err, ThreadCPUArea(reinterpret_cast<_TEB*>(Info.TebBaseAddress))};
}

ThreadCPUArea GetCPUArea() {
  return ThreadCPUArea(NtCurrentTeb());
}

bool IsEmulatorStackAddress(uint64_t Address) {
  return Address <= GetCPUArea().EmulatorStackBase() && Address >= GetCPUArea().EmulatorStackLimit();
}

bool IsDispatcherAddress(uint64_t Address) {
  const auto& Config = SignalDelegator->GetConfig();
  return Address >= Config.DispatcherBegin && Address < Config.DispatcherEnd;
}

EXCEPTION_RECORD HandleGuestException(EXCEPTION_RECORD *Src, ARM64_NT_CONTEXT *Context) {
  auto* Thread = GetCPUArea().ThreadState();
  auto &Fault = Thread->CurrentFrame->SynchronousFaultData;
  if (!Fault.FaultToTopAndGeneratedException) return *Src;
  Fault.FaultToTopAndGeneratedException = false;

  EXCEPTION_RECORD Dst{};
  Dst.ExceptionAddress = reinterpret_cast<void *>(Context->Pc);

  switch (Fault.Signal) {
  case FEXCore::Core::FAULT_SIGILL:
    Dst.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
    return Dst;
  case FEXCore::Core::FAULT_SIGTRAP:
    switch (Fault.TrapNo) {
    case FEXCore::X86State::X86_TRAPNO_DB:
      Dst.ExceptionCode = EXCEPTION_SINGLE_STEP;
      return Dst;
    case FEXCore::X86State::X86_TRAPNO_BP:
      Context->Pc -= 1;
      Dst.ExceptionAddress = reinterpret_cast<void *>(Context->Pc);
      Dst.ExceptionCode = EXCEPTION_BREAKPOINT;
      Dst.NumberParameters = 1;
      Dst.ExceptionInformation[0] = 0;
      return Dst;
    default:
      LogMan::Msg::EFmt("Unknown SIGTRAP trap: {}", Fault.TrapNo);
      break;
    }
    break;
  case FEXCore::Core::FAULT_SIGSEGV:
    switch (Fault.TrapNo) {
    case FEXCore::X86State::X86_TRAPNO_GP:
      if ((Fault.err_code & 0b111) == 0b010) {
        switch (Fault.err_code >> 3) {
        case 0x2d:
          Context->Pc += 2;
          Dst.ExceptionCode = EXCEPTION_BREAKPOINT;
          Dst.ExceptionAddress = reinterpret_cast<void *>(Context->Pc + 1);
          Dst.NumberParameters = 1;
          Dst.ExceptionInformation[0] = Context->X8; // RAX
	  return Dst;
        default:
          LogMan::Msg::EFmt("Unknown interrupt: 0x{:X}", Fault.err_code >> 3);
          break;
	}
      } else {
        Dst.ExceptionCode = EXCEPTION_PRIV_INSTRUCTION;
	return Dst;
      }
      break;
    case FEXCore::X86State::X86_TRAPNO_OF:
      Dst.ExceptionCode = EXCEPTION_INT_OVERFLOW;
      return Dst;
    default:
      LogMan::Msg::EFmt("Unknown SIGSEGV trap: {}", Fault.TrapNo);
      break;
    }
    break;
  default:
    LogMan::Msg::EFmt("Unknown signal type: {}", Fault.Signal);
    break;
  }

  // Default to SIGILL
  Dst.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
  return Dst;
}
} // namespace

namespace Context {
void LoadStateFromECContext(FEXCore::Core::InternalThreadState* Thread, CONTEXT* Context) {
  auto& State = Thread->CurrentFrame->State;

  // General register state
  State.gregs[FEXCore::X86State::REG_RAX] = Context->Rax;
  State.gregs[FEXCore::X86State::REG_RCX] = Context->Rcx;
  State.gregs[FEXCore::X86State::REG_RDX] = Context->Rdx;
  State.gregs[FEXCore::X86State::REG_RBX] = Context->Rbx;
  State.gregs[FEXCore::X86State::REG_RSP] = Context->Rsp;
  State.gregs[FEXCore::X86State::REG_RBP] = Context->Rbp;
  State.gregs[FEXCore::X86State::REG_RSI] = Context->Rsi;
  State.gregs[FEXCore::X86State::REG_RDI] = Context->Rdi;
  State.gregs[FEXCore::X86State::REG_R8] = Context->R8;
  State.gregs[FEXCore::X86State::REG_R9] = Context->R9;
  State.gregs[FEXCore::X86State::REG_R10] = Context->R10;
  State.gregs[FEXCore::X86State::REG_R11] = Context->R11;
  State.gregs[FEXCore::X86State::REG_R12] = Context->R12;
  State.gregs[FEXCore::X86State::REG_R13] = Context->R13;
  State.gregs[FEXCore::X86State::REG_R14] = Context->R14;
  State.gregs[FEXCore::X86State::REG_R15] = Context->R15;

  State.rip = Context->Rip;
  CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags);

  State.es_idx = Context->SegEs & 0xffff;
  State.cs_idx = Context->SegCs & 0xffff;
  State.ss_idx = Context->SegSs & 0xffff;
  State.ds_idx = Context->SegDs & 0xffff;
  State.fs_idx = Context->SegFs & 0xffff;
  State.gs_idx = Context->SegGs & 0xffff;

  // The TEB is the only populated GDT entry by default
  const auto TEB = reinterpret_cast<uint64_t>(NtCurrentTeb());
  State.gdt[(Context->SegGs & 0xffff) >> 3].base = TEB;
  State.gs_cached = TEB;
  State.fs_cached = 0;
  State.es_cached = 0;
  State.cs_cached = 0;
  State.ss_cached = 0;
  State.ds_cached = 0;

  // Floating-point register state
  CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(Context->FltSave.XmmRegisters), nullptr);
  memcpy(State.mm, Context->FltSave.FloatRegisters, sizeof(State.mm));

  State.FCW = Context->FltSave.ControlWord;
  State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (Context->FltSave.StatusWord >> 8) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (Context->FltSave.StatusWord >> 9) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (Context->FltSave.StatusWord >> 10) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (Context->FltSave.StatusWord >> 14) & 1;
  State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (Context->FltSave.StatusWord >> 11) & 0b111;
  State.AbridgedFTW = Context->FltSave.TagWord;
}

void ReconstructThreadState(ARM64_NT_CONTEXT* Context) {
  const auto& Config = SignalDelegator->GetConfig();
  auto* Thread = GetCPUArea().ThreadState();
  auto& State = Thread->CurrentFrame->State;

  State.rip = CTX->RestoreRIPFromHostPC(Thread, Context->Pc);

  // Spill all SRA GPRs
  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    State.gregs[i] = Context->X[Config.SRAGPRMapping[i]];
  }

  // Spill all SRA FPRs
  for (size_t i = 0; i < Config.SRAFPRCount; i++) {
    memcpy(State.xmm.sse.data[i], &Context->V[Config.SRAFPRMapping[i]], sizeof(__uint128_t));
  }
}

ARM64_NT_CONTEXT ReconstructPackedECContext(ARM64_NT_CONTEXT* Context) {
  ReconstructThreadState(Context);
  ARM64_NT_CONTEXT ECContext {};

  ECContext.ContextFlags = CONTEXT_ARM64_CONTROL | CONTEXT_ARM64_INTEGER | CONTEXT_ARM64_FLOATING_POINT;

  auto* Thread = GetCPUArea().ThreadState();
  auto& State = Thread->CurrentFrame->State;

  ECContext.X8 = State.gregs[FEXCore::X86State::REG_RAX];
  ECContext.X0 = State.gregs[FEXCore::X86State::REG_RCX];
  ECContext.X1 = State.gregs[FEXCore::X86State::REG_RDX];
  ECContext.X27 = State.gregs[FEXCore::X86State::REG_RBX];
  ECContext.Sp = State.gregs[FEXCore::X86State::REG_RSP];
  ECContext.Fp = State.gregs[FEXCore::X86State::REG_RBP];
  ECContext.X25 = State.gregs[FEXCore::X86State::REG_RSI];
  ECContext.X26 = State.gregs[FEXCore::X86State::REG_RDI];
  ECContext.X2 = State.gregs[FEXCore::X86State::REG_R8];
  ECContext.X3 = State.gregs[FEXCore::X86State::REG_R9];
  ECContext.X4 = State.gregs[FEXCore::X86State::REG_R10];
  ECContext.X5 = State.gregs[FEXCore::X86State::REG_R11];
  ECContext.X19 = State.gregs[FEXCore::X86State::REG_R12];
  ECContext.X20 = State.gregs[FEXCore::X86State::REG_R13];
  ECContext.X21 = State.gregs[FEXCore::X86State::REG_R14];
  ECContext.X22 = State.gregs[FEXCore::X86State::REG_R15];

  ECContext.Pc = State.rip;

  CTX->ReconstructXMMRegisters(Thread, reinterpret_cast<__uint128_t*>(&ECContext.V[0]), nullptr);
  ECContext.Lr = State.mm[0][0];
  ECContext.X6 = State.mm[1][0];
  ECContext.X7 = State.mm[2][0];
  ECContext.X9 = State.mm[3][0];

  ECContext.X16 = (State.mm[3][1] & 0xff) << 16 | (State.mm[2][1] & 0xff) << 16 |
	  (State.mm[1][1] & 0xff) << 8 | (State.mm[0][1] & 0xff); 

  ECContext.X10 = State.mm[4][0];
  ECContext.X11 = State.mm[5][0];
  ECContext.X12 = State.mm[6][0];
  ECContext.X15 = State.mm[7][0];

  ECContext.X17 = (State.mm[7][1] & 0xff) << 16 | (State.mm[6][1] & 0xff) << 16 |
	  (State.mm[5][1] & 0xff) << 8 | (State.mm[4][1] & 0xff); 

  ECContext.X13 = 0;
  ECContext.X14 = 0;
  ECContext.X18 = 0;
  ECContext.X23 = 0;
  ECContext.X24 = 0;
  ECContext.X28 = 0;

  ECContext.Cpsr = Context->Cpsr;
  ECContext.Fpcr = Context->Fpcr;
  ECContext.Fpsr = Context->Fpsr;

  return ECContext;
}

static std::optional<FEX::Windows::TSOHandlerConfig> HandlerConfig;

bool HandleUnalignedAccess(ARM64_NT_CONTEXT* Context) {
  if (!CTX->IsAddressInCodeBuffer(GetCPUArea().ThreadState(), Context->Pc)) {
    return false;
  }

  const auto Result = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(GetCPUArea().ThreadState(), HandlerConfig->GetUnalignedHandlerType(), Context->Pc, &Context->X0);
  if (!Result.first) {
    return false;
  }

  Context->Pc += Result.second;
  return true;
}
} // namespace Context

namespace Logging {
void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  const auto Output = fextl::fmt::format("[{}][{:X}] {}\n", LogMan::DebugLevelStr(Level), GetCurrentThreadId(), Message);
  __wine_dbg_output(Output.c_str());
}

void AssertHandler(const char* Message) {
  const auto Output = fextl::fmt::format("[ASSERT] {}\n", Message);
  __wine_dbg_output(Output.c_str());
}

void Init() {
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);
}
} // namespace Logging

class ECSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  ECSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_WIN32;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    return 0;
  }

  FEXCore::HLE::SyscallABI GetSyscallABI(uint64_t Syscall) override {
    return {.NumArgs = 0, .HasReturn = false, .HostSyscallNumber = -1};
  }

  FEXCore::HLE::AOTIRCacheEntryLookupResult LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) override {
    return {0, 0};
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->ReprotectRWXIntervals(Start, Length);
  }
};

void ProcessInit() {
  Logging::Init();
  FEX::Config::InitializeConfigs();
  FEXCore::Config::Initialize();
  FEXCore::Config::AddLayer(FEX::Config::CreateGlobalMainLayer());
  FEXCore::Config::AddLayer(FEX::Config::CreateMainLayer());
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();

  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");

  // Not applicable to Windows
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_TSOAUTOMIGRATION, "0");

  FEXCore::Context::InitializeStaticTables(FEXCore::Context::MODE_64BIT);

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  SyscallHandler = fextl::make_unique<ECSyscallHandler>();
  Context::HandlerConfig.emplace();

  CTX = FEXCore::Context::Context::CreateNewContext();
  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->InitCore();
  InvalidationTracker.emplace(*CTX, Threads);
  CPUFeatures.emplace(*CTX);
  auto Thunk = reinterpret_cast<uint64_t>(GetProcAddress(GetModuleHandle("ntdll.dll"), "KiUserExceptionDispatcher"));
  KiUserExceptionDispatcher = Thunk + 14 + *reinterpret_cast<int32_t *>(Thunk + 10);
}

extern "C" void SyncThreadContext() {
  auto* Context = reinterpret_cast<CONTEXT*>(GetCPUArea().Area->ContextAmd64);
  auto* Thread = GetCPUArea().ThreadState();
  Context::LoadStateFromECContext(Thread, Context);
}

void ProcessTerm() {}

class ScopedCallbackDisable {
private:
  bool Prev;

public:
  ScopedCallbackDisable() {
    Prev = GetCPUArea().Area->InSyscallCallback;
    GetCPUArea().Area->InSyscallCallback = true;
  }

  ~ScopedCallbackDisable() {
    GetCPUArea().Area->InSyscallCallback = Prev;
  }
};

NTSTATUS ResetToConsistentState(EXCEPTION_POINTERS* Ptrs, ARM64_NT_CONTEXT* Context, BOOLEAN* Continue) {
  ScopedCallbackDisable Guard;
  const auto* Exception = Ptrs->ExceptionRecord;
  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Context::HandleUnalignedAccess(Context)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", Context->Pc);
    *Continue = true;
    return STATUS_SUCCESS;
  }

  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    bool HandledRWX = false;
    if (InvalidationTracker && GetCPUArea().ThreadState()) {
      std::scoped_lock Lock(ThreadCreationMutex);
      HandledRWX = InvalidationTracker->HandleRWXAccessViolation(FaultAddress);
    }

    if (HandledRWX) {
      LogMan::Msg::DFmt("Handled self-modifying code: pc: {:X} fault: {:X}", Context->Pc, FaultAddress);
      *Continue = true;
      return STATUS_SUCCESS;
    }
  }

  if (!CTX->IsAddressInCodeBuffer(GetCPUArea().ThreadState(), Context->Pc) && !IsDispatcherAddress(Context->Pc)) {
    return STATUS_SUCCESS;
  }

  if (IsEmulatorStackAddress(reinterpret_cast<uint64_t>(__builtin_frame_address(0)))) {
    const auto& Config = SignalDelegator->GetConfig();
    uint64_t GuestSp = Context->X[Config.SRAGPRMapping[static_cast<size_t>(FEXCore::X86State::REG_RSP)]];
    struct DispatchArgs {
      ARM64_NT_CONTEXT Context;
      EXCEPTION_RECORD Rec;
      uint64_t Align;
      uint64_t Redzone[2];
    } *Args = reinterpret_cast<DispatchArgs *>(FEXCore::AlignDown(GuestSp, 64)) - 1;

    LogMan::Msg::DFmt("Reconstructing context");
    Args->Context = Context::ReconstructPackedECContext(Context);
    LogMan::Msg::DFmt("pc: {:X} rip: {:X}", Context->Pc, Args->Context.Pc);
    Args->Rec = HandleGuestException( Ptrs->ExceptionRecord, &Args->Context );
    Context->Sp = reinterpret_cast<uint64_t>(Args);
    Context->Pc = KiUserExceptionDispatcher;
    *Continue = true;
    LogMan::Msg::DFmt("Rethrowing onto guest stack: {:X}", Context->Sp);
    return STATUS_SUCCESS;
  }

  LogMan::Msg::EFmt("Unhandled path");
  return STATUS_SUCCESS;
}

void NotifyMemoryAlloc(void* Address, SIZE_T Size, ULONG Type, ULONG Prot) {
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), Prot);
}

void NotifyMemoryFree(void* Address, SIZE_T Size, ULONG FreeType) {
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  if (!Size) {
    InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);
  } else if (FreeType & MEM_DECOMMIT) {
    InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), true);
  }
}

void NotifyMemoryProtect(void* Address, SIZE_T Size, ULONG NewProt) {
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), NewProt);
}

void NotifyUnmapViewOfSection(void* Address) {
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);
}

void BTCpu64FlushInstructionCache(const void* Address, SIZE_T Size) {
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void FEXAddNoTSOCodeRange(void* Address, SIZE_T Size) {
  if (!GetCPUArea().ThreadState()) {
    return;
  }

  CTX->AddNoTSOCodeRange(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size));
}

NTSTATUS ThreadInit() {
  const auto CPUArea = GetCPUArea();

  auto* Thread = CTX->CreateThread(0, 0);
  Thread->CurrentFrame->Pointers.Common.ExitFunctionEC = reinterpret_cast<uintptr_t>(&ExitFunctionEC);
  CPUArea.StateFrame() = Thread->CurrentFrame;
  auto* Context = reinterpret_cast<CONTEXT*>(CPUArea.Area->ContextAmd64);

  Context::LoadStateFromECContext(Thread, Context);
  uint64_t EnterEC = Thread->CurrentFrame->Pointers.Common.DispatcherLoopTopEnterEC;
  CPUArea.DispatcherLoopTopEnterEC() = EnterEC;

  uint64_t EnterECFillSRA = Thread->CurrentFrame->Pointers.Common.DispatcherLoopTopEnterECFillSRA;
  CPUArea.DispatcherLoopTopEnterECFillSRA() = EnterECFillSRA;

  {
    std::scoped_lock Lock(ThreadCreationMutex);
    Threads.emplace(GetCurrentThreadId(), Thread);
  }

  CPUArea.ThreadState() = Thread;
  return STATUS_SUCCESS;
}

NTSTATUS ThreadTerm(HANDLE Thread) {
  const auto [Err, CPUArea] = GetThreadCPUArea(Thread);
  if (Err) {
    return Err;
  }
  auto* OldThreadState = CPUArea.ThreadState();
  CPUArea.ThreadState() = nullptr;

  {
    THREAD_BASIC_INFORMATION Info;
    if (NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
      return Err;
    }

    const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
    std::scoped_lock Lock(ThreadCreationMutex);
    Threads.erase(ThreadTID);
  }

  CTX->DestroyThread(OldThreadState);
  return STATUS_SUCCESS;
}

BOOLEAN BTCpu64IsProcessorFeaturePresent(UINT Feature) {
  return CPUFeatures->IsFeaturePresent(Feature) ? TRUE : FALSE;
}

void UpdateProcessorInformation(SYSTEM_CPU_INFORMATION* Info) {
  CPUFeatures->UpdateInformation(Info);
}
