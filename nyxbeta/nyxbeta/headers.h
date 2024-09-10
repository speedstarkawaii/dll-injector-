
#include <Windows.h>
#include <iostream>
#include <subauth.h>
#include <shlwapi.h>
#include <psapi.h>
#include <filesystem>
#include "xor.h"
#include <thread>
#include <vector>
#include <TlHelp32.h>

#include <string>
#include <algorithm>
#include <WinInet.h>
#include <fstream>
#include <chrono>
#include <filesystem>

HMODULE NTDLL = NULL;

#define MF(Name,Module) ((ULONG_PTR (*)(...))GetProcAddress(Module,Name))
#define NtF(Name) MF(Name,NTDLL)
typedef struct _SYSTEM_MODULE { PVOID  Reserved1;    PVOID  Reserved2;     PVOID  ImageBase;     ULONG  ImageSize;     ULONG  Flags;     USHORT Index;     USHORT NameLength;     USHORT LoadCount;     USHORT PathLength;     CHAR   ImageName[256]; }  SYSTEM_MODULE, * PSYSTEM_MODULE;
typedef struct _SYSTEM_MODULE_INFORMATION { ULONG                ModulesCount;   SYSTEM_MODULE        Modules[0]; } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
typedef LONG KPRIORITY;
struct CLIENT_ID
{
    DWORD UniqueProcess; // Process ID
#ifdef _WIN64
    ULONG pad1;
#endif
    DWORD UniqueThread;  // Thread ID
#ifdef _WIN64
    ULONG pad2;
#endif
};

typedef struct {
    FILETIME ProcessorTime;    FILETIME UserTime;    FILETIME CreateTime;    ULONG WaitTime;
#ifdef _WIN64
    ULONG pad1;
#endif
    PVOID StartAddress;    CLIENT_ID Client_Id;    KPRIORITY CurrentPriority;    KPRIORITY BasePriority;    ULONG ContextSwitchesPerSec;    ULONG ThreadState;    ULONG ThreadWaitReason;    ULONG pad2;
} SYSTEM_THREAD_INFORMATION;
typedef struct {
    ULONG_PTR PeakVirtualSize;    ULONG_PTR VirtualSize;    ULONG PageFaultCount;
#ifdef _WIN64
    ULONG pad1;
#endif
    ULONG_PTR PeakWorkingSetSize;    ULONG_PTR WorkingSetSize;    ULONG_PTR QuotaPeakPagedPoolUsage;    ULONG_PTR QuotaPagedPoolUsage;    ULONG_PTR QuotaPeakNonPagedPoolUsage;    ULONG_PTR QuotaNonPagedPoolUsage;    ULONG_PTR PagefileUsage;    ULONG_PTR PeakPagefileUsage;
} VM_COUNTERS;
typedef struct {
    ULONG NextOffset;    ULONG ThreadCount;    LARGE_INTEGER WorkingSetPrivateSize;    ULONG HardFaultCount;    ULONG NumberOfThreadsHighWatermark;    ULONGLONG CycleTime;    FILETIME CreateTime;    FILETIME UserTime;    FILETIME KernelTime;    UNICODE_STRING ImageName;    KPRIORITY BasePriority;
#ifdef _WIN64
    ULONG pad1;
#endif
    ULONG ProcessId;
#ifdef _WIN64
    ULONG pad2;
#endif
    ULONG InheritedFromProcessId;
#ifdef _WIN64
    ULONG pad3;
#endif
    ULONG HandleCount;    ULONG SessionId;    ULONG_PTR UniqueProcessKey;    VM_COUNTERS VirtualMemoryCounters;    ULONG_PTR PrivatePageCount;    IO_COUNTERS IoCounters;    SYSTEM_THREAD_INFORMATION ThreadInfos[1];
} SYSTEM_PROCESS_INFORMATION;
typedef enum _SYSTEM_INFORMATION_CLASS { SystemBasicInformation, SystemProcessorInformation, SystemPerformanceInformation, SystemTimeOfDayInformation, SystemPathInformation, SystemProcessInformation, SystemCallCountInformation, SystemDeviceInformation, SystemProcessorPerformanceInformation, SystemFlagsInformation, SystemCallTimeInformation, SystemModuleInformation, SystemLocksInformation, SystemStackTraceInformation, SystemPagedPoolInformation, SystemNonPagedPoolInformation, SystemHandleInformation, SystemObjectInformation, SystemPageFileInformation, SystemVdmInstemulInformation, SystemVdmBopInformation, SystemFileCacheInformation, SystemPoolTagInformation, SystemInterruptInformation, SystemDpcBehaviorInformation, SystemFullMemoryInformation, SystemLoadGdiDriverInformation, SystemUnloadGdiDriverInformation, SystemTimeAdjustmentInformation, SystemSummaryMemoryInformation, SystemNextEventIdInformation, SystemEventIdsInformation, SystemCrashDumpInformation, SystemExceptionInformation, SystemCrashDumpStateInformation, SystemKernelDebuggerInformation, SystemContextSwitchInformation, SystemRegistryQuotaInformation, SystemExtendServiceTableInformation, SystemPrioritySeperation, SystemPlugPlayBusInformation, SystemDockInformation } SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO { HANDLE HandleValue; ULONG_PTR HandleCount;    ULONG_PTR PointerCount;    ULONG GrantedAccess;    ULONG ObjectTypeIndex;    ULONG HandleAttributes;    ULONG Reserved; } PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION { ULONG_PTR NumberOfHandles;    ULONG_PTR Reserved;    _Field_size_(NumberOfHandles) PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1]; } PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;
typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;
typedef enum _WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout, // LARGE_INTEGER
    WorkerFactoryRetryTimeout, // LARGE_INTEGER
    WorkerFactoryIdleTimeout, // s: LARGE_INTEGER
    WorkerFactoryBindingCount, // s: ULONG
    WorkerFactoryThreadMinimum, // s: ULONG
    WorkerFactoryThreadMaximum, // s: ULONG
    WorkerFactoryPaused, // ULONG or BOOLEAN
    WorkerFactoryBasicInformation, // q: WORKER_FACTORY_BASIC_INFORMATION
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation, // 10
    WorkerFactoryThreadBasePriority, // s: ULONG
    WorkerFactoryTimeoutWaiters, // s: ULONG, since THRESHOLD
    WorkerFactoryFlags, // s: ULONG
    WorkerFactoryThreadSoftMaximum, // s: ULONG
    WorkerFactoryThreadCpuSets, // since REDSTONE5
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;
typedef struct _WORKER_FACTORY_BASIC_INFORMATION {
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;
typedef struct _TP_TASK_CALLBACKS
{
    void* ExecuteCallback;
    void* Unposted;
} TP_TASK_CALLBACKS, * PTP_TASK_CALLBACKS;

typedef struct _TP_TASK
{
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char Padding_242[3];
    struct _LIST_ENTRY ListEntry;
} TP_TASK, * PTP_TASK;

typedef struct _TPP_REFCOUNT
{
    volatile INT32 Refcount;
} TPP_REFCOUNT, * PTPP_REFCOUNT;

typedef struct _TPP_CALLER
{
    void* ReturnAddress;
} TPP_CALLER, * PTPP_CALLER;

typedef struct _TPP_PH
{
    struct _TPP_PH_LINKS* Root;
} TPP_PH, * PTPP_PH;

typedef struct _TP_DIRECT
{
    struct _TP_TASK Task;
    UINT64 Lock;
    struct _LIST_ENTRY IoCompletionInformationList;
    void* Callback;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char __PADDING__[3];
} TP_DIRECT, * PTP_DIRECT;

typedef struct _TPP_TIMER_SUBQUEUE
{
    INT64 Expiration;
    struct _TPP_PH WindowStart;
    struct _TPP_PH WindowEnd;
    void* Timer;
    void* TimerPkt;
    struct _TP_DIRECT Direct;
    UINT32 ExpirationWindow;
    INT32 __PADDING__[1];
} TPP_TIMER_SUBQUEUE, * PTPP_TIMER_SUBQUEUE;

typedef struct _TPP_TIMER_QUEUE
{
    struct _RTL_SRWLOCK Lock;
    struct _TPP_TIMER_SUBQUEUE AbsoluteQueue;
    struct _TPP_TIMER_SUBQUEUE RelativeQueue;
    INT32 AllocatedTimerCount;
    INT32 __PADDING__[1];
} TPP_TIMER_QUEUE, * PTPP_TIMER_QUEUE;

typedef struct _TPP_NUMA_NODE
{
    INT32 WorkerCount;
} TPP_NUMA_NODE, * PTPP_NUMA_NODE;

typedef union _TPP_POOL_QUEUE_STATE
{
    union
    {
        INT64 Exchange;
        struct
        {
            INT32 RunningThreadGoal : 16;
            UINT32 PendingReleaseCount : 16;
            UINT32 QueueLength;
        };
    };
} TPP_POOL_QUEUE_STATE, * PTPP_POOL_QUEUE_STATE;

typedef struct _TPP_QUEUE
{
    struct _LIST_ENTRY Queue;
    struct _RTL_SRWLOCK Lock;
} TPP_QUEUE, * PTPP_QUEUE;

typedef struct _FULL_TP_POOL
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_239;
    union _TPP_POOL_QUEUE_STATE QueueState;
    struct _TPP_QUEUE* TaskQueue[3];
    struct _TPP_NUMA_NODE* NumaNode;
    struct _GROUP_AFFINITY* ProximityInfo;
    void* WorkerFactory;
    void* CompletionPort;
    struct _RTL_SRWLOCK Lock;
    struct _LIST_ENTRY PoolObjectList;
    struct _LIST_ENTRY WorkerList;
    struct _TPP_TIMER_QUEUE TimerQueue;
    struct _RTL_SRWLOCK ShutdownLock;
    UINT8 ShutdownInitiated;
    UINT8 Released;
    UINT16 PoolFlags;
    long Padding_240;
    struct _LIST_ENTRY PoolLinks;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    volatile INT32 AvailableWorkerCount;
    volatile INT32 LongRunningWorkerCount;
    UINT32 LastProcCount;
    volatile INT32 NodeStatus;
    volatile INT32 BindingCount;
    UINT32 CallbackChecksDisabled : 1;
    UINT32 TrimTarget : 11;
    UINT32 TrimmedThrdCount : 11;
    UINT32 SelectedCpuSetCount;
    long Padding_241;
    struct _RTL_CONDITION_VARIABLE TrimComplete;
    struct _LIST_ENTRY TrimmedWorkerList;
} FULL_TP_POOL, * PFULL_TP_POOL;

typedef struct _ALPC_WORK_ON_BEHALF_TICKET
{
    UINT32 ThreadId;
    UINT32 ThreadCreationTimeLow;
} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

typedef union _TPP_WORK_STATE
{
    union
    {
        INT32 Exchange;
        UINT32 Insertable : 1;
        UINT32 PendingCallbackCount : 31;
    };
} TPP_WORK_STATE, * PTPP_WORK_STATE;

typedef struct _TPP_ITE_WAITER
{
    struct _TPP_ITE_WAITER* Next;
    void* ThreadId;
} TPP_ITE_WAITER, * PTPP_ITE_WAITER;

typedef struct _TPP_PH_LINKS
{
    struct _LIST_ENTRY Siblings;
    struct _LIST_ENTRY Children;
    INT64 Key;
} TPP_PH_LINKS, * PTPP_PH_LINKS;

typedef struct _TPP_ITE
{
    struct _TPP_ITE_WAITER* First;
} TPP_ITE, * PTPP_ITE;

typedef union _TPP_FLAGS_COUNT
{
    union
    {
        UINT64 Count : 60;
        UINT64 Flags : 4;
        INT64 Data;
    };
} TPP_FLAGS_COUNT, * PTPP_FLAGS_COUNT;

typedef struct _TPP_BARRIER
{
    volatile union _TPP_FLAGS_COUNT Ptr;
    struct _RTL_SRWLOCK WaitLock;
    struct _TPP_ITE WaitList;
} TPP_BARRIER, * PTPP_BARRIER;

typedef struct _TP_CLEANUP_GROUP
{
    struct _TPP_REFCOUNT Refcount;
    INT32 Released;
    struct _RTL_SRWLOCK MemberLock;
    struct _LIST_ENTRY MemberList;
    struct _TPP_BARRIER Barrier;
    struct _RTL_SRWLOCK CleanupLock;
    struct _LIST_ENTRY CleanupList;
} TP_CLEANUP_GROUP, * PTP_CLEANUP_GROUP;


typedef struct _TPP_CLEANUP_GROUP_MEMBER
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_233;
    const struct _TPP_CLEANUP_GROUP_MEMBER_VFUNCS* VFuncs;
    struct _TP_CLEANUP_GROUP* CleanupGroup;
    void* CleanupGroupCancelCallback;
    void* FinalizationCallback;
    struct _LIST_ENTRY CleanupGroupMemberLinks;
    struct _TPP_BARRIER CallbackBarrier;
    union
    {
        void* Callback;
        void* WorkCallback;
        void* SimpleCallback;
        void* TimerCallback;
        void* WaitCallback;
        void* IoCallback;
        void* AlpcCallback;
        void* AlpcCallbackEx;
        void* JobCallback;
    };
    void* Context;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    void* SubProcessTag;
    struct _GUID ActivityId;
    struct _ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
    void* RaceDll;
    FULL_TP_POOL* Pool;
    struct _LIST_ENTRY PoolObjectLinks;
    union
    {
        volatile INT32 Flags;
        UINT32 LongFunction : 1;
        UINT32 Persistent : 1;
        UINT32 UnusedPublic : 14;
        UINT32 Released : 1;
        UINT32 CleanupGroupReleased : 1;
        UINT32 InCleanupGroupCleanupList : 1;
        UINT32 UnusedPrivate : 13;
    };
    long Padding_234;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    enum _TP_CALLBACK_PRIORITY CallbackPriority;
    INT32 __PADDING__[1];
} TPP_CLEANUP_GROUP_MEMBER, * PTPP_CLEANUP_GROUP_MEMBER;

typedef struct _FULL_TP_WORK
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_TASK Task;
    volatile union _TPP_WORK_STATE WorkState;
    INT32 __PADDING__[1];
} FULL_TP_WORK, * PFULL_TP_WORK;

typedef struct _FULL_TP_TIMER
{
    struct _FULL_TP_WORK Work;
    struct _RTL_SRWLOCK Lock;
    union
    {
        struct _TPP_PH_LINKS WindowEndLinks;
        struct _LIST_ENTRY ExpirationLinks;
    };
    struct _TPP_PH_LINKS WindowStartLinks;
    INT64 DueTime;
    struct _TPP_ITE Ite;
    UINT32 Window;
    UINT32 Period;
    UINT8 Inserted;
    UINT8 WaitTimer;
    union
    {
        UINT8 TimerStatus;
        UINT8 InQueue : 1;
        UINT8 Absolute : 1;
        UINT8 Cancelled : 1;
    };
    UINT8 BlockInsert;
    INT32 __PADDING__[1];
} FULL_TP_TIMER, * PFULL_TP_TIMER;

typedef struct _FULL_TP_WAIT
{
    struct _FULL_TP_TIMER Timer;
    void* Handle;
    void* WaitPkt;
    void* NextWaitHandle;
    union _LARGE_INTEGER NextWaitTimeout;
    struct _TP_DIRECT Direct;
    union
    {
        union
        {
            UINT8 AllFlags;
            UINT8 NextWaitActive : 1;
            UINT8 NextTimeoutActive : 1;
            UINT8 CallbackCounted : 1;
            UINT8 Spare : 5;
        };
    } WaitFlags;
    char __PADDING__[7];
} FULL_TP_WAIT, * PFULL_TP_WAIT;

typedef struct _FULL_TP_IO
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_DIRECT Direct;
    void* File;
    volatile INT32 PendingIrpCount;
    INT32 __PADDING__[1];
} FULL_TP_IO, * PFULL_TP_IO;

typedef struct _FULL_TP_ALPC
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* AlpcPort;
    INT32 DeferredSendCount;
    INT32 LastConcurrencyCount;
    union
    {
        UINT32 Flags;
        UINT32 ExTypeCallback : 1;
        UINT32 CompletionListRegistered : 1;
        UINT32 Reserved : 30;
    };
    INT32 __PADDING__[1];
} FULL_TP_ALPC, * PFULL_TP_ALPC;

typedef struct _FULL_TP_JOB
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* JobHandle;
    union
    {
        volatile int64_t CompletionState;
        int64_t Rundown : 1;
        int64_t CompletionCount : 63;
    };
    struct _RTL_SRWLOCK RundownLock;
} FULL_TP_JOB, * PFULL_TP_JOB;

typedef struct _OBJECT_TYPE_INFORMATION { UNICODE_STRING          TypeName;    ULONG                   TotalNumberOfHandles;    ULONG                   TotalNumberOfObjects;    WCHAR                   Unused1[8];    ULONG                   HighWaterNumberOfHandles;    ULONG                   HighWaterNumberOfObjects;    WCHAR                   Unused2[8];    ACCESS_MASK             InvalidAttributes;    GENERIC_MAPPING         GenericMapping;    ACCESS_MASK             ValidAttributes;    BOOLEAN                 SecurityRequired;    BOOLEAN                 MaintainHandleCount;    USHORT                  MaintainTypeList;    POOL_TYPE               PoolType;    ULONG                   DefaultPagedPoolCharge;    ULONG                   DefaultNonPagedPoolCharge; } OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

#define RBXModuleName L"RobloxPlayerBeta.exe"

bool DoesProcessExist(const std::wstring& processName) {
    DWORD processIds[1024], cbNeeded;
    if (!EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {
        return false;
    }

    DWORD processCount = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < processCount; ++i) {
        if (processIds[i] == 0) {
            continue;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
        if (hProcess) {
            WCHAR processNameBuffer[MAX_PATH];
            if (GetModuleBaseName(hProcess, nullptr, processNameBuffer, sizeof(processNameBuffer) / sizeof(WCHAR))) {
                if (_wcsicmp(processNameBuffer, processName.c_str()) == 0) {
                    CloseHandle(hProcess);
                    return true;
                }
            }
            CloseHandle(hProcess);
        }
    }
    return false;
}
