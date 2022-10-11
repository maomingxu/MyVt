#pragma once
#include <intrin.h>
#include <ntddk.h>
#include "vtsystem.h"

// VMCS Region Size
#define VMCS_SIZE   4096

// VMXON Region Size
#define VMXON_SIZE   4096
// Alignment Size
#define ALIGNMENT_PAGE_SIZE   4096

// Hypervisor reserved range for RDMSR and WRMSR
#define RESERVED_MSR_RANGE_LOW 0x40000000
#define RESERVED_MSR_RANGE_HI  0x400000F0
#define VMM_STACK_SIZE 0x20000
typedef union _MOV_CR_QUALIFICATION
{
    ULONG_PTR All;
    struct
    {
        ULONG ControlRegister : 4;
        ULONG AccessType : 2;
        ULONG LMSWOperandType : 1;
        ULONG Reserved1 : 1;
        ULONG Register : 4;
        ULONG Reserved2 : 4;
        ULONG LMSWSourceData : 16;
        ULONG Reserved3;
    } Fields;
} MOV_CR_QUALIFICATION, * PMOV_CR_QUALIFICATION;

/*
when a logical processor is reset. The relevant bits of the MSR are:
• Bit 0 is the lock bit. If this bit is clear, VMXON causes a general-protection exception. If the lock bit is set,
WRMSR to this MSR causes a general-protection exception; the MSR cannot be modified until a power-up reset
condition. System BIOS can use this bit to provide a setup option for BIOS to disable support for VMX. To
enable VMX support in a platform, BIOS must set bit 1, bit 2, or both (see below), as well as the lock bit.
• Bit 1 enables VMXON in SMX operation. If this bit is clear, execution of VMXON in SMX operation causes a
general-protection exception. Attempts to set this bit on logical processors that do not support both VMX
operation (see Section 23.6) and SMX operation (see Chapter 6, “Safer Mode Extensions Reference,” in Intel®
64 and IA-32 Architectures Software Developer’s Manual, Volume 2D) cause general-protection exceptions.
• Bit 2 enables VMXON outside SMX operation. If this bit is clear, execution of VMXON outside SMX
operation causes a general-protection exception. Attempts to set this bit on logical processors that do not
support VMX operation (see Section 23.6) cause general-protection exceptions.
*/
typedef union _IA32_FEATURE_CONTROL_MSR
{
    ULONG64 All;
    struct
    {
        ULONG64 Lock : 1;                // [0]
        ULONG64 EnableSMX : 1;           // [1]
        ULONG64 EnableVmxon : 1;         // [2]
        ULONG64 Reserved2 : 5;           // [3-7]
        ULONG64 EnableLocalSENTER : 7;   // [8-14]
        ULONG64 EnableGlobalSENTER : 1;  // [15]
        ULONG64 Reserved3a : 16;         //
        ULONG64 Reserved3b : 32;         // [16-63]
    } Fields;
} IA32_FEATURE_CONTROL_MSR, *PIA32_FEATURE_CONTROL_MSR;

typedef struct _CPUID
{
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUID, *PCPUID;

enum SEGREGS
{
    ES = 0,
    CS,
    SS,
    DS,
    FS,
    GS,
    LDTR,
    TR
};

typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxonRegion; // VMXON region
    UINT64 VmcsRegion;  // VMCS region
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

typedef struct _VMX_VMXOFF_STATE
{
    BOOLEAN IsVmxoffExecuted;					// Shows whether the VMXOFF executed or not
    UINT64  GuestRip;							// Rip address of guest to return
    UINT64  GuestRsp;							// Rsp address of guest to return

} VMX_VMXOFF_STATE, * PVMX_VMXOFF_STATE;

typedef struct _VMX_VARS
{
    BOOLEAN IsOnVmxRootMode;										// Detects whether the current logical core is on Executing on VMX Root Mode
    BOOLEAN IncrementRip;											// Checks whether it has to redo the previous instruction or not (it used mainly in Ept routines)
    BOOLEAN HasLaunched;											// Indicate whether the core is virtualized or not

    PVOID              pVmxOnRegion_VA;
    UINT64             pVmxOnRegion_PA;
    PVOID              pVmcsRegion_VA;
    UINT64             pVmcsRegion_PA;
    UINT64             pVmmHostStack_VA;
    PVOID              pMsrBitMap_VA;
    UINT64             pMsrBitMap_PA;

    VMX_VMXOFF_STATE   VmxoffState;									// Shows the vmxoff state of the guest
}S_VMX_VARS,*PS_VMX_VARS;

typedef union _IA32_VMX_BASIC_MSR
{
    ULONG64 All;
    struct
    {
        ULONG32 RevisionIdentifier : 31;   // [0-30]
        ULONG32 Reserved1 : 1;             // [31]
        ULONG32 RegionSize : 12;           // [32-43]
        ULONG32 RegionClear : 1;           // [44]
        ULONG32 Reserved2 : 3;             // [45-47]
        ULONG32 SupportedIA64 : 1;         // [48]
        ULONG32 SupportedDualMoniter : 1;  // [49]
        ULONG32 MemoryType : 4;            // [50-53]
        ULONG32 VmExitReport : 1;          // [54]
        ULONG32 VmxCapabilityHint : 1;     // [55]
        ULONG32 Reserved3 : 8;             // [56-63]
    } Fields;
} IA32_VMX_BASIC_MSR, *PIA32_VMX_BASIC_MSR;

typedef union _MSR
{
    struct
    {
        ULONG Low;
        ULONG High;
    };

    ULONG64 Content;
} MSR, *PMSR;

typedef union SEGMENT_ATTRIBUTES
{
    USHORT UCHARs;
    struct
    {
        USHORT TYPE : 4; /* 0;  Bit 40-43 */
        USHORT S : 1;    /* 4;  Bit 44 */
        USHORT DPL : 2;  /* 5;  Bit 45-46 */
        USHORT P : 1;    /* 7;  Bit 47 */

        USHORT AVL : 1; /* 8;  Bit 52 */
        USHORT L : 1;   /* 9;  Bit 53 */
        USHORT DB : 1;  /* 10; Bit 54 */
        USHORT G : 1;   /* 11; Bit 55 */
        USHORT GAP : 4;

    } Fields;
} SEGMENT_ATTRIBUTES;

typedef struct SEGMENT_SELECTOR
{
    USHORT             SEL;
    SEGMENT_ATTRIBUTES ATTRIBUTES;
    ULONG32            LIMIT;
    ULONG64            BASE;
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
    USHORT LIMIT0;
    USHORT BASE0;
    UCHAR  BASE1;
    UCHAR  ATTR0;
    UCHAR  LIMIT1ATTR1;
    UCHAR  BASE2;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

struct Idtr {
    unsigned short limit;
    ULONG_PTR base;
};

struct Gdtr
{
    unsigned short limit;
    ULONG_PTR base;
};

union FlagRegisterX64 {
    ULONG_PTR all;
    struct {
        ULONG_PTR cf : 1;          //!< [0] Carry flag
        ULONG_PTR reserved1 : 1;   //!< [1] Always 1
        ULONG_PTR pf : 1;          //!< [2] Parity flag
        ULONG_PTR reserved2 : 1;   //!< [3] Always 0
        ULONG_PTR af : 1;          //!< [4] Borrow flag
        ULONG_PTR reserved3 : 1;   //!< [5] Always 0
        ULONG_PTR zf : 1;          //!< [6] Zero flag
        ULONG_PTR sf : 1;          //!< [7] Sign flag
        ULONG_PTR tf : 1;          //!< [8] Trap flag
        ULONG_PTR intf : 1;        //!< [9] Interrupt flag
        ULONG_PTR df : 1;          //!< [10] Direction flag
        ULONG_PTR of : 1;          //!< [11] Overflow flag
        ULONG_PTR iopl : 2;        //!< [12:13] I/O privilege level
        ULONG_PTR nt : 1;          //!< [14] Nested task flag
        ULONG_PTR reserved4 : 1;   //!< [15] Always 0
        ULONG_PTR rf : 1;          //!< [16] Resume flag
        ULONG_PTR vm : 1;          //!< [17] Virtual 8086 mode
        ULONG_PTR ac : 1;          //!< [18] Alignment check
        ULONG_PTR vif : 1;         //!< [19] Virtual interrupt flag
        ULONG_PTR vip : 1;         //!< [20] Virtual interrupt pending
        ULONG_PTR id : 1;          //!< [21] Identification flag
        ULONG_PTR reserved5 : 10;  //!< [22:31] Always 0
    } fields;
};

/// Represents a stack layout after PUSHAQ
struct GpRegistersX64 {
    ULONG_PTR r15;
    ULONG_PTR r14;
    ULONG_PTR r13;
    ULONG_PTR r12;
    ULONG_PTR r11;
    ULONG_PTR r10;
    ULONG_PTR r9;
    ULONG_PTR r8;
    ULONG_PTR di;
    ULONG_PTR si;
    ULONG_PTR bp;
    ULONG_PTR sp;
    ULONG_PTR bx;
    ULONG_PTR dx;
    ULONG_PTR cx;
    ULONG_PTR ax;
};
typedef struct GpRegistersX64 GpRegisters;
typedef union FlagRegisterX64 FlagRegister;

// Represents a stack layout after a sequence of PUSHFx, PUSHAx
struct AllRegistersX64 {
    GpRegisters  gp;
    FlagRegister flags;
};
typedef struct AllRegistersX64 AllRegisters;


/// See: MODEL-SPECIFIC REGISTERS (MSRS)
enum  eMsr{
    kIa32ApicBase = 0x01B,

    kIa32FeatureControl = 0x03A,

    kIa32SysenterCs = 0x174,
    kIa32SysenterEsp = 0x175,
    kIa32SysenterEip = 0x176,

    kIa32Debugctl = 0x1D9,

    kIa32MtrrCap = 0xFE,
    kIa32MtrrDefType = 0x2FF,
    kIa32MtrrPhysBaseN = 0x200,
    kIa32MtrrPhysMaskN = 0x201,
    kIa32MtrrFix64k00000 = 0x250,
    kIa32MtrrFix16k80000 = 0x258,
    kIa32MtrrFix16kA0000 = 0x259,
    kIa32MtrrFix4kC0000 = 0x268,
    kIa32MtrrFix4kC8000 = 0x269,
    kIa32MtrrFix4kD0000 = 0x26A,
    kIa32MtrrFix4kD8000 = 0x26B,
    kIa32MtrrFix4kE0000 = 0x26C,
    kIa32MtrrFix4kE8000 = 0x26D,
    kIa32MtrrFix4kF0000 = 0x26E,
    kIa32MtrrFix4kF8000 = 0x26F,

    kIa32VmxBasic = 0x480,
    kIa32VmxPinbasedCtls = 0x481,
    kIa32VmxProcBasedCtls = 0x482,
    kIa32VmxExitCtls = 0x483,
    kIa32VmxEntryCtls = 0x484,
    kIa32VmxMisc = 0x485,
    kIa32VmxCr0Fixed0 = 0x486,
    kIa32VmxCr0Fixed1 = 0x487,
    kIa32VmxCr4Fixed0 = 0x488,
    kIa32VmxCr4Fixed1 = 0x489,
    kIa32VmxVmcsEnum = 0x48A,
    kIa32VmxProcBasedCtls2 = 0x48B,
    kIa32VmxEptVpidCap = 0x48C,
    kIa32VmxTruePinbasedCtls = 0x48D,
    kIa32VmxTrueProcBasedCtls = 0x48E,
    kIa32VmxTrueExitCtls = 0x48F,
    kIa32VmxTrueEntryCtls = 0x490,
    kIa32VmxVmfunc = 0x491,

    kIa32Efer = 0xC0000080,
    kIa32Star = 0xC0000081,
    kIa32Lstar = 0xC0000082,

    kIa32Fmask = 0xC0000084,

    kIa32FsBase = 0xC0000100,
    kIa32GsBase = 0xC0000101,
    kIa32KernelGsBase = 0xC0000102,
    kIa32TscAux = 0xC0000103,
};

typedef enum eMsr Msr;


UINT64 VirtualToPhysicalAddress(void* va);
UINT64 PhysicalToVirtualAddress(void* pa);
BOOLEAN IsVmxSupported();

/*
Before executing VMXON, we should allocate a naturally aligned 4-KByte region of memory that our logical processor will use it to support VMX operation.
This region is called the VMXON Region. The address of the VMXON Region (the VMXON pointer) is provided in an operand to VMXON instruction.
A VMM should use different VMXON Regions for each logical processor; otherwise, the behavior is “undefined”.
Please note that VMX operation requires that the following bits be 1 in VMX operation: CR0.PE, CR0.NE, CR0.PG, and CR4.VMXE. 
The restrictions on CR0.PE and CR0.PG implies that VMX operation is supported only in paged protected-mode. 
Therefore, the guest software cannot be run in unpaged protected-mode or in real-address mode.
Now that we are configuring the hypervisor, we should have a global variable that describes the state of our virtual machine.
The following structure is created for this purpose. We currently have two fields called (VMXON_REGION and VMCS_REGION), but we will add new fields and enhance this structure in the future.
*/
BOOLEAN AllocateVmxonRegion();

BOOLEAN SetVmxOnRevisionId();

BOOLEAN SetupVmxOnRegion();

BOOLEAN SetupVmcxRegion();
BOOLEAN CreateVmcsData(PVOID pGuestStack);
BOOLEAN VmxAllocateMsrBitmap();
BOOLEAN VmxInitalize(PVOID pGuestStack);
VOID VtEnable();
VOID
VmResumeInstruction();
VOID
MainVmexitHandler(PGUEST_REGS GuestRegs);