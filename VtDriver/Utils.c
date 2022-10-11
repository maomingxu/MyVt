
#include "Utils.h"
#include "vtsystem.h"

extern inline void AsmEnableVmxOperation();
extern inline void AsmVmexitHandler();
extern inline void AsmVmEntryGuest();
extern inline USHORT  GetCs(VOID);
extern inline USHORT  GetDs(VOID);
extern inline USHORT  GetEs(VOID);
extern inline USHORT  GetSs(VOID);
extern inline USHORT  GetFs(VOID);
extern inline USHORT  GetGs(VOID);
extern inline USHORT  GetLdtr(VOID);
extern inline USHORT  GetTr(VOID);

extern inline ULONG64 Asm_GetIdtBase(VOID);
extern inline ULONG64 Asm_GetGdtBase(VOID);
extern inline USHORT   Asm_GetGdtLimit(VOID);
extern inline USHORT   Asm_GetIdtLimit(VOID);
extern inline ULONG64 Asm_GetLdtr(VOID);
extern inline ULONG64 Asm_GetRflags(VOID);
extern inline void Asm_CPUID(ULONG64 uFn,PULONG64 uRet_RAX,PULONG64 uRet_RBX,PULONG64 uRet_RCX,PULONG64 uRet_RDX);
extern inline void AsmVmxRestoreState();

VIRTUAL_MACHINE_STATE* g_GuestState;
S_VMX_VARS             g_vmx_vars;


UINT64 VirtualToPhysicalAddress(void* va)
{
	return MmGetPhysicalAddress(va).QuadPart;
}

UINT64 PhysicalToVirtualAddress(void* pa)
{
	PHYSICAL_ADDRESS physicalAddr;
	physicalAddr.QuadPart = pa;

	return (UINT64)MmGetVirtualForPhysical(physicalAddr);
}
BOOLEAN
GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector,
	USHORT            Selector,
	PUCHAR            GdtBase)
{
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4)
	{
		return FALSE;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL               = Selector;
	SegmentSelector->BASE              = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT             = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10))
	{ // LA_ACCESSED
		ULONG64 Tmp;
		// this is a TSS or callgate etc, save the base high part
		Tmp                   = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G)
	{
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}

VOID 
VmGuestEntry()
{
	
}

VOID
VmResumeInstruction()
{
	__vmx_vmresume();

	// if VMRESUME succeeds will never be here !

	ULONG64 ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();
	DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

	//
	// It's such a bad error because we don't where to go!
	// prefer to break
	//
	DbgBreakPoint();
}

/* Handles in the cases when RDMSR causes a Vmexit*/
VOID HvHandleMsrWrite(PGUEST_REGS GuestRegs)
{
	MSR msr = { 0 };

	/*
	Execute WRMSR or RDMSR on behalf of the guest. Important that this
	can cause bug check when the guest tries to access unimplemented MSR
	even within the SEH block* because the below WRMSR or RDMSR raises
	#GP and are not protected by the SEH block (or cannot be protected
	either as this code run outside the thread stack region Windows
	requires to proceed SEH). Hypervisors typically handle this by noop-ing
	WRMSR and returning zero for RDMSR with non-architecturally defined
	MSRs. Alternatively, one can probe which MSRs should cause #GP prior
	to installation of a hypervisor and the hypervisor can emulate the
	results.
	*/

	// Check for sanity of MSR if they're valid or they're for reserved range for WRMSR and RDMSR
	if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF))
		|| (GuestRegs->rcx >= RESERVED_MSR_RANGE_LOW && (GuestRegs->rcx <= RESERVED_MSR_RANGE_HI)))
	{
		msr.Low = (ULONG)GuestRegs->rax;
		msr.High = (ULONG)GuestRegs->rdx;
		__writemsr(GuestRegs->rcx, msr.Content);
	}
}

void HandleRDMSR(PGUEST_REGS GuestRegs)
{
	MSR msr = { 0 };


	// RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
	// 
	// The "use MSR bitmaps" VM-execution control is 0.
	// The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
	// The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
	//   where n is the value of ECX.
	// The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
	//   where n is the value of ECX & 00001FFFH.

	/*
	Execute WRMSR or RDMSR on behalf of the guest. Important that this
	can cause bug check when the guest tries to access unimplemented MSR
	even within the SEH block* because the below WRMSR or RDMSR raises
	#GP and are not protected by the SEH block (or cannot be protected
	either as this code run outside the thread stack region Windows
	requires to proceed SEH). Hypervisors typically handle this by noop-ing
	WRMSR and returning zero for RDMSR with non-architecturally defined
	MSRs. Alternatively, one can probe which MSRs should cause #GP prior
	to installation of a hypervisor and the hypervisor can emulate the
	results.
	*/

	// Check for sanity of MSR if they're valid or they're for reserved range for WRMSR and RDMSR
	if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF))
		|| (GuestRegs->rcx >= RESERVED_MSR_RANGE_LOW && (GuestRegs->rcx <= RESERVED_MSR_RANGE_HI)))
	{
		msr.Content = __readmsr(GuestRegs->rcx);
	}

	GuestRegs->rax = msr.Low;
	GuestRegs->rdx = msr.High;
}


void HandleCPUID(PGUEST_REGS GuestRegs)
{
	/**/
	//Asm_CPUID(GuestRegs->rax, &GuestRegs->rax, &GuestRegs->rbx, &GuestRegs->rcx, &GuestRegs->rdx);
	int cpuInfo[4] = { 0 };
	int function_id = (int)(GuestRegs->rax &0xffffffff);
	__cpuid(cpuInfo, function_id);

	GuestRegs->rax = cpuInfo[0];
	GuestRegs->rbx = cpuInfo[1];
	GuestRegs->rcx = cpuInfo[2];
	GuestRegs->rdx = cpuInfo[3];
}

void HandleCrAccess(PGUEST_REGS GuestRegs)
{
	PMOV_CR_QUALIFICATION CrExitQualification;
	INT64 GuestRsp = 0;
	ULONG ExitQualification = 0;
	__vmx_vmread(EXIT_QUALIFICATION, (size_t *)(&ExitQualification));
	CrExitQualification = (PMOV_CR_QUALIFICATION)&ExitQualification;

	PULONG64 RegPtr = (PULONG64)&GuestRegs->rax + CrExitQualification->Fields.Register;

	/* Because its RSP and as we didn't save RSP correctly (because of pushes) so we have make it points to the GUEST_RSP */
	if (CrExitQualification->Fields.Register == 4)
	{
		__vmx_vmread(GUEST_RSP, &GuestRsp);
		*RegPtr = GuestRsp;
	}

	if( CrExitQualification->Fields.ControlRegister != 3 ){    // not for cr3
		DbgBreakPoint();
	}

	if (CrExitQualification->Fields.AccessType == 0) {         // CR3 <-- reg32
		__vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));
	} else {                            // reg32 <-- CR3
		 
		__vmx_vmread(GUEST_CR3,RegPtr);
		 
	}
}


VOID
MainVmexitHandler(PGUEST_REGS GuestRegs)
{
	/*
	   GuestRegs is a pointer var,it just point to the address of rax,
	   so when i change the value of GuestRegs the relative register(rax ,rbx,or rcx...) will be changed too.
	*/
	ULONG ExitReason = 0;
	__vmx_vmread(VM_EXIT_REASON, &ExitReason);

	ULONG64 guestRip = 0;
 	__vmx_vmread(GUEST_RIP,&guestRip);
 
	ULONG64 guestRsp = 0;
	__vmx_vmread(GUEST_RSP,&guestRsp);

	ULONG64 guestEflags = 0;
	__vmx_vmread(GUEST_RFLAGS,&guestEflags);

	g_vmx_vars.IsOnVmxRootMode = TRUE;
	g_vmx_vars.IncrementRip = TRUE;
	/*If in VMCs data,the guest state not be set,the ExitReason is 33.*/
	//DbgPrint("\EXIT_QUALIFICATION 0x%x\n", ExitQualification);
	//DbgBreakPoint();
	switch (ExitReason)
	{
		//
		// 25.1.2  Instructions That Cause VM Exits Unconditionally
		// The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
		// INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
		// VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
		//
		case EXIT_REASON_CR_ACCESS:
		{
			HandleCrAccess(GuestRegs);
			break;
		}
		case EXIT_REASON_CPUID:
		{
			HandleCPUID(GuestRegs);
   
			break;
		}
		case EXIT_REASON_MSR_READ:
		{
			HandleRDMSR(GuestRegs);
			break;
		}
		case EXIT_REASON_MSR_WRITE:
		{
			HvHandleMsrWrite(GuestRegs);
			break;
		}
  		default:
		{
			DbgBreakPoint();
			break;
		}
	}

//Resume:
	size_t ExitInstructionLength = 0;
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN,&ExitInstructionLength);
	ULONG64 uNextGuestRip = guestRip + ExitInstructionLength;

	__vmx_vmwrite(GUEST_RIP, uNextGuestRip);

	g_vmx_vars.IsOnVmxRootMode = FALSE;

}
ULONG  AdjustControls(ULONG Ctl, ULONG Msr)
{
	MSR MsrValue = {0};

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

VOID
FillGuestSelectorData(
	PVOID  GdtBase,
	ULONG  Segreg,
	USHORT Selector)
{
	SEGMENT_SELECTOR SegmentSelector = {0};
	ULONG            AccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		AccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}

BOOLEAN IsVmxSupported()
/*
the following code checks IA32_FEATURE_CONTROL MSR (MSR address 3AH) to see if the lock bit is set or not
*/
{
	CPUID Data = { 0 };

	/*
	Before system software enters into VMX operation, it must discover the presence of VMX support in the processor.
	System software can determine whether a processor supports VMX operation using CPUID. If
	CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported.
	*/
	__cpuid((UINT32*)&Data, 1);
	if ((Data.ecx & 1 << 5) == 0)
		return FALSE;

	/*
	VMXON is also controlled by the IA32_FEATURE_CONTROL MSR (MSR address 3AH). This MSR is cleared to zero when a logical processor is reset.
	*/
#define IA32_FEATURE_CONTROL 0x3A
	IA32_FEATURE_CONTROL_MSR Contrl = { 0 };
	Contrl.All = __readmsr(IA32_FEATURE_CONTROL);

	//
	//bios lock check
	//
	if (Contrl.Fields.Lock == 0)
	{
		Contrl.Fields.Lock = TRUE;
		Contrl.Fields.EnableVmxon = TRUE;
		__writemsr(IA32_FEATURE_CONTROL, Contrl.All);
	}
	else if (Contrl.Fields.EnableVmxon == FALSE)
	{
		DbgPrint("[*] VMX locked off in BIOS");
		return FALSE;
	}

	return TRUE;
}

BOOLEAN AllocateVmxonRegion()
{
	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };
	UINT64 VmxonSize;
	int VmxonStatus;
	PVOID VmxonRegion;
	UINT64 VmxonRegionPhysicalAddr;
	UINT64 AlignedVmxonRegion;
	UINT64 AlignedVmxonRegionPhysicalAddr;


	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PhysicalMax.QuadPart = MAXULONG64;

	VmxonSize = 2 * VMXON_SIZE;

	// Allocating a 4-KByte Contigous Memory region
	VmxonRegion = MmAllocateContiguousMemory(VmxonSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);

	if (VmxonRegion == NULL) {
		DbgPrint("Couldn't Allocate Buffer for VMXON Region.");
		return FALSE;
	}

	VmxonRegionPhysicalAddr = VirtualToPhysicalAddress(VmxonRegion);

	// zero-out memory 
	RtlSecureZeroMemory(VmxonRegion, VmxonSize + ALIGNMENT_PAGE_SIZE);


	AlignedVmxonRegion = (PVOID)((ULONG_PTR)((UINT64)VmxonRegion + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	DbgPrint("VMXON Region Address : %llx", AlignedVmxonRegion);

	// 4 kb >= buffers are aligned, just a double check to ensure if it's aligned
	AlignedVmxonRegionPhysicalAddr = (PVOID)((ULONG_PTR)(VmxonRegionPhysicalAddr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	DbgPrint("VMXON Region Physical Address : %llx", AlignedVmxonRegionPhysicalAddr);

	// get IA32_VMX_BASIC_MSR RevisionId
	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);
	DbgPrint("Revision Identifier (MSR_IA32_VMX_BASIC - MSR 0x480) : 0x%x", VmxBasicMsr.Fields.RevisionIdentifier);

	//Changing Revision Identifier
	*(UINT64*)AlignedVmxonRegion = VmxBasicMsr.Fields.RevisionIdentifier;

	// Execute Vmxon instruction
	VmxonStatus = __vmx_on(&AlignedVmxonRegionPhysicalAddr);
	if (VmxonStatus)
	{
		DbgPrint("Executing Vmxon instruction failed with status : %d", VmxonStatus);
		return FALSE;
	}


	g_vmx_vars.pVmxOnRegion_PA = AlignedVmxonRegionPhysicalAddr;

	// We save the allocated buffer (not the aligned buffer) because we want to free it in vmx termination
	g_vmx_vars.pVmxOnRegion_VA = VmxonRegion;

	return TRUE;
}

/* Allocate Vmcs region and set the Revision ID based on IA32_VMX_BASIC_MSR */
BOOLEAN VmxAllocateVmcsRegion()
{
	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	int VmcsSize;
	PVOID VmcsRegion;
	UINT64 VmcsPhysicalAddr;
	UINT64 AlignedVmcsRegion;
	UINT64 AlignedVmcsRegionPhysicalAddr;
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };


	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PhysicalMax.QuadPart = MAXULONG64;

	VmcsSize = 2 * VMCS_SIZE;
	VmcsRegion = MmAllocateContiguousMemory(VmcsSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	if (VmcsRegion == NULL) {
		DbgPrint("Couldn't Allocate Buffer for VMCS Region.");
		return FALSE;
	}
	RtlSecureZeroMemory(VmcsRegion, VmcsSize + ALIGNMENT_PAGE_SIZE);

	VmcsPhysicalAddr = VirtualToPhysicalAddress(VmcsRegion);

	AlignedVmcsRegion = (PVOID)((ULONG_PTR)((ULONG64)VmcsRegion + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	DbgPrint("VMCS Region Address : %llx", AlignedVmcsRegion);

	AlignedVmcsRegionPhysicalAddr = (PVOID)((ULONG_PTR)(VmcsPhysicalAddr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	DbgPrint("VMCS Region Physical Address : %llx", AlignedVmcsRegionPhysicalAddr);

	// get IA32_VMX_BASIC_MSR RevisionId
	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);
	DbgPrint("Revision Identifier (MSR_IA32_VMX_BASIC - MSR 0x480) : 0x%x", VmxBasicMsr.Fields.RevisionIdentifier);


	//Changing Revision Identifier
	*(UINT64*)AlignedVmcsRegion = VmxBasicMsr.Fields.RevisionIdentifier;

	g_vmx_vars.pVmcsRegion_PA = AlignedVmcsRegionPhysicalAddr;
	// We save the allocated buffer (not the aligned buffer) because we want to free it in vmx termination
	g_vmx_vars.pVmcsRegion_VA = VmcsRegion;

	return TRUE;
}

BOOLEAN SetVmxOnRevisionId()
/*
Before executing VMXON, software should write the VMCS revision identifier to the VMXON region.
(Specifically, it should write the 31-bit VMCS revision identifier to bits 30:0 of the first 4 bytes of the VMXON region; bit 31 should be cleared to 0.)
*/
{
	IA32_VMX_BASIC_MSR basic = { 0 };
	basic.All = (UINT64)__readmsr(MSR_IA32_VMX_BASIC);

	UINT32 revisionId = basic.Fields.RevisionIdentifier;

	*(UINT32*)g_vmx_vars.pVmxOnRegion_VA = revisionId;

	return TRUE;
}

BOOLEAN SetupVmxOnRegion()
/*
   Enable and Entering VMX operation.
*/
{
	//1
	AllocateVmxonRegion();

#pragma region "alloc_stack_for_host"

	/*How to use this stack?
	when guest call vm-exit to host, host will handle the exit,it will use this stack to do some operation.
	so the size of this stack need not too large.
	*/
	PVOID hostVmmStack_VA = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, 'hstc');
	if (!hostVmmStack_VA)
	{
		DbgPrint("[*] error,allocate host stack memory failed\n");
		return FALSE;
	}
	RtlZeroMemory(hostVmmStack_VA, VMM_STACK_SIZE);

	g_vmx_vars.pVmmHostStack_VA = hostVmmStack_VA;


#pragma endregion
	return TRUE;
}


BOOLEAN SetupVmcxRegion()
{
	VmxAllocateVmcsRegion();

	NTSTATUS Status = __vmx_vmclear(&g_vmx_vars.pVmcsRegion_PA);
	if (Status)
	{
		DbgPrint("[*] VMCS clear failed with status %d\n", Status);
		__vmx_off();
		return FALSE;
	}

	Status = __vmx_vmptrld(&g_vmx_vars.pVmcsRegion_PA);
	if (Status)
	{
		DbgPrint("[*] VMCS load failed with status %d\n", Status);
		return FALSE;
	}

	return TRUE;
}


BOOLEAN CreateVmcsData(PVOID pGuestStack)
{


	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };
	// Reading IA32_VMX_BASIC_MSR 
	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);

	//1.Guest-State,VM entries load processor state from these fields and VM exits store processor state into these fields
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_DR7, 0x400);/*Debug register DR7,the default value is 0x400,it is request the 10bit is set 1*/

	//when vmx entry the guest,the rsp and rip indicate the guest the location of rip and rsp.
	__vmx_vmwrite(GUEST_RSP, ((ULONG64)pGuestStack )); // setup guest sp
	__vmx_vmwrite(GUEST_RIP, (ULONG64)AsmVmxRestoreState); // setup guest ip

	__vmx_vmwrite(GUEST_RFLAGS, Asm_GetRflags());
	PVOID gdtBase = (PVOID)Asm_GetGdtBase();
	FillGuestSelectorData(gdtBase, ES, GetEs());
	FillGuestSelectorData(gdtBase, CS, GetCs());
	FillGuestSelectorData(gdtBase, SS, GetSs());
	FillGuestSelectorData(gdtBase, DS, GetDs());
	FillGuestSelectorData(gdtBase, FS, GetFs());
	FillGuestSelectorData(gdtBase, GS, GetGs());
	FillGuestSelectorData(gdtBase, LDTR, GetLdtr());
	FillGuestSelectorData(gdtBase, TR, GetTr());


	__vmx_vmwrite(GUEST_GDTR_BASE, Asm_GetGdtBase());
	__vmx_vmwrite(GUEST_IDTR_BASE, Asm_GetIdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, Asm_GetGdtLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, Asm_GetIdtLimit());

	
	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	//
	// Setting the link pointer to the required value for 4KB VMCS
	//
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state 



	//===================================================

	/* Time-stamp counter offset */
	__vmx_vmwrite(TSC_OFFSET, 0);

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	// Set up VPID
	/* For all processors, we will use a VPID = 1. This allows the processor to separate caching
	of EPT structures away from the regular OS page translation tables in the TLB.	*/
	__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, 0x1);

	__vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);

	__vmx_vmwrite(CR0_READ_SHADOW, 0);
	__vmx_vmwrite(CR4_READ_SHADOW, 0);
	//=================================================




	//2.Host-State 
	//CAUTION:If some fields of Host-State not be set, it will cause crash.so we must set all the fields of Host-state according to Intel-pdf.
#pragma region "HOST_STATE"
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());

	/*host_rip indicate that when vm-exit called,the processor should return to VMM environment,the RIP is the first instruction the cpu should excute.*/
	__vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmexitHandler);
	__vmx_vmwrite(HOST_RSP, ((ULONG64)g_vmx_vars.pVmmHostStack_VA + VMM_STACK_SIZE-0x200 ));

	__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);

	__vmx_vmwrite(MSR_BITMAP, g_vmx_vars.pMsrBitMap_PA);

	/*Base-address fields for FS, GS, TR, GDTR, and IDTR (64 bits each; 32 bits on processors that do not support Intel 64 architecture).*/
	{
		__vmx_vmwrite(HOST_GDTR_BASE, Asm_GetGdtBase());
		__vmx_vmwrite(HOST_IDTR_BASE, Asm_GetIdtBase());
		__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
		__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

		SEGMENT_SELECTOR SegmentSelector = { 0 };

		GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)Asm_GetGdtBase());
		__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);
	}

	/*MSRs*/
	{
		__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
		__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
		__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	}
	

#pragma endregion

#pragma region "VM_CONTROL"
	//VM Control
	//3.1 VM-Excution
	//Pin based ---cpu hardware interrupt.
	/*the bit of cr3 read/write set 1,so we must handle these vm-exit from guest
	COMMENTS:bit 28:This control determines whether MSR bitmaps are used to control execution of the RDMSR 
    and WRMSR instructions (see Section 24.6.9 and Section 25.1.3).
    For this control, ¡°0¡± means ¡°do not use MSR bitmaps¡± and ¡°1¡± means ¡°use MSR bitmaps.¡± If the 
    MSR bitmaps are not used, all executions of the RDMSR and WRMSR instructions cause 
    VM exits
	I didn't set bit28 to 1,so all executions of the RDMSR and WRMSR in non-root environment cause VM exit.
	*/
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
		VmxBasicMsr.Fields.VmxCapabilityHint ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP|CPU_BASED_CTL2_ENABLE_INVPCID |CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS|CPU_BASED_CTL2_ENABLE_VPID, MSR_IA32_VMX_PROCBASED_CTLS2));

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0,VmxBasicMsr.Fields.VmxCapabilityHint ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS));	

	//3.2 VM-Exit
	__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE, VmxBasicMsr.Fields.VmxCapabilityHint ? MSR_IA32_VMX_TRUE_EXIT_CTLS : MSR_IA32_VMX_EXIT_CTLS));
	//3.3 VM-Entry
	__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, VmxBasicMsr.Fields.VmxCapabilityHint ? MSR_IA32_VMX_TRUE_ENTRY_CTLS : MSR_IA32_VMX_ENTRY_CTLS));
#pragma endregion
	return TRUE;
}

/* Allocate a buffer forr Msr Bitmap */
BOOLEAN VmxAllocateMsrBitmap()
{
	// Allocate memory for MSRBitMap
	g_vmx_vars.pMsrBitMap_VA = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'msrb');  // should be aligned

	if (g_vmx_vars.pMsrBitMap_VA== NULL)
	{
		DbgPrint("Insufficient memory in allocationg Msr bitmaps");
		return FALSE;
	}
	RtlZeroMemory(g_vmx_vars.pMsrBitMap_VA, PAGE_SIZE);

	g_vmx_vars.pMsrBitMap_PA = VirtualToPhysicalAddress(g_vmx_vars.pMsrBitMap_VA);

	 DbgPrint("Msr Bitmap Virtual Address : 0x%llx",  g_vmx_vars.pMsrBitMap_VA);
	 DbgPrint("Msr Bitmap Physical Address : 0x%llx",  g_vmx_vars.pMsrBitMap_PA );

	// (Uncomment if you want to break on RDMSR and WRMSR to a special MSR Register)

	/*
	if (HvSetMsrBitmap(0xc0000082, ProcessorID, TRUE, TRUE))
	{
	LogError("Invalid parameters sent to the HvSetMsrBitmap function");
	return FALSE;
	}
	*/

	return TRUE;
}

/* Returns the stack pointer, to change in the case of Vmxoff */
UINT64 HvReturnStackPointerForVmxoff()
{
	__vmx_vmread(GUEST_RSP, &g_vmx_vars.VmxoffState.GuestRsp);
	return g_vmx_vars.VmxoffState.GuestRsp;
}

/* Returns the instruction pointer, to change in the case of Vmxoff */
UINT64 HvReturnInstructionPointerForVmxoff()
{
	__vmx_vmread(GUEST_RIP, &g_vmx_vars.VmxoffState.GuestRip);
	return g_vmx_vars.VmxoffState.GuestRip;
}

VOID VtEnable()
{
	//
	// Enabling VMX Operation
	//
	AsmEnableVmxOperation();
	DbgPrint("[*] VMX Operation Enabled Successfully !");

}

BOOLEAN VmxInitalize(PVOID pGuestStack)
{
	CreateVmcsData(pGuestStack);
	//launch vmx
	__vmx_vmlaunch();

	//=============it the following code can be executed , that means vmlaunch failed.
	ULONG64 ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();
	DbgPrint("ERROR,VmLaunch failed,0x%llx\n", ErrorCode);
	DbgBreakPoint();
	DbgPrint("================================\n");
	 
	return FALSE;
}