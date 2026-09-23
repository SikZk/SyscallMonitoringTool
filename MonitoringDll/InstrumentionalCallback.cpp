#include "InstrumentionalCallback.h"
#include "peb.h"

KNOWN_CALLBACKS KnownCallbacks;

BOOLEAN IsUnbacked(_In_ PVOID Address) {
	MEMORY_BASIC_INFORMATION Info;

	if (VirtualQuery(Address, &Info, sizeof(Info)) == 0)
	{
		return TRUE;
	}

	return (Info.Type == MEM_PRIVATE);
}

EXTERN_C VOID WINAPI PiCallback(
	_In_ PVOID OriginalTarget
) {
	if (OriginalTarget == KnownCallbacks.KiUserExceptionDispatcher
		||
		OriginalTarget == KnownCallbacks.LdrInitializeThunk
		||
		OriginalTarget == KnownCallbacks.KiUserApcDispatcher
		||
		OriginalTarget == KnownCallbacks.KiUserCallbackDispatcher)
	{
		return;
	}


	PTEB Teb = NtCurrentTeb();

	if (Teb->InstrumentationCallbackDisabled == TRUE) {
		return;
	}
	Teb->InstrumentationCallbackDisabled = TRUE;

	if (IsUnbacked(OriginalTarget) == TRUE)
	{
		__fastfail(REASON_UNBACKED_TARGET);
	}

	Teb->InstrumentationCallbackDisabled = FALSE;

}

void InitializePiCallback() {
	HMODULE NtdllAddress = GetModuleHandleW(L"ntdll.dll");

	if (NtdllAddress == 0) {
		return;
	}

	KnownCallbacks.KiUserExceptionDispatcher = GetProcAddress(NtdllAddress, "KiUserExceptionDispatcher");

	if (KnownCallbacks.KiUserExceptionDispatcher == 0) {
		return;
	}

	KnownCallbacks.LdrInitializeThunk = GetProcAddress(NtdllAddress, "LdrInitializeThunk");

	if (KnownCallbacks.LdrInitializeThunk == 0) {
		return;
	}

	KnownCallbacks.KiUserApcDispatcher = GetProcAddress(NtdllAddress, "KiUserApcDispatcher");

	if (KnownCallbacks.KiUserApcDispatcher == 0) {
		return;
	}

	KnownCallbacks.KiUserCallbackDispatcher = GetProcAddress(NtdllAddress, "KiUserCallbackDispatcher");

	if (KnownCallbacks.KiUserCallbackDispatcher == 0) {
		return;
	}

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION PiInfo = {
		0,
		0,
		PiThunk
	};

	NtSetInformationProcess(
		NtCurrentProcess,
		40,
		&PiInfo,
		sizeof(PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION)
	);
}