#RequireAdmin
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_Comment=A PoC that will trigger a Blue Screen Of Death
#AutoIt3Wrapper_Res_Description=A PoC that will trigger a Blue Screen Of Death
#AutoIt3Wrapper_Res_Fileversion=1.0.0.0
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
; Sample by Joakim Schicht
#include <WinAPI.au3>
Global Const $tagOBJECTATTRIBUTES = "ulong Length;hwnd RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $OBJ_CASE_INSENSITIVE = 0x00000040
Global Const $tagUNICODESTRING = "ushort Length;ushort MaximumLength;ptr Buffer"
_SetPrivilege("SeDebugPrivilege")
$ProcId = DllCall("kernel32.dll", "dword", "GetCurrentProcessId")
If @error Then
	ConsoleWrite("GetCurrentProcessId: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	Exit
EndIf
ConsoleWrite("PID: " & $ProcId[0] & @CRLF)
$Test = _SetProcessCritical($ProcId[0],1)
; You should now see the Blue Screen Of Death

Func _SetProcessCritical($PID, $Flag)
    Local $sOA = DllStructCreate($tagOBJECTATTRIBUTES)
    DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
    DllStructSetData($sOA, "RootDirectory", 0)
    DllStructSetData($sOA, "ObjectName", 0)
    DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
    DllStructSetData($sOA, "SecurityDescriptor", 0)
    DllStructSetData($sOA, "SecurityQualityOfService", 0)
    Local $ClientID = DllStructCreate("dword_ptr UniqueProcessId;dword_ptr UniqueThreadId")
    DllStructSetData($ClientID, "UniqueProcessId", $PID)
    DllStructSetData($ClientID, "UniqueThreadId", 0)
    Local $aCall = DllCall("ntdll.dll", "hwnd", "NtOpenProcess", "handle*", 0, "dword", 0x001F0FFF, "struct*", $sOA, "struct*", $ClientID)
    If Not NT_SUCCESS($aCall[0]) Then
        Return SetError(1, 0, $aCall[0])
    Else
        $hProcess = $aCall[1]
    EndIf
	LOcal $SpecialStruct = DllStructCreate("dword")
	DllStructSetData($SpecialStruct,1,$Flag)
	$aCall = DllCall("ntdll.dll", "int", "NtSetInformationProcess", "handle", $hProcess, "dword", 29, "ptr", DllStructGetPtr($SpecialStruct),  "dword", DllStructGetSize($SpecialStruct))
	If Not NT_SUCCESS($aCall[0]) Then
		ConsoleWrite("Error in NtSetInformationProcess" & @CRLF)
		Return SetError(1,0,$aCall[0])
	EndIf
EndFunc

Func NT_SUCCESS($status)
    If 0 <= $status And $status <= 0x7FFFFFFF Then
        Return True
    Else
        Return False
    EndIf
EndFunc

Func _SetPrivilege($Privilege)
    Local $tagLUIDANDATTRIB = "int64 Luid;dword Attributes"
    Local $count = 1
    Local $tagTOKENPRIVILEGES = "dword PrivilegeCount;byte LUIDandATTRIB[" & $count * 12 & "]" ; count of LUID structs * sizeof LUID struct
    Local $TOKEN_ADJUST_PRIVILEGES = 0x20
    Local $SE_PRIVILEGE_ENABLED = 0x2

    Local $curProc = DllCall("kernel32.dll", "ptr", "GetCurrentProcess")
	Local $call = DllCall("advapi32.dll", "int", "OpenProcessToken", "ptr", $curProc[0], "dword", $TOKEN_ALL_ACCESS, "ptr*", "")
    If Not $call[0] Then Return False
    Local $hToken = $call[3]

    $call = DllCall("advapi32.dll", "int", "LookupPrivilegeValue", "str", "", "str", $Privilege, "int64*", "")
    Local $iLuid = $call[3]

    Local $TP = DllStructCreate($tagTOKENPRIVILEGES)
	Local $TPout = DllStructCreate($tagTOKENPRIVILEGES)
    Local $LUID = DllStructCreate($tagLUIDANDATTRIB, DllStructGetPtr($TP, "LUIDandATTRIB"))

    DllStructSetData($TP, "PrivilegeCount", $count)
    DllStructSetData($LUID, "Luid", $iLuid)
    DllStructSetData($LUID, "Attributes", $SE_PRIVILEGE_ENABLED)

    $call = DllCall("advapi32.dll", "int", "AdjustTokenPrivileges", "ptr", $hToken, "int", 0, "ptr", DllStructGetPtr($TP), "dword", DllStructGetSize($TPout), "ptr", DllStructGetPtr($TPout), "dword*", 0)
	$lasterror = _WinAPI_GetLastError()
	If $lasterror <> 0 Then
		ConsoleWrite("AdjustTokenPrivileges: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	EndIf
    DllCall("kernel32.dll", "int", "CloseHandle", "ptr", $hToken)
    Return ($call[0] <> 0) ; $call[0] <> 0 is success
EndFunc