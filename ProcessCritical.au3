#RequireAdmin
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_Comment=Retrieve or manipulate the CriticalFlag on processes
#AutoIt3Wrapper_Res_Description=Retrieve or manipulate the CriticalFlag on processes
#AutoIt3Wrapper_Res_Fileversion=1.0.0.0
#AutoIt3Wrapper_Res_LegalCopyright=Joakim Schicht
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
; by Joakim Schicht
#include <WinAPI.au3>
Global Const $tagOBJECTATTRIBUTES = "ulong Length;hwnd RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $OBJ_CASE_INSENSITIVE = 0x00000040
Global Const $tagUNICODESTRING = "ushort Length;ushort MaximumLength;ptr Buffer"

Select
	Case $cmdline[0] <> 4 And $cmdline[0] <> 0
		_ShowHelp()
	Case $cmdline[0] = 0
		_SetPrivilege("SeDebugPrivilege")
		$list = ProcessList()
		$NumberOfHits = $list[0][0]
		If $NumberOfHits = 0 Then Exit
		For $i = 1 To $list[0][0]
			$Test = _GetProcessCritical($list[$i][1])
			If @error Then
				ConsoleWrite("PID: " & $list[$i][1] & " ("&$list[$i][0]&")" & @CRLF)
				ConsoleWrite("Error: _GetProcessCritical returned NTSTATUS: 0x"&Hex($Test,8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($Test,8))) & @CRLF)
			Else
				ConsoleWrite("PID: " & $list[$i][1] & " ("&$list[$i][0]&")" & @CRLF)
				ConsoleWrite("CriticalFlag: " & $Test & @CRLF)
				ConsoleWrite(@CRLF)
			EndIf
		Next
	Case $cmdline[1] = "-pid" And $cmdline[3] = "-CriticalFlag"
		If Not StringIsDigit($cmdline[2]) Or StringIsDigit($cmdline[4]) = 0 Then
			ConsoleWrite("Error: Both -pid and -CriticalFlag must be digits" & @CRLF)
			Exit
		ElseIf $cmdline[4] <> 0 And $cmdline[4] <> 1 Then
			ConsoleWrite("Error: -CriticalFlag must be either 0 or 1" & @CRLF)
			Exit
		EndIf
		_SetPrivilege("SeDebugPrivilege")
		$Test = _SetProcessCritical($cmdline[2],$cmdline[4])
		ConsoleWrite("_SetProcessCritical returned NTSTATUS: 0x"&Hex($Test,8) &" -> "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($Test,8))) & @CRLF)
	Case Else
		_ShowHelp()
EndSelect

Func _ShowHelp()
	ConsoleWrite("The syntax is:" & @CRLF)
	ConsoleWrite("ProcessCritical.exe -pid value -CriticalFlag value" & @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("Examples:" & @CRLF)
	ConsoleWrite("Set the critical flag to 1 for process with ID 2366:" & @CRLF)
	ConsoleWrite("ProcessCritical.exe -pid 2366 -CriticalFlag 1" & @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("Set the critical flag to 0 (remove the flag) for process with ID 244:" & @CRLF)
	ConsoleWrite("ProcessCritical.exe -pid 244 -CriticalFlag 0" & @CRLF)
	ConsoleWrite(@CRLF)
	ConsoleWrite("Dump the critical flag for all processes:" & @CRLF)
	ConsoleWrite("ProcessCritical.exe" & @CRLF)
EndFunc

Func _GetProcessCritical($PID)
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
	$aCall = DllCall("ntdll.dll", "int", "NtQueryInformationProcess", "handle", $hProcess, "dword", 29, "ptr", DllStructGetPtr($SpecialStruct),  "dword", DllStructGetSize($SpecialStruct), "dword*", 0)
	If Not NT_SUCCESS($aCall[0]) Then
		ConsoleWrite("Error in NtQueryInformationProcess" & @CRLF)
		Return SetError(1,0,$aCall[0])
	EndIf
	Return DllStructGetData($SpecialStruct,1)
EndFunc

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
	Else
		Return $aCall[0]
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

Func _RtlNtStatusToDosError($Status)
    Local $aCall = DllCall("ntdll.dll", "ulong", "RtlNtStatusToDosError", "dword", $Status)
    If Not NT_SUCCESS($aCall[0]) Then
        ConsoleWrite("Error in RtlNtStatusToDosError: " & Hex($aCall[0], 8) & @CRLF)
        Return SetError(1, 0, $aCall[0])
    Else
        Return $aCall[0]
    EndIf
EndFunc

Func _TranslateErrorCode($ErrCode)
	Local $tBufferPtr = DllStructCreate("ptr")

	Local $nCount = _FormatMessage(BitOR($__WINAPICONSTANT_FORMAT_MESSAGE_ALLOCATE_BUFFER, $__WINAPICONSTANT_FORMAT_MESSAGE_FROM_SYSTEM), _
			0, $ErrCode, 0, $tBufferPtr, 0, 0)
	If @error Then Return SetError(@error, 0, "")

	Local $sText = ""
	Local $pBuffer = DllStructGetData($tBufferPtr, 1)
	If $pBuffer Then
		If $nCount > 0 Then
			Local $tBuffer = DllStructCreate("wchar[" & ($nCount + 1) & "]", $pBuffer)
			$sText = DllStructGetData($tBuffer, 1)
		EndIf
		_LocalFree($pBuffer)
	EndIf

	Return $sText
EndFunc

Func _FormatMessage($iFlags, $pSource, $iMessageID, $iLanguageID, ByRef $pBuffer, $iSize, $vArguments)
	Local $sBufferType = "struct*"
	If IsString($pBuffer) Then $sBufferType = "wstr"
	Local $aResult = DllCall("Kernel32.dll", "dword", "FormatMessageW", "dword", $iFlags, "ptr", $pSource, "dword", $iMessageID, "dword", $iLanguageID, _
			$sBufferType, $pBuffer, "dword", $iSize, "ptr", $vArguments)
	If @error Then Return SetError(@error, @extended, 0)
	If $sBufferType = "wstr" Then $pBuffer = $aResult[5]
	Return $aResult[0]
EndFunc

Func _LocalFree($hMem)
	Local $aResult = DllCall("kernel32.dll", "handle", "LocalFree", "handle", $hMem)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc