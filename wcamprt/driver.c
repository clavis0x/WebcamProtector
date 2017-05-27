#include <Ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <Ntstrsafe.h>
#include <stdlib.h>
#include <fltKernel.h>
#pragma comment (linker, "/SUBSYSTEM:NATIVE") 
#pragma comment (lib, "ntdll.lib")

// Device type
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_START_PROTECTION CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_STOP_PROTECTION CTL_CODE( SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_UPDATE_DEVICE CTL_CODE( SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_EVENT_ACCPID CTL_CODE( SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_CLEAR_EXAPP CTL_CODE( SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_ADD_EXAPP CTL_CODE( SIOCTL_TYPE, 0x805, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

const WCHAR deviceNameBuffer[] = L"\\Device\\wcamprt";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\wcamprt";
PDEVICE_OBJECT g_MyDevice; // Global pointer to our device object

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]

PMDL  g_pmdlSystemCall;
PVOID *MappedSystemCallTable;
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
#define HOOK_SYSCALL(_Function, _Hook, _Orig )  \
       _Orig = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Hook, _Orig )  \
       InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#ifndef _In_
#define _In_
#endif

#ifndef _In_opt_
#define _In_opt_
#endif

#ifndef _Out_
#define _Out_
#endif

#ifndef _Out_opt_
#define _Out_opt_
#endif

typedef NTSTATUS(*ZWDEVICEIOCONTROLFILE)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            IoControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength
	);

ZWDEVICEIOCONTROLFILE	OldZwDeviceIoControlFile;

typedef NTSTATUS(*NTREADVIRTUALMEMORY)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL
	);

NTREADVIRTUALMEMORY	OldNtReadVirtualMemory;

typedef NTSTATUS(*ZWTERMINATEPROCESS)(
	HANDLE   ProcessHandle,
	NTSTATUS ExitStatus
	);

ZWTERMINATEPROCESS OldZwTerminateProcess;

ULONG myPID; // user-level 제어 프로그램 PID
char *devAddr[10]; // 장치(웹캠) 주소
int nDevNum; // 장치 개수
int bEnableProtection; // 보호 실행 여부

					   // 접근 차단 알림용 이벤트 핸들
HANDLE SharedEventHandle;
PKEVENT SharedEvent;

typedef struct _appRule {
	int pid;
	int rule; // 0: block, 1: allow
} APP_RULE;

APP_RULE blockPID;

typedef struct _appPIDList {
	int pid;
	int rule; // 0: block, 1: allow
	struct _appPIDList * next;
} APP_PID_LIST;

APP_PID_LIST * appPidList;

typedef struct _appPathLis {
	char *path; // Device Path
	struct _appPathList * next;
} APP_PATH_LIST;

APP_PATH_LIST * appPathList;

typedef struct _sInitPrtInfo {
	unsigned int mainPid;
	void* cbFunc;
} INIT_PRT_INFO;

int DelRuleApp(int pid);
int ViewRuleApp();
int ViewExApp();

int asm_strcmp(char *str1, char *str2)
{
	_asm
	{
		mov esi, dword ptr[str1]
		mov edi, dword ptr[str2]
		func:
		mov al, byte ptr[esi]
			mov bl, byte ptr[edi]
			cmp al, bl
			jnz diff
			cmp al, 0x00
			je same
			inc esi
			inc edi
			jmp func
			diff :
		mov eax, -1
			jmp end
			same :
		mov eax, 0
			end :
	}
}

// 장치 주소 배열 초기화
int InitDeviceAddress()
{
	int i;
	for (i = 0; i<nDevNum; i++)
		ExFreePool(devAddr[i]);

	nDevNum = 0;

	return 0;
}

// 장치 주소 추가
int AddDeviceAddress(char *str, int n)
{
	devAddr[nDevNum] = (char*)ExAllocatePool(NonPagedPool, n + 2);
	RtlStringCchCopyA(devAddr[nDevNum], n + 1, str);
	nDevNum++;

	return 0;
}

// 장치 주소 등록 함수
// ex) str : "2 //Device//... //Device//..."
int DriverListTok(char* str)
{
	int i, j;
	int bEnd = 0;
	int nCount = str[0] - 0x30;
	int nResult;
	char *pStr;
	DbgPrint("Count : %d\n", nCount);
	str++;

	if (nCount < 0 || nCount >= 10)
		return -1;

	InitDeviceAddress(); // clear

						 // 장치 주소 분리
	for (i = 0; i<nCount; i++) {
		j = 0;
		pStr = str;
		while (*str != ' ') {
			if (*str == '\0') {
				bEnd = 1;
				break;
			}
			str++;
			j++;
		}
		*str = '\0';
		//DbgPrint("%d %s\n", j, pStr);

		AddDeviceAddress(pStr, j);

		if (bEnd == 0) str++;
		else break;
	}

	return 0;
}

// 애플리케이션 규칙 추가
int AddRuleApp(int pid, int rule)
{
	APP_PID_LIST *newNode = (APP_PID_LIST*)ExAllocatePool(NonPagedPool, sizeof(APP_PID_LIST));
	APP_PID_LIST *pNode = appPidList;

	DelRuleApp(pid);

	newNode->pid = pid;
	newNode->rule = rule;
	newNode->next = NULL;

	if (appPidList == NULL) {
		appPidList = newNode;
	}
	else {
		pNode = appPidList;
		while (pNode->next != NULL)
			pNode = pNode->next;
		pNode->next = newNode;
	}
	ViewRuleApp();
	return 0;
}

// 애플리케이션 규칙 찾기
int SearchRuleApp(int pid)
{
	APP_PID_LIST *pNode;
	APP_PID_LIST *cNode;

	if (appPidList != NULL) {
		pNode = appPidList;
		if (appPidList->pid == pid) {
			return appPidList->rule;
		}
		else {
			while (pNode->next != NULL) {
				cNode = pNode->next;
				if (cNode->pid == pid) {
					return cNode->rule;
				}
				else {
					pNode = pNode->next;
				}
			}
		}
	}

	return -1;
}

// 애플리케이션 규칙 삭제
int DelRuleApp(int pid)
{
	APP_PID_LIST *pNode;
	APP_PID_LIST *cNode;

	if (appPidList != NULL) {
		pNode = appPidList;
		if (appPidList->pid == pid) {
			appPidList = appPidList->next;
			ExFreePool(pNode);
		}
		else {
			while (pNode->next != NULL) {
				cNode = pNode->next;
				if (cNode->pid == pid) {
					pNode->next = cNode->next;
					ExFreePool(cNode);
					break;
				}
				else {
					pNode = pNode->next;
				}
			}
		}
	}
	ViewRuleApp();

	return 0;
}

// 애플리케이션 규칙 초기화
int InitRuleApp()
{
	APP_PID_LIST *cNode;
	APP_PID_LIST *nextNode;

	if (appPidList != NULL) {
		cNode = appPidList;
		nextNode = appPidList->next;
		appPidList = NULL;
		ExFreePool(cNode);
		while (nextNode != NULL) {
			cNode = nextNode;
			nextNode = cNode->next;
			ExFreePool(cNode);
		}
	}

	return 0;
}

int ViewRuleApp()
{
	APP_PID_LIST *pNode;

	DbgPrint("-- Pid List --\n");
	if (appPidList != NULL) {
		pNode = appPidList;
		DbgPrint("%d, %d\n", pNode->pid, pNode->rule);
		while (pNode->next != NULL) {
			pNode = pNode->next;
			DbgPrint("%d, %d\n", pNode->pid, pNode->rule);
		}
	}
	DbgPrint("--------------\n");
	return 0;
}

NTSTATUS GetDriverLetterByDevicePath() { // \\Device\\HarddiskVolumeX -> X:
	NTSTATUS nts;
	UNICODE_STRING ObjectName;
	PFILE_OBJECT f_object;
	PDEVICE_OBJECT d_object;
	WCHAR DNAME[] = L"\\Device\\HarddiskVolume3";

	RtlInitUnicodeString(&ObjectName, DNAME);
	if ((nts = IoGetDeviceObjectPointer(&ObjectName, FILE_READ_ATTRIBUTES, &f_object, &d_object)) == STATUS_SUCCESS)
	{
		UNICODE_STRING dName;
		DbgPrint("IoGetDeviceObjectPointer Success");
		if ((nts = RtlVolumeDeviceToDosName(d_object, &dName)) == STATUS_SUCCESS)
		{
			DbgPrint("Name:%ws", dName.Buffer);
		}
	}
	else
	{
		DbgPrint("ErrorCode:%x -> IoGetDeviceObjectPointer UnSuccess", nts);
	}
	return nts;
}

NTSTATUS GetDriveLetterLinkTarget(IN char *SourceNameStr, OUT PCHAR *LinkTarget) // X: -> \\Device\\HarddiskVolumeX
{
	static WCHAR        targetNameBuffer[50];
	STRING              ntNameString;
	NTSTATUS            status;
	UNICODE_STRING      sourceName;
	UNICODE_STRING      targetName;
	OBJECT_ATTRIBUTES   objectAttributes;
	HANDLE              linkHandle;
	HANDLE              directoryHandle;
	//
	// Open the Win32 object name-space directory - Refer WinObj.exe
	//
	RtlInitUnicodeString(&sourceName, (PWCHAR)L"\\??");
	InitializeObjectAttributes(&objectAttributes,
		&sourceName,
		OBJ_CASE_INSENSITIVE,
		(HANDLE)NULL,
		(PSECURITY_DESCRIPTOR)NULL);
	status = ZwOpenDirectoryObject(&directoryHandle,
		DIRECTORY_QUERY,
		&objectAttributes);
	if (!NT_SUCCESS(status))
		return status;
	// RtlInitUnicodeString(&sourceName, SourceNameStr);
	// Open symbolic link object(s)
	RtlInitAnsiString(&ntNameString, SourceNameStr);
	status = RtlAnsiStringToUnicodeString(&sourceName,
		&ntNameString,
		TRUE);
	if (!NT_SUCCESS(status))
		return status;
	InitializeObjectAttributes(&objectAttributes,
		&sourceName,
		OBJ_CASE_INSENSITIVE,
		(HANDLE)directoryHandle,
		(PSECURITY_DESCRIPTOR)NULL);
	status = ZwOpenSymbolicLinkObject(&linkHandle,
		SYMBOLIC_LINK_QUERY,
		&objectAttributes);
	RtlFreeUnicodeString(&sourceName);
	if (NT_SUCCESS(status)) {
		RtlZeroMemory(targetNameBuffer, sizeof(targetNameBuffer));
		targetName.Buffer = targetNameBuffer;
		targetName.MaximumLength = sizeof(targetNameBuffer);
		status = ZwQuerySymbolicLinkObject(linkHandle,
			&targetName,
			NULL);
		ZwClose(linkHandle);
	}
	if (NT_SUCCESS(status)) {
		RtlUnicodeStringToAnsiString(&ntNameString, &targetName, TRUE);
		*LinkTarget = ntNameString.Buffer;
	}
	else {
		*LinkTarget = NULL;
	}
	ZwClose(directoryHandle);
	//RtlFreeAnsiString(&ntNameString);
	return (status);
}

// 예외 애플리케이션 리스트 초기화
int InitPathApp()
{
	APP_PATH_LIST *cNode;
	APP_PATH_LIST *nextNode;

	if (appPathList != NULL) {
		cNode = appPathList;
		nextNode = appPathList->next;
		appPathList = NULL;
		ExFreePool(cNode->path);
		ExFreePool(cNode);
		while (nextNode != NULL) {
			cNode = nextNode;
			nextNode = cNode->next;
			ExFreePool(cNode->path);
			ExFreePool(cNode);
		}
	}

	// 애플리케이션 규칙 초기화
	InitRuleApp();

	return 0;
}

int AddPathApp(char* str)
{
	unsigned int i;
	unsigned int pathLen, letterLen, SymLinkLen, sumLen;
	PSTR linkTarget;
	WCHAR dosName[20];
	APP_PATH_LIST *pNode = appPathList;
	APP_PATH_LIST *newNode = (APP_PATH_LIST*)ExAllocatePool(NonPagedPool, sizeof(APP_PATH_LIST));
	char *szFilePath;
	char driverLetter[256] = { 0 };

	RtlStringCbLengthA(str, NTSTRSAFE_MAX_CCH * sizeof(char), &pathLen);

	for (i = 0; i<pathLen; i++) {
		if (str[i] == '\\')
			break;
	}
	pathLen = pathLen - i;
	letterLen = i;

	RtlCopyMemory(&driverLetter, str, i);

	// 애플리케이션의 Device Letter 구하기
	GetDriveLetterLinkTarget(driverLetter, &linkTarget);
	RtlStringCbLengthA(linkTarget, NTSTRSAFE_MAX_CCH * sizeof(char), &SymLinkLen);

	// 애플리케이션 경로의 Drive Letter를 Device Letter로 대체
	szFilePath = (char*)ExAllocatePool(NonPagedPool, pathLen + SymLinkLen + 1);
	RtlZeroMemory(szFilePath, sizeof(pathLen + SymLinkLen + 1));
	RtlStringCbCopyNA(szFilePath, SymLinkLen + 1, linkTarget, SymLinkLen + 1);
	RtlStringCbCopyNA(szFilePath + SymLinkLen, pathLen + 1, str + letterLen, pathLen + 1);

	DbgPrint(szFilePath);
	RtlStringCbLengthA(szFilePath, NTSTRSAFE_MAX_CCH * sizeof(char), &sumLen);

	//RtlStringCbCopyNA(szFilePath, sumLen+1, str, sumLen+1);
	newNode->path = szFilePath;
	newNode->next = NULL;

	// 예외 애플리케이션 리스트 추가
	if (appPathList == NULL) {
		appPathList = newNode;
	}
	else {
		pNode = appPathList;
		while (pNode->next != NULL)
			pNode = pNode->next;
		pNode->next = newNode;
	}
	ViewExApp();

	return 0;
}

int ViewExApp()
{
	APP_PATH_LIST *pNode;

	DbgPrint("-- ExApp List --\n");
	if (appPathList != NULL) {
		pNode = appPathList;
		DbgPrint("%s\n", pNode->path);
		while (pNode->next != NULL) {
			pNode = pNode->next;
			DbgPrint("%s\n", pNode->path);
		}
	}
	DbgPrint("--------------\n");
	return 0;
}

int GetProcessNameFromPid(HANDLE pid, char *szProcPath)
{
	PEPROCESS Process;
	PUNICODE_STRING pProcessName;
	ULONG cb;
	//char szText[1024] = {0};

	// EPROCESS 주소 구하기
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER) {
		return -1;
	}
	SeLocateProcessImageName(Process, &pProcessName);

	RtlUnicodeToMultiByteN(szProcPath, pProcessName->Length, &cb, pProcessName->Buffer, pProcessName->Length);
	//DbgPrint(szProcPath);

	ExFreePool(pProcessName);

	return 0;
}

int CheckExceptionApp(HANDLE pid)
{
	APP_PATH_LIST *pNode;
	char szProcPath[1024] = { 0 };

	// 프로세스의 Device Path 구하기
	GetProcessNameFromPid(pid, szProcPath);
	DbgPrint("ProcPath: %s", szProcPath);

	// 등록된 예외 애플리케이션과 비교
	if (appPathList != NULL) {
		pNode = appPathList;
		if (asm_strcmp(szProcPath, pNode->path) == 0)
			return 1;
		while (pNode->next != NULL) {
			pNode = pNode->next;
			if (asm_strcmp(szProcPath, pNode->path) == 0)
				return 1;
		}
	}

	return -1;
}

int InitProtector(unsigned char* str)
{
	INIT_PRT_INFO sInitInfo;
	UNICODE_STRING eventName;

	// user-level 제어 프로그램 PID 등록
	RtlCopyMemory(&sInitInfo, str, sizeof(INIT_PRT_INFO));
	myPID = sInitInfo.mainPid;

	// AccessWebcamEvent 이벤트 생성
	// user-level: Global\\AccessWebcamEvent
	RtlInitUnicodeString(&eventName, (L"\\BaseNamedObjects\\AccessWebcamEvent"));
	SharedEvent = IoCreateNotificationEvent(&eventName, &SharedEventHandle);
	if (SharedEvent != NULL) {
		ObReferenceObject(SharedEvent);
	}
	else {
		DbgPrint("[Error] IoCreateNotificationEvent");
		return -1;
	}

	return 0;
}

NTSTATUS NewZwTerminateProcess(
	_In_opt_ HANDLE   ProcessHandle,
	_In_     NTSTATUS ExitStatus)
{
	NTSTATUS ntStatus;
	NTSTATUS ntRtn;

	//DbgPrint("TerminateProcess : %d", (int)ProcessHandle);

	// 프로세스 종료(TerminateProcess) 대상 프로세스의 PID 찾기
	if (ProcessHandle != (HANDLE)0 && ProcessHandle != (HANDLE)-1) {
		// 타 프로세스에 의한 종료
		PEPROCESS eProcess = 0;
		OBJECT_HANDLE_INFORMATION obj_handle;
		HANDLE pid;

		// ProcessHandle -> PID
		ntRtn = ObReferenceObjectByHandle(ProcessHandle, GENERIC_ALL, NULL, KernelMode, (PVOID*)&eProcess, &obj_handle);
		if (eProcess != 0) {
			pid = PsGetProcessId(eProcess);
			//DbgPrint("process PID is %d", pid);
			ObDereferenceObject(eProcess);
			// 종료 대상 프로세스가 제어 프로그램인 경우 - 보호(차단)
			if (pid == (HANDLE)myPID) {
				return STATUS_ACCESS_DENIED;
			}
			DelRuleApp((int)pid);
		}
	}
	else {
		// 프로세스 스스로 종료
		HANDLE pid;
		pid = PsGetCurrentProcessId();
		DbgPrint("self-pid: %d", pid);
		DelRuleApp((int)pid);
	}

	// ZwTerminateProcess 실행
	ntStatus = ((ZWTERMINATEPROCESS)(OldZwTerminateProcess)) (
		ProcessHandle,
		ExitStatus);

	return ntStatus;
}

NTSTATUS NewZwDeviceIoControlFile(
	_In_      HANDLE           FileHandle,
	_In_opt_  HANDLE           Event,
	_In_opt_  PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_  PVOID            ApcContext,
	_Out_     PIO_STATUS_BLOCK IoStatusBlock,
	_In_      ULONG            IoControlCode,
	_In_opt_  PVOID            InputBuffer,
	_In_      ULONG            InputBufferLength,
	_Out_opt_ PVOID            OutputBuffer,
	_In_      ULONG            OutputBufferLength)
{
	NTSTATUS ntStatus;
	NTSTATUS ntRtn;
	ULONG nSize = 0;
	PPUBLIC_OBJECT_TYPE_INFORMATION pstInfo = NULL;
	PUBLIC_OBJECT_TYPE_INFORMATION stInfo = { 0, };
	int i;
	int nResult;
	ULONG pid;

	if (bEnableProtection == 1) {
		// 장치 유형 검사 (Imaging Devices: 0x2f______)
		if ((IoControlCode >> 16) == 0x2f) {
			pstInfo = &stInfo;
			// Device Name 정보
			ntRtn = ZwQueryObject(FileHandle, (OBJECT_INFORMATION_CLASS)1, pstInfo, sizeof(stInfo), &nSize);
			if (ntRtn == STATUS_SUCCESS) {
				ULONG cb;
				int nResult;
				char szText[100] = { 0 };

				RtlUnicodeToMultiByteN(szText, pstInfo->TypeName.Length, &cb, pstInfo->TypeName.Buffer, pstInfo->TypeName.Length);
				// DbgPrint(szText);

				// 등록된 장치 주소와 비교
				for (i = 0; i<nDevNum; i++) {
					if (asm_strcmp(szText, devAddr[i]) == 0) {
						// 등록된 장치로의 접근(주소 일치)
						// 접근 시도한 프로세스의 ID 구하기
						pid = (ULONG)PsGetCurrentProcessId();

						// 이전에 접근 시도한 PID와 비교
						nResult = SearchRuleApp(pid);
						if (nResult == -1) {
							// 예외 애플리케이션 여부 검사
							nResult = CheckExceptionApp((HANDLE)pid);
							if (nResult == -1) {
								AddRuleApp(pid, 0); // 차단 규칙 추가
													// 이벤트 발생
								KeSetEvent(SharedEvent, 0, FALSE);
								//KeDelayExecutionThread
								blockPID.pid = pid;
								blockPID.rule = 0;
								DbgPrint("pid: %d", pid);
								DbgPrint("Block!");
								return STATUS_ACCESS_DENIED;
							}
							else {
								AddRuleApp(pid, 1); // 허용 규칙 추가
								blockPID.pid = pid;
								blockPID.rule = 1;
								DbgPrint("pid: %d", pid);
								DbgPrint("Allow");
								break;
							}
						}
						else if (nResult == 1) {
							break;
						}
						else {
							return STATUS_ACCESS_DENIED;
						}
					}
				}
			}
			else {
				DbgPrint("Query Failed");
			}
		}
	}

	// ZwDeviceIoControlFile 실행
	ntStatus = ((ZWDEVICEIOCONTROLFILE)(OldZwDeviceIoControlFile)) (
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		IoControlCode,
		InputBuffer,
		InputBufferLength,
		OutputBuffer,
		OutputBufferLength);

	return ntStatus;
}

NTSTATUS Function_IRP_MJ_CREATE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	DbgPrint("Webcam Protector: IRP_MJ_CREATE");
	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CLOSE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	DbgPrint("Webcam Protector: IRP_MJ_CLOSE");
	return STATUS_SUCCESS;
}

NTSTATUS FuncIRPDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION pIoStackLocation;
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;

	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_START_PROTECTION: // Start
		bEnableProtection = 1;
		DbgPrint("Webcam Protector: Start Protection");
		InitProtector((unsigned char*)pBuf);
		//RtlCharToInteger((char*)pBuf, 10, &myPID);
		DbgPrint("%d", myPID);
		break;
	case IOCTL_STOP_PROTECTION: // Stop
		bEnableProtection = 0;
		DbgPrint("Webcam Protector: Stop Protection");
		break;
	case IOCTL_UPDATE_DEVICE: // 장치 리스트 생성
		DbgPrint("Webcam Protector: Update Device");
		DriverListTok((char*)pBuf);
		break;
	case IOCTL_EVENT_ACCPID: // 차단된 애플리케이션 PID 반환
		RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(pBuf, &blockPID, sizeof(APP_RULE));
		Irp->IoStatus.Information = sizeof(APP_RULE);
		break;
	case IOCTL_CLEAR_EXAPP: // 예외 애플리케이션 초기화
		InitPathApp();
		break;
	case IOCTL_ADD_EXAPP: // 예외 애플리케이션 추가
		AddPathApp((char*)pBuf);
		break;
	}

	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	Irp->IoStatus.Status = STATUS_SUCCESS;
	//Irp->IoStatus.Information = strlen(welcome);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

VOID OnUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING symLink;

	RtlInitUnicodeString(&symLink, deviceSymLinkBuffer);
	InitPathApp();

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("Webcam Protector: OnUnload called\n");

	// unhook system calls
	UNHOOK_SYSCALL(ZwDeviceIoControlFile, OldZwDeviceIoControlFile, NewZwDeviceIoControlFile);
	UNHOOK_SYSCALL(ZwTerminateProcess, OldZwTerminateProcess, NewZwTerminateProcess);

	// Unlock and Free MDL
	if (g_pmdlSystemCall)
	{
		MmUnmapLockedPages(MappedSystemCallTable, g_pmdlSystemCall);
		IoFreeMdl(g_pmdlSystemCall);
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath)
{

	NTSTATUS ntStatus = 0;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	// Normalize name and symbolic link.
	RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, deviceSymLinkBuffer);

	// Create the device.
	ntStatus = IoCreateDevice(pDriverObject,
		0, // For driver extension
		&deviceNameUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_UNKNOWN,
		FALSE,
		&g_MyDevice);

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);

	// Register a dispatch function for Unload
	pDriverObject->DriverUnload = OnUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FuncIRPDeviceControl;

	DbgPrint("Webcam Protector: DriverEntry\n");
	bEnableProtection = 0;

	appPidList = NULL;

	// save old system call locations
	OldZwDeviceIoControlFile = (ZWDEVICEIOCONTROLFILE)(SYSTEMSERVICE(ZwDeviceIoControlFile));
	OldZwTerminateProcess = (ZWTERMINATEPROCESS)(SYSTEMSERVICE(ZwTerminateProcess));

	// Map the memory into our domain so we can change the permissions on the MDL
	g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices * 4);
	if (!g_pmdlSystemCall)
		return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(g_pmdlSystemCall);

	// Change the flags of the MDL
	g_pmdlSystemCall->MdlFlags = g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

	MappedSystemCallTable = MmMapLockedPages(g_pmdlSystemCall, KernelMode);

	// hook system calls
	HOOK_SYSCALL(ZwDeviceIoControlFile, NewZwDeviceIoControlFile, OldZwDeviceIoControlFile);
	HOOK_SYSCALL(ZwTerminateProcess, NewZwTerminateProcess, OldZwTerminateProcess);

	return STATUS_SUCCESS;
}
