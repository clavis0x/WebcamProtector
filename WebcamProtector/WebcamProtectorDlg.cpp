
// WebcamProtectorDlg.cpp : 구현 파일
//

#include "stdafx.h"
#include "WebcamProtector.h"
#include "WebcamProtectorDlg.h"
#include "afxdialogex.h"

#include <setupapi.h> // Device setup APIs
#pragma comment( lib, "setupapi.lib" )

#include <devguid.h>

#include <devpropdef.h>
#define INITGUID

#include <DEVPKEY.H>
#include <cfgmgr32.h>   // for MAX_DEVICE_ID_LEN, CM_Get_Parent and CM_Get_Device_ID

#include <winioctl.h>
#include <winsvc.h>

CWebcamProtectorDlg *g_pParent;

SC_HANDLE hScm, hSrv;
CWinThread*	pThreadWaitEvent = NULL;

// Device type
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_START_PROTECTION CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_STOP_PROTECTION CTL_CODE( SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_UPDATE_DEVICE CTL_CODE( SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_EVENT_ACCPID CTL_CODE( SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_CLEAR_EXAPP CTL_CODE( SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_ADD_EXAPP CTL_CODE( SIOCTL_TYPE, 0x805, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define ARRAY_SIZE(arr)     (sizeof(arr)/sizeof(arr[0]))

#define DBT_DEVNODES_CHANGED			0x0007
#define DBT_DEVICEARRIVAL               0x8000  // system detected a new device
#define DBT_DEVICEQUERYREMOVE           0x8001  // wants to remove, may fail
#define DBT_DEVICEQUERYREMOVEFAILED     0x8002  // removal aborted
#define DBT_DEVICEREMOVEPENDING         0x8003  // about to remove, still avail.
#define DBT_DEVICEREMOVECOMPLETE        0x8004  // device is gone
#define DBT_DEVICETYPESPECIFIC          0x8005  // type specific event

typedef BOOL (WINAPI *FN_SetupDiGetDevicePropertyW)(
  __in       HDEVINFO DeviceInfoSet,
  __in       PSP_DEVINFO_DATA DeviceInfoData,
  __in       const DEVPROPKEY *PropertyKey,
  __out      DEVPROPTYPE *PropertyType,
  __out_opt  PBYTE PropertyBuffer,
  __in       DWORD PropertyBufferSize,
  __out_opt  PDWORD RequiredSize,
  __in       DWORD Flags
);

typedef struct _sInitPrtInfo{
	unsigned int mainPid;
	void* cbFunc;
} INIT_PRT_INFO;

typedef struct _appRule{
	int pid;
	int rule; // 0: block, 1: allow
} APP_RULE;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CWebcamProtectorDlg 대화 상자




CWebcamProtectorDlg::CWebcamProtectorDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CWebcamProtectorDlg::IDD, pParent)
	, m_checkProtection(0)
	, m_labelStatus(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CWebcamProtectorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_Device, ctr_listDevice);
	DDX_Check(pDX, IDC_CHECK_Protection, m_checkProtection);
	DDX_Control(pDX, IDC_CHECK_Protection, ctr_checkProtection);
	DDX_Text(pDX, IDC_STATIC_Status, m_labelStatus);
}

BEGIN_MESSAGE_MAP(CWebcamProtectorDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DEVICECHANGE()
	ON_BN_CLICKED(IDC_CHECK_Protection, &CWebcamProtectorDlg::OnBnClickedCheckProtection)
	ON_WM_DESTROY()
	ON_NOTIFY(NM_CLICK, IDC_SYSLINK_Exception, &CWebcamProtectorDlg::OnNMClickSyslinkException)
	ON_REGISTERED_MESSAGE(WM_ALERT_ACCESSWEBCAM, AlertAccessWebcamPopup) // WM_ALERT_ACCESSWEBCAM
END_MESSAGE_MAP()


// CWebcamProtectorDlg 메시지 처리기

BOOL CWebcamProtectorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 이 대화 상자의 아이콘을 설정합니다. 응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	DWORD pid;
	CString strMsg;

	g_pParent = this; // 부모 개체 선언

	ctr_listDevice.DeleteAllItems(); // 모든 아이템 삭제
	ctr_listDevice.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER); // List Control 스타일 설정
	
	ctr_listDevice.InsertColumn(0, _T("Name"), LVCFMT_LEFT, 150, -1);
	ctr_listDevice.InsertColumn(1, _T("Device Name"), LVCFMT_LEFT, 150, -1);
	ctr_listDevice.InsertColumn(2, _T("Hardware IDs"), LVCFMT_LEFT, 250, -1);
	
	m_isRunningService = false;
	m_enableProtection = false;

	m_labelStatus.SetString("OFF");
	UpdateData(false);

	// 제어 프로그램 PID 구하기
	GetWindowThreadProcessId(AfxGetMainWnd()->m_hWnd, &pid);
	m_myPID = pid;

	// 장치 목록 업데이트
	const GUID *pDevClass;
	pDevClass = &GUID_DEVCLASS_IMAGE; // &GUID_DEVCLASS_IMAGE
	UpdateDeviceList(pDevClass);

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다. 문서/뷰 모델을 사용하는 MFC 응용 프로그램의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CWebcamProtectorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CWebcamProtectorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BOOL CWebcamProtectorDlg::OnDeviceChange(UINT nEventType, DWORD dwData)
{
	const GUID *pDevClass;
	CString strMsg;

	switch(nEventType)
	{
		case DBT_DEVICEARRIVAL: // 장치 연결
		case DBT_DEVICEREMOVECOMPLETE: // 장치 해제
		case DBT_DEVNODES_CHANGED:
			pDevClass = &GUID_DEVCLASS_IMAGE; // &GUID_DEVCLASS_IMAGE
			UpdateDeviceList(pDevClass); // 장치 목록 업데이트
			break;
	}

	return TRUE;
}

void CWebcamProtectorDlg::UpdateDeviceList(const GUID *pDevClass)
{
	HDEVINFO hDev;
	SP_DEVINFO_DATA devInfo;
	DWORD devIndex=0;
	PCHAR *DeviceDesc;
	PCHAR *HardwareId;
	CString strMsg;
	
	CONFIGRET status;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD dwSize, dwPropertyRegDataType;
	WCHAR szDesc[1024], szHardwareIDs[4096];
	WCHAR szBuffer[4096];
	char szTemp[4096] = {0};
	DEVPROPTYPE ulPropertyType;

	LPTSTR pszToken, pszNextToken;
	TCHAR szDeviceInstanceID [MAX_DEVICE_ID_LEN];
	const static LPCTSTR arPrefix[3] = {TEXT("VID_"), TEXT("PID_"), TEXT("MI_")};
	TCHAR szVid[MAX_DEVICE_ID_LEN], szPid[MAX_DEVICE_ID_LEN], szMi[MAX_DEVICE_ID_LEN];
	
	int nStatus, probNum;

	FN_SetupDiGetDevicePropertyW fn_SetupDiGetDevicePropertyW = (FN_SetupDiGetDevicePropertyW)
        GetProcAddress (GetModuleHandle (TEXT("Setupapi.dll")), "SetupDiGetDevicePropertyW");

	// GUID_DEVCLASS_IMAGE의 장치 리스트 구하기
	hDev= SetupDiGetClassDevs(pDevClass , NULL, NULL, DIGCF_PRESENT) ;

	devInfo.cbSize = sizeof(SP_DEVINFO_DATA) ;

	ctr_listDevice.DeleteAllItems(); // 모든 아이템 삭제

	m_listDeviceName.clear();

	// 각 장치의 상세정보 열거
	for(devIndex=0; SetupDiEnumDeviceInfo(hDev,devIndex,&devInfo); devIndex++)
	{
		int listNum = ctr_listDevice.GetItemCount();
		
		devInfo.cbSize = sizeof (devInfo);
		if (!SetupDiEnumDeviceInfo(hDev, devIndex, &devInfo))
			break;
		
		// Device Instance ID 구하기
		status = CM_Get_Device_ID(devInfo.DevInst, szDeviceInstanceID, MAX_PATH, 0);
		if (status != CR_SUCCESS)
			continue;

		if (SetupDiGetDeviceRegistryProperty (hDev, &devInfo, SPDRP_DEVICEDESC, &dwPropertyRegDataType, (BYTE*)szDesc, sizeof(szDesc), &dwSize)){

			strMsg.Empty();
			if (fn_SetupDiGetDevicePropertyW (hDev, &devInfo, &DEVPKEY_Device_FriendlyName,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0))
			{				
					WideCharToMultiByte(CP_ACP, 0, szBuffer, 1024, (char*)szTemp, 1024, 0, FALSE);
					strMsg.Format("%s", szTemp);
					ctr_listDevice.InsertItem(listNum, strMsg);

			}
			else if(fn_SetupDiGetDevicePropertyW (hDev, &devInfo, &DEVPKEY_Device_BusReportedDeviceDesc,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0))
			{

					WideCharToMultiByte(CP_ACP, 0, szBuffer, 1024, (char*)szTemp, 1024, 0, FALSE);
					strMsg.Format("%s", szTemp);
					ctr_listDevice.InsertItem(listNum, strMsg);

			}
			if(strMsg.IsEmpty() == true){
				strMsg.Format("%s", szDesc);
				ctr_listDevice.InsertItem(listNum, strMsg);
			}

			if(fn_SetupDiGetDevicePropertyW (hDev, &devInfo, &DEVPKEY_Device_PDOName,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0))
			{
				WideCharToMultiByte(CP_ACP, 0, szBuffer, 1024, (char*)szTemp, 1024, 0, FALSE);
				strMsg.Format("%s", szTemp);
				ctr_listDevice.SetItemText(listNum, 1, strMsg);

				m_listDeviceName.push_back(strMsg);
			}
		}
		
		ctr_listDevice.SetItemText(listNum, 2, szDeviceInstanceID);

	}

	// kernel-level 프로그램에 장치 리스트 전달
	SendMessageDriverDevice();

}

void CWebcamProtectorDlg::OnBnClickedCheckProtection()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	UpdateData(true);

	if(m_checkProtection == 1){
		if(m_enableProtection == true) return;
		StartWebcamProtection();
		
	}else{
		StopWebcamProtection();
	}

}

void CWebcamProtectorDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	// TODO: 여기에 메시지 처리기 코드를 추가합니다.
	if(m_isRunningService == true){
		if(m_enableProtection == true){
			StopWebcamProtection();
		}
		CloseDriverService();
	}
}

// 웹캠 접근 알림 이벤트 스레드
static UINT AccessWebcamEvent(LPVOID lpParam)
{
	CWebcamProtectorDlg* pParent = (CWebcamProtectorDlg*) lpParam;
	char szCommand[100] = {0};
	char ReadBuffer[50] = {0};
	DWORD dwBytesRead = 0;
	APP_RULE tmpAppRule;

	// 이벤트 초기화
	ResetEvent(pParent->m_hAccessWebcam);

	do{
		// 이벤트 대기
		WaitForSingleObject(pParent->m_hAccessWebcam, INFINITE);
		if(pParent->m_enableProtection == false)
			break;

		// 접근 시도 프로세스 ID 요청
		DeviceIoControl(pParent->m_hDevice, IOCTL_EVENT_ACCPID, szCommand, strlen(szCommand)+1, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
		memcpy(&tmpAppRule, ReadBuffer, sizeof(APP_RULE));

		CString strMsg;
		strMsg.Format("%d", tmpAppRule.pid);
		//AfxMessageBox(strMsg);
		
		// 웹캠 접근 차단 Dialog 띄우기
		PostMessage(g_pParent->m_hWnd, WM_ALERT_ACCESSWEBCAM, tmpAppRule.pid, NULL); // WM_ALERT_ACCESSWEBCAM

	}while(pParent->m_enableProtection);

	pThreadWaitEvent = NULL;
	return 0;
}


bool CWebcamProtectorDlg::StartWebcamProtection()
{
	int nResult;
	unsigned char szCommand[100] = {0};
	char ReadBuffer[50] = {0};
	DWORD dwBytesRead = 0;

	INIT_PRT_INFO sInitInfo;
	sInitInfo.mainPid = m_myPID;

	if(m_listDeviceName.size() == 0){
		AfxMessageBox("Not Found - Webcam");
		m_checkProtection = 0;
		UpdateData(false);
		return false;
	}
	m_labelStatus.SetString("Init...");
	UpdateData(false);
	
	// 드라이버(wcamprt)가 실행중이지 않으면 서비스 시작
	if(m_isRunningService == false){
		nResult = InitDriverService();
		if(nResult == false)
			return false;
	}

	// 접근 차단 알림 이벤트 생성
	m_hDevice = CreateFile("\\\\.\\wcamprt", GENERIC_WRITE|GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(m_hDevice == INVALID_HANDLE_VALUE){
		AfxMessageBox("[Error]");
		m_checkProtection = 0;
		UpdateData(false);
		return false;
	}
	m_enableProtection = true;
	
	// 장치 목록 업데이트
	UpdateDeviceList(&GUID_DEVCLASS_IMAGE);

	m_hAccessWebcam = CreateEvent(NULL, FALSE, FALSE, "Global\\AccessWebcamEvent");
	pThreadWaitEvent = AfxBeginThread(AccessWebcamEvent, this, THREAD_PRIORITY_NORMAL, 0, 0);
	if(pThreadWaitEvent == NULL){
		AfxMessageBox("[Error] Thread is already running.", true);
		return false;
	}

	// 드라이버에 예외 애플리케이션 리스트 전달
	SendMessageDriverExApp();
	
	// 보호 시작 옵션 전달
	memcpy(szCommand, &sInitInfo, sizeof(INIT_PRT_INFO));
	DeviceIoControl(m_hDevice, IOCTL_START_PROTECTION, szCommand, sizeof(INIT_PRT_INFO), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	
	m_labelStatus.SetString("ON");
	UpdateData(false);

	return 0;
}


bool CWebcamProtectorDlg::StopWebcamProtection()
{
	char szCommand[100] = {0};
	char ReadBuffer[50] = {0};
	DWORD dwBytesRead = 0;
	DWORD nExitCode = NULL;
	DWORD dw;
	
	m_enableProtection = false;

	// 차단 알림 이벤트 제거
	SetEvent(m_hAccessWebcam);
	dw = WaitForSingleObject(pThreadWaitEvent, 1000);
	if(dw == WAIT_TIMEOUT){
		GetExitCodeThread( pThreadWaitEvent->m_hThread, &nExitCode );
		TerminateThread( pThreadWaitEvent->m_hThread, nExitCode );
		pThreadWaitEvent = NULL;
	}
	
	// 보호 종료 옵션 전달
	DeviceIoControl(m_hDevice, IOCTL_STOP_PROTECTION, szCommand, strlen(szCommand)+1, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	CloseHandle(m_hDevice);

	m_labelStatus.SetString("OFF");
	UpdateData(false);

	return 0;
}

// wcamprt 드라이버 서비스 초기화 및 실행
bool CWebcamProtectorDlg::InitDriverService()
{
	BOOL result;

	HRSRC hrResource;
	HGLOBAL hData;
	unsigned char *aFilePtr;
	DWORD dwFileSize, dwNumWritten;;
	HANDLE hFileHandle;
	TCHAR lpDrvPath[MAX_PATH]={0,};

	CString str_pathSysFile;
	TCHAR str_pathSysDirectory[1024];

    SERVICE_STATUS status;
	int err;
	CString strErr;
	
	// 시스템 디렉토리 경로 구하기(system32)
	GetSystemDirectory(str_pathSysDirectory, 1024);
	str_pathSysFile.Format("%s\\wcamprt.sys", str_pathSysDirectory);
	
	// ========== wcamprt.sys 생성 시작 ========== //
	hrResource = FindResource(NULL, MAKEINTRESOURCE(IDR_DRIVER_WCP), "DRIVER");
	if(!hrResource)
		return false;
  
	hData = LoadResource(NULL, hrResource);
	if(!hData)
		return false;
     
	aFilePtr = (unsigned char *)LockResource(hData);
	if(!aFilePtr)
		return false;
     
	dwFileSize = SizeofResource(NULL, hrResource);
	wsprintf(lpDrvPath, "%s", str_pathSysFile);
		
	hFileHandle = CreateFile(lpDrvPath,	FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if(INVALID_HANDLE_VALUE == hFileHandle)
		return false;
   
	while(dwFileSize--){
		WriteFile(hFileHandle, aFilePtr, 1, &dwNumWritten, NULL);
		aFilePtr++;
	}

	CloseHandle(hFileHandle);

	// ========== wcamprt.sys 생성 끝 ========== //

	// 서비스 시작
    hScm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	hSrv = OpenService(hScm, "wcamprt", SERVICE_ALL_ACCESS);
    if (hSrv == NULL)
    {
		hSrv = CreateService(   hScm,
								"wcamprt",
								"wcamprt",
								SERVICE_ALL_ACCESS,
								SERVICE_KERNEL_DRIVER,
								SERVICE_SYSTEM_START,
								SERVICE_ERROR_NORMAL,
								str_pathSysFile,
								NULL,
								NULL,
								NULL,
								NULL,
								NULL);
	}

    result = StartService(hSrv, 0, NULL);
	if(result == 0){
		err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING)
        {
			// Failed to start service; clean-up:
			strErr.Format("[Error] 서비스 시작 실패\n(code : 0x%0.4X)", err);
			AfxMessageBox(strErr, false);
			ControlService(hSrv, SERVICE_CONTROL_STOP, &status);
			DeleteService(hSrv);
			CloseServiceHandle(hSrv);
			hSrv = NULL;
			SetLastError(err);
			return false;
        }
	}

	m_isRunningService = true;

	return true;
}

// wcamprt 드라이버 서비스 종료
bool CWebcamProtectorDlg::CloseDriverService()
{
	CString str_pathSysFile;
	TCHAR str_pathSysDirectory[1024];

    SERVICE_STATUS status;
	int err;
	CString strErr;

	ControlService(hSrv, SERVICE_CONTROL_STOP, &status);
	DeleteService(hSrv);
	CloseServiceHandle(hSrv);
	CloseServiceHandle(hScm);

	GetSystemDirectory(str_pathSysDirectory, 1024);
	str_pathSysFile.Format("%s\\wcamprt.sys", str_pathSysDirectory);
	
	if(PathFileExists(str_pathSysFile))
		DeleteFile(str_pathSysFile);

	return true;
}

// 장치 리스트 전달 함수
bool CWebcamProtectorDlg::SendMessageDriverDevice()
{
	char szDeviceList[1024] = {0};
	char ReadBuffer[50] = {0};
	DWORD dwBytesRead = 0;
	
	if(m_enableProtection == false)
		return false;

	// 장치 개수
	szDeviceList[0] = m_listDeviceName.size() + 0x30;

	// string 형식의 리스트 작성
	list<CString>::iterator itor = m_listDeviceName.begin();
	while(itor != m_listDeviceName.end())
	{
		strcat(szDeviceList, (LPSTR)(LPCSTR)*itor);
		strcat(szDeviceList, " ");
		itor++;
	}

	// 리스트 전달
	DeviceIoControl(m_hDevice, IOCTL_UPDATE_DEVICE, szDeviceList, strlen(szDeviceList)+1, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);

	return true;
}

// 예외 애플리케이션 전달 함수
bool CWebcamProtectorDlg::SendMessageDriverExApp()
{
	char szExAppList[1024] = {0};
	char ReadBuffer[50] = {0};
	DWORD dwBytesRead = 0;
	
	if(m_enableProtection == false)
		return false;

	// Reset Exception App
	DeviceIoControl(m_hDevice, IOCTL_CLEAR_EXAPP, szExAppList, strlen(szExAppList)+1, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	
	// Add Exception App
	list<EXCEPTION_APP>::iterator itor = m_listExceptionApp.begin();
	while(itor != m_listExceptionApp.end())
	{
		strcpy_s(szExAppList, itor->path);
		DeviceIoControl(m_hDevice, IOCTL_ADD_EXAPP, szExAppList, strlen(szExAppList)+1, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
		itor++;
	}

	return true;
}

// 보호 예외 설정 Dialog
void CWebcamProtectorDlg::OnNMClickSyslinkException(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	if(m_pExceptionSettingDlg.GetSafeHwnd() == NULL){
		m_pExceptionSettingDlg.Create(IDD_EXCEPTIONSETTINGDLG);
		m_pExceptionSettingDlg.CenterWindow(CWnd::FromHandle(this->m_hWnd));
	}
	m_pExceptionSettingDlg.ShowWindow(SW_SHOW);

	*pResult = 0;
}

// 접근 차단 알림 Dialog
LRESULT CWebcamProtectorDlg::AlertAccessWebcamPopup(WPARAM wParam, LPARAM lParam)
{
	m_hPidAccessApp = (HANDLE)wParam;

	if(g_pParent->m_pAlertAccessWebcamDlg.GetSafeHwnd() == NULL){
		m_pAlertAccessWebcamDlg.Create(IDD_ALERTACCESSWEBCAMDLG);
		//m_pAlertAccessWebcamDlg.CenterWindow(CWnd::FromHandle(this->m_hWnd));
	}
	m_pAlertAccessWebcamDlg.ShowWindow(SW_SHOW);

	return 0;
}