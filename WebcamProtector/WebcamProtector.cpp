
// WebcamProtector.cpp : 응용 프로그램에 대한 클래스 동작을 정의합니다.
//

#include "stdafx.h"
#include "WebcamProtector.h"
#include "WebcamProtectorDlg.h"

#include <Lm.h>
#pragma comment(lib, "netapi32.lib")

#pragma comment(lib, "winmm")
#pragma comment(lib, "version")

BOOL GetWindowsVersion(DWORD& dwMajor, DWORD& dwMinor); // Check Windows Version
BOOL GetWindowsVersion(DWORD& dwMajor, DWORD& dwMinor, DWORD& dwServicePack);
BOOL IsCurrentProcess64bit(); // Check x64
BOOL IsCurrentProcessWow64();
BOOL Is64BitWindows();
BOOL GetProcessElevation(TOKEN_ELEVATION_TYPE *pElevationType, BOOL *pIsAdmin); // Check Admin

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CWebcamProtectorApp

BEGIN_MESSAGE_MAP(CWebcamProtectorApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CWebcamProtectorApp 생성

CWebcamProtectorApp::CWebcamProtectorApp()
{
	// 다시 시작 관리자 지원
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: 여기에 생성 코드를 추가합니다.
	// InitInstance에 모든 중요한 초기화 작업을 배치합니다.
}


// 유일한 CWebcamProtectorApp 개체입니다.

CWebcamProtectorApp theApp;


// CWebcamProtectorApp 초기화

BOOL CWebcamProtectorApp::InitInstance()
{
	// 응용 프로그램 매니페스트가 ComCtl32.dll 버전 6 이상을 사용하여 비주얼 스타일을
	// 사용하도록 지정하는 경우, Windows XP 상에서 반드시 InitCommonControlsEx()가 필요합니다.
	// InitCommonControlsEx()를 사용하지 않으면 창을 만들 수 없습니다.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// 응용 프로그램에서 사용할 모든 공용 컨트롤 클래스를 포함하도록
	// 이 항목을 설정하십시오.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// 대화 상자에 셸 트리 뷰 또는
	// 셸 목록 뷰 컨트롤이 포함되어 있는 경우 셸 관리자를 만듭니다.
	CShellManager *pShellManager = new CShellManager;

	// 표준 초기화
	// 이들 기능을 사용하지 않고 최종 실행 파일의 크기를 줄이려면
	// 아래에서 필요 없는 특정 초기화
	// 루틴을 제거해야 합니다.
	// 해당 설정이 저장된 레지스트리 키를 변경하십시오.
	// TODO: 이 문자열을 회사 또는 조직의 이름과 같은
	// 적절한 내용으로 수정해야 합니다.
	SetRegistryKey(_T("로컬 응용 프로그램 마법사에서 생성된 응용 프로그램"));
	
	m_handle = ::CreateEvent(NULL, FALSE, FALSE, _T("wcamprt - 중복 실행 방지"));
	if (::GetLastError() == ERROR_ALREADY_EXISTS){
		m_execError = 1; // 중복 실행
		return false;
	}

	BOOL bResult64;
	DWORD dwMajor, dwMinor, dwServicePack;
	GetWindowsVersion(dwMajor, dwMinor, dwServicePack);
	if(dwMajor < 6){
		//m_execError = 2; // 지원되지 않는 운영체제
		//return false;
	}else{
		m_winVersion[0] = dwMajor;
		m_winVersion[1] = dwMinor;
		m_winVersion[2] = dwServicePack;
		bResult64 = Is64BitWindows();
		if(bResult64 == TRUE){
			m_execError = 3; // 64비트 운영체제
			m_is64bit = true;
			return false;
		}else{
			m_is64bit = false;
		}
	}

	TOKEN_ELEVATION_TYPE t;
	BOOL bAdmin = FALSE;
	char szUser[0xFF] = {0};
	DWORD dwUser = _countof(szUser);
	GetUserName(szUser, &dwUser);

	if(GetProcessElevation(&t, &bAdmin)){
		if(t == TokenElevationTypeLimited){
			m_execError = 4; // 관리자 권한
			return false;
		}
	}

	CWebcamProtectorDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: 여기에 [확인]을 클릭하여 대화 상자가 없어질 때 처리할
		//  코드를 배치합니다.
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: 여기에 [취소]를 클릭하여 대화 상자가 없어질 때 처리할
		//  코드를 배치합니다.
	}

	// 위에서 만든 셸 관리자를 삭제합니다.
	if (pShellManager != NULL)
	{
		delete pShellManager;
	}

	// 대화 상자가 닫혔으므로 응용 프로그램의 메시지 펌프를 시작하지 않고  응용 프로그램을 끝낼 수 있도록 FALSE를
	// 반환합니다.
	return FALSE;
}



int CWebcamProtectorApp::ExitInstance()
{
	// TODO: 여기에 특수화된 코드를 추가 및/또는 기본 클래스를 호출합니다.
	CString strMsg;
	if (m_handle != nullptr) ::CloseHandle(m_handle); // 중복 실행 방지 해제
	
	if(m_execError != 0){
		switch(m_execError)
		{
			case 1:
				AfxMessageBox("프로그램이 이미 실행 중입니다.\n(중복 실행 불가능)", MB_ICONSTOP);
				break;
			case 2:
				AfxMessageBox("지원되지 않는 운영체제 버전입니다.\n\n[지원되는 운영체제]\n - Windows 7 x64\n - Windows 8/8.1 x64 이상", MB_ICONSTOP);
				break;
			case 3:
				AfxMessageBox("64bit 운영체제는 지원하지 않습니다.\n(32bit 운영체제에서 실행해주세요.)", MB_ICONSTOP);
				break;
			case 4:
				AfxMessageBox("관리자 권한으로 실행되지 않았습니다.\n관리자 권한으로 다시 실행해주세요.", MB_ICONSTOP);
				break;
		}
	}

	return CWinApp::ExitInstance();
}

BOOL GetWindowsVersion(DWORD& dwMajor, DWORD& dwMinor)
{
    static DWORD dwMajorCache = 0, dwMinorCache = 0;
    if (0 != dwMajorCache)
    {
        dwMajor = dwMajorCache;
        dwMinor = dwMinorCache;
        return TRUE;
    }

    LPWKSTA_INFO_100 pBuf = NULL;
    if (NERR_Success != NetWkstaGetInfo(NULL, 100, (LPBYTE*)&pBuf))
        return FALSE;

    dwMajor = dwMajorCache = pBuf->wki100_ver_major;
    dwMinor = dwMinorCache = pBuf->wki100_ver_minor;
    NetApiBufferFree(pBuf);

    return TRUE;
}

BOOL GetWindowsVersion(DWORD& dwMajor, DWORD& dwMinor, DWORD& dwServicePack)
{
    if (!GetWindowsVersion(dwMajor, dwMinor))
        return FALSE;

    static DWORD dwServicePackCache = ULONG_MAX;
    if (ULONG_MAX != dwServicePackCache)
    {
        dwServicePack = dwServicePackCache;
        return TRUE;
    }

    const int nServicePackMax = 10;
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, VER_EQUAL);
	
    for (int i = 0; i < nServicePackMax; ++i)
    {
        osvi.wServicePackMajor = i;
        if (VerifyVersionInfo(&osvi, VER_SERVICEPACKMAJOR, dwlConditionMask))
        {
            dwServicePack = dwServicePackCache = i;
            return TRUE;
        }
    }

    return FALSE;
}

BOOL IsCurrentProcess64bit() // 현재 프로세스가 32bit 인지 64bit 인지 확인
{
	#if defined(_WIN64)
		return TRUE;
	#else
		return FALSE;
	#endif
}

BOOL IsCurrentProcessWow64() // 현재 프로세스가 WOW64 환경에서 동작중인지 확인
{
    BOOL bIsWow64 = FALSE;
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
    if (!fnIsWow64Process)
        return FALSE;

    return fnIsWow64Process(GetCurrentProcess(), &bIsWow64) && bIsWow64;
}

BOOL Is64BitWindows() // 현재 설치된 윈도우가 32bit 인지 64bit 인지 확인
{
    if (IsCurrentProcess64bit())
        return TRUE;

    return IsCurrentProcessWow64();
}

BOOL GetProcessElevation(TOKEN_ELEVATION_TYPE *pElevationType, BOOL *pIsAdmin) // 관리자 권한 확인
{
    HANDLE hToken = NULL;
    BOOL bResult = FALSE;
    DWORD dwSize = 0;

    // 현재 프로세스의 토큰을 얻는다.
    if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) )
        return FALSE;

    // 권한상승 형태에 대한 정보를 얻는다.
    if ( GetTokenInformation(hToken, TokenElevationType, pElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwSize) )
    {
        BYTE adminSID[SECURITY_MAX_SID_SIZE];
        dwSize = sizeof(adminSID);
        
        // 관리자 그룹의 SID 값을 생성한다.
        CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID, &dwSize);

        if ( *pElevationType == TokenElevationTypeLimited )
        {
            HANDLE hUnfilteredToken = NULL;
            
            // 연결된 토큰의 핸들을 얻는다.
            GetTokenInformation(hToken, TokenLinkedToken, (void *)&hUnfilteredToken, sizeof(HANDLE), &dwSize);

            // 원래의 토큰이 관리자의 SID를 포함하고 있는지 여부를 확인한다.
            if ( CheckTokenMembership(hUnfilteredToken, &adminSID, pIsAdmin) )
                bResult = TRUE;
            
            CloseHandle(hUnfilteredToken);
        }
        else
        {
            *pIsAdmin = IsUserAnAdmin();
            bResult = TRUE;
        }
    }

    CloseHandle(hToken);
    return bResult;
}
