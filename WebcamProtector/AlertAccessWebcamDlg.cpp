// AlertAccessWebcamDlg.cpp : 구현 파일입니다.
//

#include "stdafx.h"
#include "WebcamProtector.h"
#include "AlertAccessWebcamDlg.h"
#include "afxdialogex.h"
#include "WebcamProtectorDlg.h"

extern CWebcamProtectorDlg *g_pParent;


// CAlertAccessWebcamDlg 대화 상자입니다.

IMPLEMENT_DYNAMIC(CAlertAccessWebcamDlg, CDialog)

CAlertAccessWebcamDlg::CAlertAccessWebcamDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CAlertAccessWebcamDlg::IDD, pParent)
{

}

CAlertAccessWebcamDlg::~CAlertAccessWebcamDlg()
{
}

void CAlertAccessWebcamDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_SYSLINK_ProcPath, ctr_linkProcPath);
}


BEGIN_MESSAGE_MAP(CAlertAccessWebcamDlg, CDialog)
	ON_BN_CLICKED(IDC_BUTTON_Allow, &CAlertAccessWebcamDlg::OnBnClickedButtonAllow)
	ON_BN_CLICKED(IDC_BUTTON_Block, &CAlertAccessWebcamDlg::OnBnClickedButtonBlock)
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CAlertAccessWebcamDlg 메시지 처리기입니다.



BOOL CAlertAccessWebcamDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  여기에 추가 초기화 작업을 추가합니다.
	CString strTemp;
	HANDLE handle;
	char szPath[1024] = {0};
	DWORD dwLen = 0;

	CString appPath; // PATH
	
	RECT rectWin;
	GetWindowRect(&rectWin);
	
	int m_Desktowidth = GetSystemMetrics(SM_CXSCREEN);
	int m_DesktopHeight = GetSystemMetrics(SM_CYSCREEN);
	
	SetWindowPos(NULL, m_Desktowidth - (rectWin.right - rectWin.left) - 10, m_DesktopHeight - (rectWin.bottom - rectWin.top) - 40, 0, 0, SWP_NOSIZE);

	handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (DWORD)g_pParent->m_hPidAccessApp);	
	if(GetModuleFileNameEx(handle, NULL, szPath, 1024)){
		m_strTargetAppPath = szPath;
		strTemp.Format("[%d] %s", g_pParent->m_hPidAccessApp, PathFindFileName(szPath));
		GetDlgItem(IDC_STATIC_ProcName)->SetWindowTextA(strTemp);

		appPath = szPath;
		int nPos = appPath.ReverseFind('\\'); // 실행파일 경로에서 파일명 제외
		if(nPos > 0)
			appPath = appPath.Left(nPos);

		strTemp.Format("(<a>%s</a>)", appPath);
		ctr_linkProcPath.SetWindowTextA(strTemp);
	}


	return TRUE;  // return TRUE unless you set the focus to a control
	// 예외: OCX 속성 페이지는 FALSE를 반환해야 합니다.
}


void CAlertAccessWebcamDlg::OnClose()
{
	// TODO: 여기에 메시지 처리기 코드를 추가 및/또는 기본값을 호출합니다.
	DestroyWindow();

	CDialog::OnClose();
}


void CAlertAccessWebcamDlg::OnBnClickedButtonAllow()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	
	EXCEPTION_APP sExceptionApp;
	list<EXCEPTION_APP>::iterator itor = g_pParent->m_listExceptionApp.begin();
	bool result = true;
	CString strFilePath;
	CString strFileName;
	
	strFilePath = m_strTargetAppPath;
	strFileName = PathFindFileName(strFilePath);

	// 중복 검사
	while(itor != g_pParent->m_listExceptionApp.end())
	{
		if(strFileName.Compare(itor->name) == 0){
			result = false;
			break;
		}
		itor++;
	}
	if(result == true){
		sExceptionApp.name.SetString(strFileName);
		sExceptionApp.path.SetString(strFilePath);
		g_pParent->m_listExceptionApp.push_back(sExceptionApp);
		g_pParent->SendMessageDriverExApp();
	}
	DestroyWindow();
}


void CAlertAccessWebcamDlg::OnBnClickedButtonBlock()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	DestroyWindow();
}