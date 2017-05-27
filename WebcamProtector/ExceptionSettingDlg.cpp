// ExceptionSettingDlg.cpp : 구현 파일입니다.
//

#include "stdafx.h"
#include "WebcamProtector.h"
#include "ExceptionSettingDlg.h"
#include "afxdialogex.h"
#include "WebcamProtectorDlg.h"

extern CWebcamProtectorDlg *g_pParent;


// CExceptionSettingDlg 대화 상자입니다.

IMPLEMENT_DYNAMIC(CExceptionSettingDlg, CDialog)

CExceptionSettingDlg::CExceptionSettingDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CExceptionSettingDlg::IDD, pParent)
{

}

CExceptionSettingDlg::~CExceptionSettingDlg()
{
}

void CExceptionSettingDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_Exception, ctr_listException);
}


BEGIN_MESSAGE_MAP(CExceptionSettingDlg, CDialog)
	ON_WM_DESTROY()
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_BUTTON_Add, &CExceptionSettingDlg::OnBnClickedButtonAdd)
	ON_BN_CLICKED(IDC_BUTTON_Del, &CExceptionSettingDlg::OnBnClickedButtonDel)
END_MESSAGE_MAP()


// CExceptionSettingDlg 메시지 처리기입니다.


BOOL CExceptionSettingDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  여기에 추가 초기화 작업을 추가합니다.
	ctr_listException.DeleteAllItems(); // 모든 아이템 삭제
	ctr_listException.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER); // List Control 스타일 설정
	
	ctr_listException.InsertColumn(0, _T("Name"), LVCFMT_LEFT, 120, -1);
	ctr_listException.InsertColumn(1, _T("Path"), LVCFMT_LEFT, 250, -1);

	UpdateExceptionList();

	return TRUE;  // return TRUE unless you set the focus to a control
	// 예외: OCX 속성 페이지는 FALSE를 반환해야 합니다.
}


void CExceptionSettingDlg::OnDestroy()
{
	CDialog::OnDestroy();

	// TODO: 여기에 메시지 처리기 코드를 추가합니다.
}


void CExceptionSettingDlg::OnClose()
{
	// TODO: 여기에 메시지 처리기 코드를 추가 및/또는 기본값을 호출합니다.
	DestroyWindow();

	CDialog::OnClose();
}

void CExceptionSettingDlg::UpdateExceptionList()
{
	int listNum;
	list<EXCEPTION_APP>::iterator itor = g_pParent->m_listExceptionApp.begin();
	
	ctr_listException.DeleteAllItems(); // 모든 아이템 삭제
	while(itor != g_pParent->m_listExceptionApp.end())
	{ 
		listNum = ctr_listException.GetItemCount();

		ctr_listException.InsertItem(listNum, itor->name);
		ctr_listException.SetItemText(listNum, 1, itor->path);
		itor++;
	}
	g_pParent->SendMessageDriverExApp();
}

void CExceptionSettingDlg::OnBnClickedButtonAdd()
{
	CString strFilePath;
	CString szFilter, szDefExt;
	EXCEPTION_APP sExceptionApp;

	szFilter = "실행 파일(*.exe)|*.exe|";
	szDefExt = "exe";

	CFileDialog fileDlg(TRUE, szDefExt, NULL, OFN_PATHMUSTEXIST | OFN_HIDEREADONLY, szFilter, this);
	if(fileDlg.DoModal() == IDOK)
	{ 
		int listNum;
		bool result = true;
		CString strFileName;
		list<EXCEPTION_APP>::iterator itor = g_pParent->m_listExceptionApp.begin();
		strFilePath = fileDlg.GetPathName();
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
		if(result == false){
			return;
		}else{
			sExceptionApp.name.SetString(strFileName);
			sExceptionApp.path.SetString(strFilePath);
			g_pParent->m_listExceptionApp.push_back(sExceptionApp);
			UpdateExceptionList();
		}
	}

}


void CExceptionSettingDlg::OnBnClickedButtonDel()
{
	int nItem;
	CString strFileName;
	list<EXCEPTION_APP>::iterator itor;
	POSITION pos = ctr_listException.GetFirstSelectedItemPosition();
	if(pos == NULL){
		return;
	}else{
		while(pos){
			nItem = ctr_listException.GetNextSelectedItem(pos);
			strFileName = ctr_listException.GetItemText(nItem, 0);
			
			itor = g_pParent->m_listExceptionApp.begin();
			while(itor != g_pParent->m_listExceptionApp.end())
			{
				if(strFileName.Compare(itor->name) == 0){
					g_pParent->m_listExceptionApp.erase(itor);
					break;
				}
				itor++;
			}
		}
	}
	UpdateExceptionList();

}
