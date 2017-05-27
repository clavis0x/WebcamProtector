#pragma once
#include "afxcmn.h"


// CAlertAccessWebcamDlg 대화 상자입니다.

class CAlertAccessWebcamDlg : public CDialog
{
	DECLARE_DYNAMIC(CAlertAccessWebcamDlg)

public:
	CAlertAccessWebcamDlg(CWnd* pParent = NULL);   // 표준 생성자입니다.
	virtual ~CAlertAccessWebcamDlg();

// 대화 상자 데이터입니다.
	enum { IDD = IDD_ALERTACCESSWEBCAMDLG };

	CString m_strTargetAppPath;

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonAllow();
	afx_msg void OnBnClickedButtonBlock();
	virtual BOOL OnInitDialog();
	afx_msg void OnClose();
	CLinkCtrl ctr_linkProcPath;
};
