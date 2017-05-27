#pragma once

// CExceptionSettingDlg 대화 상자입니다.

class CExceptionSettingDlg : public CDialog
{
	DECLARE_DYNAMIC(CExceptionSettingDlg)

public:
	CExceptionSettingDlg(CWnd* pParent = NULL);   // 표준 생성자입니다.
	virtual ~CExceptionSettingDlg();

// 대화 상자 데이터입니다.
	enum { IDD = IDD_EXCEPTIONSETTINGDLG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnDestroy();
	afx_msg void OnClose();
	CListCtrl ctr_listException;
	void UpdateExceptionList();
	afx_msg void OnBnClickedButtonAdd();
	afx_msg void OnBnClickedButtonDel();
};
