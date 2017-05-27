
// WebcamProtectorDlg.h : 헤더 파일
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include "ExceptionSettingDlg.h"
#include "AlertAccessWebcamDlg.h"

typedef struct _exceptionApp{
	CString name;
	CString path;
} EXCEPTION_APP;

const UINT WM_ALERT_ACCESSWEBCAM = ::RegisterWindowMessage("WM_ALERT_ACCESSWEBCAM");

// CWebcamProtectorDlg 대화 상자
class CWebcamProtectorDlg : public CDialogEx
{
// 생성입니다.
public:
	CWebcamProtectorDlg(CWnd* pParent = NULL);	// 표준 생성자입니다.

// 대화 상자 데이터입니다.
	enum { IDD = IDD_WEBCAMPROTECTOR_DIALOG };

	unsigned int m_myPID;
	bool m_enableProtection; // 보호 실행 여부
	list<CString> m_listDeviceName; // 장치 이름 리스트
	list<EXCEPTION_APP> m_listExceptionApp; // 예외 애플리케이션 리스트
	
	HANDLE m_hDevice;
	bool m_isRunningService; // 서비스 실행 여부

	HANDLE m_hAccessWebcam; // 접근 차단 이벤트 핸들
	HANDLE m_hPidAccessApp; // 접근 시도 애플리케이션 PID

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.


// 구현입니다.
protected:
	HICON m_hIcon;

	// 생성된 메시지 맵 함수
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
	BOOL OnDeviceChange(UINT nEventType, DWORD dwData);
public:
	CListCtrl ctr_listDevice;
	CButton ctr_checkProtection;
	afx_msg void OnBnClickedCheckProtection();
	afx_msg void OnDestroy();
	afx_msg void OnNMClickSyslinkException(NMHDR *pNMHDR, LRESULT *pResult);
	CExceptionSettingDlg m_pExceptionSettingDlg;
	CAlertAccessWebcamDlg m_pAlertAccessWebcamDlg;
	bool StartWebcamProtection();
	bool StopWebcamProtection();
	bool InitDriverService();
	bool CloseDriverService();
	void UpdateDeviceList(const GUID *pDevClass);
	bool SendMessageDriverDevice();
	bool SendMessageDriverExApp();
	LRESULT AlertAccessWebcamPopup(WPARAM wParam, LPARAM lParam);
	int m_checkProtection;
	CString m_labelStatus;
};
