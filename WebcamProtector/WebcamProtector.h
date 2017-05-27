
// WebcamProtector.h : PROJECT_NAME 응용 프로그램에 대한 주 헤더 파일입니다.
//

#pragma once

#ifndef __AFXWIN_H__
	#error "PCH에 대해 이 파일을 포함하기 전에 'stdafx.h'를 포함합니다."
#endif

#include "resource.h"		// 주 기호입니다.


// CWebcamProtectorApp:
// 이 클래스의 구현에 대해서는 WebcamProtector.cpp을 참조하십시오.
//

class CWebcamProtectorApp : public CWinApp
{
public:
	CWebcamProtectorApp();
	
	HANDLE m_handle;
	int m_myVersion[4];
	int m_newVersion[4];
	int m_execError;

	int m_winVersion[3];
	bool m_is64bit;

// 재정의입니다.
public:
	virtual BOOL InitInstance();

// 구현입니다.

	DECLARE_MESSAGE_MAP()
	virtual int ExitInstance();
};

extern CWebcamProtectorApp theApp;