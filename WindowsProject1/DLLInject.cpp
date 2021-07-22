// DLLInject.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "DLLInject.h"
#include <windows.h>
#include "resource.h"
#include <TlHelp32.h>
#include <stdio.h>
#include <direct.h>
#define PROCESS_NAME "WeChat.exe"



INT_PTR CALLBACK DialogProc(_In_ HWND hwndDlg, _In_ UINT UMsg, _In_ WPARAM wParam, _In_ LPARAM IParam);
DWORD GetProcessPID(LPCSTR ProcessName);
VOID InjectDLL(LPVOID* VirtualAllocresult, HANDLE* CreateRemoteThreadresult);
VOID RemoveDLL(LPVOID* VirtualAllocresult, HANDLE* CreateRemoteThreadresult);




int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	DialogBox(hInstance, MAKEINTRESOURCE(MAIN_Window), NULL, &DialogProc); //啓動對話框
	return 0;
}


INT_PTR CALLBACK DialogProc(_In_ HWND hwndDlg, _In_  UINT UMsg, _In_  WPARAM wParam, _In_ LPARAM IParam) //對話框處理函數
{
	/*if (UMsg == WM_INITDIALOG) { //首次運行
		MessageBox(NULL,"first","windows",0);
	}*/
	LPVOID VAdd = NULL;
	HANDLE CRAdd = NULL;

	if (UMsg == WM_CLOSE) { //UMsg按鈕事件
		EndDialog(hwndDlg,NULL); //hwndDlg程序句柄
	}
	//所有界面上的按鈕事件都是走這個WM_COMMAND宏
	if (UMsg == WM_COMMAND) { 
		
		if (wParam == DLL_Inject) { //wParam 控件ID
			InjectDLL(&VAdd, &CRAdd);
			/*CHAR SuccessInfo[0x160] = { 0 };
			sprintf_s(SuccessInfo, "dll返回值,dllAddPoint is %X,InjectAddress is %X", VAdd, CRAdd);
			MessageBox(NULL, SuccessInfo, "Info", 0);*/
		}
		if (wParam == DLL_Uninstall) {
			CHAR SuccessInfo[0x160] = { 0 };
			/*sprintf_s(SuccessInfo, "dll進入值,dllAddPoint is %X,InjectAddress is %X", VAdd, CRAdd);
			MessageBox(NULL, SuccessInfo, "Info", 0);
			RemoveDLL(&VAdd, &CRAdd);*/
			
		}
	}

	return FALSE;
}

//1、獲取微信進程句柄
//通過進程名獲取pid，通過pid獲取進程句柄
DWORD GetProcessPID(LPCSTR ProcessName) { //LPCSTR Long Point Const STR  //LPSTR Long Point STR 
	//#include <TlHelp32.h>
	//獲取系統進程快照
	HANDLE ALLProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
	//快照中對比進程名稱獲得PID
	PROCESSENTRY32 Process = {};
	Process.dwSize = sizeof(PROCESSENTRY32);
	do {
		if (strcmp(ProcessName, Process.szExeFile) == 0) { //此處判斷相等，相等即返回0
			return Process.th32ProcessID; //返回進程PID
		}
	} while (Process32Next(ALLProcess, &Process));
	//對比PID獲取句柄->InjectDLL()

	//未找到句柄，返回0
	return 0;
}



//2、在微信内部申請内存存放dll路徑
VOID InjectDLL(LPVOID* VirtualAllocresult, HANDLE* CreateRemoteThreadresult) {
	//通過PID 獲取 微信句柄
	DWORD PID = GetProcessPID(PROCESS_NAME);
	if (PID == 0) {
		MessageBox(NULL, "未找到所需要的進程句柄，請查看程式是否啓動", "Error", 0);
		return;
	}
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS,FALSE,PID); //參數分別爲權限、是否繼承、進程PID //此處繼承需注意
	if (ProcessHandle == NULL) {
		MessageBox(NULL, "句柄開啓失敗，請檢查權限", "Error", 0);
		return;
	}
	//
	//CHAR pathStr[0x100] = {"C://dll.dll"};
	//CHAR pathStr[0x100] = {"E://CppWorkSpace//HookWeiXinLs1//WindowsProject2_wx1//Debug//WindowsProject2_wx1.dll"};
	//處理路徑,獲取當前路徑wechatdll.dll
	CHAR pathStr[0x100] = { 0 };
	char *buffer = NULL;
	if ((buffer = _getcwd(NULL, 0)) == NULL) {
		MessageBox(NULL, "Error", "Error", 0);
	}
	else {
		sprintf_s(pathStr, "%s\\wechatdll.dll", buffer);
	}
	
	//申請内存
	LPVOID dllAddPoint = VirtualAllocEx(ProcessHandle,NULL,sizeof(pathStr), MEM_COMMIT, PAGE_READWRITE);//參數分別是注入的進程句柄、分配的内存地址NULL為隨機、内存分配類型、内存頁保護狀態
	if (dllAddPoint == NULL) {
		MessageBox(NULL, "内存申請失敗,檢查dll路徑", "Error", 0);
		return;
	}
	
	

	//3、寫入dll路徑，通過遠程綫程執行函數去執行loadLibrary函數去加載路徑中的dll
	//寫入dll路徑到微信/需要注入的進程中
	if (WriteProcessMemory(ProcessHandle, dllAddPoint, pathStr, sizeof(pathStr), NULL) == 0) {
		MessageBox(NULL, "dll路徑寫入失敗", "Error", 0);
		return;
	}
	//LoadLibrary,加載dll
	HMODULE k32 = GetModuleHandle("kernel32.dll");
	FARPROC LoadAddress=GetProcAddress(k32,"LoadLibraryA");
	HANDLE Inject =CreateRemoteThread(ProcessHandle,NULL,0,(LPTHREAD_START_ROUTINE)LoadAddress, dllAddPoint,0,NULL); //目的進程的句柄，NULL表示創建的句柄不能被繼承，0表示默認大小，kernel32中LoadLibrary的地址(執行的函數)，插入的dll地址的指針(加載的參數)
	if (Inject == NULL) {
		MessageBox(NULL, "dll注入失敗", "Error", 0);
		return;
	}
	else {
		*CreateRemoteThreadresult = Inject;
		*VirtualAllocresult = dllAddPoint;
		CHAR SuccessInfo[0x100] = { 0 };
		sprintf_s(SuccessInfo, "dll注入成功,dllAddPoint is %X,InjectAddress is %X", dllAddPoint, Inject);
		MessageBox(NULL, SuccessInfo, "Info", 0);
		return;
	}
	
}



VOID RemoveDLL(LPVOID* VirtualAllocresult, HANDLE* CreateRemoteThreadresult) { //卸載功能處於不可用狀態
	CHAR SuccessInfo[0x100] = { 0 };
	sprintf_s(SuccessInfo, "dll加載中,dllAddPoint is %X,InjectAddress is %X", *VirtualAllocresult, *CreateRemoteThreadresult);
	MessageBox(NULL, SuccessInfo, "Info", 0);
	DWORD PID = GetProcessPID(PROCESS_NAME);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	//使用CE找到的想要卸载的DLL的地址
	CHAR DLLAddStr[0x100] = { 0 };
	sprintf_s(DLLAddStr, "地址%X卸載成功", *CreateRemoteThreadresult);
	//MessageBox(NULL, DLLAddStr, "Info", 0);

	LPVOID pRetAddress = *CreateRemoteThreadresult;

	HMODULE hModule = LoadLibrary("KERNEL32.DLL");

	//使用CE找到的FreeLibrary的地址是 
	LPTHREAD_START_ROUTINE lp_start_address = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lp_start_address, pRetAddress, 0, NULL);

	WaitForSingleObject(hThread, 2000);

	//CHAR pathStr[0x100] = {"C://dll.dll"};
	//CHAR pathStr[0x100] = {"E://CppWorkSpace//HookWeiXinLs1//WindowsProject2_wx1//Debug//WindowsProject2_wx1.dll"};
	//處理路徑,獲取當前路徑wechatdll.dll
	CHAR pathStr[0x100] = { 0 };
	char *buffer = NULL;
	if ((buffer = _getcwd(NULL, 0)) == NULL) {
		MessageBox(NULL, "Error", "Error", 0);
	}
	else {
		sprintf_s(pathStr, "%s\\wechatdll.dll", buffer);
	}
	if (VirtualFree(OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID), sizeof(pathStr), MEM_DECOMMIT)==0) {
		MessageBox(NULL, "VirtualFree Error", "Error", 0);
	}

	CloseHandle(hThread);
	CloseHandle(hProcess);

	MessageBox(NULL, DLLAddStr, "DLL卸載", 0);
}

