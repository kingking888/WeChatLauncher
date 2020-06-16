// Launcher.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <string>
#include "multiopen.h"
#include <io.h>
#include <iostream>
#include <TlHelp32.h>
#include <atlconv.h>

typedef struct
{
	HWND hWnd;
	DWORD dwPid;
}WNDINFO;

char* wstring2string(std::wstring wstr)
{
	char* str;
	int wstr_len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
	str = (char*)malloc((wstr_len + 1) * sizeof(char));
	if (str != 0) {
		memset(str, 0, sizeof(char) * (wstr_len + 1));
		WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, str, wstr_len, NULL, NULL);
	}
	return str;
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	WNDINFO* pInfo = (WNDINFO*)lParam;
	DWORD dwProcessId = 0;
	GetWindowThreadProcessId(hWnd, &dwProcessId);
	if (dwProcessId == pInfo->dwPid)
	{
		wchar_t title_buffer[100] = { 0 };
		wchar_t class_buffer[100] = { 0 };
		GetWindowText(hWnd, title_buffer, 100);
		RealGetWindowClass(hWnd, class_buffer, 100);
		std::wstring title = title_buffer;
		std::wstring classname = class_buffer;
		if (title == L"登录" and classname == L"WeChatLoginWndForPC") {
			pInfo->hWnd = hWnd;
			return TRUE;
		}
	}
	return TRUE;
}

HWND GetHwndByProcessId(DWORD dwProcessId)
{
	WNDINFO info = { 0 };
	info.hWnd = NULL;
	info.dwPid = dwProcessId;
	EnumWindows(EnumWindowsProc, (LPARAM)&info);
	return info.hWnd;
}

DWORD FindPIDByPName(const char* process_name)
{
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hProcess, &pe32) == TRUE)
	{
		do
		{
			USES_CONVERSION;
			if (strcmp(process_name, wstring2string(pe32.szExeFile)) == 0)
			{
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hProcess, &pe32));
	}
	return 0;
}

int main(int argc, char* argv[])
{
	bool multi = false;
	char* current_path = argv[0];
	(strrchr(current_path, '\\'))[1] = 0;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "multi")) {
			multi = true;
			break;
		}
	}
    HKEY hKey;
    std::string dll_path;
    std::wstring wechat_path;
    LPCTSTR data_set = (LPCTSTR)L"Software\\Tencent\\WeChat";
	//查询微信注册表信息
	if (!::RegOpenKeyEx(HKEY_CURRENT_USER, data_set, 0, KEY_READ, &hKey)) {
		DWORD version;
		DWORD version_size = sizeof(DWORD);
		DWORD version_type = REG_DWORD;
		if (::RegQueryValueEx(hKey, (LPCTSTR)L"Version", 0, &version_type, (LPBYTE)&version, &version_size))
		{
			std::cout << -1;
			return -1;
		}
		dll_path = current_path;
		dll_path.append(std::to_string(version));
		dll_path.append("\\WeChatSpy.dll");
		if (_access(dll_path.c_str(), 0) == -1) {
			std::cout << -2;
			return -2;
		}
        wchar_t path[256];
        DWORD path_size = sizeof(path);
        DWORD path_type = REG_SZ;
        if (::RegQueryValueEx(hKey, (LPCTSTR)L"InstallPath", 0, &path_type, (LPBYTE)&path, &path_size))
        {
			std::cout << -3;
			return -3;
        }
        wechat_path = path;
        wechat_path.append(L"\\WeChat.exe");
    }
	DWORD process_id;
	HANDLE wechat_process_handle;
	BOOL ret;
	//创建微信进程&获取微信进程句柄
	if (multi) {
		ret = MultiOpenWeChat((wchar_t*)wechat_path.c_str(), process_id, wechat_process_handle);
		if (ret) {
			std::cout << -4;
			return -4;
		}
		HWND login_window_handle;
		for (int i = 0; i < 100; i++) {
			login_window_handle = GetHwndByProcessId(process_id);
			if (login_window_handle) {
				break;
			}
			else {
				Sleep(100);
			}
		}
		if (!login_window_handle) {
			std::cout << -6;
			return -6;
		}
		CloseHandle(login_window_handle);
	}
	else {
		process_id = FindPIDByPName("WeChat.exe");
		if (process_id) {
			wechat_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
		}
		else {
			STARTUPINFO  si;
			PROCESS_INFORMATION pi;
			ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);
			ZeroMemory(&pi, sizeof(pi));
			ret = CreateProcess(NULL, (LPWSTR)wechat_path.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
			if (!ret) {
				std::cout << -5;
				return -5;
			}
			CloseHandle(pi.hThread);
			process_id = pi.dwProcessId;
			wechat_process_handle = pi.hProcess;
			HWND login_window_handle;
			for (int i = 0; i < 100; i++) {
				login_window_handle = GetHwndByProcessId(process_id);
				if (login_window_handle) {
					break;
				}
				else {
					Sleep(100);
				}
			}
			if (!login_window_handle) {
				std::cout << -6;
				return -6;
			}
			CloseHandle(login_window_handle);
		}
	}
	//注入DLL
	LPVOID alloc_address = VirtualAllocEx(wechat_process_handle, NULL, dll_path.length(), MEM_COMMIT, PAGE_READWRITE);
	if (!alloc_address) {
		std::cout << -7;
		return -7;
	}
	ret = WriteProcessMemory(wechat_process_handle, alloc_address, dll_path.c_str(), dll_path.length(), NULL);
	if (!ret) {
		std::cout << -8;
		return -8;
	} 
	HMODULE kernel_handle = GetModuleHandle(L"Kernel32.dll");
	FARPROC func_handle = GetProcAddress(kernel_handle, "LoadLibraryA");
	if (!func_handle) {
		std::cout << -9;
		return -9;
	}
	HANDLE thread_handle = CreateRemoteThread(wechat_process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)func_handle, alloc_address, 0, NULL);
	if (!thread_handle) {
		std::cout << -10;
		return -10;
	}
	std::cout << process_id;
	return process_id;
}