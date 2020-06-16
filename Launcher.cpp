// Launcher.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <string>
#include "multiopen.h"
#include <io.h>
#include <iostream>
#include <TlHelp32.h>
#include <atlconv.h>


DWORD FindPIDByPName(const wchar_t* process_name)
{
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hProcess, &pe32) == TRUE)
	{
		do
		{
			USES_CONVERSION;
			if (wcscmp(process_name, pe32.szExeFile) == 0)
			{
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hProcess, &pe32));
	}
	return 0;
}

bool OpenWeChat(const wchar_t* wechat_path, DWORD& process_id, HANDLE& process_handle, HANDLE& process_thread) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	PatchWeChat();
	if (!CreateProcess(NULL, (LPWSTR)wechat_path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return false;
	}
	process_handle = pi.hProcess;
	process_id = pi.dwProcessId;
	process_thread = pi.hThread;
	return true;
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
	DWORD process_id = FindPIDByPName(L"WeChat.exe");
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	HANDLE process_thread = NULL;
	//创建微信进程&获取微信进程句柄
	if (multi) {
		if (!OpenWeChat(wechat_path.c_str(), process_id, process_handle, process_thread)) {
			std::cout << -4;
			return -4;
		}
	}
	else if (!process_handle) {
		if (!OpenWeChat(wechat_path.c_str(), process_id, process_handle, process_thread)) {
			std::cout << -5;
			return -5;
		}
	}
	//注入DLL
	LPVOID alloc_address = VirtualAllocEx(process_handle, NULL, dll_path.length(), MEM_COMMIT, PAGE_READWRITE);
	if (!alloc_address) {
		std::cout << -7;
		return -7;
	}
	if(!WriteProcessMemory(process_handle, alloc_address, dll_path.c_str(), dll_path.length(), NULL))
	 {
		std::cout << -8;
		return -8;
	} 
	HMODULE kernel_handle = GetModuleHandle(L"Kernel32.dll");
	FARPROC func_handle = GetProcAddress(kernel_handle, "LoadLibraryA");
	if (!func_handle) {
		std::cout << -9;
		return -9;
	}
	if (!CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)func_handle, alloc_address, 0, NULL)) {
		std::cout << -10;
		return -10;
	}
	Sleep(500);
	ResumeThread(process_thread);
	std::cout << process_id;
	return process_id;
}