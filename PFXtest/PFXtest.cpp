#include "stdafx.h"
#include "resource.h"

#ifndef _MAX_NTFS_PATH
#define _MAX_NTFS_PATH   0x8000
#endif

TCHAR g_pBuf[_MAX_NTFS_PATH];

INT_PTR CALLBACK PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		SetFocus(GetDlgItem(hDlg, ID_PASSWEDIT));
		return (INT_PTR)FALSE;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			if (!GetDlgItemText(hDlg, ID_PASSWEDIT, g_pBuf, _MAX_NTFS_PATH)) g_pBuf[0] = _T('\0');
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

#ifdef NDEBUG //release build
int WINAPI WinMainCRTStartup(void)//no crt
#else
int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
#endif
{
	SecureZeroMemory(g_pBuf, sizeof(TCHAR)*_MAX_NTFS_PATH);

	HANDLE hFile = NULL;
	CRYPT_DATA_BLOB pfxPacket;
	pfxPacket.cbData =0;
	pfxPacket.pbData = NULL;

	OPENFILENAME ofn;
	SecureZeroMemory(&ofn, sizeof(ofn));

	int argc;	
	LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (NULL != szArglist)
	{
		if (argc > 1) ofn.lpstrFile = szArglist[1];
		else 
		{
			ofn.lStructSize = sizeof(ofn);
			ofn.lpstrTitle = _T("Open PFX file");
			ofn.lpstrFile = g_pBuf;
			ofn.nMaxFile = _MAX_NTFS_PATH;
			ofn.lpstrFile[0] = _T('\0');
			ofn.lpstrFilter = _T("PFX files\0*.pfx\0All files\0*.*\0");
			ofn.nFilterIndex = 1;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
			if (!GetOpenFileName(&ofn)) goto CLEANUP;
		}
	}
	else
	{
		MessageBox(HWND_DESKTOP, _T("Command line parsing failed"), _T("PFX Test"), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
		goto CLEANUP;
	}

	hFile = CreateFile(ofn.lpstrFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(HWND_DESKTOP, _T("Cannot open file"), _T("PFX Test"), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
		goto CLEANUP;
	}

	pfxPacket.cbData = GetFileSize(hFile, NULL);
	if (pfxPacket.cbData == 0)
	{
		MessageBox(HWND_DESKTOP, _T("PFX file is not valid"), _T("PFX Test"), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
		goto CLEANUP;
	}

	pfxPacket.pbData = (LPBYTE)CryptMemAlloc(pfxPacket.cbData);
	if (pfxPacket.pbData == NULL)
	{
		MessageBox(HWND_DESKTOP, _T("Out of memory"), _T("PFX Test"), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
		goto CLEANUP;
	}

	DWORD dwReadByte;
	if (!ReadFile(hFile, pfxPacket.pbData, pfxPacket.cbData, &dwReadByte, NULL) || (dwReadByte != pfxPacket.cbData))
	{
		MessageBox(HWND_DESKTOP, _T("Error reading PFX file"), _T("PFX Test"), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
		goto CLEANUP;
	}

	if (!PFXIsPFXBlob(&pfxPacket))
	{
		MessageBox(HWND_DESKTOP, _T("File is not valid PFX packet"), _T("PFX Test"), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
		goto CLEANUP;
	}

ASKPASSWORD:
	if (DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_PASSWDIALOG), HWND_DESKTOP, (DLGPROC)PasswordDialogProc) != IDOK) goto CLEANUP;

	if (!PFXVerifyPassword(&pfxPacket, g_pBuf, 0))
	{
		if (MessageBox(HWND_DESKTOP, _T("PFX password is not correct\n\nTry again?"), _T("PFX Test"), MB_YESNO | MB_ICONERROR) == IDYES) goto ASKPASSWORD;
		goto CLEANUP;
	}
	MessageBox(HWND_DESKTOP, TEXT("Password verified"), _T("PFX Test"), MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);

CLEANUP:
	if (hFile) CloseHandle(hFile);
	if (pfxPacket.pbData) CryptMemFree(pfxPacket.pbData);
	if (szArglist) LocalFree(szArglist);

#ifdef NDEBUG
	ExitProcess(0);
#endif
	return 0;
}
