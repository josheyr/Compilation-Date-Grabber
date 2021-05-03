// josh's dps grabber.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <iostream>
#include <stdio.h>      /* puts */
#include <time.h>
#include <ctime>
#include <string.h>
#include <sstream>

std::wstring openfilename(WCHAR* filter, HWND owner = NULL) {
	OPENFILENAME ofn;
	WCHAR fileName[MAX_PATH] = L"";
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = owner;
	ofn.lpstrFilter = filter;
	ofn.lpstrFile = fileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	ofn.lpstrDefExt = L"";
	std::wstring fileNameStr;
	if (GetOpenFileName(&ofn))
		fileNameStr = fileName;
	return fileNameStr;
}

bool valid_tm(const std::tm& tm)
{
	auto cpy = tm;
	const auto as_time_t = std::mktime(std::addressof(cpy));
	if (as_time_t) {
		if (std::addressof(as_time_t)) {
			if (std::localtime(std::addressof(as_time_t))) {
				try {
					cpy = *std::localtime(std::addressof(as_time_t));

					return tm.tm_mday == cpy.tm_mday && // valid day
						tm.tm_mon == cpy.tm_mon && // valid month
						tm.tm_year == cpy.tm_year && // valid year
						tm.tm_wday == cpy.tm_wday; // valid day of week
				}
				catch (EXCEPINFO) {

				}
			}
		}
	}

	return false;
}

std::string getCompileDateString(std::string filePath) {
	const int MAX_FILEPATH = 255;
	char fileName[MAX_FILEPATH] = { 0 };

	memcpy_s(&fileName, MAX_FILEPATH, filePath.c_str(), MAX_FILEPATH);

	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;

	file = CreateFileA(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) return 0;

	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

	if (fileData) {

		// read file bytes to memory
		if (ReadFile(file, fileData, fileSize, &bytesRead, NULL)) {

			// IMAGE_DOS_HEADER
			dosHeader = (PIMAGE_DOS_HEADER)fileData;
			imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);

			time_t epch;
			try {
				epch = imageNTHeaders->FileHeader.TimeDateStamp;
			}
			catch (EXCEPINFO) {
				return "none";
			}

			char buffer2[32];

			try {
				std::tm* ptm = std::localtime(&epch);
				if (ptm->tm_hour >= 1)
					ptm->tm_hour -= 1;
				else if (ptm->tm_hour == 0) {
					ptm->tm_mday -= 1;
					ptm->tm_hour += 23;
				}
				else {

				}

				if (valid_tm(*ptm)) {
					std::strftime(buffer2, 32, "%Y/%m/%d:%H:%M:%S", ptm);

					std::stringstream ss;
					ss << buffer2;

					std::cout << "found..." << std::endl;
					return ss.str();
				}
			}
			catch (EXCEPINFO) {
			}
		}
	}

	return "none";
}

int main(int argc, char* argv[]) {

	const int MAX_FILEPATH = 255;
	char fileName[MAX_FILEPATH] = { 0 };
	std::wstring ws = openfilename((WCHAR*)L"Executables (*.exe)\0*.exe\0");
	std::string s(ws.begin(), ws.end());	
	
	std::cout << getCompileDateString(s);

	getchar();

	return 0;
}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
