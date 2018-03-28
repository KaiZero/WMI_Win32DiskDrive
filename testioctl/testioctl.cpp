// testioctl.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"
#include "testioctl.h"
//#include <conio.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include <comutil.h>
#include <Wscapi.h>
#include <intrin.h>
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "iphlpapi.lib" )

// 유일한 응용 프로그램 개체입니다.
CString GetDriveDeviceInfo(CString _csLogical);
CWinApp theApp;
CString GetMACAddres();
using namespace std;
void GetPhysicalDriveSerialNumber(UINT nDriveNumber IN, CString& strSerialNumber OUT);
CString GetDeviceNameFromLogical(CString _csLogical);
bool GetAntiVirusProduct(CString& _productName);
bool IsWindowsVersion(USHORT wMajorVersion, USHORT wMinorVersion, USHORT wServicePackMajor, int comparisonType);
bool IsWindowsVistaOrGreater();
int main()
{
    int nRetCode = 0;

    HMODULE hModule = ::GetModuleHandle(nullptr);

    if (hModule != nullptr)
    {
        // MFC를 초기화합니다. 초기화하지 못한 경우 오류를 인쇄합니다.
        if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
        {
            // TODO: 오류 코드를 필요에 따라 수정합니다.
            wprintf(L"심각한 오류: MFC를 초기화하지 못했습니다.\n");
            nRetCode = 1;
        }
        else
        {
            // TODO: 응용 프로그램의 동작은 여기에서 코딩합니다.
        }
    }
    else
    {
        // TODO: 오류 코드를 필요에 따라 수정합니다.
        wprintf(L"심각한 오류: GetModuleHandle 실패\n");
        nRetCode = 1;
    }
	
	char a = getchar();
	CString local(a);
	CString cs = GetDriveDeviceInfo(local);
	GetDeviceNameFromLogical(L"D");
	//wprintf(cs);
	getchar();
	getchar();
	
    return nRetCode;
}


CString GetDriveDeviceInfo(CString _csLogical)
{
	CString csReturn;

	CString csLogical;
	csLogical.Format(_T("\\\\.\\\\%s:"), _csLogical);
	CString csPhysical;

	// Logical Drive 문자로부터 Physical 드라이브 정보를 얻기 위함
	HANDLE hr = CreateFile(csLogical, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hr == INVALID_HANDLE_VALUE) return CString("");
	// 에러 체크
	STORAGE_DEVICE_NUMBER sd;
	DWORD dwRet;

	BOOL bRet = ::DeviceIoControl(hr, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sd, sizeof(STORAGE_DEVICE_NUMBER), &dwRet, NULL);
	if (bRet == false)
	{
		return CString("");
	}
	// 체크

	// Physical 드라이브 순서 획득 및 쿼리에 필요한 이름 조합 
	
	csPhysical.Format(_T("\\\\\\\\.\\\\PhysicalDrive%d"), sd.DeviceNumber);
	
	CloseHandle(hr);

	IWbemLocator* pWmiLocator;
	IWbemServices* pWmiServices;
	IEnumWbemClassObject* pEnumerator = NULL;

	// CoInitializeEx
	CoInitializeEx(0, COINIT_MULTITHREADED);
	HRESULT hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE
		, NULL, EOAC_NONE, NULL);

	if (FAILED(hres)) return false;

	// Initialize locator

	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER | CLSCTX_NO_FAILURE_LOG | CLSCTX_NO_CODE_DOWNLOAD, IID_IWbemLocator, (LPVOID*)&pWmiLocator);
	if (FAILED(hres)) return false;
	

	if (FAILED(hres)) return false;

	hres = pWmiLocator->ConnectServer(_bstr_t(L"\\\\.\\root\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pWmiServices);
	
	if (FAILED(hres)) return false;

	hres = CoSetProxyBlanket(pWmiServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
		NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

	if (FAILED(hres)) return false;
	CString csQuery;
	
	// Wmi쿼리
	csQuery.Format(L"Select Model, Caption, InterfaceType from Win32_DiskDrive WHERE Name=\"%s\"", csPhysical);
	hres = pWmiServices->ExecQuery(L"WQL", _bstr_t(csQuery),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	ULONG uReturn = 0;
	HRESULT result;
	IWbemClassObject *pclsObj = NULL;

	while (pEnumerator && hres == WBEM_S_NO_ERROR)
	{
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (FAILED(hres) || uReturn == 0) {
			break;
		}

		VARIANT vtProp;
		result = pclsObj->Get(L"Model", 0, &vtProp, 0, 0);
		csReturn = CString(vtProp.bstrVal);
		VARIANT vtProp2;
		result = pclsObj->Get(L"Caption", 0, &vtProp2, 0, 0);
		VARIANT vtProp3;
		result = pclsObj->Get(L"InterfaceType", 0, &vtProp, 0, 0);
		
		CString csType;
		csType = vtProp.bstrVal;
		int  c = 0;
		wprintf(csReturn);
		wprintf(L"\n");
		wprintf(csType);
		VariantClear(&vtProp);
		pclsObj->Release();
	}
	pWmiLocator->Release();
	return csReturn;
}

CString GetMACAddres()
{
	char szMac[256];
	DWORD size = sizeof(PIP_ADAPTER_INFO);

	PIP_ADAPTER_INFO info;
	memset(&info, 0, sizeof(PIP_ADAPTER_INFO));

	int result = GetAdaptersInfo(info, &size);        // 첫번째 랜카드 MAC address 가져오기
	if (result == ERROR_BUFFER_OVERFLOW)    // GetAdaptersInfo가 메모리가 부족하면 재 할당하고 재호출
	{
		info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(info, &size);
	}

	sprintf(szMac, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X",
		info->Address[0], info->Address[1], info->Address[2], info->Address[3], info->Address[4], info->Address[5]);
	return CString(szMac);
}

CString GetDeviceNameFromLogical(CString _csLogical) // ex : "C", "D", "E"
{
	CString csLogical;
	csLogical.Format(_T("\\\\.\\\\%s:"), _csLogical);
	CString csPhysical;
	HANDLE hr = CreateFile(csLogical, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hr == INVALID_HANDLE_VALUE) return CString("");
	// 에러 체크
	STORAGE_DEVICE_NUMBER sd;
	DWORD dwRet;

	BOOL bRet = ::DeviceIoControl(hr, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sd, sizeof(STORAGE_DEVICE_NUMBER), &dwRet, NULL);
	if (bRet == false)
	{
		return CString("");
	}
	// 체크
	csPhysical.Format(_T("\\\\.\\PhysicalDrive%d"), sd.DeviceNumber);
	CloseHandle(hr);

	HANDLE hIoCtrl = ::CreateFile(csPhysical, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL);

	if (hIoCtrl == INVALID_HANDLE_VALUE)
	{
		DWORD dErr = GetLastError();
	}
	STORAGE_PROPERTY_QUERY sQuery;
	sQuery.PropertyId = StorageDeviceProperty;
	sQuery.QueryType = PropertyStandardQuery;
	sQuery.AdditionalParameters[0] = NULL;
	BYTE pcbData[4096];

	bRet = ::DeviceIoControl(hIoCtrl, IOCTL_STORAGE_QUERY_PROPERTY, &sQuery, sizeof(STORAGE_PROPERTY_QUERY), pcbData, 4096, &dwRet, NULL);

	if (bRet == false)
	{
		DWORD dErr = GetLastError();
	}
	STORAGE_DEVICE_DESCRIPTOR* pDescriptor = NULL;
	pDescriptor = (STORAGE_DEVICE_DESCRIPTOR*)pcbData;

	if (pDescriptor->ProductIdOffset)
	{
		char* model = (char*)pDescriptor + pDescriptor->ProductIdOffset;
		CStringA cs(model);
		CString csT(cs);
		csPhysical.Format(_T("%s"), csT);
	}

	CloseHandle(hIoCtrl);

	return csPhysical;
}

void GetPhysicalDriveSerialNumber(UINT nDriveNumber IN, CString& strSerialNumber OUT)
{
	//HRESULT hr = ::CoInitializeEx(0, COINIT_MULTITHREADED);

	strSerialNumber.Empty();

	CString strDrivePath;
	strDrivePath.Format(_T("\\\\.\\PhysicalDrive%u"), nDriveNumber);

	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa393617(v=vs.85).aspx
	HRESULT hr = ::CoInitializeSecurity(
		NULL,                        
		-1,                          
		NULL,                        
		NULL,                        
		RPC_C_AUTHN_LEVEL_DEFAULT,   
		RPC_C_IMP_LEVEL_IMPERSONATE, 
		NULL,                        
		EOAC_NONE,                   
		NULL);                       

	ATLENSURE_SUCCEEDED(hr);

	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa389749(v=vs.85).aspx

	CComPtr<IWbemLocator> pIWbemLocator;
	hr = ::CoCreateInstance(CLSID_WbemLocator, 0,
		CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pIWbemLocator);

	ATLENSURE_SUCCEEDED(hr);

	CComPtr<IWbemServices> pIWbemServices;
	hr = pIWbemLocator->ConnectServer(L"ROOT\\CIMV2",
		NULL, NULL, 0, NULL, 0, 0, &pIWbemServices);

	ATLENSURE_SUCCEEDED(hr);

	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa393619(v=vs.85).aspx
	hr = ::CoSetProxyBlanket(
		pIWbemServices,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE);

	ATLENSURE_SUCCEEDED(hr);

	const BSTR szQueryLanguage = L"WQL";
	const BSTR szQuery = L"SELECT Tag, Caption FROM CIM_PhysicalMedia";
	CComPtr<IEnumWbemClassObject> pIEnumWbemClassObject;
	hr = pIWbemServices->ExecQuery(
		szQueryLanguage,                                       // Query language
		szQuery,                                               // Query
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,   // Flags
		NULL,                                                  // Context
		&pIEnumWbemClassObject);                               // Enumerator

	ATLENSURE_SUCCEEDED(hr);

	ULONG uReturn = 0;
	while (pIEnumWbemClassObject)
	{
		CComPtr<IWbemClassObject> pIWbemClassObject;
		hr = pIEnumWbemClassObject->Next(WBEM_INFINITE, 1, &pIWbemClassObject, &uReturn);
		if (0 == uReturn || FAILED(hr))
			break;

		VARIANT vtTag;           
		VARIANT vtSerialNumber;  

		hr = pIWbemClassObject->Get(L"Tag", 0, &vtTag, NULL, NULL);
		ATLENSURE_SUCCEEDED(hr);

		CString strTag(vtTag.bstrVal);
		if (!strTag.CompareNoCase(strDrivePath)) // physical drive found
		{
			hr = pIWbemClassObject->Get(L"Caption", 0, &vtSerialNumber, NULL, NULL);
			ATLENSURE_SUCCEEDED(hr);
			strSerialNumber = vtSerialNumber.bstrVal; // get the serial number
			break;
		}
	}
}

bool IsWindowsVersion(USHORT wMajorVersion, USHORT wMinorVersion, USHORT wServicePackMajor, int comparisonType)
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0,{ 0 }, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(VerSetConditionMask(
			0, VER_MAJORVERSION, comparisonType),
			VER_MINORVERSION, comparisonType),
		VER_SERVICEPACKMAJOR, comparisonType);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != false;
}


bool IsWindowsVistaOrGreater() {
	// 0x0600 == vista
	return IsWindowsVersion(HIBYTE(0x0600), LOBYTE(0x0600), 0, VER_GREATER_EQUAL);
}

bool GetAntiVirusProduct(CString& _productName)
{
	IWbemLocator* pWmiLocator;
	IWbemServices* pWmiServices;
	IEnumWbemClassObject* pEnumerator = NULL;

	// CoInitializeEx
	CoInitializeEx(0, COINIT_MULTITHREADED);
	HRESULT hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE
		, NULL, EOAC_NONE, NULL);

	if (FAILED(hres)) return false;


	// Initialize locator

	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER | CLSCTX_NO_FAILURE_LOG | CLSCTX_NO_CODE_DOWNLOAD, IID_IWbemLocator, (LPVOID*)&pWmiLocator);

	if (FAILED(hres)) return false;

	if (IsWindowsVistaOrGreater())
	{
		hres = pWmiLocator->ConnectServer(_bstr_t(L"\\\\.\\root\\SecurityCenter2"), NULL, NULL, 0, NULL, 0, 0, &pWmiServices);
	}
	else
	{
		// vista 이전 pWmiLocator->ConnectServer(_bstr_t(L"\\\\.\\root\\SecurityCenter"), NULL, NULL, 0, NULL, 0, 0, &pWmiServices);
		hres = pWmiLocator->ConnectServer(_bstr_t(L"\\\\.\\root\\SecurityCenter"), NULL, NULL, 0, NULL, 0, 0, &pWmiServices);
	}

	if (FAILED(hres)) return false;

	hres = CoSetProxyBlanket(pWmiServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
		NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

	if (FAILED(hres)) return false;

	// 쿼리
	if (IsWindowsVistaOrGreater())
	{
		hres = pWmiServices->ExecQuery(L"WQL", _bstr_t(L"Select displayName, productState from AntiVirusProduct"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	}
	else
	{
		hres = pWmiServices->ExecQuery(L"WQL", _bstr_t(L"Select displayName, onAccessScanningEnabled from AntiVirusProduct"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	}


	if (FAILED(hres)) return false;

	// 데이터 얻기

	ULONG uReturn = 0;
	HRESULT result;

	IWbemClassObject *pclsObj = NULL;
	WCHAR pfieldname[1024] = { 0, };
	while (pEnumerator && hres == WBEM_S_NO_ERROR)
	{
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (FAILED(hres) || uReturn == 0) {
			break;
		}

		VARIANT vtProp;
		result = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);

		//if (StrCmpC(L"Windows Defender", vtProp.bstrVal) == 0) continue; // 기본인 Defender는 패스
		if (FAILED(result)) {
			pclsObj->Release();
			continue;
		}

		//////////////////////////////////////////////////////////////////////////
		// 비스타 이후
		if (IsWindowsVistaOrGreater())
		{
			VARIANT vtProductState;
			result = pclsObj->Get(L"productState", 0, &vtProductState, 0, 0);
			int productState = vtProductState.intVal;
			WSC_SECURITY_PROVIDER  securityProvider = (WSC_SECURITY_PROVIDER)((productState & 0xFF0000) >> 16);
			int scannerSetting = (productState & 0xFF00) >> 8; // 1 알 수 없는 상태 16 작동중
			int updateSetting = productState & 0xFF; // 0 최신버전 16 구버전
		}
		//////////////////////////////////////////////////////////////////////////
		// 비스타 이전
		else
		{
			VARIANT vtScanningEnable;
			result = pclsObj->Get(L"onAccessScanningEnabled", 0, &vtScanningEnable, 0, 0);
			if (vtScanningEnable.boolVal)
				wprintf(L"True \n");
			else
				wprintf(L"false \n");
		}

		_productName = CString(vtProp.bstrVal);
		wprintf(_productName);
		wprintf(L"\n");
		VariantClear(&vtProp);
		pclsObj->Release();
	}

	pWmiServices->Release();
	pWmiLocator->Release();
	pEnumerator->Release();

	return true;
}