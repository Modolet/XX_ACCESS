#include "ssdt.h"
#include "pch.h"
#include <aux_klib.h>

namespace SSDT {
//���Һ���
NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress) {
    NTSTATUS          status           = STATUS_SUCCESS;
    HANDLE            hFile            = NULL;
    HANDLE            hSection         = NULL;
    OBJECT_ATTRIBUTES objectAttributes = {0};
    IO_STATUS_BLOCK   iosb             = {0};
    PVOID             pBaseAddress     = NULL;
    SIZE_T            viewSize         = 0;

    // �� DLL �ļ�, ����ȡ�ļ����
    InitializeObjectAttributes(&objectAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttributes, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ����һ���ڶ���, �� PE �ṹ�е� SectionALignment ��С����ӳ���ļ�
    status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
    if (!NT_SUCCESS(status)) {
        ZwClose(hFile);
        return status;
    }

    // ӳ�䵽�ڴ�
    status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN,
                                PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        ZwClose(hSection);
        ZwClose(hFile);
        return status;
    }

    // ��������
    *phFile        = hFile;
    *phSection     = hSection;
    *ppBaseAddress = pBaseAddress;

    return status;
}

//ӳ���ļ�
LONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName) {
    LONG ulFunctionIndexAdd = 0; // Dos Header

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress; // NT Header

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew); // Export Table

    PIMAGE_EXPORT_DIRECTORY pExportTable =
        (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader +
                                  pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress); // �����Ƶĵ�����������
    ULONG ulNumberOfNames = pExportTable->NumberOfNames;

    // �����������Ƶ�ַ��
    PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
    PCHAR  lpName      = NULL;

    // ��ʼ����������
    for (ULONG i = 0; i < ulNumberOfNames; i++) {
        lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);

        // �ж��Ƿ���ҵĺ���
        if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName))) {
            // ��ȡ����������ַ
            USHORT uHint      = *(USHORT *)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
            ULONG  ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
            PVOID  lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);

            // ��ȡ SSDT ���� Index
#ifdef _WIN64
            ulFunctionIndexAdd = *(ULONG *)((PUCHAR)lpFuncAddr + 4);
#else
            ulFunctionIndexAdd = *(ULONG *)((PUCHAR)lpFuncAddr + 1);
#endif

            // DbgPrint("Function = %s, %d, %x\n", lpName, ulFunctionIndexAdd, lpFuncAddr);

            if (((int)ulFunctionIndexAdd > -1) && ((int)ulFunctionIndexAdd < 1000)) {
                break;
            }
        }
    }

    return ulFunctionIndexAdd;
}

//��ȡ��������Ӧ���
ULONG GetSSDTFunctionIndexAndAdd(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName) {
    ULONG ulFunctionIndexAdd = 0;
    NTSTATUS  status             = STATUS_SUCCESS;
    HANDLE    hFile              = NULL;
    HANDLE    hSection           = NULL;
    PVOID     pBaseAddress       = NULL;

    // �ڴ�ӳ���ļ�
    status = DllFileMap(ustrDllFileName, &hFile, &hSection, &pBaseAddress);
    if (!NT_SUCCESS(status)) {
        return ulFunctionIndexAdd;
    }

    // ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
    ulFunctionIndexAdd = GetIndexFromExportTable(pBaseAddress, pszFunctionName);

    // �ͷ�
    ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
    ZwClose(hSection);
    ZwClose(hFile);

    return ulFunctionIndexAdd;
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase() {
    PUCHAR                                  ntosBase = (PUCHAR)GetKernelBase(NULL);
    static PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT   = NULL;
    // Already found
    if (g_SSDT != NULL)
        return g_SSDT;

    if (!ntosBase)
        return NULL;

    PIMAGE_NT_HEADERS     pHdr      = RtlImageNtHeader(ntosBase);
    PIMAGE_SECTION_HEADER pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++) {
        // Non-paged, non-discardable, readable sections
        // Probably still not fool-proof enough...
        if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED && pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            !(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) && (*(PULONG)pSec->Name != 'TINI') &&
            (*(PULONG)pSec->Name != 'EGAP')) {
            PVOID pFound = NULL;

            // KiSystemServiceRepeat pattern
            UCHAR    pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
            NTSTATUS status    = XXSearchPattern(pattern, 0xCC, sizeof(pattern) - 1, ntosBase + pSec->VirtualAddress,
                                              pSec->Misc.VirtualSize, &pFound);
            if (NT_SUCCESS(status)) {
                g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
                // DPRINT( "BlackBone: %s: KeSystemServiceDescriptorTable = 0x%p\n", __FUNCTION__, g_SSDT );
                return g_SSDT;
            }
        }
    }

    return NULL;
}

PVOID GetSSDTEntry(IN ULONG index) {
    ULONG                            size  = 0;
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTBase();
    PVOID                            pBase = GetKernelBase(&size);

    if (pSSDT && pBase) {
        // Index range check
        if (index > pSSDT->NumberOfServices)
            return NULL;

        return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
    }

    return NULL;
}
}; // namespace SSDT