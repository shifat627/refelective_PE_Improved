#include<stdio.h>
#include<windows.h>
#include<assert.h>
#include<winternl.h>


/*
 typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
  } PEB,*PPEB;

  typedef struct _TEB {
    PVOID Reserved1[12];
    PPEB ProcessEnvironmentBlock;
    PVOID Reserved2[399];
    BYTE Reserved3[1952];
    PVOID TlsSlots[64];
    BYTE Reserved4[8];
    PVOID Reserved5[26];
    PVOID ReservedForOle;
    PVOID Reserved6[4];
    PVOID TlsExpansionSlots;
  } TEB;

  typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
  } LIST_ENTRY,*PLIST_ENTRY,*RESTRICTED_POINTER PRLIST_ENTRY;


    typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
  } PEB_LDR_DATA,*PPEB_LDR_DATA;
*/

#ifdef _WIN64
#define BASE_REL_TYPE 10
#else
#define BASE_REL_TYPE 3
#endif

typedef struct _relocation_entry_
{
    WORD offset:12;WORD type:4;
}TYPE_ENTRY , *LPTYPE_ENTRY;

typedef struct CUSTOM_TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} MYTEB, * PMYTEB;


typedef struct _LDR_MODULE {



  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
  PVOID                   BaseAddress;
  PVOID                   EntryPoint;
  ULONG                   SizeOfImage;
  UNICODE_STRING          FullDllName;
  UNICODE_STRING          BaseDllName;
  ULONG                   Flags;
  SHORT                   LoadCount;
  SHORT                   TlsIndex;
  LIST_ENTRY              HashTableEntry;
  ULONG                   TimeDateStamp;

} LDR_MODULE, *PLDR_MODULE;

LPVOID GetKernelAndProc(LPVOID * dll){
	LPVOID tempDll;
	char fname[16];
	
	*(PDWORD)fname = 0x50746547; //GetP
	*(PDWORD)(&fname[4]) = 0x41636f72; //rocA
	*(PDWORD)(&fname[8]) = 0x65726464; //ddre
	*(PWORD)(&fname[12]) = 0x7373; //ss
	*(PWORD)(&fname[14]) = 0x7373 ^ 0x7373; //NULL
	
	PMYTEB teb = (PMYTEB)NtCurrentTeb();
	* dll = tempDll =((PLDR_MODULE)(  (LPVOID) teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink - FIELD_OFFSET(LDR_MODULE,InMemoryOrderModuleList) ))->BaseAddress;
	
	
	
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(tempDll + ((PIMAGE_DOS_HEADER)tempDll)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY) (tempDll + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	//printf("%s\n",fname);
	
	PDWORD AddressOFunc = (PDWORD) (tempDll + exp->AddressOfFunctions);
	PDWORD AddressOfNames = (PDWORD) (tempDll + exp->AddressOfNames);
	PWORD AddressOfOrd = (PWORD) (tempDll + exp->AddressOfNameOrdinals); 
	
	
	int i;
	i ^= i;
	
	for (;i<exp->NumberOfNames;i++){
		
		char * name = (char *) (tempDll + AddressOfNames[i]);
		//printf("%s\n",name);
		
		BYTE found = 1;
		char * destName = fname;
		while(*name && *destName){
			
			if (*name != *destName){
				found = 1 ^ 1;
				break;
			}
			
			
			destName++;
			name++;
		}
		
		if (found){
			return tempDll + AddressOFunc[AddressOfOrd[i]];
		}
	}
	return NULL;
}




LPVOID CopyData(LPVOID rawData){
	
	LPVOID Image,dll,GetProcAddr;
	//LPVOID VirtualAllocAddr,WriteProcessMemoryAddr;
	char fname [24];
	
	LPVOID WINAPI (* VirtualAllocFunc) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	WINBOOL WINAPI (*WriteProcessMemoryFunc )(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
	
	GetProcAddr = GetKernelAndProc(&dll);
	
	*(PDWORD)fname = 0x74726956 ; //Virt
	*(PDWORD)&fname[4] = 0x416c6175 ; //ualA
	*(PDWORD)&fname[8] = 0x636f6c6c ; //lloc
	*(PBYTE)&fname[12]=1^1;
	
	//printf("%s\n",fname);
	
	VirtualAllocFunc = (* (LPVOID (*) (LPVOID , char *))GetProcAddr)(dll,fname);
	
	
	*(PDWORD) fname=0x74697257;
	*(PDWORD) &fname[4]=0x6f725065;
	*(PDWORD) &fname[8]=0x73736563;
	*(PDWORD) &fname[12]=0x6f6d654d;
	*(PWORD) &fname[16]=0x7972;
	*(PBYTE)&fname[18]=1^1;
	
	//printf("%s\n",fname);
	
	WriteProcessMemoryFunc = (* (LPVOID (*) (LPVOID , char *))GetProcAddr)(dll,fname);
	
	
	
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)rawData;
	
	if(dos->e_magic != 0x5a4d){
		return NULL;
	}
	
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS) (rawData + dos->e_lfanew);
	if(nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC){
		return NULL;
	}
	
	PIMAGE_SECTION_HEADER sections =(PIMAGE_SECTION_HEADER) (nt+1);
	
	
	Image = (* VirtualAllocFunc)((LPVOID)nt->OptionalHeader.ImageBase,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	if(!Image){
		Image = (*VirtualAllocFunc)(NULL,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
		if(!Image){
			return NULL;
		}
	}
	
	
	(*WriteProcessMemoryFunc)((HANDLE)-1,Image,rawData,nt->OptionalHeader.SizeOfHeaders,NULL);
	
	
	int i=0;
	for(;i<nt->FileHeader.NumberOfSections;i++){
		//printf("%s\n",sections[i].Name);
		(*WriteProcessMemoryFunc)((HANDLE)-1,Image + sections[i].VirtualAddress,rawData + sections[i].PointerToRawData,sections[i].SizeOfRawData,NULL);
	}
	
	return Image;
}



LPVOID SetupPE(LPVOID Image){
	
	
	LPVOID dll,GetProcAddr,LoadLib;
	char fname [24];
	
	*(PDWORD) fname=0x64616f4c;
	*(PDWORD) &fname[4]=0x7262694c;
	*(PDWORD) &fname[8]=0x41797261;
	*(PBYTE)  &fname[12]=0;
	
	
	
	
	GetProcAddr = GetKernelAndProc(&dll);
	
	LoadLib = (* (LPVOID (*) (LPVOID , char *))GetProcAddr)(dll,fname);
	
	
	
	
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);
	
	if((LPVOID)nt->OptionalHeader.ImageBase != Image){
		
		UINT_PTR delta = (UINT_PTR)Image - (UINT_PTR)nt->OptionalHeader.ImageBase;
		
		if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress){
			PIMAGE_BASE_RELOCATION rloc = Image + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
			
			while(rloc->VirtualAddress){
				int totalEntry = (rloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
				
				LPVOID startAddr = (LPVOID)(Image + rloc->VirtualAddress);
				
				LPTYPE_ENTRY indexes = (LPTYPE_ENTRY)((LPVOID)rloc+sizeof(IMAGE_BASE_RELOCATION));
				
				int i=0;
				for(;i<totalEntry;i++){
					if(indexes->type == BASE_REL_TYPE){
						UINT_PTR * Op = (UINT_PTR * )(startAddr + indexes->offset);
						*Op += delta;
					}
					
					indexes++;
				}
				
				rloc = (LPVOID)rloc + rloc->SizeOfBlock;
			}
			
		}
		
		
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	//LoadIng Import
	if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress){
		
		PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)(Image+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		
		while(importDir->Name){
			
			char *ImportdllName = Image + importDir->Name;
			//printf("%s\n",ImportdllName);
			LPVOID ImportDll = (* (LPVOID (*) (char *))LoadLib)(ImportdllName);
			PIMAGE_THUNK_DATA orig,ft;
			orig =(PIMAGE_THUNK_DATA) (Image + importDir->OriginalFirstThunk);
			ft = (PIMAGE_THUNK_DATA) (Image + importDir->FirstThunk);
			
			if(!importDir->OriginalFirstThunk)
			orig=ft;
			
			while(orig->u1.AddressOfData){
				if(orig->u1.AddressOfData & IMAGE_ORDINAL_FLAG){
					*(UINT_PTR *)ft=(UINT_PTR)(* (LPVOID (*) (LPVOID , LPSTR))GetProcAddr)(ImportDll,(LPSTR)IMAGE_ORDINAL(orig->u1.Ordinal));
				}
				else{
					PIMAGE_IMPORT_BY_NAME ImportFuncName =(PIMAGE_IMPORT_BY_NAME) (Image + orig->u1.AddressOfData);
					//printf("%s\n",ImportFuncName->Name);
					*(UINT_PTR *)ft=(UINT_PTR)(* (LPVOID (*) (LPVOID , char *))GetProcAddr)(ImportDll,ImportFuncName->Name);
				}
				ft++;
				orig++;
			}
			importDir++;
		}
	}
	

	//Delayed Import

	if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress){
		
		PIMAGE_DELAYLOAD_DESCRIPTOR importDir = (PIMAGE_DELAYLOAD_DESCRIPTOR)(Image+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
		
		while(importDir->DllNameRVA){
			
			char *ImportdllName = Image + importDir->DllNameRVA;
			//printf("%s\n",ImportdllName);
			LPVOID ImportDll = (* (LPVOID (*) (char *))LoadLib)(ImportdllName);
			PIMAGE_THUNK_DATA orig,ft;
			orig =(PIMAGE_THUNK_DATA) (Image + importDir->ImportNameTableRVA);
			ft = (PIMAGE_THUNK_DATA) (Image + importDir->ImportAddressTableRVA);

			if (!importDir->ImportNameTableRVA)
				orig = ft;

			while (orig->u1.AddressOfData)
			{
				if (orig->u1.AddressOfData & IMAGE_ORDINAL_FLAG)
				{
					*(UINT_PTR *)ft = (UINT_PTR)(*(LPVOID(*)(LPVOID, LPSTR))GetProcAddr)(ImportDll, (LPSTR)IMAGE_ORDINAL(orig->u1.Ordinal));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME ImportFuncName = (PIMAGE_IMPORT_BY_NAME)(Image + orig->u1.AddressOfData);
					// printf("%s\n",ImportFuncName->Name);
					*(UINT_PTR *)ft = (UINT_PTR)(*(LPVOID(*)(LPVOID, char *))GetProcAddr)(ImportDll, ImportFuncName->Name);
				}
				ft++;
				orig++;
			}
			importDir++;
		}
	}
	
	//Calling TLS
	
	if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress){
		PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(Image+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		if(tls->AddressOfCallBacks){
			PIMAGE_TLS_CALLBACK * callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
			while(*callback)
			{
				
				(* callback)(Image,1,NULL);callback++;
			}
		}
	}
	
	
	(* (void (*) (LPVOID , DWORD , LPVOID))(Image+nt->OptionalHeader.AddressOfEntryPoint))(Image,1,NULL);
	
}

/*
int ShortCut(LPVOID data){
	SetupPE(CopyData(data));
	return 22;
}
*/

int main(int j,char **args){
	
//	DWORD SLEN = (DWORD )( (UINT_PTR)main - (UINT_PTR)GetKernelAndProc);
//	DWORD CopyDataIndex = (DWORD )( (UINT_PTR)CopyData - (UINT_PTR)GetKernelAndProc);
//	DWORD SetupIndex = (DWORD )( (UINT_PTR)SetupPE - (UINT_PTR)GetKernelAndProc);
//	//DWORD ShortCutIndex = (DWORD )( (UINT_PTR)ShortCut - (UINT_PTR)SetupPE);
//	
//	//printf("LEN: %ld -- CopyData: %ld -- SetupPe: %ld -- ShortCut: %ld\n\n",SLEN,CopyDataIndex,SetupIndex,ShortCutIndex);
//	printf("LEN: %ld -- CopyData: %ld -- SetupPe: %ld\n\n",SLEN,CopyDataIndex,SetupIndex);
//	
//	
//	unsigned char * p = (char *)GetKernelAndProc;
//	
//	DWORD i =0;
//	
//	for (i=0;i<SLEN;i++){
//		printf("%.2x",*(p+i));
//	}
	
	
	HANDLE file;
	LPVOID Mem;
	
	if (j != 2)
	{
		printf("[*]Usage %s <DLL>\n", args[0]);
		return 0;
	}
	
	printf("[*]Opening And Reading File\n");
	if ((file = CreateFileA(args[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		printf("[-]Failed To Open File");
		return -1;
	}

	DWORD File_len = GetFileSize(file, NULL);
	printf("[+]Allocating Memory....\n");
	if ((Mem = VirtualAlloc(NULL, File_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL)
	{
		printf("[-]Failed To Allocate Memory..");
		CloseHandle(file);
		return - 1;
	}

	
	ReadFile(file, Mem, File_len, NULL, NULL);
	CloseHandle(file);
	//ShortCut(Mem);
	
	LPVOID Image = CopyData(Mem);
	if(Image){
		printf("Data is loaded\n");
	}
	
	
	SetupPE(Image);
	
	VirtualFree(Mem,0,MEM_RELEASE);
	VirtualFree(Image,0,MEM_RELEASE);
	
	
	
	
	
	return 0;
}
