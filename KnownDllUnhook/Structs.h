#pragma once



#ifndef _STRUCTS_
#define _STRUCTS_


#include <Windows.h>




#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;



typedef PVOID PACTIVATION_CONTEXT;



typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;



#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L



typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;



typedef struct _PEB_LDR_DATA {
    ULONG                   Length;
    ULONG                   Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
    UCHAR InheritedAddressSpace;                                            
    UCHAR ReadImageFileExecOptions;                                         
    UCHAR BeingDebugged;                                                   
    union
    {
        UCHAR BitField;                                                    
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    
            UCHAR IsProtectedProcess : 1;                                     
            UCHAR IsImageDynamicallyRelocated : 1;                            
            UCHAR SkipPatchingUser32Forwarders : 1;                           
            UCHAR IsPackagedProcess : 1;                                      
            UCHAR IsAppContainer : 1;                                         
            UCHAR IsProtectedProcessLight : 1;                                
            UCHAR IsLongPathAwareProcess : 1;                                
        };
    };
    UCHAR Padding0[4];                                                     
    VOID* Mutant;                                                           
    VOID* ImageBaseAddress;                                                
    struct _PEB_LDR_DATA* Ldr;                                             
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 
    VOID* SubSystemData;                                                    
    VOID* ProcessHeap;                                                      
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         
    VOID* IFEOKey;                                                          
    union
    {
        ULONG CrossProcessFlags;                                            
        struct
        {
            ULONG ProcessInJob : 1;                                           
            ULONG ProcessInitializing : 1;                                    
            ULONG ProcessUsingVEH : 1;                                        
            ULONG ProcessUsingVCH : 1;                                        
            ULONG ProcessUsingFTH : 1;                                        
            ULONG ProcessPreviouslyThrottled : 1;                             
            ULONG ProcessCurrentlyThrottled : 1;                              
            ULONG ProcessImagesHotPatched : 1;                               
            ULONG ReservedBits0 : 24;                                         
        };
    };
    UCHAR Padding1[4];                                                      
    union
    {
        VOID* KernelCallbackTable;                                         
        VOID* UserSharedInfoPtr;                                            
    };
    ULONG SystemReserved;                                                  
    ULONG AtlThunkSListPtr32;                                              
    VOID* ApiSetMap;                                                        
    ULONG TlsExpansionCounter;                                             
    UCHAR Padding2[4];                                                      
    VOID* TlsBitmap;                                                       
    ULONG TlsBitmapBits[2];                                                 
    VOID* ReadOnlySharedMemoryBase;                                         
    VOID* SharedData;                                                       
    VOID** ReadOnlyStaticServerData;                                        
    VOID* AnsiCodePageData;                                                
    VOID* OemCodePageData;                                                 
    VOID* UnicodeCaseTableData;                                             
    ULONG NumberOfProcessors;                                               
    ULONG NtGlobalFlag;                                                     
    union _LARGE_INTEGER CriticalSectionTimeout;                            
    ULONGLONG HeapSegmentReserve;                                           
    ULONGLONG HeapSegmentCommit;                                          
    ULONGLONG HeapDeCommitTotalFreeThreshold;                              
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               
    ULONG NumberOfHeaps;                                                   
    ULONG MaximumNumberOfHeaps;                                             
    VOID** ProcessHeaps;                                                    
    VOID* GdiSharedHandleTable;                                             
    VOID* ProcessStarterHelper;                                             
    ULONG GdiDCAttributeList;                                               
    UCHAR Padding3[4];                                                      
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               
    ULONG OSMajorVersion;                                                  
    ULONG OSMinorVersion;                                                   
    USHORT OSBuildNumber;                                                   
    USHORT OSCSDVersion;                                                   
    ULONG OSPlatformId;                                                    
    ULONG ImageSubsystem;                                                  
    ULONG ImageSubsystemMajorVersion;                                      
    ULONG ImageSubsystemMinorVersion;                                       
    UCHAR Padding4[4];                                                      
    ULONGLONG ActiveProcessAffinityMask;                                   
    ULONG GdiHandleBuffer[60];                                              
    VOID(*PostProcessInitRoutine)();                                      
    VOID* TlsExpansionBitmap;                                              
    ULONG TlsExpansionBitmapBits[32];                                       
    ULONG SessionId;                                                        
    UCHAR Padding5[4];                                                     
    union _ULARGE_INTEGER AppCompatFlags;                                   
    union _ULARGE_INTEGER AppCompatFlagsUser;                              
    VOID* pShimData;                                                       
    VOID* AppCompatInfo;                                                   
    struct _UNICODE_STRING CSDVersion;                                      
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;   
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                
    ULONGLONG MinimumStackCommit;                                           
    struct _FLS_CALLBACK_INFO* FlsCallback;                               
    struct _LIST_ENTRY FlsListHead;                                         
    VOID* FlsBitmap;                                                        
    ULONG FlsBitmapBits[4];                                                 
    ULONG FlsHighIndex;                                                     
    VOID* WerRegistrationData;                                             
    VOID* WerShipAssertPtr;                                                 
    VOID* pUnused;                                                         
    VOID* pImageHeaderHash;                                                 
    union
    {
        ULONG TracingFlags;                                                 
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     
            ULONG CritSecTracingEnabled : 1;                                  
            ULONG LibLoaderTracingEnabled : 1;                                
            ULONG SpareTracingBits : 29;                                      
        };
    };
    UCHAR Padding6[4];                                                     
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                           
    ULONGLONG TppWorkerpListLock;                                          
    struct _LIST_ENTRY TppWorkerpList;                                      
    VOID* WaitOnAddressHashTable[128];                                      
    VOID* TelemetryCoverageHeader;                                          
    ULONG CloudFileFlags;                                                   
    ULONG CloudFileDiagFlags;                                              
    CHAR PlaceholderCompatibilityMode;                                      
    CHAR PlaceholderCompatibilityModeReserved[7];                           
    struct _LEAP_SECOND_DATA* LeapSecondData;                              
    union
    {
        ULONG LeapSecondFlags;                                             
        struct
        {
            ULONG SixtySecondEnabled : 1;                                     
            ULONG Reserved : 31;                                             
        };
    };
    ULONG NtGlobalFlag2;                                                    
} PEB, * PPEB;



#endif // !_STRUCTS_
