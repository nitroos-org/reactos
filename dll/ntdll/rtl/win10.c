/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Small Rtl functions that ntdll exports on Windows 8 and later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Behaviour, including the answers to inputs a caller should not pass, measured on Windows 10 22H2 (x64 and x86).
 */

#include <ntdll.h>

#define NDEBUG
#include <debug.h>

/* MISC *********************************************************************/

BOOLEAN
NTAPI
RtlIsZeroMemory(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length)
{
    const UCHAR *Bytes = Buffer;

    while (Length != 0)
    {
        if (*Bytes++ != 0)
            return FALSE;
        Length--;
    }

    return TRUE;
}

#ifdef _M_IX86
/* x86 ntdll exports the function; on 64-bit builds it is in the runtime library and not exported by name */
VOID
NTAPI
RtlpFillMemoryUlonglong32(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONGLONG Fill)
{
    PULONG Dest = Destination;
    SIZE_T Count = Length / sizeof(ULONG);
    BOOLEAN High = FALSE;

    /* Ulong by ulong, the low half first: a length that is no multiple of eight ends in the low half */
    while (Count > 0)
    {
        *Dest++ = High ? (ULONG)(Fill >> 32) : (ULONG)Fill;
        High = !High;
        Count--;
    }
}
#endif

/* CRC-32C (Castagnoli), reflected, polynomial 0x82F63B78 (0x1EDC6F41) */
static const ULONG RtlpCrc32Table[256] =
{
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C,
    0x26A1E7E8, 0xD4CA64EB, 0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
    0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24, 0x105EC76F, 0xE235446C,
    0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC,
    0xBC267848, 0x4E4DFB4B, 0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
    0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35, 0xAA64D611, 0x580F5512,
    0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD,
    0x1642AE59, 0xE4292D5A, 0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
    0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595, 0x417B1DBC, 0xB3109EBF,
    0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F,
    0xED03A29B, 0x1F682198, 0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
    0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38, 0xDBFC821C, 0x2997011F,
    0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E,
    0x4767748A, 0xB50CF789, 0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
    0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46, 0x7198540D, 0x83F3D70E,
    0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE,
    0xDDE0EB2A, 0x2F8B6829, 0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
    0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93, 0x082F63B7, 0xFA44E0B4,
    0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B,
    0xB4091BFF, 0x466298FC, 0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
    0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033, 0xA24BB5A6, 0x502036A5,
    0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975,
    0x0E330A81, 0xFC588982, 0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
    0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622, 0x38CC2A06, 0xCAA7A905,
    0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8,
    0xE52CC12C, 0x1747422F, 0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
    0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0, 0xD3D3E1AB, 0x21B862A8,
    0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78,
    0x7FAB5E8C, 0x8DC0DD8F, 0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
    0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1, 0x69E9F0D5, 0x9B8273D6,
    0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69,
    0xD5CF889D, 0x27A40B9E, 0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
    0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
};

/* CRC-64/NVME, reflected, polynomial 0x9A6C9329AC4BC9B5 (0xAD93D23594C93659) */
static const ULONGLONG RtlpCrc64Table[256] =
{
    0x0000000000000000ULL, 0x7F6EF0C830358979ULL, 0xFEDDE190606B12F2ULL,
    0x81B31158505E9B8BULL, 0xC962E5739841B68FULL, 0xB60C15BBA8743FF6ULL,
    0x37BF04E3F82AA47DULL, 0x48D1F42BC81F2D04ULL, 0xA61CECB46814FE75ULL,
    0xD9721C7C5821770CULL, 0x58C10D24087FEC87ULL, 0x27AFFDEC384A65FEULL,
    0x6F7E09C7F05548FAULL, 0x1010F90FC060C183ULL, 0x91A3E857903E5A08ULL,
    0xEECD189FA00BD371ULL, 0x78E0FF3B88BE6F81ULL, 0x078E0FF3B88BE6F8ULL,
    0x863D1EABE8D57D73ULL, 0xF953EE63D8E0F40AULL, 0xB1821A4810FFD90EULL,
    0xCEECEA8020CA5077ULL, 0x4F5FFBD87094CBFCULL, 0x30310B1040A14285ULL,
    0xDEFC138FE0AA91F4ULL, 0xA192E347D09F188DULL, 0x2021F21F80C18306ULL,
    0x5F4F02D7B0F40A7FULL, 0x179EF6FC78EB277BULL, 0x68F0063448DEAE02ULL,
    0xE943176C18803589ULL, 0x962DE7A428B5BCF0ULL, 0xF1C1FE77117CDF02ULL,
    0x8EAF0EBF2149567BULL, 0x0F1C1FE77117CDF0ULL, 0x7072EF2F41224489ULL,
    0x38A31B04893D698DULL, 0x47CDEBCCB908E0F4ULL, 0xC67EFA94E9567B7FULL,
    0xB9100A5CD963F206ULL, 0x57DD12C379682177ULL, 0x28B3E20B495DA80EULL,
    0xA900F35319033385ULL, 0xD66E039B2936BAFCULL, 0x9EBFF7B0E12997F8ULL,
    0xE1D10778D11C1E81ULL, 0x606216208142850AULL, 0x1F0CE6E8B1770C73ULL,
    0x8921014C99C2B083ULL, 0xF64FF184A9F739FAULL, 0x77FCE0DCF9A9A271ULL,
    0x08921014C99C2B08ULL, 0x4043E43F0183060CULL, 0x3F2D14F731B68F75ULL,
    0xBE9E05AF61E814FEULL, 0xC1F0F56751DD9D87ULL, 0x2F3DEDF8F1D64EF6ULL,
    0x50531D30C1E3C78FULL, 0xD1E00C6891BD5C04ULL, 0xAE8EFCA0A188D57DULL,
    0xE65F088B6997F879ULL, 0x9931F84359A27100ULL, 0x1882E91B09FCEA8BULL,
    0x67EC19D339C963F2ULL, 0xD75ADABD7A6E2D6FULL, 0xA8342A754A5BA416ULL,
    0x29873B2D1A053F9DULL, 0x56E9CBE52A30B6E4ULL, 0x1E383FCEE22F9BE0ULL,
    0x6156CF06D21A1299ULL, 0xE0E5DE5E82448912ULL, 0x9F8B2E96B271006BULL,
    0x71463609127AD31AULL, 0x0E28C6C1224F5A63ULL, 0x8F9BD7997211C1E8ULL,
    0xF0F5275142244891ULL, 0xB824D37A8A3B6595ULL, 0xC74A23B2BA0EECECULL,
    0x46F932EAEA507767ULL, 0x3997C222DA65FE1EULL, 0xAFBA2586F2D042EEULL,
    0xD0D4D54EC2E5CB97ULL, 0x5167C41692BB501CULL, 0x2E0934DEA28ED965ULL,
    0x66D8C0F56A91F461ULL, 0x19B6303D5AA47D18ULL, 0x980521650AFAE693ULL,
    0xE76BD1AD3ACF6FEAULL, 0x09A6C9329AC4BC9BULL, 0x76C839FAAAF135E2ULL,
    0xF77B28A2FAAFAE69ULL, 0x8815D86ACA9A2710ULL, 0xC0C42C4102850A14ULL,
    0xBFAADC8932B0836DULL, 0x3E19CDD162EE18E6ULL, 0x41773D1952DB919FULL,
    0x269B24CA6B12F26DULL, 0x59F5D4025B277B14ULL, 0xD846C55A0B79E09FULL,
    0xA72835923B4C69E6ULL, 0xEFF9C1B9F35344E2ULL, 0x90973171C366CD9BULL,
    0x1124202993385610ULL, 0x6E4AD0E1A30DDF69ULL, 0x8087C87E03060C18ULL,
    0xFFE938B633338561ULL, 0x7E5A29EE636D1EEAULL, 0x0134D92653589793ULL,
    0x49E52D0D9B47BA97ULL, 0x368BDDC5AB7233EEULL, 0xB738CC9DFB2CA865ULL,
    0xC8563C55CB19211CULL, 0x5E7BDBF1E3AC9DECULL, 0x21152B39D3991495ULL,
    0xA0A63A6183C78F1EULL, 0xDFC8CAA9B3F20667ULL, 0x97193E827BED2B63ULL,
    0xE877CE4A4BD8A21AULL, 0x69C4DF121B863991ULL, 0x16AA2FDA2BB3B0E8ULL,
    0xF86737458BB86399ULL, 0x8709C78DBB8DEAE0ULL, 0x06BAD6D5EBD3716BULL,
    0x79D4261DDBE6F812ULL, 0x3105D23613F9D516ULL, 0x4E6B22FE23CC5C6FULL,
    0xCFD833A67392C7E4ULL, 0xB0B6C36E43A74E9DULL, 0x9A6C9329AC4BC9B5ULL,
    0xE50263E19C7E40CCULL, 0x64B172B9CC20DB47ULL, 0x1BDF8271FC15523EULL,
    0x530E765A340A7F3AULL, 0x2C608692043FF643ULL, 0xADD397CA54616DC8ULL,
    0xD2BD67026454E4B1ULL, 0x3C707F9DC45F37C0ULL, 0x431E8F55F46ABEB9ULL,
    0xC2AD9E0DA4342532ULL, 0xBDC36EC59401AC4BULL, 0xF5129AEE5C1E814FULL,
    0x8A7C6A266C2B0836ULL, 0x0BCF7B7E3C7593BDULL, 0x74A18BB60C401AC4ULL,
    0xE28C6C1224F5A634ULL, 0x9DE29CDA14C02F4DULL, 0x1C518D82449EB4C6ULL,
    0x633F7D4A74AB3DBFULL, 0x2BEE8961BCB410BBULL, 0x548079A98C8199C2ULL,
    0xD53368F1DCDF0249ULL, 0xAA5D9839ECEA8B30ULL, 0x449080A64CE15841ULL,
    0x3BFE706E7CD4D138ULL, 0xBA4D61362C8A4AB3ULL, 0xC52391FE1CBFC3CAULL,
    0x8DF265D5D4A0EECEULL, 0xF29C951DE49567B7ULL, 0x732F8445B4CBFC3CULL,
    0x0C41748D84FE7545ULL, 0x6BAD6D5EBD3716B7ULL, 0x14C39D968D029FCEULL,
    0x95708CCEDD5C0445ULL, 0xEA1E7C06ED698D3CULL, 0xA2CF882D2576A038ULL,
    0xDDA178E515432941ULL, 0x5C1269BD451DB2CAULL, 0x237C997575283BB3ULL,
    0xCDB181EAD523E8C2ULL, 0xB2DF7122E51661BBULL, 0x336C607AB548FA30ULL,
    0x4C0290B2857D7349ULL, 0x04D364994D625E4DULL, 0x7BBD94517D57D734ULL,
    0xFA0E85092D094CBFULL, 0x856075C11D3CC5C6ULL, 0x134D926535897936ULL,
    0x6C2362AD05BCF04FULL, 0xED9073F555E26BC4ULL, 0x92FE833D65D7E2BDULL,
    0xDA2F7716ADC8CFB9ULL, 0xA54187DE9DFD46C0ULL, 0x24F29686CDA3DD4BULL,
    0x5B9C664EFD965432ULL, 0xB5517ED15D9D8743ULL, 0xCA3F8E196DA80E3AULL,
    0x4B8C9F413DF695B1ULL, 0x34E26F890DC31CC8ULL, 0x7C339BA2C5DC31CCULL,
    0x035D6B6AF5E9B8B5ULL, 0x82EE7A32A5B7233EULL, 0xFD808AFA9582AA47ULL,
    0x4D364994D625E4DAULL, 0x3258B95CE6106DA3ULL, 0xB3EBA804B64EF628ULL,
    0xCC8558CC867B7F51ULL, 0x8454ACE74E645255ULL, 0xFB3A5C2F7E51DB2CULL,
    0x7A894D772E0F40A7ULL, 0x05E7BDBF1E3AC9DEULL, 0xEB2AA520BE311AAFULL,
    0x944455E88E0493D6ULL, 0x15F744B0DE5A085DULL, 0x6A99B478EE6F8124ULL,
    0x224840532670AC20ULL, 0x5D26B09B16452559ULL, 0xDC95A1C3461BBED2ULL,
    0xA3FB510B762E37ABULL, 0x35D6B6AF5E9B8B5BULL, 0x4AB846676EAE0222ULL,
    0xCB0B573F3EF099A9ULL, 0xB465A7F70EC510D0ULL, 0xFCB453DCC6DA3DD4ULL,
    0x83DAA314F6EFB4ADULL, 0x0269B24CA6B12F26ULL, 0x7D0742849684A65FULL,
    0x93CA5A1B368F752EULL, 0xECA4AAD306BAFC57ULL, 0x6D17BB8B56E467DCULL,
    0x12794B4366D1EEA5ULL, 0x5AA8BF68AECEC3A1ULL, 0x25C64FA09EFB4AD8ULL,
    0xA4755EF8CEA5D153ULL, 0xDB1BAE30FE90582AULL, 0xBCF7B7E3C7593BD8ULL,
    0xC399472BF76CB2A1ULL, 0x422A5673A732292AULL, 0x3D44A6BB9707A053ULL,
    0x759552905F188D57ULL, 0x0AFBA2586F2D042EULL, 0x8B48B3003F739FA5ULL,
    0xF42643C80F4616DCULL, 0x1AEB5B57AF4DC5ADULL, 0x6585AB9F9F784CD4ULL,
    0xE436BAC7CF26D75FULL, 0x9B584A0FFF135E26ULL, 0xD389BE24370C7322ULL,
    0xACE74EEC0739FA5BULL, 0x2D545FB4576761D0ULL, 0x523AAF7C6752E8A9ULL,
    0xC41748D84FE75459ULL, 0xBB79B8107FD2DD20ULL, 0x3ACAA9482F8C46ABULL,
    0x45A459801FB9CFD2ULL, 0x0D75ADABD7A6E2D6ULL, 0x721B5D63E7936BAFULL,
    0xF3A84C3BB7CDF024ULL, 0x8CC6BCF387F8795DULL, 0x620BA46C27F3AA2CULL,
    0x1D6554A417C62355ULL, 0x9CD645FC4798B8DEULL, 0xE3B8B53477AD31A7ULL,
    0xAB69411FBFB21CA3ULL, 0xD407B1D78F8795DAULL, 0x55B4A08FDFD90E51ULL,
    0x2ADA5047EFEC8728ULL,
};

/* The CRC-32C (Castagnoli) of the buffer, continuing the CRC in InitialCrc (0 to start) */
ULONG
NTAPI
RtlCrc32(
    _In_reads_bytes_(Size) const VOID *Buffer,
    _In_ SIZE_T Size,
    _In_ ULONG InitialCrc)
{
    const UCHAR *Bytes = Buffer;
    ULONG Crc = ~InitialCrc;

    while (Size != 0)
    {
        Crc = RtlpCrc32Table[(Crc ^ *Bytes++) & 0xFF] ^ (Crc >> 8);
        Size--;
    }

    return ~Crc;
}

/*
 * The CRC-64 of the buffer, continuing the CRC in InitialCrc (0 to start): reflected, polynomial 0xAD93D23594C93659
 * (0x9A6C9329AC4BC9B5 reflected), the register starts as the complement of InitialCrc and the result is the
 * complement of the register, the same convention as RtlCrc32 (this is CRC-64/NVME; "123456789" gives
 * 0xAE8B14860A799888). An empty buffer returns InitialCrc.
 */
ULONGLONG
NTAPI
RtlCrc64(
    _In_reads_bytes_(Size) const VOID *Buffer,
    _In_ SIZE_T Size,
    _In_ ULONGLONG InitialCrc)
{
    const UCHAR *Bytes = Buffer;
    ULONGLONG Crc = ~InitialCrc;

    while (Size != 0)
    {
        Crc = RtlpCrc64Table[(Crc ^ *Bytes++) & 0xFF] ^ (Crc >> 8);
        Size--;
    }

    return ~Crc;
}

BOOLEAN
NTAPI
RtlIsCurrentProcess(
    _In_ HANDLE ProcessHandle)
{
    PROCESS_BASIC_INFORMATION BasicInfo;

    if (ProcessHandle == NtCurrentProcess())
        return TRUE;

    if (!NT_SUCCESS(NtQueryInformationProcess(ProcessHandle,
                                              ProcessBasicInformation,
                                              &BasicInfo,
                                              sizeof(BasicInfo),
                                              NULL)))
    {
        return FALSE;
    }

    return BasicInfo.UniqueProcessId == (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
}

BOOLEAN
NTAPI
RtlIsCurrentThread(
    _In_ HANDLE ThreadHandle)
{
    THREAD_BASIC_INFORMATION BasicInfo;

    if (ThreadHandle == NtCurrentThread())
        return TRUE;

    if (!NT_SUCCESS(NtQueryInformationThread(ThreadHandle,
                                             ThreadBasicInformation,
                                             &BasicInfo,
                                             sizeof(BasicInfo),
                                             NULL)))
    {
        return FALSE;
    }

    return BasicInfo.ClientId.UniqueThread == NtCurrentTeb()->ClientId.UniqueThread;
}

/* SHARED USER DATA *********************************************************/

PWSTR
NTAPI
RtlGetNtSystemRoot(VOID)
{
    return SharedUserData->NtSystemRoot;
}

ULONG
NTAPI
RtlGetSuiteMask(VOID)
{
    return SharedUserData->SuiteMask;
}

ULONG
NTAPI
RtlGetActiveConsoleId(VOID)
{
    return SharedUserData->ActiveConsoleId;
}

/*
 * The version is major.minor.build.revision as four words, the revision being the UBR value of the CurrentVersion
 * key (0 where there is none); family 3 is the desktop family, form 0 is unknown.
 */
VOID
NTAPI
RtlGetDeviceFamilyInfoEnum(
    _Out_opt_ PULONGLONG UapInfo,
    _Out_opt_ PULONG DeviceFamily,
    _Out_opt_ PULONG DeviceForm)
{
    if (UapInfo)
    {
        RTL_OSVERSIONINFOW VersionInfo = { sizeof(VersionInfo) };
        ULONG Revision = 0;
        UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
        UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"UBR");
        OBJECT_ATTRIBUTES ObjectAttributes;
        HANDLE KeyHandle;
        ULONG InfoBuffer[(FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG) + sizeof(ULONG) - 1) /
                         sizeof(ULONG)];
        PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)InfoBuffer;
        ULONG ResultLength;

        RtlGetVersion(&VersionInfo);

        /* The value is read by hand: it is only a revision when it is a REG_DWORD, whatever the key holds */
        InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes)))
        {
            if (NT_SUCCESS(NtQueryValueKey(KeyHandle,
                                           &ValueName,
                                           KeyValuePartialInformation,
                                           Info,
                                           sizeof(InfoBuffer),
                                           &ResultLength)) &&
                (Info->Type == REG_DWORD) && (Info->DataLength == sizeof(ULONG)))
            {
                Revision = *(PULONG)Info->Data;
            }
            NtClose(KeyHandle);
        }

        *UapInfo = ((ULONGLONG)(VersionInfo.dwMajorVersion & 0xFFFF) << 48) |
                   ((ULONGLONG)(VersionInfo.dwMinorVersion & 0xFFFF) << 32) |
                   ((ULONGLONG)(VersionInfo.dwBuildNumber & 0xFFFF) << 16) |
                   (Revision & 0xFFFF);
    }

    if (DeviceFamily)
        *DeviceFamily = 3;

    if (DeviceForm)
        *DeviceForm = 0;
}

/*
 * The names of the family and form RtlGetDeviceFamilyInfoEnum reports: sizes are in bytes and count
 * the terminating null. Where one buffer is too small both sizes come back and nothing is copied.
 */
NTSTATUS
NTAPI
RtlConvertDeviceFamilyInfoToString(
    _Inout_ PULONG DeviceFamilySize,
    _Inout_ PULONG DeviceFormSize,
    _Out_writes_bytes_opt_(*DeviceFamilySize) PWSTR DeviceFamily,
    _Out_writes_bytes_opt_(*DeviceFormSize) PWSTR DeviceForm)
{
    static const WCHAR FamilyName[] = L"Windows.Desktop";
    static const WCHAR FormName[] = L"Unknown";

    if (!DeviceFamilySize || !DeviceFormSize)
        return STATUS_INVALID_PARAMETER;

    if (*DeviceFamilySize < sizeof(FamilyName) || *DeviceFormSize < sizeof(FormName) ||
        !DeviceFamily || !DeviceForm)
    {
        *DeviceFamilySize = sizeof(FamilyName);
        *DeviceFormSize = sizeof(FormName);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(DeviceFamily, FamilyName, sizeof(FamilyName));
    RtlCopyMemory(DeviceForm, FormName, sizeof(FormName));
    *DeviceFamilySize = sizeof(FamilyName);
    *DeviceFormSize = sizeof(FormName);
    return STATUS_SUCCESS;
}

/* STRINGS ******************************************************************/

BOOLEAN
NTAPI
RtlDoesNameContainWildCards(
    _In_ PCUNICODE_STRING Expression)
{
    PWCHAR Char = Expression->Buffer;
    PWCHAR End = Char + Expression->Length / sizeof(WCHAR);

    for (; Char < End; Char++)
    {
        if (*Char == L'*' || *Char == L'?' || *Char == L'<' || *Char == L'>' || *Char == L'"')
            return TRUE;
    }

    return FALSE;
}

/* The GUID in lower case, as {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}: 38 characters */
NTSTATUS
NTAPI
RtlStringFromGUIDEx(
    _In_ const GUID *Guid,
    _Inout_ PUNICODE_STRING GuidString,
    _In_ BOOLEAN AllocateGuidString)
{
    static const WCHAR Digits[] = L"0123456789abcdef";
    static const UCHAR Groups[] = { 4, 2, 2, 2, 6 };
    const UCHAR *Bytes[16];
    const UCHAR Order[16] = { 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 };
    ULONG i, Group, Pos = 0;
    PWCHAR Buffer;

    if (AllocateGuidString)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, 78);
        if (!Buffer)
            return STATUS_NO_MEMORY;
        GuidString->Buffer = Buffer;
        GuidString->MaximumLength = 78;
    }
    else
    {
        if (GuidString->MaximumLength < 78)
            return STATUS_BUFFER_TOO_SMALL;
        Buffer = GuidString->Buffer;
    }

    for (i = 0; i < 16; i++)
        Bytes[i] = (const UCHAR *)Guid + Order[i];

    Buffer[Pos++] = L'{';
    i = 0;
    for (Group = 0; Group < RTL_NUMBER_OF(Groups); Group++)
    {
        ULONG n;

        if (Group != 0)
            Buffer[Pos++] = L'-';
        for (n = 0; n < Groups[Group]; n++, i++)
        {
            Buffer[Pos++] = Digits[*Bytes[i] >> 4];
            Buffer[Pos++] = Digits[*Bytes[i] & 0xF];
        }
    }
    Buffer[Pos++] = L'}';
    Buffer[Pos] = UNICODE_NULL;

    GuidString->Length = 76;
    return STATUS_SUCCESS;
}

/* ETHERNET ADDRESSES *******************************************************/

typedef struct _DL_EUI48_ADDRESS
{
    UCHAR Byte[6];
} DL_EUI48_ADDRESS;

static
LONG
HexDigitValue(
    _In_ ULONG Char)
{
    if (Char >= '0' && Char <= '9') return Char - '0';
    if (Char >= 'a' && Char <= 'f') return Char - 'a' + 10;
    if (Char >= 'A' && Char <= 'F') return Char - 'A' + 10;
    return -1;
}

PSTR
NTAPI
RtlEthernetAddressToStringA(
    _In_ const DL_EUI48_ADDRESS *Address,
    _Out_writes_(18) PSTR S)
{
    static const CHAR Digits[] = "0123456789ABCDEF";
    ULONG i;

    for (i = 0; i < 6; i++)
    {
        if (i != 0)
            *S++ = '-';
        *S++ = Digits[Address->Byte[i] >> 4];
        *S++ = Digits[Address->Byte[i] & 0xF];
    }
    *S = ANSI_NULL;
    return S;
}

PWSTR
NTAPI
RtlEthernetAddressToStringW(
    _In_ const DL_EUI48_ADDRESS *Address,
    _Out_writes_(18) PWSTR S)
{
    static const WCHAR Digits[] = L"0123456789ABCDEF";
    ULONG i;

    for (i = 0; i < 6; i++)
    {
        if (i != 0)
            *S++ = L'-';
        *S++ = Digits[Address->Byte[i] >> 4];
        *S++ = Digits[Address->Byte[i] & 0xF];
    }
    *S = UNICODE_NULL;
    return S;
}

/* Six pairs of hex digits, each pair after the first led by '-' or ':' (the two may be mixed) */
#define ETHERNET_STRING_TO_ADDRESS(CharType)                                    \
    DL_EUI48_ADDRESS Result;                                                    \
    const CharType *Pos = S;                                                    \
    ULONG i;                                                                    \
                                                                                \
    for (i = 0; i < 6; i++)                                                     \
    {                                                                           \
        LONG High, Low;                                                         \
                                                                                \
        if (i != 0)                                                             \
        {                                                                       \
            if (*Pos != '-' && *Pos != ':')                                     \
                goto Fail;                                                      \
            Pos++;                                                              \
        }                                                                       \
        High = HexDigitValue(Pos[0]);                                           \
        if (High < 0)                                                           \
            goto Fail;                                                          \
        Low = HexDigitValue(Pos[1]);                                            \
        if (Low < 0)                                                            \
        {                                                                       \
            Pos++;                                                              \
            goto Fail;                                                          \
        }                                                                       \
        Result.Byte[i] = (UCHAR)((High << 4) | Low);                            \
        Pos += 2;                                                               \
    }                                                                           \
    *Address = Result;                                                          \
    *Terminator = Pos;                                                          \
    return STATUS_SUCCESS;                                                      \
Fail:                                                                           \
    *Terminator = Pos;                                                          \
    return STATUS_INVALID_PARAMETER;

NTSTATUS
NTAPI
RtlEthernetStringToAddressA(
    _In_ PCSTR S,
    _Out_ PCSTR *Terminator,
    _Out_ DL_EUI48_ADDRESS *Address)
{
    ETHERNET_STRING_TO_ADDRESS(CHAR)
}

NTSTATUS
NTAPI
RtlEthernetStringToAddressW(
    _In_ PCWSTR S,
    _Out_ PCWSTR *Terminator,
    _Out_ DL_EUI48_ADDRESS *Address)
{
    ETHERNET_STRING_TO_ADDRESS(WCHAR)
}

/* SYNCHRONIZATION **********************************************************/

/* Waits until no one owns the lock, then leaves it free */
VOID
NTAPI
RtlAcquireReleaseSRWLockExclusive(
    _Inout_ PRTL_SRWLOCK SRWLock)
{
    RtlAcquireSRWLockExclusive(SRWLock);
    RtlReleaseSRWLockExclusive(SRWLock);
}

/* WOW64 ********************************************************************/

/* The machine of the code that is running: the architecture ntdll was built for */
USHORT
NTAPI
RtlWow64GetCurrentMachine(VOID)
{
#if defined(_M_AMD64)
    return IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM)
    return IMAGE_FILE_MACHINE_ARMNT;
#else
    return IMAGE_FILE_MACHINE_I386;
#endif
}

/* SECURITY *****************************************************************/

NTSTATUS
NTAPI
RtlAllocateAndInitializeSidEx(
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    _In_reads_(SubAuthorityCount) PULONG SubAuthorities,
    _Outptr_ PSID *Sid)
{
    PSID NewSid;
    ULONG i;

    if (SubAuthorityCount > SID_MAX_SUB_AUTHORITIES)
        return STATUS_INVALID_PARAMETER;

    NewSid = RtlAllocateHeap(RtlGetProcessHeap(), 0, RtlLengthRequiredSid(SubAuthorityCount));
    if (!NewSid)
        return STATUS_NO_MEMORY;

    RtlInitializeSid(NewSid, IdentifierAuthority, SubAuthorityCount);
    for (i = 0; i < SubAuthorityCount; i++)
        *RtlSubAuthoritySid(NewSid, i) = SubAuthorities[i];

    *Sid = NewSid;
    return STATUS_SUCCESS;
}
