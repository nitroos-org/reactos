/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     groups
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * PROJECT:     ReactOS FS utility tool
 * PURPOSE:     Command group tables and usage text, byte-identical to Windows 10 22H2 fsutil.
 *              The listings were captured from real Windows (bare "fsutil <group>").
 *              Sub-commands with a NULL handler are listed by Windows but not implemented here.
 */

#include "fsutil.h"

HandlerProc DirtyQueryMain;
HandlerProc DirtySetMain;
HandlerProc FsInfoDriveTypeMain;
HandlerProc FsInfoDrivesMain;
HandlerProc FsInfoNtfsInfoMain;
HandlerProc FsInfoStatisticsMain;
HandlerProc FsInfoVolumeInfoMain;
HandlerProc HardLinkCreateMain;
HandlerProc VolumeDiskFreeMain;
HandlerProc VolumeDismountMain;
HandlerProc VolumeListMain;

static const TCHAR D8dot3nameListing[] =
    _T("---- 8DOT3NAME Commands Supported ----\n")
    _T("\n")
    _T("query   Query the current setting for the shortname behaviour on the system\n")
    _T("scan    Scan for impacted registry entries\n")
    _T("set     Change the setting that controls the shortname behavior on the system\n")
    _T("strip   Remove the shortnames for all files within a directory\n");
static HandlerItem D8dot3nameItems[] =
{
    { NULL, _T("query") },
    { NULL, _T("scan") },
    { NULL, _T("set") },
    { NULL, _T("strip") },
};
int D8dot3nameGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, D8dot3nameListing, D8dot3nameItems, RTL_NUMBER_OF(D8dot3nameItems));
}

static const TCHAR BehaviorListing[] =
    _T("---- BEHAVIOR Commands Supported ----\n")
    _T("\n")
    _T("query           Query the file system behavior parameters\n")
    _T("set             Change the file system behavior parameters\n");
static HandlerItem BehaviorItems[] =
{
    { NULL, _T("query") },
    { NULL, _T("set") },
};
int BehaviorGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, BehaviorListing, BehaviorItems, RTL_NUMBER_OF(BehaviorItems));
}

static const TCHAR DaxListing[] =
    _T("---- DAX Commands Supported ----\n")
    _T("\n")
    _T("queryFileAlignment        Query file alignment on dax volume\n");
static HandlerItem DaxItems[] =
{
    { NULL, _T("queryfilealignment") },
};
int DaxGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, DaxListing, DaxItems, RTL_NUMBER_OF(DaxItems));
}

static const TCHAR DirtyListing[] =
    _T("---- DIRTY Commands Supported ----\n")
    _T("\n")
    _T("query           Query the dirty bit\n")
    _T("set             Set the dirty bit\n");
static HandlerItem DirtyItems[] =
{
    { DirtyQueryMain, _T("query") },
    { DirtySetMain, _T("set") },
};
int DirtyGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, DirtyListing, DirtyItems, RTL_NUMBER_OF(DirtyItems));
}

static const TCHAR FileListing[] =
    _T("---- FILE Commands Supported ----\n")
    _T("\n")
    _T("createNew                Creates a new file of a specified size\n")
    _T("findBySID                Find a file by security identifier\n")
    _T("layout                   Query all the information available about the file\n")
    _T("optimizeMetadata         Optimize metadata for a file\n")
    _T("queryAllocRanges         Query the allocated ranges for a file\n")
    _T("queryCaseSensitiveInfo   Query the case sensitive information for a directory\n")
    _T("queryEA                  Query the extended attributes (EA) information for a file\n")
    _T("queryExtents             Query the extents for a file\n")
    _T("queryExtentsAndRefCounts Query the extents and their corresponding refcounts for a file\n")
    _T("queryFileID              Queries the file ID of the specified file\n")
    _T("queryFileNameById        Displays a random link name for the file ID\n")
    _T("queryOptimizeMetadata    Query the optimize metadata state for a file\n")
    _T("queryValidData           Queries the valid data length for a file\n")
    _T("setCaseSensitiveInfo     Set the case sensitive information for a directory\n")
    _T("setShortName             Set the short name for a file\n")
    _T("setValidData             Set the valid data length for a file\n")
    _T("setZeroData              Set the zero data for a file\n")
    _T("setEOF                   Sets the end of file for an existing file\n")
    _T("setStrictlySequential    Sets ReFS SMR file as strictly sequential\n");
static HandlerItem FileItems[] =
{
    { NULL, _T("createnew") },
    { NULL, _T("findbysid") },
    { NULL, _T("layout") },
    { NULL, _T("optimizemetadata") },
    { NULL, _T("queryallocranges") },
    { NULL, _T("querycasesensitiveinfo") },
    { NULL, _T("queryea") },
    { NULL, _T("queryextents") },
    { NULL, _T("queryextentsandrefcounts") },
    { NULL, _T("queryfileid") },
    { NULL, _T("queryfilenamebyid") },
    { NULL, _T("queryoptimizemetadata") },
    { NULL, _T("queryvaliddata") },
    { NULL, _T("setcasesensitiveinfo") },
    { NULL, _T("setshortname") },
    { NULL, _T("setvaliddata") },
    { NULL, _T("setzerodata") },
    { NULL, _T("seteof") },
    { NULL, _T("setstrictlysequential") },
};
int FileGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, FileListing, FileItems, RTL_NUMBER_OF(FileItems));
}

static const TCHAR FsinfoListing[] =
    _T("---- FSINFO Commands Supported ----\n")
    _T("\n")
    _T("drives          List all drives\n")
    _T("driveType       Query drive type for a drive\n")
    _T("ntfsInfo        Query NTFS specific volume information\n")
    _T("refsInfo        Query REFS specific volume information\n")
    _T("sectorInfo      Query sector information\n")
    _T("statistics      Query file system statistics\n")
    _T("volumeInfo      Query volume information\n");
static HandlerItem FsinfoItems[] =
{
    { FsInfoDrivesMain, _T("drives") },
    { FsInfoDriveTypeMain, _T("drivetype") },
    { FsInfoNtfsInfoMain, _T("ntfsinfo") },
    { NULL, _T("refsinfo") },
    { NULL, _T("sectorinfo") },
    { FsInfoStatisticsMain, _T("statistics") },
    { FsInfoVolumeInfoMain, _T("volumeinfo") },
};
int FsinfoGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, FsinfoListing, FsinfoItems, RTL_NUMBER_OF(FsinfoItems));
}

static const TCHAR HardlinkListing[] =
    _T("---- HARDLINK Commands Supported ----\n")
    _T("\n")
    _T("create          Create a hardlink\n")
    _T("list            Enumerate hardlinks on a file\n");
static HandlerItem HardlinkItems[] =
{
    { HardLinkCreateMain, _T("create") },
    { NULL, _T("list") },
};
int HardlinkGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, HardlinkListing, HardlinkItems, RTL_NUMBER_OF(HardlinkItems));
}

static const TCHAR ObjectidListing[] =
    _T("---- OBJECTID Commands Supported ----\n")
    _T("\n")
    _T("create          Create the object identifier\n")
    _T("delete          Delete the object identifier\n")
    _T("query           Query the object identifier\n")
    _T("set             Change the object identifier\n");
static HandlerItem ObjectidItems[] =
{
    { NULL, _T("create") },
    { NULL, _T("delete") },
    { NULL, _T("query") },
    { NULL, _T("set") },
};
int ObjectidGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, ObjectidListing, ObjectidItems, RTL_NUMBER_OF(ObjectidItems));
}

static const TCHAR QuotaListing[] =
    _T("---- QUOTA Commands Supported ----\n")
    _T("\n")
    _T("disable         Disable quota tracking and enforcement\n")
    _T("enforce         Enable quota enforcement\n")
    _T("modify          Set disk quota for a user\n")
    _T("query           Query disk quotas\n")
    _T("track           Enable quota tracking\n")
    _T("violations      Display quota violations\n");
static HandlerItem QuotaItems[] =
{
    { NULL, _T("disable") },
    { NULL, _T("enforce") },
    { NULL, _T("modify") },
    { NULL, _T("query") },
    { NULL, _T("track") },
    { NULL, _T("violations") },
};
int QuotaGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, QuotaListing, QuotaItems, RTL_NUMBER_OF(QuotaItems));
}

static const TCHAR RepairListing[] =
    _T("---- REPAIR Commands Supported ----\n")
    _T("\n")
    _T("enumerate      Enumerate the entries of a volume's corruption log\n")
    _T("initiate       Initiate the repair of a file\n")
    _T("query          Query the self healing state of the volume\n")
    _T("set            Set the self healing state of the volume\n")
    _T("state          Query the corruption state of the volume(s)\n")
    _T("wait           Wait for repair(s) to complete\n");
static HandlerItem RepairItems[] =
{
    { NULL, _T("enumerate") },
    { NULL, _T("initiate") },
    { NULL, _T("query") },
    { NULL, _T("set") },
    { NULL, _T("state") },
    { NULL, _T("wait") },
};
int RepairGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, RepairListing, RepairItems, RTL_NUMBER_OF(RepairItems));
}

static const TCHAR ReparsepointListing[] =
    _T("---- REPARSEPOINT Commands Supported ----\n")
    _T("\n")
    _T("delete          Delete a reparse point\n")
    _T("query           Query a reparse point\n");
static HandlerItem ReparsepointItems[] =
{
    { NULL, _T("delete") },
    { NULL, _T("query") },
};
int ReparsepointGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, ReparsepointListing, ReparsepointItems, RTL_NUMBER_OF(ReparsepointItems));
}

static const TCHAR ResourceListing[] =
    _T("---- RESOURCE Commands Supported ----\n")
    _T("\n")
    _T("create          Create a Secondary Transactional Resource Manager\n")
    _T("info            Display information relating to a Transactional Resource Manager\n")
    _T("setAutoReset    Set whether a default Transactional Resource Manager will clean its transactional metadata on next mount\n")
    _T("setAvailable    Set a Transactional Resource Manager to prefer availability over consistency\n")
    _T("setConsistent   Set a Transactional Resource Manager to prefer consistency over availability\n")
    _T("setLog          Change characteristics of a running Transactional Resource Manager\n")
    _T("start           Start a Transactional Resource Manager\n")
    _T("stop            Stop a Transactional Resource Manager\n");
static HandlerItem ResourceItems[] =
{
    { NULL, _T("create") },
    { NULL, _T("info") },
    { NULL, _T("setautoreset") },
    { NULL, _T("setavailable") },
    { NULL, _T("setconsistent") },
    { NULL, _T("setlog") },
    { NULL, _T("start") },
    { NULL, _T("stop") },
};
int ResourceGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, ResourceListing, ResourceItems, RTL_NUMBER_OF(ResourceItems));
}

static const TCHAR SparseListing[] =
    _T("---- SPARSE Commands Supported ----\n")
    _T("\n")
    _T("queryFlag       Query sparse\n")
    _T("queryRange      Query range\n")
    _T("setFlag         Set sparse\n")
    _T("setRange        Set sparse range\n");
static HandlerItem SparseItems[] =
{
    { NULL, _T("queryflag") },
    { NULL, _T("queryrange") },
    { NULL, _T("setflag") },
    { NULL, _T("setrange") },
};
int SparseGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, SparseListing, SparseItems, RTL_NUMBER_OF(SparseItems));
}

static const TCHAR TieringListing[] =
    _T("---- TIERING Commands Supported ----\n")
    _T("\n")
    _T("clearFlags      Disable tiering behavior flags of a volume\n")
    _T("queryFlags      Display the tiering behavior flags of a volume\n")
    _T("regionList      List the regions of a volume and their respective storage tiers\n")
    _T("setFlags        Enable tiering behavior flags of a volume\n")
    _T("tierList        List the storage tiers associated with a volume\n");
static HandlerItem TieringItems[] =
{
    { NULL, _T("clearflags") },
    { NULL, _T("queryflags") },
    { NULL, _T("regionlist") },
    { NULL, _T("setflags") },
    { NULL, _T("tierlist") },
};
int TieringGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, TieringListing, TieringItems, RTL_NUMBER_OF(TieringItems));
}

static const TCHAR TransactionListing[] =
    _T("---- TRANSACTION Commands Supported ----\n")
    _T("\n")
    _T("commit          Commit a specified transaction\n")
    _T("fileinfo        Display transaction information for a specific file\n")
    _T("list            Display currently running transactions\n")
    _T("query           Display information on a specified transaction\n")
    _T("rollback        Rollback a specified transaction\n");
static HandlerItem TransactionItems[] =
{
    { NULL, _T("commit") },
    { NULL, _T("fileinfo") },
    { NULL, _T("list") },
    { NULL, _T("query") },
    { NULL, _T("rollback") },
};
int TransactionGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, TransactionListing, TransactionItems, RTL_NUMBER_OF(TransactionItems));
}

static const TCHAR UsnListing[] =
    _T("---- USN Commands Supported ----\n")
    _T("\n")
    _T("createJournal           Create a USN journal\n")
    _T("deleteJournal           Delete a USN journal\n")
    _T("enableRangeTracking     Enable write range tracking for a volume\n")
    _T("enumData                Enumerate USN data\n")
    _T("queryJournal            Query the USN data for a volume\n")
    _T("readJournal             Reads the USN records in the USN journal\n")
    _T("readData                Read the USN data for a file\n");
static HandlerItem UsnItems[] =
{
    { NULL, _T("createjournal") },
    { NULL, _T("deletejournal") },
    { NULL, _T("enablerangetracking") },
    { NULL, _T("enumdata") },
    { NULL, _T("queryjournal") },
    { NULL, _T("readjournal") },
    { NULL, _T("readdata") },
};
int UsnGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, UsnListing, UsnItems, RTL_NUMBER_OF(UsnItems));
}

static const TCHAR VolumeListing[] =
    _T("---- VOLUME Commands Supported ----\n")
    _T("\n")
    _T("allocationReport      Allocated clusters report\n")
    _T("diskFree              Query the free space of a volume\n")
    _T("dismount              Dismount a volume\n")
    _T("fileLayout            Query all the information available about the file(s)\n")
    _T("flush                 Flush a volume\n")
    _T("list                  List volumes\n")
    _T("queryCluster          Query which file is using a particular cluster\n")
    _T("queryLabel            Query the label for a volume\n")
    _T("queryNumaInfo         Queries the NUMA node for the given volume\n")
    _T("setLabel              Set the label for a volume\n")
    _T("smrGC                 Control SMR Garbage Collection\n")
    _T("smrInfo               Query SMR information\n")
    _T("thinProvisioningInfo  Query thin provisioning info for the given volume\n");
static HandlerItem VolumeItems[] =
{
    { NULL, _T("allocationreport") },
    { VolumeDiskFreeMain, _T("diskfree") },
    { VolumeDismountMain, _T("dismount") },
    { NULL, _T("filelayout") },
    { NULL, _T("flush") },
    { VolumeListMain, _T("list") },
    { NULL, _T("querycluster") },
    { NULL, _T("querylabel") },
    { NULL, _T("querynumainfo") },
    { NULL, _T("setlabel") },
    { NULL, _T("smrgc") },
    { NULL, _T("smrinfo") },
    { NULL, _T("thinprovisioninginfo") },
};
int VolumeGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, VolumeListing, VolumeItems, RTL_NUMBER_OF(VolumeItems));
}

static const TCHAR WimListing[] =
    _T("---- WIM Commands Supported ----\n")
    _T("\n")
    _T("enumFiles           Enumerate WIM backed files\n")
    _T("enumWims            Enumerate backing WIM files\n")
    _T("removeWim           Remove a WIM from backing files\n")
    _T("queryFile           Query the origin of a specific file\n")
    _T("\n");
static HandlerItem WimItems[] =
{
    { NULL, _T("enumfiles") },
    { NULL, _T("enumwims") },
    { NULL, _T("removewim") },
    { NULL, _T("queryfile") },
};
int WimGroupMain(int argc, const TCHAR *argv[])
{
    return RunGroup(argc, argv, WimListing, WimItems, RTL_NUMBER_OF(WimItems));
}

/* captured only by name: its own usage text was not probed (oracle rule: one probe) */
int StoragereserveGroupMain(int argc, const TCHAR *argv[])
{
    return NotImplementedMain(_T("storageReserve"), argc > 1 ? argv[1] : NULL);
}

const TCHAR TopListing[] =
    _T("---- Commands Supported ----\n")
    _T("\n")
    _T("8dot3name         8dot3name management\n")
    _T("behavior          Control file system behavior\n")
    _T("dax               Dax volume management\n")
    _T("dirty             Manage volume dirty bit\n")
    _T("file              File specific commands\n")
    _T("fsInfo            File system information\n")
    _T("hardlink          Hardlink management\n")
    _T("objectID          Object ID management\n")
    _T("quota             Quota management\n")
    _T("repair            Self healing management\n")
    _T("reparsePoint      Reparse point management\n")
    _T("storageReserve    Storage Reserve management\n")
    _T("resource          Transactional Resource Manager management\n")
    _T("sparse            Sparse file control\n")
    _T("tiering           Storage tiering property management\n")
    _T("transaction       Transaction management\n")
    _T("usn               USN management\n")
    _T("volume            Volume management\n")
    _T("wim               Transparent wim hosting management\n");
HandlerItem TopItems[] =
{
    { D8dot3nameGroupMain, _T("8dot3name") },
    { BehaviorGroupMain, _T("behavior") },
    { DaxGroupMain, _T("dax") },
    { DirtyGroupMain, _T("dirty") },
    { FileGroupMain, _T("file") },
    { FsinfoGroupMain, _T("fsinfo") },
    { HardlinkGroupMain, _T("hardlink") },
    { ObjectidGroupMain, _T("objectid") },
    { QuotaGroupMain, _T("quota") },
    { RepairGroupMain, _T("repair") },
    { ReparsepointGroupMain, _T("reparsepoint") },
    { StoragereserveGroupMain, _T("storagereserve") },
    { ResourceGroupMain, _T("resource") },
    { SparseGroupMain, _T("sparse") },
    { TieringGroupMain, _T("tiering") },
    { TransactionGroupMain, _T("transaction") },
    { UsnGroupMain, _T("usn") },
    { VolumeGroupMain, _T("volume") },
    { WimGroupMain, _T("wim") },
};
const int TopItemCount = RTL_NUMBER_OF(TopItems);
