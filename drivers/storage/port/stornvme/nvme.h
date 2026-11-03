/*
 * PROJECT:         ReactOS NVMe Storport Miniport Driver
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         NVM Express controller registers and data structures
 * COPYRIGHT:       Copyright 2026 Tomas Srnka
 *
 * Written from the public NVM Express Base Specification (revision 1.4) only.
 * No third-party source code was used.
 */

#pragma once

#include <pshpack1.h>

/* Controller registers (BAR0), NVMe 1.4 section 3.1 */
#define NVME_REG_CAP        0x0000  /* Controller Capabilities, 64 bit */
#define NVME_REG_VS         0x0008  /* Version */
#define NVME_REG_INTMS      0x000C  /* Interrupt Mask Set */
#define NVME_REG_INTMC      0x0010  /* Interrupt Mask Clear */
#define NVME_REG_CC         0x0014  /* Controller Configuration */
#define NVME_REG_CSTS       0x001C  /* Controller Status */
#define NVME_REG_NSSR       0x0020  /* NVM Subsystem Reset */
#define NVME_REG_AQA        0x0024  /* Admin Queue Attributes */
#define NVME_REG_ASQ        0x0028  /* Admin Submission Queue Base Address, 64 bit */
#define NVME_REG_ACQ        0x0030  /* Admin Completion Queue Base Address, 64 bit */
#define NVME_REG_DOORBELL   0x1000  /* First doorbell */

/* CAP fields (on the 64-bit value) */
#define NVME_CAP_MQES(c)    ((ULONG)((c) & 0xFFFF))             /* 0's based */
#define NVME_CAP_CQR(c)     ((ULONG)(((c) >> 16) & 0x1))
#define NVME_CAP_TO(c)      ((ULONG)(((c) >> 24) & 0xFF))       /* 500 ms units */
#define NVME_CAP_DSTRD(c)   ((ULONG)(((c) >> 32) & 0xF))
#define NVME_CAP_CSS(c)     ((ULONG)(((c) >> 37) & 0xFF))
#define NVME_CAP_MPSMIN(c)  ((ULONG)(((c) >> 48) & 0xF))
#define NVME_CAP_MPSMAX(c)  ((ULONG)(((c) >> 52) & 0xF))

#define NVME_CAP_CSS_NVM    0x01

/* CC fields */
#define NVME_CC_EN              0x00000001
#define NVME_CC_CSS_NVM         (0 << 4)
#define NVME_CC_MPS(n)          ((ULONG)(n) << 7)
#define NVME_CC_AMS_RR          (0 << 11)
#define NVME_CC_SHN_MASK        (3 << 14)
#define NVME_CC_SHN_NORMAL      (1 << 14)
#define NVME_CC_SHN_ABRUPT      (2 << 14)
#define NVME_CC_IOSQES(n)       ((ULONG)(n) << 16)
#define NVME_CC_IOCQES(n)       ((ULONG)(n) << 20)

/* CSTS fields */
#define NVME_CSTS_RDY           0x00000001
#define NVME_CSTS_CFS           0x00000002
#define NVME_CSTS_SHST_MASK     0x0000000C
#define NVME_CSTS_SHST_NORMAL   0x00000000
#define NVME_CSTS_SHST_OCCURING 0x00000004
#define NVME_CSTS_SHST_COMPLETE 0x00000008

/* Admin command opcodes */
#define NVME_ADMIN_DELETE_SQ        0x00
#define NVME_ADMIN_CREATE_SQ        0x01
#define NVME_ADMIN_GET_LOG_PAGE     0x02
#define NVME_ADMIN_DELETE_CQ        0x04
#define NVME_ADMIN_CREATE_CQ        0x05
#define NVME_ADMIN_IDENTIFY         0x06
#define NVME_ADMIN_ABORT            0x08
#define NVME_ADMIN_SET_FEATURES     0x09
#define NVME_ADMIN_GET_FEATURES     0x0A

/* NVM command set opcodes */
#define NVME_CMD_FLUSH              0x00
#define NVME_CMD_WRITE              0x01
#define NVME_CMD_READ               0x02
#define NVME_CMD_WRITE_ZEROES       0x08
#define NVME_CMD_DSM                0x09

/* Identify CNS values */
#define NVME_CNS_NAMESPACE          0x00
#define NVME_CNS_CONTROLLER         0x01
#define NVME_CNS_ACTIVE_NS_LIST     0x02

/* Feature identifiers */
#define NVME_FEAT_POWER_MGMT        0x02
#define NVME_FEAT_VOLATILE_WC       0x06
#define NVME_FEAT_NUM_QUEUES        0x07

/* Read/Write CDW12 */
#define NVME_RW_FUA                 (1UL << 30)

/* Dataset Management CDW11 */
#define NVME_DSM_ATTR_DEALLOCATE    (1UL << 2)

/* Identify Controller ONCS bits */
#define NVME_ONCS_DSM               0x0004
#define NVME_ONCS_WRITE_ZEROES      0x0008

/* Identify Controller VWC */
#define NVME_VWC_PRESENT            0x01

/* Submission queue entry, 64 bytes */
typedef struct _NVME_COMMAND
{
    union
    {
        struct
        {
            UCHAR Opcode;
            UCHAR Flags;                /* FUSE[1:0], PSDT[7:6] */
            USHORT CommandId;
        };
        ULONG Cdw0;
    };
    ULONG Nsid;
    ULONG Cdw2;
    ULONG Cdw3;
    ULONGLONG Mptr;
    ULONGLONG Prp1;
    ULONGLONG Prp2;
    ULONG Cdw10;
    ULONG Cdw11;
    ULONG Cdw12;
    ULONG Cdw13;
    ULONG Cdw14;
    ULONG Cdw15;
} NVME_COMMAND, *PNVME_COMMAND;

C_ASSERT(sizeof(NVME_COMMAND) == 64);

/* Completion queue entry, 16 bytes */
typedef struct _NVME_COMPLETION
{
    ULONG Dw0;
    ULONG Dw1;
    USHORT SqHead;
    USHORT SqId;
    USHORT CommandId;
    USHORT Status;              /* P[0], SC[8:1], SCT[11:9], CRD[13:12], M[14], DNR[15] */
} NVME_COMPLETION, *PNVME_COMPLETION;

C_ASSERT(sizeof(NVME_COMPLETION) == 16);

#define NVME_CQE_PHASE(s)       ((s) & 1)
#define NVME_CQE_SC(s)          (((s) >> 1) & 0xFF)
#define NVME_CQE_SCT(s)         (((s) >> 9) & 0x7)
#define NVME_CQE_DNR(s)         (((s) >> 15) & 0x1)

/* Status code types */
#define NVME_SCT_GENERIC            0
#define NVME_SCT_COMMAND_SPECIFIC   1
#define NVME_SCT_MEDIA              2
#define NVME_SCT_PATH               3

/* Generic command status */
#define NVME_SC_SUCCESS                 0x00
#define NVME_SC_INVALID_OPCODE          0x01
#define NVME_SC_INVALID_FIELD           0x02
#define NVME_SC_CID_CONFLICT            0x03
#define NVME_SC_DATA_TRANSFER_ERROR     0x04
#define NVME_SC_POWER_LOSS_ABORT        0x05
#define NVME_SC_INTERNAL_ERROR          0x06
#define NVME_SC_ABORT_REQUESTED         0x07
#define NVME_SC_ABORT_SQ_DELETED        0x08
#define NVME_SC_ABORT_FUSED_FAIL        0x09
#define NVME_SC_ABORT_FUSED_MISSING     0x0A
#define NVME_SC_INVALID_NAMESPACE       0x0B
#define NVME_SC_COMMAND_SEQUENCE_ERROR  0x0C
#define NVME_SC_FORMAT_IN_PROGRESS      0x84
#define NVME_SC_LBA_OUT_OF_RANGE        0x80
#define NVME_SC_CAPACITY_EXCEEDED       0x81
#define NVME_SC_NAMESPACE_NOT_READY     0x82
#define NVME_SC_RESERVATION_CONFLICT    0x83

/* Command specific status */
#define NVME_SC_ATTEMPTED_WRITE_RO      0x82    /* Attempted write to read only range */
#define NVME_SC_NS_WRITE_PROTECTED      0x20

/* Media and data integrity errors */
#define NVME_SC_WRITE_FAULT             0x80
#define NVME_SC_UNRECOVERED_READ        0x81
#define NVME_SC_GUARD_CHECK             0x82
#define NVME_SC_APPTAG_CHECK            0x83
#define NVME_SC_REFTAG_CHECK            0x84
#define NVME_SC_COMPARE_FAILURE         0x85
#define NVME_SC_ACCESS_DENIED           0x86
#define NVME_SC_DEALLOCATED_LBA         0x87

/* Identify Controller data structure (4096 bytes), only the fields this driver uses */
typedef struct _NVME_IDENTIFY_CONTROLLER
{
    USHORT Vid;                 /* 0 */
    USHORT Ssvid;               /* 2 */
    UCHAR Sn[20];               /* 4 */
    UCHAR Mn[40];               /* 24 */
    UCHAR Fr[8];                /* 64 */
    UCHAR Rab;                  /* 72 */
    UCHAR Ieee[3];              /* 73 */
    UCHAR Cmic;                 /* 76 */
    UCHAR Mdts;                 /* 77 */
    USHORT Cntlid;              /* 78 */
    ULONG Ver;                  /* 80 */
    ULONG Rtd3r;                /* 84 */
    ULONG Rtd3e;                /* 88 */
    ULONG Oaes;                 /* 92 */
    ULONG Ctratt;               /* 96 */
    UCHAR Reserved100[156];     /* 100 */
    USHORT Oacs;                /* 256 */
    UCHAR Acl;                  /* 258 */
    UCHAR Aerl;                 /* 259 */
    UCHAR Frmw;                 /* 260 */
    UCHAR Lpa;                  /* 261 */
    UCHAR Elpe;                 /* 262 */
    UCHAR Npss;                 /* 263 */
    UCHAR Avscc;                /* 264 */
    UCHAR Apsta;                /* 265 */
    UCHAR Reserved266[246];     /* 266 */
    UCHAR Sqes;                 /* 512 */
    UCHAR Cqes;                 /* 513 */
    USHORT Maxcmd;              /* 514 */
    ULONG Nn;                   /* 516 */
    USHORT Oncs;                /* 520 */
    USHORT Fuses;               /* 522 */
    UCHAR Fna;                  /* 524 */
    UCHAR Vwc;                  /* 525 */
    USHORT Awun;                /* 526 */
    USHORT Awupf;               /* 528 */
    UCHAR Nvscc;                /* 530 */
    UCHAR Nwpc;                 /* 531 */
    USHORT Acwu;                /* 532 */
    USHORT Reserved534;         /* 534 */
    ULONG Sgls;                 /* 536 */
    UCHAR Reserved540[3556];    /* 540 */
} NVME_IDENTIFY_CONTROLLER, *PNVME_IDENTIFY_CONTROLLER;

C_ASSERT(FIELD_OFFSET(NVME_IDENTIFY_CONTROLLER, Oacs) == 256);
C_ASSERT(FIELD_OFFSET(NVME_IDENTIFY_CONTROLLER, Sqes) == 512);
C_ASSERT(FIELD_OFFSET(NVME_IDENTIFY_CONTROLLER, Vwc) == 525);
C_ASSERT(sizeof(NVME_IDENTIFY_CONTROLLER) == 4096);

typedef struct _NVME_LBA_FORMAT
{
    USHORT Ms;                  /* Metadata size */
    UCHAR Lbads;                /* LBA data size, 2^n */
    UCHAR Rp;                   /* Relative performance [1:0] */
} NVME_LBA_FORMAT, *PNVME_LBA_FORMAT;

/* Identify Namespace data structure (4096 bytes) */
typedef struct _NVME_IDENTIFY_NAMESPACE
{
    ULONGLONG Nsze;             /* 0 */
    ULONGLONG Ncap;             /* 8 */
    ULONGLONG Nuse;             /* 16 */
    UCHAR Nsfeat;               /* 24 */
    UCHAR Nlbaf;                /* 25 */
    UCHAR Flbas;                /* 26 */
    UCHAR Mc;                   /* 27 */
    UCHAR Dpc;                  /* 28 */
    UCHAR Dps;                  /* 29 */
    UCHAR Nmic;                 /* 30 */
    UCHAR Rescap;               /* 31 */
    UCHAR Fpi;                  /* 32 */
    UCHAR Dlfeat;               /* 33 */
    USHORT Nawun;               /* 34 */
    USHORT Nawupf;              /* 36 */
    USHORT Nacwu;               /* 38 */
    USHORT Nabsn;               /* 40 */
    USHORT Nabo;                /* 42 */
    USHORT Nabspf;              /* 44 */
    USHORT Noiob;               /* 46 */
    UCHAR Nvmcap[16];           /* 48 */
    USHORT Npwg;                /* 64 */
    USHORT Npwa;                /* 66 */
    USHORT Npdg;                /* 68 */
    USHORT Npda;                /* 70 */
    USHORT Nows;                /* 72 */
    UCHAR Reserved74[30];       /* 74 */
    UCHAR Nguid[16];            /* 104 */
    UCHAR Eui64[8];             /* 120 */
    NVME_LBA_FORMAT Lbaf[16];   /* 128 */
    UCHAR Reserved192[3904];    /* 192 */
} NVME_IDENTIFY_NAMESPACE, *PNVME_IDENTIFY_NAMESPACE;

C_ASSERT(FIELD_OFFSET(NVME_IDENTIFY_NAMESPACE, Nguid) == 104);
C_ASSERT(FIELD_OFFSET(NVME_IDENTIFY_NAMESPACE, Lbaf) == 128);
C_ASSERT(sizeof(NVME_IDENTIFY_NAMESPACE) == 4096);

#define NVME_NSFEAT_THIN        0x01
#define NVME_FLBAS_INDEX(f)     ((f) & 0x0F)
#define NVME_FLBAS_EXTENDED     0x10

/* Dataset Management range, 16 bytes */
typedef struct _NVME_DSM_RANGE
{
    ULONG Attributes;
    ULONG LengthInLba;
    ULONGLONG StartingLba;
} NVME_DSM_RANGE, *PNVME_DSM_RANGE;

C_ASSERT(sizeof(NVME_DSM_RANGE) == 16);

#include <poppack.h>
