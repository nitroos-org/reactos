/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     resource
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _DISKMGMT_RESOURCE_H_
#define _DISKMGMT_RESOURCE_H_

#define IDI_DISKMGMT            1
#define IDR_MAINMENU            101
#define IDR_ACCEL               102
#define IDR_POPUP               103
#define IDB_PROP                110
#define IDB_REFRESH             111

/* commands */
#define ID_EXIT                 200
#define ID_REFRESH              201
#define ID_PROPERTIES           202
#define ID_TOP_DISKLIST         210
#define ID_TOP_VOLLIST          211
#define ID_TOP_GRAPH            212
#define ID_BOT_DISKLIST         220
#define ID_BOT_VOLLIST          221
#define ID_BOT_GRAPH            222
#define ID_BOT_HIDDEN           223
#define ID_ABOUT                230

/* actions of the writer */
#define ID_ACT_FIRST            240
#define ID_OPEN                 240
#define ID_EXPLORE              241
#define ID_MARK_ACTIVE          242
#define ID_CHANGE_LETTER        243
#define ID_FORMAT               244
#define ID_DELETE_VOLUME        245
#define ID_DELETE_PARTITION     246
#define ID_NEW_VOLUME           247
#define ID_INIT_DISK            248
#define ID_CONVERT_GPT          249
#define ID_CONVERT_MBR          250
#define ID_RESCAN               251
#define ID_ACT_LAST             262
#define ID_ALL_TASKS            260

/* control ids of the main window */
#define IDC_TOOLBAR             300
#define IDC_STATUSBAR           301
#define IDC_DISKLIST            302
#define IDC_VOLLIST             303
#define IDC_GRAPH               306

/* property pages */
#define IDD_VOL_GENERAL         400
#define IDD_VOL_PARTITION       401
#define IDD_DISK_GENERAL        402
#define IDD_DISK_VOLUMES        403

#define IDC_VOL_ICON            410
#define IDC_VOL_NAME            411
#define IDC_VOL_TYPE            412
#define IDC_VOL_FS              413
#define IDC_VOL_USED_BYTES      414
#define IDC_VOL_USED_HUMAN      415
#define IDC_VOL_FREE_BYTES      416
#define IDC_VOL_FREE_HUMAN      417
#define IDC_VOL_CAP_BYTES       418
#define IDC_VOL_CAP_HUMAN       419
#define IDC_VOL_PIE             420
#define IDC_VOL_DRIVE           421
#define IDC_VOL_USED_COLOR      422
#define IDC_VOL_FREE_COLOR      423
#define IDC_VOL_NOTE            424
#define IDC_VOL_USED_LABEL      425
#define IDC_VOL_FREE_LABEL      426

#define IDC_PROP_LIST           430

#define IDC_DISK_ICON           440
#define IDC_DISK_NAME           441
#define IDC_DISK_DEVTYPE        442
#define IDC_DISK_LOCATION       443
#define IDC_DISK_STATUS         444

#define IDC_DV_DISK             450
#define IDC_DV_TYPE             451
#define IDC_DV_STATUS           452
#define IDC_DV_STYLE            453
#define IDC_DV_CAPACITY         454
#define IDC_DV_UNALLOC          455
#define IDC_DV_RESERVED         456
#define IDC_DV_LIST             457
#define IDC_DV_PROPERTIES       458

/* strings */
#define IDS_APPTITLE            500
#define IDS_COL_VOLUME          501
#define IDS_COL_LAYOUT          502
#define IDS_COL_TYPE            503
#define IDS_COL_FS              504
#define IDS_COL_STATUS          505
#define IDS_COL_CAPACITY        506
#define IDS_COL_FREE            507
#define IDS_COL_PCTFREE         508
#define IDS_COL_FAULT           509
#define IDS_COL_OVERHEAD        510
#define IDS_COL_DISK            511
#define IDS_COL_UNALLOC         512
#define IDS_COL_DEVTYPE         513
#define IDS_COL_STYLE           514
#define IDS_LEGEND_UNALLOC      520
#define IDS_LEGEND_PRIMARY      521
#define IDS_LEGEND_EXTENDED     522
#define IDS_LEGEND_FREE         523
#define IDS_LEGEND_LOGICAL      524
#define IDS_STATUS_COUNTS       530
#define IDS_ABOUT_TEXT          532
#define IDS_TIP_PROPERTIES      533
#define IDS_TIP_REFRESH         534
#define IDS_STYLE_MBR_SHORT     535
#define IDS_STYLE_GPT_SHORT     536
#define IDS_PROP_VOLUME_TITLE   540
#define IDS_PROP_PARTITION_TITLE 541
#define IDS_PROP_DISK_TITLE     542
#define IDS_PAGE_GENERAL        543
#define IDS_PAGE_PARTITION      544
#define IDS_PAGE_VOLUMES        545
#define IDS_TYPE_LOCAL          546
#define IDS_TYPE_CDROM          547
#define IDS_TYPE_REMOVABLE      548
#define IDS_NOTE_NOFS           549
#define IDS_DRIVE_FMT           550
#define IDS_DEVTYPE_DISK        551
#define IDS_LOCATION_FMT        552
#define IDS_STYLE_MBR           553
#define IDS_STYLE_GPT           554
#define IDS_STYLE_RAW           555
#define IDS_COL_PROPERTY        556
#define IDS_COL_VALUE           557
#define IDS_COL_VOL_NAME        558
#define IDS_COL_VOL_CAP         559
#define IDS_MB_FMT              560
#define IDS_YES                 561
#define IDS_NO                  562
#define IDS_PROP_DISK           563
#define IDS_PROP_PARTNUM        564
#define IDS_PROP_STYLE          565
#define IDS_PROP_TYPE           566
#define IDS_PROP_OFFSET         567
#define IDS_PROP_LENGTH         568
#define IDS_PROP_ACTIVE         569
#define IDS_PROP_VOLGUID        570
#define IDS_PROP_PATHS          571
#define IDS_PROP_PARTID         572
#define IDS_PROP_PARTNAME       573
#define IDS_PROP_STATUS         574
#define IDS_PROP_LABEL          575
#define IDS_BYTES_FMT           576
#define IDS_NOT_AVAILABLE       579

/* dialogs of the actions */
#define IDD_INITDISK            600
#define IDD_LETTER              602
#define IDD_PICKLETTER          603
#define IDD_FORMAT              604
#define IDD_PROGRESS            605

#define IDC_ID_TEXT             610
#define IDC_ID_MBR              611
#define IDC_ID_GPT              612


#define IDC_CL_VOLUME           630
#define IDC_CL_LIST             631
#define IDC_CL_ADD              632
#define IDC_CL_CHANGE           633
#define IDC_CL_REMOVE           634

#define IDC_PL_LETTER_RADIO     640
#define IDC_PL_LETTER           641
#define IDC_PL_FOLDER_RADIO     642
#define IDC_PL_FOLDER           643

#define IDC_FM_LABEL            651
#define IDC_FM_FS               652
#define IDC_FM_CLUSTER          653
#define IDC_FM_QUICK            654

#define IDC_PR_TEXT             660
#define IDC_PR_BAR              661

/* strings of the actions */
#define IDS_ACT_OPEN            600
#define IDS_ACT_EXPLORE         601
#define IDS_ACT_ACTIVE          602
#define IDS_ACT_LETTER          603
#define IDS_ACT_FORMAT          604
#define IDS_ACT_DELETE_VOLUME   605
#define IDS_ACT_DELETE_PARTITION 606
#define IDS_ACT_NEW             607
#define IDS_ACT_INIT            608
#define IDS_ACT_GPT             609
#define IDS_ACT_MBR             610
#define IDS_ACT_RESCAN          611
#define IDS_ACT_PROPERTIES      612
#define IDS_ACT_ALL_TASKS       613
#define IDS_CONFIRM_TITLE       620
#define IDS_CONFIRM_DELETE      621
#define IDS_CONFIRM_FORMAT      622
#define IDS_CONFIRM_ACTIVE      623
#define IDS_CONFIRM_CONVERT     624
#define IDS_CONFIRM_LETTER      625
#define IDS_CONFIRM_FORCE       626
#define IDS_CONFIRM_REMOVE_PATH 627
#define IDS_ERROR_TITLE         630
#define IDS_ERR_GENERIC         631
#define IDS_ERR_FORMAT          632
#define IDS_ERR_NO_PROVIDER     633
#define IDS_ERR_IN_USE          634
#define IDS_ERR_NOT_EMPTY       635
#define IDS_ERR_LAYOUT          636
#define IDS_ERR_NO_VOLUME       637
#define IDS_ERR_NOT_SUPPORTED   638
#define IDS_ERR_PROTECTED       639
#define IDS_ERR_FORMAT_CODE     640
#define IDS_FORMAT_DONE         641
#define IDS_FORMATTING          642
#define IDS_WORKING             643
#define IDS_ERR_CHANGED         644
#define IDS_ERR_UNREADABLE      645
#define IDS_ERR_TYPE_NOT_UPDATED 646
#define IDS_ERR_VERIFY_FAILED   647
#define IDS_ERR_RESTORE_FAILED  648
#define IDS_NV_INFO_FMT         650
#define IDS_NV_NO_LETTER        651
#define IDS_NV_NO_FORMAT        652
#define IDS_NV_SIZE_RANGE       653
#define IDS_NV_LABEL_DEFAULT    654
#define IDS_NV_NOTE_EXTENDED    655
#define IDS_NV_NOTE_RESERVED    656
#define IDS_NV_NOTE_LOGICAL     657
#define IDS_NV_TITLE            658
#define IDS_NV_CREATED_NO_VOLUME 659
#define IDS_ID_TEXT_FMT         660
#define IDS_FM_CLUSTER_DEFAULT  661
#define IDS_FM_TITLE            662
#define IDS_FM_VOLUME_FMT       663
#define IDS_CL_TITLE            664
#define IDS_PL_BAD_FOLDER       665
#define IDS_PL_NO_LETTER_FREE   666
#define IDS_CL_NOTHING          667
#define IDS_PROP_LABEL_FAILED   668
#define IDS_PL_FOLDER_PATH      669
#define IDS_ID_TITLE            670
#define IDS_PL_NO_REPARSE       671
#define IDS_ERR_PATHS_NOT_RESTORED 890
#define IDS_PL_FOLDER_TOO_LONG  891


/* the Windows 7 style dialogs and wizards */
#define IDC_ID_LIST             613
#define IDC_ID_NOTE             614
#define IDC_FM_COMPRESS         655
#define IDC_CL_TEXT             635
#define IDC_PL_BROWSE           644
#define IDC_PL_TEXT             645
#define IDC_SH_BEFORE           670
#define IDC_SH_AVAIL            671
#define IDC_SH_AMOUNT           672
#define IDC_SH_SPIN             673
#define IDC_SH_AFTER            674
#define IDC_SH_NOTE             675
#define IDC_SH_ICON             676

#define IDD_NVW_WELCOME         700
#define IDC_NVW_TITLE           701
#define IDD_NVW_SIZE            710
#define IDC_NV_MAX              711
#define IDC_NV_MIN              712
#define IDC_NV_SIZE             713
#define IDC_NV_SPIN             714
#define IDD_NVW_LETTER          720
#define IDC_NL_RADIO_LETTER     721
#define IDC_NL_LETTER           722
#define IDC_NL_RADIO_FOLDER     723
#define IDC_NL_FOLDER           724
#define IDC_NL_BROWSE           725
#define IDC_NL_RADIO_NONE       726
#define IDD_NVW_FORMAT          730
#define IDC_NF_RADIO_NO         731
#define IDC_NF_RADIO_YES        732
#define IDC_NF_FS               733
#define IDC_NF_CLUSTER          734
#define IDC_NF_LABEL            735
#define IDC_NF_QUICK            736
#define IDC_NF_COMPRESS         737
#define IDD_NVW_FINISH          750
#define IDC_NVW_FTITLE          751
#define IDC_NVW_SUMMARY         752

#define IDD_EXW_WELCOME         760
#define IDC_EXW_TITLE           761
#define IDD_EXW_DISKS           770
#define IDC_EX_AVAIL            771
#define IDC_EX_SELECTED         772
#define IDC_EX_ADD              773
#define IDC_EX_REMOVE           774
#define IDC_EX_REMOVEALL        775
#define IDC_EX_TOTAL            776
#define IDC_EX_MAX              777
#define IDC_EX_AMOUNT           778
#define IDC_EX_SPIN             779
#define IDD_EXW_FINISH          790
#define IDC_EXW_FTITLE          791
#define IDC_EX_SUMMARY          792

#define ID_EXTEND_VOLUME        252
#define ID_SHRINK_VOLUME        253
#define ID_ADD_MIRROR           254
#define ID_NEW_SPANNED          255
#define ID_NEW_STRIPED          256
#define ID_NEW_MIRRORED         257
#define ID_NEW_RAID5            258
#define ID_CONVERT_DYNAMIC      259
#define ID_OFFLINE              261
#define ID_HELP_TOPIC           262

#define IDB_WIZ_WATERMARK       112
#define IDB_WIZ_HEADER          113
#define IDD_SHRINK              606

/* menu items of the actions that only an unsupported feature or a missing driver can take away */
#define IDS_ACT_EXTEND          800
#define IDS_ACT_SHRINK          801
#define IDS_ACT_ADD_MIRROR      802
#define IDS_ACT_SPANNED         803
#define IDS_ACT_STRIPED         804
#define IDS_ACT_MIRRORED        805
#define IDS_ACT_RAID5           806
#define IDS_ACT_DYNAMIC         807
#define IDS_ACT_OFFLINE         808
#define IDS_ACT_HELP            809

/* why a menu item is greyed, shown in the status bar */
#define IDS_WHY_NO_SELECTION    820
#define IDS_WHY_NO_HELP         821
#define IDS_WHY_NO_DYNAMIC      822
#define IDS_WHY_NO_OFFLINE      823
#define IDS_WHY_DISK_STATE      824
#define IDS_WHY_NO_FS           825
#define IDS_WHY_NO_PATH         826
#define IDS_WHY_NOT_PRIMARY     827
#define IDS_WHY_ALREADY_ACTIVE  828
#define IDS_WHY_NO_VOLUME       829
#define IDS_WHY_PROTECTED       830
#define IDS_WHY_EXTENDED_USED   831
#define IDS_WHY_NO_SPACE        832
#define IDS_WHY_EXTEND_FS       833
#define IDS_WHY_SHRINK_FS       834
#define IDS_WHY_NO_GAP_BEHIND   835
#define IDS_WHY_EXTEND_DRIVER   836
#define IDS_WHY_SHRINK_DRIVER   837
#define IDS_WHY_INITIALIZED     838
#define IDS_WHY_HAS_PARTITIONS  839

#define IDS_CONFIRM_DELETE_TITLE      850
#define IDS_CONFIRM_DELETE_PART_TITLE 851
#define IDS_CONFIRM_DELETE_PART       852

#define IDS_PL_ADD_TEXT         855
#define IDS_PL_CHANGE_TEXT      856
#define IDS_PL_BROWSE           857
#define IDS_SH_QUERYING         858
#define IDS_SH_NOTHING          859

#define IDS_NVW_CAPTION         860
#define IDS_NVW_SIZE_TITLE      861
#define IDS_NVW_SIZE_SUB        862
#define IDS_NVW_LETTER_TITLE    863
#define IDS_NVW_LETTER_SUB      864
#define IDS_NVW_FORMAT_TITLE    865
#define IDS_NVW_FORMAT_SUB      866
#define IDS_NS_TYPE             867
#define IDS_NS_DISK             868
#define IDS_NS_SIZE             869
#define IDS_NS_PATH             870
#define IDS_NS_NONE             871
#define IDS_NS_FS               872
#define IDS_NS_ALLOC            873
#define IDS_NS_LABEL            874
#define IDS_NS_QUICK            875
#define IDS_EXW_CAPTION         876
#define IDS_EXW_DISKS_TITLE     877
#define IDS_EXW_DISKS_SUB       878
#define IDS_EX_DISK             879
#define IDS_ERR_EXTEND_PARTIAL  880
#define IDS_ERR_SHRINK_PARTIAL  881

#endif
