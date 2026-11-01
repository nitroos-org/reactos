
list(APPEND FONT_FILES
    arial.ttf
    arialbd.ttf
    arialbi.ttf
    ariali.ttf
    ariblk.ttf
    Caladea-Bold.ttf
    Caladea-BoldItalic.ttf
    Caladea-Italic.ttf
    Caladea-Regular.ttf
    Carlito-Bold.ttf
    Carlito-BoldItalic.ttf
    Carlito-Italic.ttf
    Carlito-Regular.ttf
    comic.ttf
    comicbd.ttf
    cour.ttf
    courbd.ttf
    courbi.ttf
    couri.ttf
    framd.ttf
    framdit.ttf
    FreeSans.ttf
    FreeSansBold.ttf
    FreeSansBoldOblique.ttf
    FreeSansOblique.ttf
    FSEX301.ttf
    FSEX301-L2.ttf
    georgia.ttf
    georgiab.ttf
    georgiai.ttf
    georgiaz.ttf
    lucon.ttf
    Marlett.ttf
    micross.ttf
    NitroCaptionIcons.ttf
    NotoEmoji-Regular.ttf
    NotoSansKR-Regular.otf
    NotoSansSC-Regular.otf
    NotoSansSymbols2-Regular.ttf
    selawk.ttf
    selawkb.ttf
    selawkl.ttf
    selawksb.ttf
    selawksl.ttf
    pala.ttf
    palab.ttf
    palabi.ttf
    palai.ttf
    SourceSansPro-Regular.ttf
    SourceSansPro-Bold.ttf
    SourceSansPro-BoldIt.ttf
    SourceSansPro-It.ttf
    #ssee874.fon # to be added (CORE-16165 and CORE-16166)
    #ssee1255.fon # to be added (CORE-16165 and CORE-16166)
    #ssee1256.fon # to be added (CORE-16165 and CORE-16166)
    #ssee1257.fon # to be added (CORE-16165 and CORE-16166)
    #sserife.fon # to be added (CORE-16165 and CORE-16166)
    #sserifeg.fon # to be added (CORE-16165 and CORE-16166)
    #sserifer.fon # to be added (CORE-16165 and CORE-16166)
    #sserifet.fon # to be added (CORE-16165 and CORE-16166)
    symbol.ttf
    tahoma.ttf
    tahomabd.ttf
    times.ttf
    timesbd.ttf
    timesbi.ttf
    timesi.ttf
    trebuc.ttf
    trebucbd.ttf
    trebucbi.ttf
    trebucit.ttf
    UniVGA16.ttf
    verdanab.ttf
    verdanaz.ttf
    verdanai.ttf
    verdana.ttf
    #vgaoem.fon # to be added (CORE-17327)
    wingding.ttf)

foreach(item ${FONT_FILES})
    add_cd_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/${item}" DESTINATION reactos/Fonts FOR all)
endforeach(item)

# Licence texts of the open fonts added for script coverage; the OFL and the Apache licence require them to travel with the fonts.
# The file names are unique because setup copies files by their source name.
foreach(item Selawik Carlito Caladea NotoSansCJK NotoSansSymbols2 NotoEmoji)
    add_cd_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/doc/${item}/${item}-LICENSE.txt" DESTINATION reactos/3rdParty FOR all)
endforeach(item)
add_cd_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/doc/Fonts-SOURCES.txt" DESTINATION reactos/3rdParty FOR all)
