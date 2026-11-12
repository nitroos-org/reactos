1 stdcall -noname QueryThemeServices()
2 stdcall -noname OpenThemeFile(wstr wstr wstr ptr long)
3 stdcall -noname CloseThemeFile(ptr)
4 stdcall -noname ApplyTheme(ptr ptr ptr)
37 stdcall BeginBufferedAnimation(ptr ptr ptr long ptr ptr ptr ptr)
38 stdcall BeginBufferedPaint(ptr ptr long ptr ptr)
7 stdcall -noname GetThemeDefaults(wstr wstr long wstr long)
8 stdcall -noname EnumThemes(wstr ptr ptr)
9 stdcall -noname EnumThemeColors(wstr wstr long ptr)
10 stdcall -noname EnumThemeSizes(wstr wstr long ptr)
11 stdcall -noname ParseThemeIniFile(wstr wstr ptr ptr)
39 stdcall BufferedPaintClear(ptr ptr)
13 stdcall -noname DrawNCPreview(ptr long ptr wstr wstr wstr ptr ptr)
14 stub -noname RegisterDefaultTheme
15 stub -noname DumpLoadedThemeToTextFile
16 stdcall -noname OpenThemeDataFromFile(ptr ptr wstr long)
17 stub -noname OpenThemeFileFromData
18 stub -noname GetThemeSysSize96
19 stub -noname GetThemeSysFont96
20 stub -noname SessionAllocate
21 stub -noname SessionFree
22 stub -noname ThemeHooksOn
23 stub -noname ThemeHooksOff
24 stub -noname AreThemeHooksActive
25 stub -noname GetCurrentChangeNumber
26 stub -noname GetNewChangeNumber
27 stub -noname SetGlobalTheme
28 stub -noname GetGlobalTheme
29 stdcall -noname CheckThemeSignature(wstr)
30 stub -noname LoadTheme
31 stub -noname InitUserTheme
32 stub -noname InitUserRegistry
33 stub -noname ReestablishServerConnection
34 stdcall -noname ThemeHooksInstall()
35 stdcall -noname ThemeHooksRemove()
36 stub -noname RefreshThemeForTS
40 stdcall BufferedPaintInit()
41 stdcall BufferedPaintRenderAnimation(ptr ptr)
42 stdcall BufferedPaintSetAlpha(ptr ptr long)
51 stdcall BufferedPaintStopAllAnimations(ptr)
52 stdcall BufferedPaintUnInit()
53 stdcall CloseThemeData(ptr)
43 stdcall -noname ClassicGetSystemMetrics(long)
44 stdcall -noname ClassicSystemParametersInfoA(long long ptr long)
45 stdcall -noname ClassicSystemParametersInfoW(long long ptr long)
46 stdcall -noname ClassicAdjustWindowRectEx(ptr long long long)
47 stdcall DrawThemeBackgroundEx(ptr ptr long long ptr ptr)
48 stdcall -noname GetThemeParseErrorInfo(ptr)
308 stdcall -stub OpenNcThemeData()
307 stdcall -stub IsThemeClassDefined(ptr ptr long long ptr ptr)
57 stdcall DrawThemeBackground(ptr ptr long long ptr ptr)
58 stdcall DrawThemeEdge(ptr ptr long long ptr long long ptr)
59 stdcall DrawThemeIcon(ptr ptr long long ptr ptr long)
70 stdcall DrawThemeParentBackground(ptr ptr ptr)
71 stdcall DrawThemeParentBackgroundEx(ptr ptr long ptr)
89 stdcall DrawThemeText(ptr ptr long long wstr long long long ptr)
103 stdcall DrawThemeTextEx(ptr ptr long long wstr long long ptr ptr)
114 stdcall EnableThemeDialogTexture(ptr long)
129 stdcall EnableTheming(long)
60 stub -noname CreateThemeDataFromObjects
61 stdcall -noname OpenThemeDataEx(ptr wstr long)
62 stub -noname ServerClearStockObjects
63 stub -noname MarkSelection
309 stub ProcessLoadTheme_RunDLLW
65 stdcall -noname SetSystemVisualStyle(wstr wstr wstr long)
312 stub ServiceClearStockObjects
300 stdcall -stub AddThemeAppCompatFlag(ptr long long long ptr)
311 stdcall -stub ResetThemeAppCompatFlags(ptr ptr long long long ptr ptr)
303 stdcall -stub EnumThemeProperties(ptr ptr long long long ptr)
134 stdcall EndBufferedAnimation(ptr long)
140 stdcall EndBufferedPaint(ptr long)
301 stdcall -stub DrawThemeIconEx(ptr long long long ptr)
306 stub IsThemeActiveByPolicy
305 stdcall -stub GetThemeClass(ptr long long long ptr)
313 stdcall -stub ThemeForwardCapturedMouseMessage(ptr long long long wstr long)
302 stdcall -stub EnableServiceConnection(ptr long)
310 stdcall -stub Remote_LoadTheme(ptr long) ; This exits a thread
141 stdcall GetBufferedPaintBits(ptr ptr ptr)
142 stdcall GetBufferedPaintDC(ptr)
143 stdcall GetBufferedPaintTargetDC(ptr)
144 stdcall GetBufferedPaintTargetRect(ptr ptr)
145 stdcall GetCurrentThemeName(wstr long wstr long wstr long)
148 stdcall GetThemeAppProperties()
149 stdcall GetThemeBackgroundContentRect(ptr ptr long long ptr ptr)
150 stdcall GetThemeBackgroundExtent(ptr ptr long long ptr ptr)
151 stdcall GetThemeBackgroundRegion(ptr ptr long long ptr ptr)
304 stub GetThemeBitMap
153 stdcall GetThemeBool(ptr long long long ptr)
154 stdcall GetThemeColor(ptr long long long ptr)
155 stdcall GetThemeDocumentationProperty(wstr wstr wstr long)
156 stdcall GetThemeEnumValue(ptr long long long ptr)
157 stdcall GetThemeFilename(ptr long long long wstr long)
158 stdcall GetThemeFont(ptr ptr long long long ptr)
159 stdcall GetThemeInt(ptr long long long ptr)
160 stdcall GetThemeIntList(ptr long long long ptr)
161 stdcall GetThemeMargins(ptr ptr long long long ptr ptr)
162 stdcall GetThemeMetric(ptr ptr long long long ptr)
163 stdcall GetThemePartSize(ptr ptr long long ptr long ptr)
164 stdcall GetThemePosition(ptr long long long ptr)
165 stdcall GetThemePropertyOrigin(ptr long long long ptr)
166 stdcall GetThemeRect(ptr long long long ptr)
167 stub GetThemeStream
168 stdcall GetThemeString(ptr long long long wstr long)
169 stdcall GetThemeSysBool(ptr long)
170 stdcall GetThemeSysColor(ptr long)
171 stdcall GetThemeSysColorBrush(ptr long)
172 stdcall GetThemeSysFont(ptr long ptr)
173 stdcall GetThemeSysInt(ptr long ptr)
174 stdcall GetThemeSysSize(ptr long)
175 stdcall GetThemeSysString(ptr long wstr long)
176 stdcall GetThemeTextExtent(ptr ptr long long wstr long long ptr ptr)
177 stdcall GetThemeTextMetrics(ptr ptr long long ptr)
179 stdcall GetThemeTransitionDuration(ptr long long long long ptr)
180 stdcall GetWindowTheme(ptr)
181 stdcall HitTestThemeBackground(ptr long long long long ptr long double ptr)
182 stdcall IsAppThemed()
183 stdcall IsCompositionActive()
184 stdcall IsThemeActive()
185 stdcall IsThemeBackgroundPartiallyTransparent(ptr long long)
186 stdcall IsThemeDialogTextureEnabled(ptr)
187 stdcall IsThemePartDefined(ptr long long)
188 stdcall OpenThemeData(ptr wstr)
190 stdcall SetThemeAppProperties(long)
191 stdcall SetWindowTheme(ptr wstr wstr)
192 stdcall SetWindowThemeAttribute(ptr long ptr long)
193 stdcall ThemeInitApiHook(long ptr)

189 stdcall OpenThemeDataForDpi(ptr wstr long) ;win7
5 stdcall -version=0x601+ BeginPanningFeedback(ptr) ;win7
6 stdcall -version=0x601+ EndPanningFeedback(ptr long) ;win7
12 stdcall -version=0x601+ UpdatePanningFeedback(ptr long long long) ;win7
