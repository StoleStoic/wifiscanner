; Inno Setup script: builds SursumWiFiScanner-Setup.exe from the PyInstaller output in dist\SursumWiFiScanner.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "Stole Sursum WiFi Scanner"
#define AppExe "SursumWiFiScanner.exe"

[Setup]
AppId={{6C0F5B8E-6B1C-4E0B-9C55-5A7D3E21B0A4}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Stole Sursum
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Per-user install: no administrator prompt needed.
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=SursumWiFiScanner-Setup
SetupIconFile=sursum.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\dist\SursumWiFiScanner\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autoprograms}\{#AppName} (Demo mode)"; Filename: "{app}\{#AppExe}"; Parameters: "--demo"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Start {#AppName}"; Flags: nowait postinstall skipifsilent
