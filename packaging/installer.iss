; Inno Setup script. Build with packaging\build.ps1 (it passes /DAppVersion and /DSourceDir).
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\vhserver"
#endif

[Setup]
AppId={{6F1B3C52-8A0E-4C57-9D55-5D1F2E0B7A11}
AppName=VHServer
AppVersion={#AppVersion}
AppPublisher=vhserver
DefaultDirName={autopf}\VHServer
DefaultGroupName=VHServer
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=VHServer-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
DisableProgramGroupPage=yes
UninstallDisplayName=VHServer
WizardStyle=modern

[Languages]
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
italian.PageTitle=Impostazioni del server
italian.PageText=Scegli come il server si presenta ai client.
italian.NameLabel=Nome del server (visibile nei client):
italian.PortLabel=Porta TCP:
italian.PublicCheck=Apri il firewall anche sulle reti classificate come Pubbliche (sconsigliato)
italian.BadName=Il nome deve avere da 1 a 64 caratteri e non può contenere virgolette o barre rovesce.
italian.BadPort=La porta deve essere un numero tra 1 e 65535.
italian.SecTitle=Sicurezza
italian.SecText=Proteggi l'uso dei dispositivi. Puoi cambiare tutto più tardi con "vhserver password" e "vhserver tls".
italian.PwLabel=Password per usare i dispositivi (vuota = nessuna password):
italian.PwAgainLabel=Ripeti la password:
italian.SslCheck=Cifra le connessioni con SSL (consigliato se usi il server fuori da casa)
italian.SslOnlyCheck=Solo SSL: disattiva la porta non cifrata
italian.PwMismatch=Le due password non coincidono.
italian.PwLength=La password deve avere da 8 a 127 caratteri.
italian.InstallFailed=La configurazione automatica non è riuscita. Apri un terminale come amministratore ed esegui:%n%n"{app}\vhserver.exe" doctor%n%nper vedere cosa manca.
italian.RunDoctor=Controlla la configurazione (vhserver doctor)
english.PageTitle=Server settings
english.PageText=Choose how the server presents itself to clients.
english.NameLabel=Server name (shown in the clients):
english.PortLabel=TCP port:
english.PublicCheck=Also open the firewall on networks classified as Public (not recommended)
english.BadName=The name must be 1 to 64 characters long and cannot contain quotation marks or backslashes.
english.BadPort=The port must be a number between 1 and 65535.
english.SecTitle=Security
english.SecText=Protect the use of the devices. You can change everything later with "vhserver password" and "vhserver tls".
english.PwLabel=Password to use the devices (empty = no password):
english.PwAgainLabel=Repeat the password:
english.SslCheck=Encrypt the connections with SSL (recommended when used away from home)
english.SslOnlyCheck=SSL only: switch the unencrypted port off
english.PwMismatch=The two passwords do not match.
english.PwLength=The password must have 8 to 127 characters.
english.InstallFailed=Automatic configuration did not complete. Open a terminal as administrator and run:%n%n"{app}\vhserver.exe" doctor%n%nto see what is missing.
english.RunDoctor=Check the configuration (vhserver doctor)

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{cm:RunDoctor}"; Filename: "{cmd}"; Parameters: "/k ""{app}\vhserver.exe"" doctor"; WorkingDir: "{app}"

[UninstallRun]
Filename: "{app}\vhserver.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "VHServerUninstall"

[Code]
var
  SettingsPage: TInputQueryWizardPage;
  SecurityPage: TInputQueryWizardPage;
  PublicCheck: TNewCheckBox;
  SslCheck: TNewCheckBox;
  SslOnlyCheck: TNewCheckBox;

function ComputerNameDefault: String;
begin
  Result := GetComputerNameString;
  if Length(Result) > 64 then
    Result := Copy(Result, 1, 64);
end;

procedure InitializeWizard;
begin
  SettingsPage := CreateInputQueryPage(wpSelectDir, CustomMessage('PageTitle'), CustomMessage('PageText'), '');
  SettingsPage.Add(CustomMessage('NameLabel'), False);
  SettingsPage.Add(CustomMessage('PortLabel'), False);
  SettingsPage.Values[0] := ComputerNameDefault;
  SettingsPage.Values[1] := '7575';
  PublicCheck := TNewCheckBox.Create(SettingsPage);
  PublicCheck.Parent := SettingsPage.Surface;
  PublicCheck.Caption := CustomMessage('PublicCheck');
  PublicCheck.Left := 0;
  PublicCheck.Top := SettingsPage.Edits[1].Top + SettingsPage.Edits[1].Height + ScaleY(16);
  PublicCheck.Width := SettingsPage.SurfaceWidth;

  SecurityPage := CreateInputQueryPage(SettingsPage.ID, CustomMessage('SecTitle'), CustomMessage('SecText'), '');
  SecurityPage.Add(CustomMessage('PwLabel'), True);
  SecurityPage.Add(CustomMessage('PwAgainLabel'), True);
  SslCheck := TNewCheckBox.Create(SecurityPage);
  SslCheck.Parent := SecurityPage.Surface;
  SslCheck.Caption := CustomMessage('SslCheck');
  SslCheck.Left := 0;
  SslCheck.Top := SecurityPage.Edits[1].Top + SecurityPage.Edits[1].Height + ScaleY(16);
  SslCheck.Width := SecurityPage.SurfaceWidth;
  SslOnlyCheck := TNewCheckBox.Create(SecurityPage);
  SslOnlyCheck.Parent := SecurityPage.Surface;
  SslOnlyCheck.Caption := CustomMessage('SslOnlyCheck');
  SslOnlyCheck.Left := ScaleX(16);
  SslOnlyCheck.Top := SslCheck.Top + SslCheck.Height + ScaleY(8);
  SslOnlyCheck.Width := SecurityPage.SurfaceWidth - ScaleX(16);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Port: Integer;
  Name, Pw: String;
begin
  Result := True;
  if CurPageID = SettingsPage.ID then
  begin
    Name := Trim(SettingsPage.Values[0]);
    if (Length(Name) < 1) or (Length(Name) > 64) or (Pos('"', Name) > 0) or (Pos('\', Name) > 0) then
    begin
      MsgBox(CustomMessage('BadName'), mbError, MB_OK);
      Result := False;
      Exit;
    end;
    Port := StrToIntDef(SettingsPage.Values[1], 0);
    if (Port < 1) or (Port > 65535) then
    begin
      MsgBox(CustomMessage('BadPort'), mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = SecurityPage.ID then
  begin
    Pw := SecurityPage.Values[0];
    if Pw <> SecurityPage.Values[1] then
    begin
      MsgBox(CustomMessage('PwMismatch'), mbError, MB_OK);
      Result := False;
    end
    else if (Pw <> '') and ((Length(Pw) < 8) or (Length(Pw) > 127)) then
    begin
      MsgBox(CustomMessage('PwLength'), mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Args, PwFile: String;
  Code: Integer;
  Lines: TArrayOfString;
begin
  if CurStep = ssPostInstall then
  begin
    Args := 'install --name "' + Trim(SettingsPage.Values[0]) + '" --port ' + IntToStr(StrToIntDef(SettingsPage.Values[1], 7575));
    if PublicCheck.Checked then
      Args := Args + ' --allow-public';
    if SslOnlyCheck.Checked then
      Args := Args + ' --ssl-only'
    else if SslCheck.Checked then
      Args := Args + ' --ssl';
    PwFile := ExpandConstant('{tmp}\vhpw.txt');
    if SecurityPage.Values[0] <> '' then
    begin
      // handed over in a file (never on the command line); vhserver reads and deletes it
      SetArrayLength(Lines, 1);
      Lines[0] := SecurityPage.Values[0];
      SaveStringsToUTF8File(PwFile, Lines, False);
      Args := Args + ' --password-file "' + PwFile + '"';
    end;
    if (not Exec(ExpandConstant('{app}\vhserver.exe'), Args, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code))
       or (Code <> 0) then
      MsgBox(ExpandConstant(CustomMessage('InstallFailed')), mbError, MB_OK);
    DeleteFile(PwFile);
  end;
end;
