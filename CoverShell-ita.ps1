<#
.SYNOPSIS
Una GUI (basata su Windows Forms) per eseguire alcuni utili comandi e funzioni in PowerShell.
.DESCRIPTION
Una interfaccia grafica mostrerà pulsanti, campi da compilare e menu a tendina per velocizzare molte operazioni, come: controllare le performance dell'host e della rete, comparare e ricercare file nelle cartelle, dividere file, creare password, ricorrere a scanner online per virus, sanificare volumi, etc.
.LINK
https://github.com/Zigul1/CoverShell
#>

# Load the .NET System.Windows.Forms class
Add-Type -AssemblyName System.Windows.Forms

# Minimize the shell
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 6)

#create the screen form-window that will contain everything
$main_form = New-Object System.Windows.Forms.Form

# Set appearence properties of the form:
$main_form.Text ='CoverShell'
$main_form.Opacity = 0.95
$main_form.Size = New-Object System.Drawing.Size(925,680)
$main_form.BackColor = "#120614"
$main_form.ForeColor = "#ffffff"
$main_form.StartPosition = "CenterScreen"
$main_form.TopMost = $false
$main_form.FormBorderStyle = "FixedSingle"
$main_form.MaximizeBox = $false
$main_form.MinimizeBox = $false

# Create Label for "contact"
$LabelC = New-Object System.Windows.Forms.Label
$LabelC.Text = "contatti: zigul1@protonmail.com"
$LabelC.Font = "Verdana, 9"
$LabelC.Location = New-Object System.Drawing.Point(10,625)
$LabelC.ForeColor = "#a354b0"
$LabelC.Size = New-Object System.Drawing.Size(210,15)
$main_form.Controls.Add($LabelC)

# Create Label for "version"
$LabelV = New-Object System.Windows.Forms.Label
$LabelV.Text = "v. 1.0.1"
$LabelV.Font = "Verdana, 9"
$LabelV.Location = New-Object System.Drawing.Point(850,625)
$LabelV.ForeColor = "#ffffff"
$LabelV.Size = New-Object System.Drawing.Size(145,15)
$main_form.Controls.Add($LabelV)



###### T A B 1 

# Create Label for TAB1
$LabelT1 = New-Object System.Windows.Forms.Label
$LabelT1.Text = "       SISTEMA"
$LabelT1.Font = [System.Drawing.Font]::new("Arial", 12, [System.Drawing.FontStyle]::Bold)
$LabelT1.Location = New-Object System.Drawing.Point(5,15)
$LabelT1.ForeColor = "#ffb91a"
$LabelT1.BackColor = "#101c28"
$LabelT1.Size = New-Object System.Drawing.Size(145,20)
$main_form.Controls.Add($LabelT1)

# Create TAB1
$PanelT1 = New-Object System.Windows.Forms.Panel
$PanelT1.Location = New-Object System.Drawing.Point(5,35)
$PanelT1.Size = New-Object System.Drawing.Size(900,590)
$PanelT1.BackColor = "#101c28"
$main_form.Controls.Add($PanelT1)


### P A N E L  1

# Create Label for PANEL 1
$LabelT11 = New-Object System.Windows.Forms.Label
$LabelT11.Text = " INFO" #"   INFO"
$LabelT11.Font = "Verdana, 11"
$LabelT11.Location = New-Object System.Drawing.Point(0,40)
$LabelT11.ForeColor = "#ebed31"
$LabelT11.BackColor = "#434c56"
$LabelT11.Size = New-Object System.Drawing.Size(145,20)
$PanelT1.Controls.Add($LabelT11)

# Create Panel
$PanelT11 = New-Object System.Windows.Forms.Panel
$PanelT11.Location = New-Object System.Drawing.Point(145,15)
$PanelT11.Size = New-Object System.Drawing.Size(900,590)
$PanelT11.BackColor = "#434c56"
$PanelT1.Controls.Add($PanelT11)

# Create a Label to signal when the Panel is selected
$Label1_1 = New-Object System.Windows.Forms.Label
$Label1_1.Text = "►"
$Label1_1.Font = "Verdana, 24"
$Label1_1.Location = New-Object System.Drawing.Point(125,-10)
$Label1_1.AutoSize = $true
$Label1_1.ForeColor = "#ebed31"
$LabelT11.Controls.Add($Label1_1)

# Create a Label to introduce the Button1 action
$Label111 = New-Object System.Windows.Forms.Label
$Label111.Text = "Riepilogo dell'ambiente hardware/software"
$Label111.Font = "Verdana, 11"
$Label111.Location = New-Object System.Drawing.Point(20,35)
$Label111.AutoSize = $true
$PanelT11.Controls.Add($Label111)

# Place the button
$Button111 = New-Object System.Windows.Forms.Button
$Button111.Location = New-Object System.Drawing.Point(20,65)
$Button111.Size = New-Object System.Drawing.Size(200,45)
$Button111.Text = "Informazioni di sistema"
$Button111.Font = "Verdana, 11"
$Button111.BackColor = "#101c28"
$PanelT11.Controls.Add($Button111)

# Assign an action to the Button1
$Button111.Add_Click({
    C:\Windows\system32\msinfo32.exe
})

# Create a Label to introduce the Button2 action
$Label112 = New-Object System.Windows.Forms.Label
$Label112.Text = "Strumenti e archiviazione"
$Label112.Font = "Verdana, 11"
$Label112.Location = New-Object System.Drawing.Point(430,35)
$Label112.AutoSize = $true
$PanelT11.Controls.Add($Label112)

# Place the button
$Button112 = New-Object System.Windows.Forms.Button
$Button112.Location = New-Object System.Drawing.Point(430,65)
$Button112.Size = New-Object System.Drawing.Size(200,45)
$Button112.Text = "Gestione computer"
$Button112.Font = "Verdana, 11"
$Button112.BackColor = "#101c28"
$PanelT11.Controls.Add($Button112)

# Assign an action to Button2
$Button112.Add_Click({
    C:\WINDOWS\System32\compmgmt.msc
})

# Create a Label to introduce the Button3 action
$Label113 = New-Object System.Windows.Forms.Label
$Label113.Text = "Avvio e gestione servizi"
$Label113.Font = "Verdana, 11"
$Label113.Location = New-Object System.Drawing.Point(20,140)
$Label113.AutoSize = $true
$PanelT11.Controls.Add($Label113)

# Place the button
$Button113 = New-Object System.Windows.Forms.Button
$Button113.Location = New-Object System.Drawing.Point(20,170)
$Button113.Size = New-Object System.Drawing.Size(200,45)
$Button113.Text = "Msconfig *"
$Button113.Font = "Verdana, 11"
$Button113.BackColor = "#101c28"
$PanelT11.Controls.Add($Button113)

# Assign an action to Button3
$Button113.Add_Click({
    C:\Windows\System32\msconfig.exe
})

# Create a Label to introduce the Button4 action
$Label114 = New-Object System.Windows.Forms.Label
$Label114.Text = "CPU, memoria, dischi e rete"
$Label114.Font = "Verdana, 11"
$Label114.Location = New-Object System.Drawing.Point(430,140)
$Label114.AutoSize = $true
$PanelT11.Controls.Add($Label114)

# Place the button
$Button114 = New-Object System.Windows.Forms.Button
$Button114.Location = New-Object System.Drawing.Point(430,170)
$Button114.Size = New-Object System.Drawing.Size(200,45)
$Button114.Text = "Monitor delle risorse *"
$Button114.Font = "Verdana, 11"
$Button114.BackColor = "#101c28"
$PanelT11.Controls.Add($Button114)

# Assign an action to Button4
$Button114.Add_Click({
    C:\Windows\system32\perfmon.exe /res
})

# Create a Label to introduce the Button5 action
$Label115 = New-Object System.Windows.Forms.Label
$Label115.Text = "Grafici per componenti e performance"
$Label115.Font = "Verdana, 11"
$Label115.Location = New-Object System.Drawing.Point(20,245)
$Label115.AutoSize = $true
$PanelT11.Controls.Add($Label115)

# Place the button on Panel1
$Button115 = New-Object System.Windows.Forms.Button
$Button115.Location = New-Object System.Drawing.Point(20,275)
$Button115.Size = New-Object System.Drawing.Size(200,45)
$Button115.Text = "Monitor delle performance"
$Button115.Font = "Verdana, 11"
$Button115.BackColor = "#101c28"
$PanelT11.Controls.Add($Button115)

# Assign an action to Button5
$Button115.Add_Click({
    C:\Windows\system32\perfmon.exe 
})

# Create a Label to introduce the Button6 action
$Label116 = New-Object System.Windows.Forms.Label
$Label116.Text = "Storico degli avvisi e delle anomalie"
$Label116.Font = "Verdana, 11"
$Label116.Location = New-Object System.Drawing.Point(430,245)
$Label116.AutoSize = $true
$PanelT11.Controls.Add($Label116)

# Place the button
$Button116 = New-Object System.Windows.Forms.Button
$Button116.Location = New-Object System.Drawing.Point(430,275)
$Button116.Size = New-Object System.Drawing.Size(200,45)
$Button116.Text = "Monitor dell'affidabilità"
$Button116.Font = "Verdana, 11"
$Button116.BackColor = "#101c28"
$PanelT11.Controls.Add($Button116)

# Assign an action to Button6
$Button116.Add_Click({
    perfmon /rel
})

# Create a Label to introduce the Button7 action
$Label117 = New-Object System.Windows.Forms.Label
$Label117.Text = "Tutti i tipi di eventi registrati"
$Label117.Font = "Verdana, 11"
$Label117.Location = New-Object System.Drawing.Point(20,350)
$Label117.AutoSize = $true
$PanelT11.Controls.Add($Label117)

# Place the button
$Button117 = New-Object System.Windows.Forms.Button
$Button117.Location = New-Object System.Drawing.Point(20,380)
$Button117.Size = New-Object System.Drawing.Size(200,45)
$Button117.Text = "Visualizzatore eventi"
$Button117.Font = "Verdana, 11"
$Button117.BackColor = "#101c28"
$PanelT11.Controls.Add($Button117)

# Assign an action to Button7
$Button117.Add_Click({
    C:\Windows\system32\eventvwr.msc
})

# Label for admin rights
$Label11adm = New-Object System.Windows.Forms.Label
$Label11adm.Text = "* Richiesti diritti di admin"
$Label11adm.Font = "Verdana, 10"
$Label11adm.ForeColor = "#8af8ff"
$Label11adm.Location = New-Object System.Drawing.Point(20,440)
$Label11adm.AutoSize = $true
$PanelT11.Controls.Add($Label11adm)


### P A N E L  2

# Create Label for PANEL 2
$LabelT12 = New-Object System.Windows.Forms.Label
$LabelT12.Text = " RIPARAZIONE"
$LabelT12.Font = "Verdana, 11"
$LabelT12.Location = New-Object System.Drawing.Point(0,75)
$LabelT12.ForeColor = "#ebed31"
$LabelT12.BackColor = "#434c56"
$LabelT12.Size = New-Object System.Drawing.Size(145,20)
$PanelT1.Controls.Add($LabelT12)

# Create Panel
$PanelT12 = New-Object System.Windows.Forms.Panel
$PanelT12.Location = New-Object System.Drawing.Point(145,15)
$PanelT12.Size = New-Object System.Drawing.Size(900,590)
$PanelT12.BackColor = "#434c56"
$PanelT1.Controls.Add($PanelT12)

# Create a Label to signal when the Panel is selected
$Label1_2 = New-Object System.Windows.Forms.Label
$Label1_2.Text = "►"
$Label1_2.Font = "Verdana, 24"
$Label1_2.Location = New-Object System.Drawing.Point(125,-10)
$Label1_2.AutoSize = $true
$Label1_2.ForeColor = "#ebed31"
$Label1_2.Visible = $false
$LabelT12.Controls.Add($Label1_2)

# Create a Label to introduce the Button1 action
$Label121 = New-Object System.Windows.Forms.Label
$Label121.Text = "Esecuzione 'shutdown /r /fw /f /t 3'"
$Label121.Font = "Verdana, 11"
$Label121.Location = New-Object System.Drawing.Point(20,35)
$Label121.AutoSize = $true
$PanelT12.Controls.Add($Label121)

# Place the button
$Button121 = New-Object System.Windows.Forms.Button
$Button121.Location = New-Object System.Drawing.Point(20,65)
$Button121.Size = New-Object System.Drawing.Size(200,45)
$Button121.Text = "Riavvia al BIOS/UEFI *"
$Button121.Font = "Verdana, 11"
$Button121.BackColor = "#101c28"
$PanelT12.Controls.Add($Button121)

# Assign an action to the Button1
$Button121.Add_Click({
    $answerB = [System.Windows.Forms.MessageBox]::Show( "Vuoi eseguire 'shutdown /r /fw /f /t 3'?", "Conferma comando", "YesNo", "Warning" )
    if ($answerB -eq "Yes") {
        shutdown /r /fw /f /t 3
    } elseif ($answerB -eq "No") {
    }
})

# Create a Label to introduce the Button2 action
$Label122 = New-Object System.Windows.Forms.Label
$Label122.Text = "Check up memoria di sistema"
$Label122.Font = "Verdana, 11"
$Label122.Location = New-Object System.Drawing.Point(430,35)
$Label122.AutoSize = $true
$PanelT12.Controls.Add($Label122)

# Place the button
$Button122 = New-Object System.Windows.Forms.Button
$Button122.Location = New-Object System.Drawing.Point(430,65)
$Button122.Size = New-Object System.Drawing.Size(200,45)
$Button122.Text = "Diagnostica memoria *"
$Button122.Font = "Verdana, 11"
$Button122.BackColor = "#101c28"
$PanelT12.Controls.Add($Button122)

# Assign an action to Button2
$Button122.Add_Click({
    C:\Windows\system32\MdSched.exe
})

# Create a Label to introduce the Button3 action
$Label123 = New-Object System.Windows.Forms.Label
$Label123.Text = "Apri finestra pulizia disco"
$Label123.Font = "Verdana, 11"
$Label123.Location = New-Object System.Drawing.Point(20,140)
$Label123.AutoSize = $true
$PanelT12.Controls.Add($Label123)

# Place the button
$Button123 = New-Object System.Windows.Forms.Button
$Button123.Location = New-Object System.Drawing.Point(20,170)
$Button123.Size = New-Object System.Drawing.Size(200,45)
$Button123.Text = "Pulizia disco"
$Button123.Font = "Verdana, 11"
$Button123.BackColor = "#101c28"
$PanelT12.Controls.Add($Button123)

# Assign an action to Button3
$Button123.Add_Click({
    C:\Windows\system32\cleanmgr.exe
})

# Create a Label to introduce the Button4 action
$Label124 = New-Object System.Windows.Forms.Label
$Label124.Text = "Deframmentazione disco"
$Label124.Font = "Verdana, 11"
$Label124.Location = New-Object System.Drawing.Point(430,140)
$Label124.AutoSize = $true
$PanelT12.Controls.Add($Label124)

# Place the button
$Button124 = New-Object System.Windows.Forms.Button
$Button124.Location = New-Object System.Drawing.Point(430,170)
$Button124.Size = New-Object System.Drawing.Size(200,45)
$Button124.Text = "Deframmenta"
$Button124.Font = "Verdana, 11"
$Button124.BackColor = "#101c28"
$PanelT12.Controls.Add($Button124)

# Assign an action to Button4
$Button124.Add_Click({
    C:\Windows\system32\dfrgui.exe
})

# Create a Label to introduce the Button5 action
$Label125 = New-Object System.Windows.Forms.Label
$Label125.Text = "Gestione sicurezza"
$Label125.Font = "Verdana, 11"
$Label125.Location = New-Object System.Drawing.Point(20,245)
$Label125.AutoSize = $true
$PanelT12.Controls.Add($Label125)

# Place the button
$Button125 = New-Object System.Windows.Forms.Button
$Button125.Location = New-Object System.Drawing.Point(20,275)
$Button125.Size = New-Object System.Drawing.Size(200,45)
$Button125.Text = "Sicurezza"
$Button125.Font = "Verdana, 11"
$Button125.BackColor = "#101c28"
$PanelT12.Controls.Add($Button125)

# Assign an action to Button5
$Button125.Add_Click({
    C:\WINDOWS\System32\wscui.cpl 
})

# Create a Label to introduce the Button6 action
$Label126 = New-Object System.Windows.Forms.Label
$Label126.Text = "Troubleshoot del sistema"
$Label126.Font = "Verdana, 11"
$Label126.Location = New-Object System.Drawing.Point(430,245)
$Label126.AutoSize = $true
$PanelT12.Controls.Add($Label126)

# Place the button
$Button126 = New-Object System.Windows.Forms.Button
$Button126.Location = New-Object System.Drawing.Point(430,275)
$Button126.Size = New-Object System.Drawing.Size(200,45)
$Button126.Text = "Troubleshooting"
$Button126.Font = "Verdana, 11"
$Button126.BackColor = "#101c28"
$PanelT12.Controls.Add($Button126)

# Assign an action to Button6
$Button126.Add_Click({
    C:\WINDOWS\System32\control.exe /name Microsoft.Troubleshooting
})

# Create a Label to introduce the Button7 action
$Label127 = New-Object System.Windows.Forms.Label
$Label127.Text = "Esecuzione 'chkdsk C: /r'"
$Label127.Font = "Verdana, 11"
$Label127.Location = New-Object System.Drawing.Point(20,350)
$Label127.AutoSize = $true
$PanelT12.Controls.Add($Label127)

# Place the button
$Button127 = New-Object System.Windows.Forms.Button
$Button127.Location = New-Object System.Drawing.Point(20,380)
$Button127.Size = New-Object System.Drawing.Size(200,45)
$Button127.Text = "Check up del disco *"
$Button127.Font = "Verdana, 11"
$Button127.BackColor = "#101c28"
$PanelT12.Controls.Add($Button127)

# Assign an action to Button7
$Button127.Add_Click({
    $answerC = [System.Windows.Forms.MessageBox]::Show( "Vuoi eseguire 'chkdsk C: /r'?", "Conferma comando", "YesNo", "Warning" )
    if ($answerC -eq "Yes") {
        Start powershell ; $wshell = New-Object -ComObject wscript.shell; $wshell.AppActivate('powershell.exe'); Sleep 1; $wshell.SendKeys("chkdsk C: /r")
    } elseif ($answerC -eq "No") {
    }
})

# Create a Label to introduce the Button6 action
$Label128 = New-Object System.Windows.Forms.Label
$Label128.Text = "'sfc /scannow' e 'DISM.exe /Online
/Cleanup-image /Restorehealth'"
$Label128.Font = "Verdana, 11"
$Label128.Location = New-Object System.Drawing.Point(430,350)
$Label128.AutoSize = $true
$PanelT12.Controls.Add($Label128)

# Place the button
$Button128 = New-Object System.Windows.Forms.Button
$Button128.Location = New-Object System.Drawing.Point(430,390)
$Button128.Size = New-Object System.Drawing.Size(200,45)
$Button128.Text = "Controllo sistema operativo *"
$Button128.Font = "Verdana, 11"
$Button128.BackColor = "#101c28"
$PanelT12.Controls.Add($Button128)

# Assign an action to Button6
$Button128.Add_Click({
    $answerD = [System.Windows.Forms.MessageBox]::Show( "Vuoi eseguire 'sfc /scannow' e poi 'DISM.exe /Online /Cleanup-image /Restorehealth'?", "Conferma comando", "YesNo", "Warning" )
    if ($answerD -eq "Yes") {
        Start powershell ; $wshell = New-Object -ComObject wscript.shell; $wshell.AppActivate('powershell.exe'); Sleep 1; $wshell.SendKeys("sfc /scannow ; DISM.exe /Online /Cleanup-image /Restorehealth")
    } elseif ($answerD -eq "No") {
    }
})

# Label for admin rights
$Label12adm = New-Object System.Windows.Forms.Label
$Label12adm.Text = "* Richiesti diritti di admin"
$Label12adm.Font = "Verdana, 10"
$Label12adm.ForeColor = "#8af8ff"
$Label12adm.Location = New-Object System.Drawing.Point(20,440)
$Label12adm.AutoSize = $true
$PanelT12.Controls.Add($Label12adm)


### P A N E L  3

# Create Label for PANEL 3
$LabelT13 = New-Object System.Windows.Forms.Label
$LabelT13.Text = " OUTPUT CHECK"
$LabelT13.Font = "Verdana, 11"
$LabelT13.Location = New-Object System.Drawing.Point(0,110)
$LabelT13.ForeColor = "#ebed31"
$LabelT13.BackColor = "#434c56"
$LabelT13.Size = New-Object System.Drawing.Size(145,20)
$PanelT1.Controls.Add($LabelT13)

# Create Panel
$PanelT13 = New-Object System.Windows.Forms.Panel
$PanelT13.Location = New-Object System.Drawing.Point(145,15)
$PanelT13.Size = New-Object System.Drawing.Size(900,590)
$PanelT13.BackColor = "#434c56"
$PanelT1.Controls.Add($PanelT13)

# Create a Label to signal when the Panel is selected
$Label1_3 = New-Object System.Windows.Forms.Label
$Label1_3.Text = "►"
$Label1_3.Font = "Verdana, 24"
$Label1_3.Location = New-Object System.Drawing.Point(125,-10)
$Label1_3.AutoSize = $true
$Label1_3.ForeColor = "#ebed31"
$Label1_3.Visible = $false
$LabelT13.Controls.Add($Label1_3)

# Create a Label to introduce the Panel 3 action
$Label130 = New-Object System.Windows.Forms.Label
$Label130.Text = "Si può impostare un comando da eseguire ad un intervallo personalizzato e controllare se il suo
output contiene una determinata stringa. Ogni presenza della stringa nell'ouput sarà salvata in
un file di log, assieme a data ed ora dell'evento.
Assomiglia al comando 'watch' in Linux e può essere usato, ad esempio, per monitorare un 
processo ('ps'), connessioni ('netstat -noa'), file di log ('cat [file] -last 10') o i risultati del
comando ping."
$Label130.Font = "Verdana, 11"
$Label130.Location = New-Object System.Drawing.Point(20,35)
$Label130.AutoSize = $true
$PanelT13.Controls.Add($Label130)

# Label and text field for the command
$Label131 = New-Object System.Windows.Forms.Label
$Label131.Location = New-Object System.Drawing.Point(20,150)
$Label131.AutoSize = $true
$Label131.Text = 'Comando da controllare:'
$Label131.Font = "Verdana, 11"
$PanelT13.Controls.Add($Label131)
$textBox131 = New-Object System.Windows.Forms.TextBox
$textBox131.Location = New-Object System.Drawing.Point(20,173)
$textBox131.Size = New-Object System.Drawing.Size(700,20)
$textBox131.Font = "Verdana, 11"
$textBox131.BackColor = "#1d1e25" #101c28 
$textBox131.ForeColor = "#ffffff"
$textBox131.Add_GotFocus({ $textBox131.BackColor = "#000000" })
$textBox131.Add_LostFocus({ $textBox131.BackColor = "#1d1e25" })
$PanelT13.Controls.Add($textBox131)

# Label and text field for the string
$Label132 = New-Object System.Windows.Forms.Label
$Label132.Location = New-Object System.Drawing.Point(20,210)
$Label132.AutoSize = $true
$Label132.Text = 'Stringa da trovare:'
$Label132.Font = "Verdana, 11"
$PanelT13.Controls.Add($Label132)
$textBox132 = New-Object System.Windows.Forms.TextBox
$textBox132.Location = New-Object System.Drawing.Point(20,233)
$textBox132.Size = New-Object System.Drawing.Size(700,20)
$textBox132.Font = "Verdana, 11"
$textBox132.BackColor = "#1d1e25"
$textBox132.ForeColor = "#ffffff"
$textBox132.Add_GotFocus({ $textBox132.BackColor = "#000000" })
$textBox132.Add_LostFocus({ $textBox132.BackColor = "#1d1e25" })
$PanelT13.Controls.Add($textBox132)

# Label and text field for the interval
$Label133 = New-Object System.Windows.Forms.Label
$Label133.Location = New-Object System.Drawing.Point(20,270)
$Label133.AutoSize = $true
$Label133.Text = 'Intervallo in secondi:'
$Label133.Font = "Verdana, 11"
$PanelT13.Controls.Add($Label133)
$textBox133 = New-Object System.Windows.Forms.TextBox
$textBox133.Location = New-Object System.Drawing.Point(20,292)
$textBox133.Size = New-Object System.Drawing.Size(100,20)
$textBox133.Font = "Verdana, 11"
$textBox133.BackColor = "#1d1e25"
$textBox133.ForeColor = "#ffffff"
$textBox133.Add_GotFocus({ $textBox133.BackColor = "#000000" })
$textBox133.Add_LostFocus({ $textBox133.BackColor = "#1d1e25" })
$PanelT13.Controls.Add($textBox133)

# Label and text field for the iteration
$Label134 = New-Object System.Windows.Forms.Label
$Label134.Location = New-Object System.Drawing.Point(210,270)
$Label134.AutoSize = $true
$Label134.Text = 'Numero di iterazioni:'
$Label134.Font = "Verdana, 11"
$PanelT13.Controls.Add($Label134)
$textBox134 = New-Object System.Windows.Forms.TextBox
$textBox134.Location = New-Object System.Drawing.Point(210,292)
$textBox134.Size = New-Object System.Drawing.Size(100,20)
$textBox134.Font = "Verdana, 11"
$textBox134.BackColor = "#1d1e25"
$textBox134.ForeColor = "#ffffff"
$textBox134.Add_GotFocus({ $textBox134.BackColor = "#000000" })
$textBox134.Add_LostFocus({ $textBox134.BackColor = "#1d1e25" })
$PanelT13.Controls.Add($textBox134)

$ButtonS = New-Object System.Windows.Forms.Button
$ButtonS.Location = New-Object System.Drawing.Point(500,270)
$ButtonS.Size = New-Object System.Drawing.Size(130,30)
$ButtonS.Text = "Cartella del log"
$ButtonS.Font = "Verdana, 9.5"
$ButtonS.BackColor = "#101c28"
$PanelT13.Controls.Add($ButtonS)

$textBox135 = New-Object System.Windows.Forms.TextBox
$textBox135.Location = New-Object System.Drawing.Point(410,300)
$textBox135.Width = "310"
$textBox135.Font = "Verdana, 10"
$textBox135.BackColor = "#101c28"
$textBox135.ForeColor = "#ffffff"
$textBox135.Font = "Verdana, 11"
$PanelT13.Controls.Add($textBox135)

#Search button configuration
$ButtonS.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.ShowDialog() | Out-Null
    $selectedPath = $folderBrowser.SelectedPath
    $textBox135.Text = $selectedPath
})

$Label136 = New-Object System.Windows.Forms.Label
$Label136.Location = New-Object System.Drawing.Point(413,330)
$Label136.Text = "(Il nome del file di log è: 'eventlist.txt')"
$Label136.AutoSize = $true
$Label136.Font = "Verdana, 11"
$PanelT13.Controls.Add($Label136)

$ButtonST = New-Object System.Windows.Forms.Button
$ButtonST.Location = New-Object System.Drawing.Point(20,350)
$ButtonST.Size = New-Object System.Drawing.Size(130,40)
$ButtonST.Text = "AVVIO"
$ButtonST.Font = "Verdana, 11"
$ButtonST.BackColor = "#101c28"
$PanelT13.Controls.Add($ButtonST)

# Final output section
$textBox136 = New-Object System.Windows.Forms.TextBox
$textBox136.Location = New-Object System.Drawing.Point(20,400)
$textBox136.Size = New-Object System.Drawing.Size(700,165)
$textBox136.ScrollBars = "both"
$textBox136.Multiline = $true
$textBox136.Font = "Verdana, 11"
$textBox136.BackColor = "#071c3b"
$textBox136.ForeColor = "#ffffff"
$PanelT13.Controls.Add($textBox136)

$Label137 = New-Object System.Windows.Forms.Label
$Label137.Location = New-Object System.Drawing.Point(200,370)
$Label137.Size = New-Object System.Drawing.Size (50,20)
$Label137.Font = "Verdana, 11"
$Label137.BackColor = "#101c28"
$PanelT13.Controls.Add($Label137)

$Label138 = New-Object System.Windows.Forms.Label
$Label138.Location = New-Object System.Drawing.Point(255,370)
$Label138.Size = New-Object System.Drawing.Size (150,20)
$Label138.Text = "Iterazioni fatte"
$Label138.Font = "Verdana, 11"
$PanelT13.Controls.Add($Label138)

$ButtonST.Add_Click({
    $textBox136.Text = ""
    for ($i = 1; $i -le $textBox134.Text; $i++) {
        $outp = Invoke-Expression $textBox131.text | Out-String
        if ($textBox132.Text -ne "") {
            if ($outp | findstr $textBox132.Text) {
                $found = $outp | findstr $textBox132.Text | Out-String
                $log = $textBox135.Text + '\\eventlist.txt'
                "$(date | Out-String)$($found)" | tee $log -Append
                $Label137.Text = " $($i) / $($textBox134.Text)"
                $textBox136.text = "$(date | Out-String)$($found)" 
                sleep $textBox133.Text
            } else {
                return
            }
        } else {
            return
        }
    }
})

# Add event handler to handle click events for the Labels
$Label_Click1 = {
    param($sender, $e)
    $clickedLabel = $sender
    if ($clickedLabel -eq $LabelT11) {
        $PanelT11.Visible = $true
        $PanelT12.Visible = $false
        $PanelT13.Visible = $false
    } elseif ($clickedLabel -eq $LabelT12) {
        $PanelT11.Visible = $false
        $PanelT12.Visible = $true
        $PanelT13.Visible = $false
    } elseif ($clickedLabel -eq $LabelT13) {
        $PanelT11.Visible = $false
        $PanelT12.Visible = $false
        $PanelT13.Visible = $true
    }
}

# Set the label indicator when its panel is active
$Label_ClickX1 = {
    param($sender, $e)
    $clickedLabel = $sender
    if ($clickedLabel -eq $LabelT11) {
        $Label1_1.Visible = $true
        $Label1_2.Visible = $false
        $Label1_3.Visible = $false
    } elseif ($clickedLabel -eq $LabelT12) {
        $Label1_1.Visible = $false
        $Label1_2.Visible = $true
        $Label1_3.Visible = $false
    } elseif ($clickedLabel -eq $LabelT13) {
        $Label1_1.Visible = $false
        $Label1_2.Visible = $false
        $Label1_3.Visible = $true
    }
}

# Assign the event handler to the Labels
$LabelT11.Add_Click($Label_Click1)
$LabelT12.Add_Click($Label_Click1)
$LabelT13.Add_Click($Label_Click1)

$LabelT11.Add_Click($Label_ClickX1)
$LabelT12.Add_Click($Label_ClickX1)
$LabelT13.Add_Click($Label_ClickX1)



###### T A B 2 

# Create Label for TAB2
$LabelT2 = New-Object System.Windows.Forms.Label
$LabelT2.Text = "          RETE"
$LabelT2.Font = [System.Drawing.Font]::new("Arial", 12, [System.Drawing.FontStyle]::Bold)
$LabelT2.Location = New-Object System.Drawing.Point(155,15)
$LabelT2.ForeColor = "#ffb91a"
$LabelT2.BackColor = "#0b335b"
$LabelT2.Size = New-Object System.Drawing.Size (145,20)
$main_form.Controls.Add($LabelT2)

# Create TAB2
$PanelT2 = New-Object System.Windows.Forms.Panel
$PanelT2.Location = New-Object System.Drawing.Point(5,35)
$PanelT2.Size = New-Object System.Drawing.Size (900,590)
$PanelT2.BackColor = "#0b335b"
$main_form.Controls.Add($PanelT2)


### P A N E L  1

# Create Label for PANEL 1
$LabelT21 = New-Object System.Windows.Forms.Label
$LabelT21.Text = " RESET"
$LabelT21.Font = "Verdana, 11"
$LabelT21.Location = New-Object System.Drawing.Point(0,40)
$LabelT21.ForeColor = "#ebed31"
$LabelT21.BackColor = "#434c56"
$LabelT21.Size = New-Object System.Drawing.Size (145,20)
$PanelT2.Controls.Add($LabelT21)

# Create Panel
$PanelT21 = New-Object System.Windows.Forms.Panel
$PanelT21.Location = New-Object System.Drawing.Point(145,15)
$PanelT21.Size = New-Object System.Drawing.Size (900,590)
$PanelT21.BackColor = "#434c56"
$PanelT2.Controls.Add($PanelT21)

# Create a Label to signal when the Panel is selected
$Label2_1 = New-Object System.Windows.Forms.Label
$Label2_1.Text = "►"
$Label2_1.Font = "Verdana, 24"
$Label2_1.Location = New-Object System.Drawing.Point(125,-10)
$Label2_1.AutoSize = $true
$Label2_1.ForeColor = "#ebed31"
$Label2_1.Visible = $true
$LabelT21.Controls.Add($Label2_1)

# Create a Label to introduce the Button1 action
$Label211 = New-Object System.Windows.Forms.Label
$Label211.Text = "'ipconfig /renew'"
$Label211.Font = "Verdana, 11"
$Label211.Location = New-Object System.Drawing.Point(60,35)
$Label211.AutoSize = $true
$PanelT21.Controls.Add($Label211)

# Place the button
$Button211 = New-Object System.Windows.Forms.Button
$Button211.Location = New-Object System.Drawing.Point(60,65)
$Button211.Size = New-Object System.Drawing.Size(200,45)
$Button211.Text = "Rinnova IP"
$Button211.Font = "Verdana, 11"
$Button211.BackColor = "#101c28"
$PanelT21.Controls.Add($Button211)

# Assign an action to the Button1
$Button211.Add_Click({
    $textBox211.Text = "Attendere..."
    $textBox211.Text = ipconfig /renew | Out-String
})

# Create a Label to introduce the Button2 action
$Label212 = New-Object System.Windows.Forms.Label
$Label212.Text = "'Clear-DnsClientCache'"
$Label212.Font = "Verdana, 11"
$Label212.Location = New-Object System.Drawing.Point(430,35)
$Label212.AutoSize = $true
$PanelT21.Controls.Add($Label212)

# Place the button
$Button212 = New-Object System.Windows.Forms.Button
$Button212.Location = New-Object System.Drawing.Point(430,65)
$Button212.Size = New-Object System.Drawing.Size(200,45)
$Button212.Text = "Svuota cache DNS"
$Button212.Font = "Verdana, 11"
$Button212.BackColor = "#101c28"
$PanelT21.Controls.Add($Button212)

# Assign an action to Button2
$Button212.Add_Click({
    $textBox211.Text = "Attendere..."
    Clear-DnsClientCache
    $textBox211.Text = $($?)
})

# Create a Label to introduce the Button3 action
$Label213 = New-Object System.Windows.Forms.Label
$Label213.Text = "'gpupdate /force'"
$Label213.Font = "Verdana, 11"
$Label213.Location = New-Object System.Drawing.Point(60,140)
$Label213.AutoSize = $true
$PanelT21.Controls.Add($Label213)

# Place the button
$Button213 = New-Object System.Windows.Forms.Button
$Button213.Location = New-Object System.Drawing.Point(60,170)
$Button213.Size = New-Object System.Drawing.Size(200,45)
$Button213.Text = "Aggiorna group policy"
$Button213.Font = "Verdana, 11"
$Button213.BackColor = "#101c28"
$PanelT21.Controls.Add($Button213)

# Assign an action to Button3
$Button213.Add_Click({
    $textBox211.Text = "Attendere..."
    $textBox211.Text = gpupdate /force | Out-String
})

# Create a Label to introduce the Button4 action
$Label214 = New-Object System.Windows.Forms.Label
$Label214.Text = "'Restart-NetAdapter'"
$Label214.Font = "Verdana, 11"
$Label214.Location = New-Object System.Drawing.Point(430,140)
$Label214.AutoSize = $true
$PanelT21.Controls.Add($Label214)

# Place the button
$Button214 = New-Object System.Windows.Forms.Button
$Button214.Location = New-Object System.Drawing.Point(430,170)
$Button214.Size = New-Object System.Drawing.Size(200,45)
$Button214.Text = "Riavvia adattatore di rete *"
$Button214.Font = "Verdana, 11"
$Button214.BackColor = "#101c28"
$PanelT21.Controls.Add($Button214)

# Assign an action to Button4
$Button214.Add_Click({
    $textBox211.Text = "Attendere..."
    $net = Get-NetConnectionProfile | findstr InterfaceAlias ; $net = $net.substring(27)
    $netrestart = try {
        Restart-NetAdapter -name $net -erroraction stop
        $textBox211.Text = "Fatto"
        } catch {
            $textBox211.Text = "Per riavviare l'adattatore di rete devi essere admin"
        }
})

# Create a Label to introduce the Button5 action
$Label215 = New-Object System.Windows.Forms.Label
$Label215.Text = "'netsh interface ip delete arpcache'"
$Label215.Font = "Verdana, 11"
$Label215.Location = New-Object System.Drawing.Point(60,245)
$Label215.AutoSize = $true
$PanelT21.Controls.Add($Label215)

# Place the button
$Button215 = New-Object System.Windows.Forms.Button
$Button215.Location = New-Object System.Drawing.Point(60,275)
$Button215.Size = New-Object System.Drawing.Size(200,45)
$Button215.Text = "Svuota ARP table *"
$Button215.Font = "Verdana, 11"
$Button215.BackColor = "#101c28"
$PanelT21.Controls.Add($Button215)

# Label for admin rights
$Label21adm = New-Object System.Windows.Forms.Label
$Label21adm.Text = "* Richiesti diritti di admin"
$Label21adm.Font = "Verdana, 10"
$Label21adm.ForeColor = "#8af8ff"
$Label21adm.Location = New-Object System.Drawing.Point(60,325)
$Label21adm.AutoSize = $true
$PanelT21.Controls.Add($Label21adm)

# Assign an action to Button5
$Button215.Add_Click({
    $textBox211.Text = "Attendere..."
    $cleararp = try {
                    netsh interface ip delete arpcache
                } catch {
                    "Per svuotare la cache arp, devi essere admin"
                }
    $textBox211.Text = $cleararp | Out-String
})

# Output textbox
$textBox211 = New-Object System.Windows.Forms.TextBox
$textBox211.Location = New-Object System.Drawing.Point(10,355)
$textBox211.Size = New-Object System.Drawing.Size(700,210)
$textBox211.ScrollBars = "both"
$textBox211.Multiline = $true
$textBox211.Font = "Verdana, 11"
$textBox211.BackColor = "#071c3b"
$textBox211.ForeColor = "#ffffff"
$PanelT21.Controls.Add($textBox211)


### P A N E L  2

# Create Label for PANEL 2
$LabelT22 = New-Object System.Windows.Forms.Label
$LabelT22.Text = " CONTROLLO"
$LabelT22.Font = "Verdana, 11"
$LabelT22.Location = New-Object System.Drawing.Point(0,75)
$LabelT22.ForeColor = "#ebed31"
$LabelT22.BackColor = "#434c56"
$LabelT22.Size = New-Object System.Drawing.Size(145,20)
$PanelT2.Controls.Add($LabelT22)

# Create Panel
$PanelT22 = New-Object System.Windows.Forms.Panel
$PanelT22.Location = New-Object System.Drawing.Point(145,15)
$PanelT22.Size = New-Object System.Drawing.Size(900,590)
$PanelT22.BackColor = "#434c56"
$PanelT2.Controls.Add($PanelT22)

# Create a Label to signal when the Panel is selected
$Label2_2 = New-Object System.Windows.Forms.Label
$Label2_2.Text = "►"
$Label2_2.Font = "Verdana, 24"
$Label2_2.Location = New-Object System.Drawing.Point(125,-10)
$Label2_2.AutoSize = $true
$Label2_2.ForeColor = "#ebed31"
$Label2_2.Visible = $false
$LabelT22.Controls.Add($Label2_2)

# Create a Label to introduce the Panel 2 action
$Label221 = New-Object System.Windows.Forms.Label
$Label221.Text = "Un controllo di rete mostrerà informazioni su: connessione all'IP del gateway, del server DNS
e del server DHCP; IP pubblico e privato; nome e velocità della rete; risultati del ping verso
un sito esterno; stato del firewall; connessioni TCP e stato di alcuni servizi principali."
$Label221.Font = "Verdana, 11"
$Label221.Location = New-Object System.Drawing.Point(10,35)
$Label221.AutoSize = $true
$PanelT22.Controls.Add($Label221)

# Place button
$ButtonST2 = New-Object System.Windows.Forms.Button
$ButtonST2.Location = New-Object System.Drawing.Point(10,110)
$ButtonST2.Size = New-Object System.Drawing.Size(130,40)
$ButtonST2.Text = "AVVIO"
$ButtonST2.Font = "Verdana, 11"
$ButtonST2.BackColor = "#101c28"
$PanelT22.Controls.Add($ButtonST2)

# Final output textbox
$textBox221 = New-Object System.Windows.Forms.TextBox
$textBox221.Location = New-Object System.Drawing.Point(10,170)
$textBox221.Size = New-Object System.Drawing.Size(700,395)
$textBox221.ScrollBars = "both"
$textBox221.Multiline = $true
$textBox221.Font = "Verdana, 11"
$textBox221.BackColor = "#071c3b"
$textBox221.ForeColor = "#ffffff"
$PanelT22.Controls.Add($textBox221)

$ButtonST2.Add_Click({
    $textBox221.Text = "Attendere..."
    $gw = (Get-NetIPConfiguration | Foreach IPv4DefaultGateway) ; $gwy = $gw.nexthop
    $dn = (Get-NetIPConfiguration | Foreach DNSServer | findstr "IPv4" | findstr ",")
    $dns1 = (($dn.split("{")[1]).trimend("} ")).split(",")[0] ; $dns2 = ((($dn.split("{")[1]).trimend("} ")).split(",")[1]).trimstart(" ")
    $dhcp = ipconfig /all | Select-String -pattern "(DHCP server|server DHCP)"
    #set output variables
    $out1 = if (ping -n 1 $gwy | findstr "TTL") {
        "`nPing gateway ($gwy): OK`n`n" | Out-String
        } else {
        "`nPing gateway ($gwy): NO`n`n" | Out-String
    }
    $out2 = if (ping -n 1 8.8.8.8 | findstr "TTL") {
        "`nPing 8.8.8.8: OK`n`n" | Out-String
        } else {
        "`nPing 8.8.8.8: NO`n`n" | Out-String
        }
    
    $out3a = nslookup myip.opendns.com. resolver1.opendns.com | Select-Object -Index 4 -OutVariable P_IP # NOT WORKING WITH "FORCED DNS" (PORTMASTER, ETC.)
    $out3b = try {
                    $P_IP.substring($P_IP.length -16)
             } catch {
                 "ignoto (problema con DNS, utilizzo di un DNS forzato o host offline)"
             }
    $out3 = "`nPublic IP: $($out3b)" | Out-String
    
    $out4a = try {
                $tdns = Resolve-DnsName www.google.com -server $dns1 -erroraction stop
                "OK "
             } catch {
                "NO "
             }
    $out4b = try {
                $tdns = Resolve-DnsName www.google.com -server $dns2 -erroraction stop
                "OK "
             } catch {
                "NO "
             }
    $out4 = "DNS: $($dns1) $($out4a)- $($dns2) $($out4b)`n`n" | Out-String
                
    $out5a = try {
                  (($dhcp.tostring()).split(":")[1]).trimstart("")
             } catch {
                            "NO"
             }
    $out5b = try {
                    if (ping -n 1 (($dhcp.tostring()).split(":")[1]).trimstart("") | findstr "TTL") {
                        "OK"
                        } else {
                            "NO (ma potrebbe essere OK, se sei su una VM host usando VirtualBox, VMware o simili)"
                    }
             } catch {
                " server non impostato o host offline"
             }
    $out5 = "`n`nDHCP server: $($out5a) - server raggiungibile? $($out5b)" | Out-String
                
    $out6a = try {
                        $net = Get-NetConnectionProfile | findstr InterfaceAlias ; $net = $net.substring(27) ; "$net " ; $inf = (Get-NetAdapter -name $net | select linkspeed) ; "-  linkspeed=$($inf.linkspeed) - VlanID=$($inf.vlanid)"
             } catch {
                    "nessuna connessione internet"
             }
    $out6 = "`n`nNome rete: $($out6a)"  | Out-String
    
    $out7a = try {
                    $ipa = (Get-NetIPAddress -AddressFamily IPV4 -interfacealias $net).IPAddress
                    if ($ipa -match "^169.254.*.*$") {
                        "DHCP non funzionante, indirizzo APIPA"
                    } else {
                        "$ipa"
                    }
             } catch {
                        "non connesso a una rete"
             }
                    
    $out7 = "`n`nHost IP address: $($out7a)" | Out-String
    
    $out8a = $names = @(); $names = (Get-NetFirewallProfile).name
             $values = @(); $v = (Get-NetFirewallProfile).enabled
             Foreach ($d in $v){
                        $values = $values + "   $d"
             }
    $out8b = "`n`nWindows firewall:"
    $out8c = "$($names)"
    $out8d = "$($values)" | Out-String
    
    $out9a = Get-Service -Name "*DHCP*","*DNS*","VSS","TermService","ssh-agent","MyWiFiDHCPDNS","gpsvc","fhsvc","defragsvc","BDESVC","UserManager","StorSvc","Spooler","SecurityHealthService","Schedule","hvsics","HvHost","hns","EventLog","DPS" -erroraction SilentlyContinue | sort status,name,displayname | 
                    ForEach ($_.status) {
                        if ($_.status -eq "running"){
                            "$($_.status) - $($_.name) - $($_.displayname)" | Out-String
                        } elseif ($_.status -eq "stopped") {
                            "$($_.status) - $($_.name) - $($_.displayname)" | Out-String
                        } else {
                            "$($_.status) - $($_.name) - $($_.displayname)" | Out-String
                        }
                    }
    $out9 = "`n $($out9a)" | Out-String
    
    $textBox221.Text = $out1,$out2,$out3,$out4,$out5,$out6,$out7,$out8b,$out8c,$out8d,"`n`nSERVICES (partial):",$out9 | Out-String
})


### P A N E L  3

# Create Label for PANEL 3
$LabelT23 = New-Object System.Windows.Forms.Label
$LabelT23.Text = " REPORT"
$LabelT23.Font = "Verdana, 11"
$LabelT23.Location = New-Object System.Drawing.Point(0,110)
$LabelT23.ForeColor = "#ebed31"
$LabelT23.BackColor = "#434c56"
$LabelT23.Size = New-Object System.Drawing.Size(145,20)
$PanelT2.Controls.Add($LabelT23)

# Create Panel
$PanelT23 = New-Object System.Windows.Forms.Panel
$PanelT23.Location = New-Object System.Drawing.Point(145,15)
$PanelT23.Size = New-Object System.Drawing.Size(900,590)
$PanelT23.BackColor = "#434c56"
$PanelT2.Controls.Add($PanelT23)

# Create a Label to signal when the Panel is selected
$Label2_3 = New-Object System.Windows.Forms.Label
$Label2_3.Text = "►"
$Label2_3.Font = "Verdana, 24"
$Label2_3.Location = New-Object System.Drawing.Point(125,-10)
$Label2_3.AutoSize = $true
$Label2_3.ForeColor = "#ebed31"
$Label2_3.Visible = $false
$LabelT23.Controls.Add($Label2_3)

# Create a Label to introduce the Panel 3 first action
$Label231 = New-Object System.Windows.Forms.Label
$Label231.Text = "Esegui il 'netsh wlan report'"
$Label231.Font = "Verdana, 11"
$Label231.Location = New-Object System.Drawing.Point(150,35)
$Label231.AutoSize = $true
$PanelT23.Controls.Add($Label231)

# Output textbox
$textBox231 = New-Object System.Windows.Forms.TextBox
$textBox231.Location = New-Object System.Drawing.Point(10,70)
$textBox231.Size = New-Object System.Drawing.Size(700,50)
$textBox231.ScrollBars = "both"
$textBox231.Multiline = $true
$textBox231.Font = "Verdana, 11"
$textBox231.BackColor = "#071c3b"
$textBox231.ForeColor = "#ffffff"
$PanelT23.Controls.Add($textBox231)

$ButtonST3a = New-Object System.Windows.Forms.Button
$ButtonST3a.Location = New-Object System.Drawing.Point(10,25)
$ButtonST3a.Size = New-Object System.Drawing.Size(130,40)
$ButtonST3a.Text = "AVVIO *"
$ButtonST3a.Font = "Verdana, 11"
$ButtonST3a.BackColor = "#101c28"
$PanelT23.Controls.Add($ButtonST3a)

$ButtonST3a.Add_Click({
    $textBox231.Text = "Attendere..."
    $textBox231.Text = netsh wlan show wlanreport | findstr "Report" | Out-String
    if ($textBox231.Text -eq "") {
       $textBox231.Text = "Devi essere admin per eseguire il report"
    }
})

# Create a Label to introduce the Panel 3 second action
$Label232a = New-Object System.Windows.Forms.Label
$Label232a.Text = "Cattura traffico di rete"
$Label232a.Font = "Verdana, 11"
$Label232a.Location = New-Object System.Drawing.Point(150,145)
$Label232a.AutoSize = $true
$PanelT23.Controls.Add($Label232a)

$Label232b = New-Object System.Windows.Forms.Label
$Label232b.Text = "durata cattura (in secondi; max 300):"
$Label232b.Font = "Verdana, 11"
$Label232b.Location = New-Object System.Drawing.Point(350,145)
$Label232b.AutoSize = $true
$PanelT23.Controls.Add($Label232b)

# Seconds textbox
$textBox232b = New-Object System.Windows.Forms.TextBox
$textBox232b.Location = New-Object System.Drawing.Point(650,143)
$textBox232b.Size = New-Object System.Drawing.Size(60,20)
$textBox232b.Font = "Verdana, 11"
$textBox232b.BackColor = "#1d1e25"
$textBox232b.ForeColor = "#ffffff"
$textBox232b.Add_GotFocus({ $textBox232b.BackColor = "#000000" })
$textBox232b.Add_LostFocus({ $textBox232b.BackColor = "#1d1e25" })
$PanelT23.Controls.Add($textBox232b)

# Output textbox
$textBox232a = New-Object System.Windows.Forms.TextBox
$textBox232a.Location = New-Object System.Drawing.Point(10,180)
$textBox232a.Size = New-Object System.Drawing.Size(700,100)
$textBox232a.ScrollBars = "both"
$textBox232a.Multiline = $true
$textBox232a.Font = "Verdana, 11"
$textBox232a.BackColor = "#071c3b"
$textBox232a.ForeColor = "#ffffff"
$PanelT23.Controls.Add($textBox232a)

$ButtonST3b = New-Object System.Windows.Forms.Button
$ButtonST3b.Location = New-Object System.Drawing.Point(10,135)
$ButtonST3b.Size = New-Object System.Drawing.Size(130,40)
$ButtonST3b.Text = "CATTURA *"
$ButtonST3b.Font = "Verdana, 11"
$ButtonST3b.BackColor = "#101c28"
$PanelT23.Controls.Add($ButtonST3b)

$ButtonST3b.Add_Click({
    $textBox232a.Text = "Attendere..."
    if (!$textBox232b.Text) {
        $textBox232a.Text = "Seleziona intervallo"
        return
    }
    if ($textBox232b.Text -match "^[0-2]?[0-9][1-9]?$" -and $textBox232b.Text -ne 0,00,000) {
           netsh trace start capture=yes report=yes correlation=yes capturetype=both tracefile=C:\NetTrace.etl
           $textBox232a.Text = "Attendere il messaggio 'cattura completata'..." | Out-String ; sleep $textBox232b.Text
           netsh trace stop ; tracerpt C:\NetTrace.etl -o C:\captlogs.csv -of csv
           $textBox232a.Text = "CATTURA COMPLETATA. `r`n Se eseguito da admin, in C:\ ora ci sono: `r`n - il file compresso 'NetTrace.cab' contenente 'report.html' `r`n - il file 'NetTrace.etl' (da aprire in EventViewer, o ancor meglio usando Networkminer o NetwokMonitor, se installati) con i pacchetti catturati `r`n - il file 'captlogs.csv' (NetTrace.etl in formato differente)" | Out-String
    } else {
           $textBox232a.Text = "Inserirer solo numeri da 1 a 300" | Out-String ; break
    }
})

# Label for admin rights
$Label23adm = New-Object System.Windows.Forms.Label
$Label23adm.Text = "* Richiesti diritti di admin"
$Label23adm.Font = "Verdana, 10"
$Label23adm.Location = New-Object System.Drawing.Point(10,280)
$Label23adm.ForeColor = "#8af8ff" #ff8ae7
$Label23adm.AutoSize = $true
$PanelT23.Controls.Add($Label23adm)

# Create a Label to introduce the Panel 3 third action
$Label234 = New-Object System.Windows.Forms.Label
$Label234.Text = "Esegui un 'ping sweep' nella rete dell'host"
$Label234.Font = "Verdana, 11"
$Label234.Location = New-Object System.Drawing.Point(150,315)
$Label234.AutoSize = $true
$PanelT23.Controls.Add($Label234)

# Output textbox
$textBox233 = New-Object System.Windows.Forms.TextBox
$textBox233.Location = New-Object System.Drawing.Point(10,350)
$textBox233.Size = New-Object System.Drawing.Size(700,215)
$textBox233.ScrollBars = "both"
$textBox233.Multiline = $true
$textBox233.Font = "Verdana, 11"
$textBox233.BackColor = "#071c3b"
$textBox233.ForeColor = "#ffffff"
$PanelT23.Controls.Add($textBox233)

$ButtonST3c = New-Object System.Windows.Forms.Button
$ButtonST3c.Location = New-Object System.Drawing.Point(10,305)
$ButtonST3c.Size = New-Object System.Drawing.Size(130,40)
$ButtonST3c.Text = "SWEEP!"
$ButtonST3c.Font = "Verdana, 11"
$ButtonST3c.BackColor = "#101c28"
$PanelT23.Controls.Add($ButtonST3c)

$ButtonST3c.Add_Click({
    $textBox233.Text = "Attendere..."
    $ip = for ($i = 1 ; $i -le 254 ; $i++) {
                        ping -n 1 -w 100 192.168.1.$i | findstr "TTL"
                    }
    $dins = ($ip | Select-String -Pattern "(?:[0-9]{1,3}\.){3}[0-9]{1,3}" | ForEach-Object {$_.Matches[0..254].Value})
    $swp = ForEach ($ipdns in $dins) {Resolve-DnsName $ipdns 2> $null | ft Type,@{n="IP";e={$ipdns}},NameHost}
    $textBox233.Text = $dins + $swp | Out-String
})

# Add event handler to handle click events for the Labels
$Label_Click = {
    param($sender, $e)
    $clickedLabel = $sender
    if ($clickedLabel -eq $LabelT21) {
        $PanelT21.Visible = $true
        $PanelT22.Visible = $false
        $PanelT23.Visible = $false
    } elseif ($clickedLabel -eq $LabelT22) {
        $PanelT21.Visible = $false
        $PanelT22.Visible = $true
        $PanelT23.Visible = $false
    } elseif ($clickedLabel -eq $LabelT23) {
        $PanelT21.Visible = $false
        $PanelT22.Visible = $false
        $PanelT23.Visible = $true
    }
}

# Set the label indicator when its panel is active
$Label_ClickX2 = {
    param($sender, $e)
    $clickedLabel = $sender
    if ($clickedLabel -eq $LabelT21) {
        $Label2_1.Visible = $true
        $Label2_2.Visible = $false
        $Label2_3.Visible = $false
    } elseif ($clickedLabel -eq $LabelT22) {
        $Label2_1.Visible = $false
        $Label2_2.Visible = $true
        $Label2_3.Visible = $false
    } elseif ($clickedLabel -eq $LabelT23) {
        $Label2_1.Visible = $false
        $Label2_2.Visible = $false
        $Label2_3.Visible = $true
    }
}

# Assign the event handler to the Labels
$LabelT21.Add_Click($Label_Click)
$LabelT22.Add_Click($Label_Click)
$LabelT23.Add_Click($Label_Click)

$LabelT21.Add_Click($Label_ClickX2)
$LabelT22.Add_Click($Label_ClickX2)
$LabelT23.Add_Click($Label_ClickX2)



###### T A B 3 

# Create Label for TAB3
$LabelT3 = New-Object System.Windows.Forms.Label
$LabelT3.Text = "          DATI"
$LabelT3.Font = [System.Drawing.Font]::new("Arial", 12, [System.Drawing.FontStyle]::Bold)
$LabelT3.Location = New-Object System.Drawing.Point(305,15)
$LabelT3.ForeColor = "#ffb91a"
$LabelT3.BackColor = "#2e5276"
$LabelT3.Size = New-Object System.Drawing.Size(145,20)
$main_form.Controls.Add($LabelT3)

# Create TAB3
$PanelT3 = New-Object System.Windows.Forms.Panel
$PanelT3.Location = New-Object System.Drawing.Point(5,35)
$PanelT3.Size = New-Object System.Drawing.Size(900,590)
$PanelT3.BackColor = "#2e5276"
$main_form.Controls.Add($PanelT3)


### P A N E L  1

# Create Label for PANEL 1
$LabelT31 = New-Object System.Windows.Forms.Label
$LabelT31.Text = " CONFRONTO"
$LabelT31.Font = "Verdana, 11"
$LabelT31.Location = New-Object System.Drawing.Point(0,40)
$LabelT31.ForeColor = "#ebed31"
$LabelT31.BackColor = "#434c56"
$LabelT31.Size = New-Object System.Drawing.Size(145,20)
$PanelT3.Controls.Add($LabelT31)

# Create Panel
$PanelT31 = New-Object System.Windows.Forms.Panel
$PanelT31.Location = New-Object System.Drawing.Point(145,15)
$PanelT31.Size = New-Object System.Drawing.Size(900,590)
$PanelT31.BackColor = "#434c56"
$PanelT3.Controls.Add($PanelT31)

# Create a Label to signal when the Panel is selected
$Label3_1 = New-Object System.Windows.Forms.Label
$Label3_1.Text = "►"
$Label3_1.Font = "Verdana, 24"
$Label3_1.Location = New-Object System.Drawing.Point(125,-10)
$Label3_1.AutoSize = $true
$Label3_1.ForeColor = "#ebed31"
$LabelT31.Controls.Add($Label3_1)

# File section

$Label31Fi = New-Object System.Windows.Forms.Label
$Label31Fi.Text = "FILE"
$Label31Fi.Font = "Verdana, 11"
$Label31Fi.ForeColor = "#ffffff"
$Label31Fi.BackColor = "#391754"
$Label31Fi.Location = New-Object System.Drawing.Point(10,10)
$Label31Fi.Size = New-Object System.Drawing.Size (40,20)
$PanelT31.Controls.Add($Label31Fi)

# First file selection
$Label311 = New-Object System.Windows.Forms.Label
$Label311.Text = "Scegli il primo file"
$Label311.Font = "Verdana, 11"
$Label311.Location = New-Object System.Drawing.Point(10,40)
$Label311.AutoSize = $true
$PanelT31.Controls.Add($Label311)

$ButtonF1 = New-Object System.Windows.Forms.Button
$ButtonF1.Location = New-Object System.Drawing.Point(210,35)
$ButtonF1.Size = New-Object System.Drawing.Size(130,30)
$ButtonF1.Text = "FILE 1"
$ButtonF1.Font = "Verdana, 10"
$ButtonF1.BackColor = "#101c28"
$PanelT31.Controls.Add($ButtonF1)

$Label3F1 = New-Object System.Windows.Forms.Label
$Label3F1.Font = "Verdana, 9"
$Label3F1.Location = New-Object System.Drawing.Point(350,42)
$Label3F1.Size = New-Object System.Drawing.Size(360,18)
$Label3F1.AutoEllipsis = $true
$Label3F1.BackColor = "#101c28"
$PanelT31.Controls.Add($Label3F1)

Function File ($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Please Select File"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = “All files (*.*)| *.*”
    If ($OpenFileDialog.ShowDialog() -eq "Cancel") {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file!", "Error", 0, 
        [System.Windows.Forms.MessageBoxIcon]::Exclamation) | Out-Null # to avoid the "ok" message to show up
    }
    $Global:SelectedFile1 = $OpenFileDialog.SafeFileName
    $Global:SelectedPath1 = $OpenFileDialog.FileName
    Return $SelectedFile1
}

$ButtonF1.Add_Click({
    $Label3F1.Text = File    
})

# Second file selection
$Label312 = New-Object System.Windows.Forms.Label
$Label312.Text = "Scegli il secondo file"
$Label312.Font = "Verdana, 11"
$Label312.Location = New-Object System.Drawing.Point(10,80)
$Label312.AutoSize = $true
$PanelT31.Controls.Add($Label312)

$ButtonF2 = New-Object System.Windows.Forms.Button
$ButtonF2.Location = New-Object System.Drawing.Point(210,75)
$ButtonF2.Size = New-Object System.Drawing.Size(130,30)
$ButtonF2.Text = "FILE 2"
$ButtonF2.Font = "Verdana, 10"
$ButtonF2.BackColor = "#101c28"
$PanelT31.Controls.Add($ButtonF2)

$Label3F2 = New-Object System.Windows.Forms.Label
$Label3F2.Font = "Verdana, 9"
$Label3F2.Location = New-Object System.Drawing.Point(350,82)
$Label3F2.Size = New-Object System.Drawing.Size(360,18)
$Label3F2.AutoEllipsis = $true
$Label3F2.BackColor = "#101c28"
$PanelT31.Controls.Add($Label3F2)

Function File2 ($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Please Select File"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = “All files (*.*)| *.*”
    If ($OpenFileDialog.ShowDialog() -eq "Cancel") {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file!", "Error", 0, 
        [System.Windows.Forms.MessageBoxIcon]::Exclamation) | Out-Null # to avoid the "ok" message to show up
    }
    $Global:SelectedFile2 = $OpenFileDialog.SafeFileName
    $Global:SelectedPath2 = $OpenFileDialog.FileName
    Return $SelectedFile2
    #Return $SelectedPath
} 

$ButtonF2.Add_Click({
    $Label3F2.Text = File2   
})

$ButtonFID = New-Object System.Windows.Forms.Button
$ButtonFID.Location = New-Object System.Drawing.Point(10,115)
$ButtonFID.Size = New-Object System.Drawing.Size(130,30)
$ButtonFID.Text = "CONFRONTA"
$ButtonFID.Font = "Verdana, 11"
$ButtonFID.BackColor = "#101c28"
$PanelT31.Controls.Add($ButtonFID)

$textBox3ID = New-Object System.Windows.Forms.TextBox
$textBox3ID.Location = New-Object System.Drawing.Point(10,150)
$textBox3ID.Size = New-Object System.Drawing.Size(700,80)
$textBox3ID.Multiline = $true
$textBox3ID.Font = "Verdana, 11"
$textBox3ID.BackColor = "#08243f"
$textBox3ID.ForeColor = "#ffffff"
$PanelT31.Controls.Add($textBox3ID)

$ButtonFID.Add_Click({
    $textBox3ID.Text = "Attendere..."
    if ($SelectedPath1 -or $SelectedPath2 -eq "") {
        $1sha1 = (Get-FileHash -Path $($SelectedPath2) -Algorithm SHA1).hash
        $2sha1 = (Get-FileHash -Path $($SelectedPath1) -Algorithm SHA1).hash
        If ($1sha1 -eq $2sha1) {
             $textBox3ID.Text = "Lo SHA1 è il medesimo: $($1sha1)" | Out-String
        } else {
             $textBox3ID.Text = "I due SHA1 differiscono: `r`n$($1sha1) `r`n$($2sha1)" | Out-String
        }
    } else {
        $textBox3ID.Text = "Scegliere i file"
    }
})

# Folder section

$Label31Fo = New-Object System.Windows.Forms.Label
$Label31Fo.Text = "CARTELLE"
$Label31Fo.Font = "Verdana, 11"
$Label31Fo.ForeColor = "#ffffff"
$Label31Fo.BackColor = "#391754"
$Label31Fo.Location = New-Object System.Drawing.Point(10,255)
$Label31Fo.Size = New-Object System.Drawing.Size (85,20)
$PanelT31.Controls.Add($Label31Fo)

# First folder selection
$Label311f = New-Object System.Windows.Forms.Label
$Label311f.Text = "Scegli la prima cartella"
$Label311f.Font = "Verdana, 11"
$Label311f.Location = New-Object System.Drawing.Point(10,285)
$Label311f.AutoSize = $true
$PanelT31.Controls.Add($Label311f)

$ButtonFf1 = New-Object System.Windows.Forms.Button
$ButtonFf1.Location = New-Object System.Drawing.Point(210,280)
$ButtonFf1.Size = New-Object System.Drawing.Size(130,30)
$ButtonFf1.Text = "CARTELLA 1"
$ButtonFf1.Font = "Verdana, 10"
$ButtonFf1.BackColor = "#101c28"
$PanelT31.Controls.Add($ButtonFf1)

$Label3Ff1 = New-Object System.Windows.Forms.Label
$Label3Ff1.Font = "Verdana, 9"
$Label3Ff1.Location = New-Object System.Drawing.Point(350,287)
$Label3Ff1.Size = New-Object System.Drawing.Size(360,18)
$Label3Ff1.AutoEllipsis = $true
$Label3Ff1.BackColor = "#101c28"
$PanelT31.Controls.Add($Label3Ff1)

$ButtonFf1.Add_Click({
    $folderBrowser1 = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser1.ShowDialog() | Out-Null
    $Label3Ff1.Text = $folderBrowser1.SelectedPath
})

# Second folder selection
$Label312f = New-Object System.Windows.Forms.Label
$Label312f.Text = "Scegli la seconda cartella"
$Label312f.Font = "Verdana, 11"
$Label312f.Location = New-Object System.Drawing.Point(10,325)
$Label312f.AutoSize = $true
$PanelT31.Controls.Add($Label312f)

$ButtonFf2 = New-Object System.Windows.Forms.Button
$ButtonFf2.Location = New-Object System.Drawing.Point(210,320)
$ButtonFf2.Size = New-Object System.Drawing.Size(130,30)
$ButtonFf2.Text = "CARTELLA 2"
$ButtonFf2.Font = "Verdana, 10"
$ButtonFf2.BackColor = "#101c28"
$PanelT31.Controls.Add($ButtonFf2)

$Label3Ff2 = New-Object System.Windows.Forms.Label
$Label3Ff2.Font = "Verdana, 9"
$Label3Ff2.Location = New-Object System.Drawing.Point(350,327)
$Label3Ff2.Size = New-Object System.Drawing.Size(360,18)
$Label3Ff2.AutoEllipsis = $true
$Label3Ff2.BackColor = "#101c28"
$PanelT31.Controls.Add($Label3Ff2)

$ButtonFf2.Add_Click({
    $folderBrowser2 = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser2.ShowDialog() | Out-Null
    $Label3Ff2.Text = $folderBrowser2.SelectedPath
})

$ButtonFIDf = New-Object System.Windows.Forms.Button
$ButtonFIDf.Location = New-Object System.Drawing.Point(10,360)
$ButtonFIDf.Size = New-Object System.Drawing.Size(130,30)
$ButtonFIDf.Text = "CONFRONTA"
$ButtonFIDf.Font = "Verdana, 11"
$ButtonFIDf.BackColor = "#101c28"
$PanelT31.Controls.Add($ButtonFIDf)

$Label31n = New-Object System.Windows.Forms.Label
$Label31n.Text = "(Cerca file con stesso nome ma dati diversi, o file che non sono in entrambe le cartelle)"
$Label31n.Font = "Verdana, 9"
$Label31n.ForeColor = "#ffffff"
$Label31n.Location = New-Object System.Drawing.Point(145,367)
$Label31n.Size = New-Object System.Drawing.Size (550,20)
$PanelT31.Controls.Add($Label31n)

$textBox3IDf = New-Object System.Windows.Forms.TextBox
$textBox3IDf.Location = New-Object System.Drawing.Point(10,395)
$textBox3IDf.Size = New-Object System.Drawing.Size(700,170)
$textBox3IDf.Multiline = $true
$textBox3IDf.ScrollBars = "both"
$textBox3IDf.Font = "Verdana, 11"
$textBox3IDf.BackColor = "#08243f"
$textBox3IDf.ForeColor = "#ffffff"
$PanelT31.Controls.Add($textBox3IDf)

$ButtonFIDf.Add_Click({
    if ($Label3Ff1.Text -and $Label3Ff2.Text -ne "") {
        $textBox3IDf.Text = "Attendere..."
        $files1 = Get-ChildItem "$($Label3Ff1.Text)" -Recurse
        $files2 = Get-ChildItem "$($Label3Ff2.Text)" -Recurse
        $files1f = Get-ChildItem "$($Label3Ff1.Text)"
        $files2f = Get-ChildItem "$($Label3Ff2.Text)"
        $textBox3IDf.Text = "`nFILE MODIFICATI (stesso nome, dati diversi), se presenti:"
        foreach ($file1f in $files1f) {
                 $file2f = $files2f | Where-Object {$_.Name -eq $file1f.Name} 
                 if ($file2f -ne $null) {
                     $hash1f = Get-FileHash $file1f.FullName | Select-Object -ExpandProperty Hash 
                     $hash2f = Get-FileHash $file2f.FullName | Select-Object -ExpandProperty Hash
                     if ($hash1f -ne $hash2f) {
                         $textBox3IDf.Text += "`r`nIl file $($file1f.FullName) e `r`n il file $($file2f.FullName) hanno contenuto diverso" | Out-String
                     }
                 }
        }
        foreach ($file1 in $files1) {
                 $file2 = $files2 | Where-Object {$_.Name -eq $file1.Name -and $_.Directory.Name -eq $file1.Directory.Name} 
                 if ($file2 -ne $null) {
                     $hash1 = Get-FileHash $file1.FullName | Select-Object -ExpandProperty Hash 
                     $hash2 = Get-FileHash $file2.FullName | Select-Object -ExpandProperty Hash
                     if ($hash1 -ne $hash2) {
                         $textBox3IDf.Text += "`r`nIl file $($file1.FullName) e `r`n il file $($file2.FullName) hanno contenuto diverso" | Out-String
                     }
                 }
        }
        $textBox3IDf.Text += "`r`n `r`nFILE UNICI (se presenti):`r`n"
        foreach ($single in (Compare-Object -ReferenceObject $files1 -DifferenceObject $files2 -PassThru)) {
            $singlelist += "`r$($single.fullname)" | Out-String
        }
        $textBox3IDf.Text += $singlelist
    } else {
        $textBox3IDf.Text = "Scegliere le cartelle"
        return
    }
})


### P A N E L  2

# Create Label for PANEL 2
$LabelT32 = New-Object System.Windows.Forms.Label
$LabelT32.Text = " RICERCA"
$LabelT32.Font = "Verdana, 11"
$LabelT32.Location = New-Object System.Drawing.Point(0,75)
$LabelT32.ForeColor = "#ebed31"
$LabelT32.BackColor = "#434c56"
$LabelT32.Size = New-Object System.Drawing.Size(145,20) 
$PanelT3.Controls.Add($LabelT32)

# Create Panel
$PanelT32 = New-Object System.Windows.Forms.Panel
$PanelT32.Location = New-Object System.Drawing.Point(145,15)
$PanelT32.Size = New-Object System.Drawing.Size(900,590)
$PanelT32.BackColor = "#434c56"
$PanelT3.Controls.Add($PanelT32)

# Create a Label to signal when the Panel is selected
$Label3_2 = New-Object System.Windows.Forms.Label
$Label3_2.Text = "►"
$Label3_2.Font = "Verdana, 24"
$Label3_2.Location = New-Object System.Drawing.Point(125,-10)
$Label3_2.AutoSize = $true
$Label3_2.ForeColor = "#ebed31"
$Label3_2.Visible = $false
$LabelT32.Controls.Add($Label3_2)

# Duplicates section

$Label32D = New-Object System.Windows.Forms.Label
$Label32D.Text = "TROVA FILE DUPLICATI"
$Label32D.Font = "Verdana, 11"
$Label32D.ForeColor = "#ffffff"
$Label32D.BackColor = "#391754"
$Label32D.Location = New-Object System.Drawing.Point(10,10)
$Label32D.Size = New-Object System.Drawing.Size (185,20)
$PanelT32.Controls.Add($Label32D)

$Label32Dd = New-Object System.Windows.Forms.Label
$Label32Dd.Text = "(basato su SHA1)"
$Label32Dd.Font = "Verdana, 9"
$Label32Dd.ForeColor = "#ffffff"
$Label32Dd.Location = New-Object System.Drawing.Point(197,12)
$Label32Dd.Size = New-Object System.Drawing.Size (130,20)
$PanelT32.Controls.Add($Label32Dd)

# Folder selection
$Label321 = New-Object System.Windows.Forms.Label
$Label321.Text = "Scegli dove cercare"
$Label321.Font = "Verdana, 11"
$Label321.Location = New-Object System.Drawing.Point(10,40)
$Label321.AutoSize = $true
$PanelT32.Controls.Add($Label321)

$ButtonF1 = New-Object System.Windows.Forms.Button
$ButtonF1.Location = New-Object System.Drawing.Point(210,35)
$ButtonF1.Size = New-Object System.Drawing.Size(130,30)
$ButtonF1.Text = "CARTELLA"
$ButtonF1.Font = "Verdana, 10"
$ButtonF1.BackColor = "#101c28"
$PanelT32.Controls.Add($ButtonF1)

$Label32F1 = New-Object System.Windows.Forms.Label
$Label32F1.Font = "Verdana, 9"
$Label32F1.Location = New-Object System.Drawing.Point(350,42)
$Label32F1.Size = New-Object System.Drawing.Size(360,18)
$Label32F1.AutoEllipsis = $true
$Label32F1.BackColor = "#101c28"
$PanelT32.Controls.Add($Label32F1)

$ButtonF1.Add_Click({
    $folderBrowser1 = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser1.ShowDialog() | Out-Null
    $Label32F1.Text = $folderBrowser1.SelectedPath
})

# Create CHECK BOX
$checkBox1 = New-Object System.Windows.Forms.CheckBox
$checkBox1.Text = " Ricerca ricorsiva"
$checkBox1.Font = "Verdana, 11"
$checkBox1.AutoSize = $true
$checkBox1.Location = New-Object System.Drawing.Point(355,75)
$panelT32.Controls.Add($checkBox1)

# Create minimum size settings
$Label323 = New-Object System.Windows.Forms.Label
$Label323.Font = "Verdana, 11"
$Label323.Location = New-Object System.Drawing.Point(355,110)
$Label323.Size = New-Object System.Drawing.Size(195,20)
$Label323.Text = "Dimensione min. (byte):"
$PanelT32.Controls.Add($Label323)

$textBox321 = New-Object System.Windows.Forms.TextBox
$textBox321.Location = New-Object System.Drawing.Point(550,105)
$textBox321.Size = New-Object System.Drawing.Size(160,18)
$textBox321.Font = "Verdana, 11"
$textBox321.BackColor = "#1d1e25"
$textBox321.ForeColor = "#ffffff"
$textBox321.Add_GotFocus({ $textBox321.BackColor = "#000000" })
$textBox321.Add_LostFocus({ $textBox321.BackColor = "#1d1e25" })
$PanelT32.Controls.Add($textBox321)

# Duplicates button and output
$ButtonFD = New-Object System.Windows.Forms.Button
$ButtonFD.Location = New-Object System.Drawing.Point(10,100)
$ButtonFD.Size = New-Object System.Drawing.Size(130,30)
$ButtonFD.Text = "TROVA"
$ButtonFD.Font = "Verdana, 11"
$ButtonFD.BackColor = "#101c28"
$PanelT32.Controls.Add($ButtonFD)

$textBox3FD = New-Object System.Windows.Forms.TextBox
$textBox3FD.Location = New-Object System.Drawing.Point(10,135)
$textBox3FD.Size = New-Object System.Drawing.Size(700,95)
$textBox3FD.Multiline = $true
$textBox3FD.ScrollBars = "both"
$textBox3FD.Font = "Verdana, 11"
$textBox3FD.BackColor = "#08243f"
$textBox3FD.ForeColor = "#ffffff"
$PanelT32.Controls.Add($textBox3FD)

$ButtonFD.Add_Click({
    $textBox3FD.Text = "Attendere..."
    if ($checkBox1.Checked) {
    $filez = {Get-ChildItem -File -Path "$($Label32F1.Text)" -Recurse}
    } else {
    $filez = {Get-ChildItem -File -Path "$($Label32F1.Text)"}
    }
    if ($textBox321.Text -eq "") {
                $textBox321.Text = 0
    }
    $files = try {
      &($filez) | where-object {$_.length -gt $textBox321.Text}
    } catch {
    }
    $list = @{}
    foreach ($file in $files) {
          $dim = $file.length
      if ($list.ContainsKey($dim)) {
          $list[$dim] += $file
      } else {
          $list[$dim] = @($file)
      }
    }
    $a = @{}
    foreach ($dim in $list.Keys) {
      $doppi = $list[$dim]
      if ($doppi.Count -gt 1) {
          foreach ($doppio in $doppi) {
              $hash = certutil -hashfile $doppio.FullName SHA1 | Select-Object -skip 1 -erroraction Ignore | select-string (1..40) -ErrorAction Ignore
              try {$hash = $hash.ToString()} catch {continue}
              try {$a[$hash] += "- "+$doppio.FullName+" ]"} catch {continue}
          }
      }
    }
    $a1 = foreach ($item in $a.GetEnumerator() | sort Name) {$item.value}
    $result = foreach ($v in $a1) {
       if ($v -match "\]\-") {
           foreach ($key in $a.GetEnumerator() | Where-Object {$_.value -eq $v}) {
               ($key.name + " (SHA1)")
           }
           "$v".split("]")
       }
    }
    $textBox3FD.Text = "File doppi (se presenti) :`r`n" + ($($result) | Out-String)
})

# Find files section

$Label32F = New-Object System.Windows.Forms.Label
$Label32F.Text = "TROVA FILE"
$Label32F.Font = [System.Drawing.Font]::new("Arial", 12, [System.Drawing.FontStyle]::Bold)
$Label32F.Font = "Verdana, 11" 
$Label32F.ForeColor = "#ffffff"
$Label32F.BackColor = "#391754"
$Label32F.Location = New-Object System.Drawing.Point(10,255)
$Label32F.Size = New-Object System.Drawing.Size (100,20)
$PanelT32.Controls.Add($Label32F)

# Folder selection
$Label324 = New-Object System.Windows.Forms.Label
$Label324.Text = "Scegli dove cercare"
$Label324.Font = "Verdana, 11"
$Label324.Location = New-Object System.Drawing.Point(10,285)
$Label324.AutoSize = $true
$PanelT32.Controls.Add($Label324)

$ButtonF2 = New-Object System.Windows.Forms.Button
$ButtonF2.Location = New-Object System.Drawing.Point(210,280)
$ButtonF2.Size = New-Object System.Drawing.Size(130,30)
$ButtonF2.Text = "CARTELLA"
$ButtonF2.Font = "Verdana, 10"
$ButtonF2.BackColor = "#101c28"
$PanelT32.Controls.Add($ButtonF2)

$Label32F2 = New-Object System.Windows.Forms.Label
$Label32F2.Font = "Verdana, 9"
$Label32F2.Location = New-Object System.Drawing.Point(350,287)
$Label32F2.Size = New-Object System.Drawing.Size(360,18)
$Label32F2.AutoEllipsis = $true
$Label32F2.BackColor = "#101c28"
$PanelT32.Controls.Add($Label32F2)

$ButtonF2.Add_Click({
    $folderBrowser2 = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser2.ShowDialog() | Out-Null
    $Label32F2.Text = $folderBrowser2.SelectedPath
})

# Create minimum size settings
$Label325 = New-Object System.Windows.Forms.Label
$Label325.Font = "Verdana, 11"
$Label325.Location = New-Object System.Drawing.Point(355,322)
$Label325.Size = New-Object System.Drawing.Size(195,20)
$Label325.Text = "Dimensione min. (byte):"
$PanelT32.Controls.Add($Label325)

$textBox322 = New-Object System.Windows.Forms.TextBox
$textBox322.Location = New-Object System.Drawing.Point(550,320)
$textBox322.Size = New-Object System.Drawing.Size(160,18)
$textBox322.Font = "Verdana, 11"
$textBox322.BackColor = "#1d1e25"
$textBox322.ForeColor = "#ffffff"
$textBox322.Add_GotFocus({ $textBox322.BackColor = "#000000" })
$textBox322.Add_LostFocus({ $textBox322.BackColor = "#1d1e25" })
$PanelT32.Controls.Add($textBox322)

# Create maximum size settings
$Label326 = New-Object System.Windows.Forms.Label
$Label326.Font = "Verdana, 11"
$Label326.Location = New-Object System.Drawing.Point(355,357)
$Label326.Size = New-Object System.Drawing.Size(195,20)
$Label326.Text = "Dimensione max (byte):"
$PanelT32.Controls.Add($Label326)

$textBox323 = New-Object System.Windows.Forms.TextBox
$textBox323.Location = New-Object System.Drawing.Point(550,355)
$textBox323.Size = New-Object System.Drawing.Size(160,18)
$textBox323.Font = "Verdana, 11"
$textBox323.BackColor = "#1d1e25"
$textBox323.ForeColor = "#ffffff"
$textBox323.Add_GotFocus({ $textBox323.BackColor = "#000000" })
$textBox323.Add_LostFocus({ $textBox323.BackColor = "#1d1e25" })
$PanelT32.Controls.Add($textBox323)

# Create file name selection
$Label325 = New-Object System.Windows.Forms.Label
$Label325.Font = "Verdana, 11"
$Label325.Location = New-Object System.Drawing.Point(10,322)
$Label325.Size = New-Object System.Drawing.Size(180,20)
$Label325.Text = "Nome file (o parziale):"
$PanelT32.Controls.Add($Label325)

$textBox324 = New-Object System.Windows.Forms.TextBox
$textBox324.Location = New-Object System.Drawing.Point(190,320)
$textBox324.Size = New-Object System.Drawing.Size(150,18)
$textBox324.Font = "Verdana, 11"
$textBox324.BackColor = "#1d1e25"
$textBox324.ForeColor = "#ffffff"
$textBox324.Add_GotFocus({ $textBox324.BackColor = "#000000" })
$textBox324.Add_LostFocus({ $textBox324.BackColor = "#1d1e25" })
$PanelT32.Controls.Add($textBox324)

# Create extension selection
$Label326 = New-Object System.Windows.Forms.Label
$Label326.Font = "Verdana, 11"
$Label326.Location = New-Object System.Drawing.Point(10,357)
$Label326.Size = New-Object System.Drawing.Size(240,20)
$Label326.Text = "Estensione file (txt, pdf, etc.):"
$PanelT32.Controls.Add($Label326)

$textBox325 = New-Object System.Windows.Forms.TextBox
$textBox325.Location = New-Object System.Drawing.Point(250,355)
$textBox325.Size = New-Object System.Drawing.Size(90,18)
$textBox325.Font = "Verdana, 11"
$textBox325.BackColor = "#1d1e25"
$textBox325.ForeColor = "#ffffff"
$textBox325.Add_GotFocus({ $textBox325.BackColor = "#000000" })
$textBox325.Add_LostFocus({ $textBox325.BackColor = "#1d1e25" })
$PanelT32.Controls.Add($textBox325)

# File finder button and output
$ButtonFF = New-Object System.Windows.Forms.Button
$ButtonFF.Location = New-Object System.Drawing.Point(10,390)
$ButtonFF.Size = New-Object System.Drawing.Size(130,30)
$ButtonFF.Text = "TROVA"
$ButtonFF.Font = "Verdana, 11"
$ButtonFF.BackColor = "#101c28"
$PanelT32.Controls.Add($ButtonFF)

$textBox3FF = New-Object System.Windows.Forms.TextBox
$textBox3FF.Location = New-Object System.Drawing.Point(10,425)
$textBox3FF.Size = New-Object System.Drawing.Size(700,140)
$textBox3FF.Multiline = $true
$textBox3FF.ScrollBars = "both"
$textBox3FF.Font = "Verdana, 11"
$textBox3FF.BackColor = "#08243f"
$textBox3FF.ForeColor = "#ffffff"
$PanelT32.Controls.Add($textBox3FF)

$ButtonFF.Add_Click({
    $textBox3FF.Text = "Attendere..."
    if (!$textBox324.Text) {
      $textBox324.Text = "*"
    }
    if (!$textBox325.Text) {
      $textBox325.Text = "*"
    }
    if (!$Label32F2.Text) {
      $Label32F2.Text = "$HOME"
    }
    if (!$textBox322.Text) {
      $textBox322.Text = "1"
    }
    if (!$textBox323.Text) {
      $textBox323.Text = "5000000000000"
    }
    $textBox3FF.Text = Get-ChildItem *$($textBox324.Text)* -Path "$($Label32F2.Text)" -Recurse -Include *.$($textBox325.Text) | Where-Object {$_.length -gt $textBox322.Text -and $_.length -lt $textBox323.Text}  | ft name,Directory | Out-String
})


### P A N E L  3

# Create Label for PANEL 3
$LabelT33 = New-Object System.Windows.Forms.Label
$LabelT33.Text = " MODIFICA"
$LabelT33.Font = "Verdana, 11"
$LabelT33.Location = New-Object System.Drawing.Point(0,110)
$LabelT33.ForeColor = "#ebed31"
$LabelT33.BackColor = "#434c56"
$LabelT33.Size = New-Object System.Drawing.Size(145,20)
$PanelT3.Controls.Add($LabelT33)

# Create Panel
$PanelT33 = New-Object System.Windows.Forms.Panel
$PanelT33.Location = New-Object System.Drawing.Point(145,15)
$PanelT33.Size = New-Object System.Drawing.Size(900,590)
$PanelT33.BackColor = "#434c56"
$PanelT3.Controls.Add($PanelT33)

# Create a Label to signal when the Panel is selected
$Label3_3 = New-Object System.Windows.Forms.Label
$Label3_3.Text = "►"
$Label3_3.Font = "Verdana, 24"
$Label3_3.Location = New-Object System.Drawing.Point(125,-10)
$Label3_3.AutoSize = $true
$Label3_3.ForeColor = "#ebed31"
$Label3_3.Visible = $false
$LabelT33.Controls.Add($Label3_3)

# Split file section

$Label33s = New-Object System.Windows.Forms.Label
$Label33s.Text = "DIVIDI FILE"
$Label33s.Font = "Verdana, 11"
$Label33s.ForeColor = "#ffffff"
$Label33s.BackColor = "#391754"
$Label33s.Location = New-Object System.Drawing.Point(10,10)
$Label33s.Size = New-Object System.Drawing.Size (100,20)
$PanelT33.Controls.Add($Label33s)

# File selection
$Label331 = New-Object System.Windows.Forms.Label
$Label331.Text = "File da dividere"
$Label331.Font = "Verdana, 11"
$Label331.Location = New-Object System.Drawing.Point(10,40)
$Label331.AutoSize = $true
$PanelT33.Controls.Add($Label331)

$ButtonF = New-Object System.Windows.Forms.Button
$ButtonF.Location = New-Object System.Drawing.Point(140,35)
$ButtonF.Size = New-Object System.Drawing.Size(120,30)
$ButtonF.Text = "FILE"
$ButtonF.Font = "Verdana, 10"
$ButtonF.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonF)

$Label3F = New-Object System.Windows.Forms.Label
$Label3F.Font = "Verdana, 9"
$Label3F.Location = New-Object System.Drawing.Point(270,42)
$Label3F.Size = New-Object System.Drawing.Size (480,18)
$Label3F.AutoEllipsis = $true
$Label3F.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3F)

Function FileAB ($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Please Select File"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = “All files (*.*)| *.*”
    If ($OpenFileDialog.ShowDialog() -eq "Cancel") {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file!", "Error", 0, 
        [System.Windows.Forms.MessageBoxIcon]::Exclamation) | Out-Null # to avoid the "ok" message to show up
    }
    $Global:SelectedFile2 = $OpenFileDialog.SafeFileName
    $Global:SelectedPath2 = $OpenFileDialog.FileName
    Return $SelectedFile2
} 

$ButtonF.Add_Click({
    $Label3F.Text = FileAB   
})

# First folder selection
$Label332 = New-Object System.Windows.Forms.Label
$Label332.Text = "Cartella 1a metà"
$Label332.Font = "Verdana, 11"
$Label332.Location = New-Object System.Drawing.Point(10,75)
$Label332.AutoSize = $true
$Label332.Visible = $true
$PanelT33.Controls.Add($Label332)

$ButtonFa = New-Object System.Windows.Forms.Button
$ButtonFa.Location = New-Object System.Drawing.Point(150,70)
$ButtonFa.Size = New-Object System.Drawing.Size(120,30)
$ButtonFa.Text = "CARTELLA A"
$ButtonFa.Font = "Verdana, 10"
$ButtonFa.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonFa)

$Label3Fa = New-Object System.Windows.Forms.Label
$Label3Fa.Font = "Verdana, 9"
$Label3Fa.Location = New-Object System.Drawing.Point(280,77)
$Label3Fa.Size = New-Object System.Drawing.Size (280,18)
$Label3Fa.AutoEllipsis = $true
$Label3Fa.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3Fa)

$ButtonFa.Add_Click({
    $folderBrowsera = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowsera.ShowDialog() | Out-Null
    $selectedPatha = $folderBrowsera.SelectedPath
    $Label3Fa.Text = "$($selectedPatha)\File_1-2"
})

# Second folder selection
$Label333 = New-Object System.Windows.Forms.Label
$Label333.Text = "Cartella 2a metà"
$Label333.Font = "Verdana, 11"
$Label333.Location = New-Object System.Drawing.Point(10,110)
$Label333.AutoSize = $true
$Label333.Visible = $true
$PanelT33.Controls.Add($Label333)

$ButtonFb = New-Object System.Windows.Forms.Button
$ButtonFb.Location = New-Object System.Drawing.Point(150,105)
$ButtonFb.Size = New-Object System.Drawing.Size(120,30)
$ButtonFb.Text = "CARTELLA B"
$ButtonFb.Font = "Verdana, 10"
$ButtonFb.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonFb)

$Label3Fb = New-Object System.Windows.Forms.Label
$Label3Fb.Font = "Verdana, 9"
$Label3Fb.Location = New-Object System.Drawing.Point(280,112)
$Label3Fb.Size = New-Object System.Drawing.Size (280,18)
$Label3Fb.AutoEllipsis = $true
$Label3Fb.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3Fb)

$ButtonFb.Add_Click({
    $folderBrowserb = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowserb.ShowDialog() | Out-Null
    $selectedPathb = $folderBrowserb.SelectedPath
    $Label3Fb.Text = "$($selectedPathb)\File_2-2"
})

# Set labels tooltips
$tooltip1 = New-Object System.Windows.Forms.ToolTip
$tooltip1.SetToolTip($Label3Fa, "...\File_1-2")
$tooltip2 = New-Object System.Windows.Forms.ToolTip
$tooltip2.SetToolTip($Label3Fb, "...\File_2-2")

# Split execution section
$ButtonFS = New-Object System.Windows.Forms.Button
$ButtonFS.Location = New-Object System.Drawing.Point(585,75)
$ButtonFS.Size = New-Object System.Drawing.Size(130,30)
$ButtonFS.Text = "DIVIDI!"
$ButtonFS.Font = "Verdana, 11"
$ButtonFS.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonFS)

$textBox3FS = New-Object System.Windows.Forms.TextBox
$textBox3FS.Location = New-Object System.Drawing.Point(585,110)
$textBox3FS.Size = New-Object System.Drawing.Size (130,30)
$textBox3FS.Multiline = $true
$textBox3FS.Font = "Verdana, 11"
$textBox3FS.BackColor = "#08243f"
$textBox3FS.ForeColor = "#ffffff"
$PanelT33.Controls.Add($textBox3FS)

$ButtonFS.Add_Click({
    $filePath = $Label3F.Text
    $bytes = [System.IO.File]::ReadAllBytes($SelectedPath2)
    $partSize = [math]::Ceiling($bytes.Length / 2)
    $part1 = $bytes[0..($partSize - 1)]
    $part2 = $bytes[$partSize..($bytes.Length - 1)]
    [System.IO.File]::WriteAllBytes($Label3Fa.Text, $part1)
    [System.IO.File]::WriteAllBytes($Label3Fb.Text, $part2)
    $textBox3FS.Text = $? | Out-String
    if ($textBox3FS.Text -match "True") {
        $textBox3FS.Text = "Fatto"
    } else {
        $textBox3FS.Text = "ERRORE!"
    }
})

# Join section

$Label33j = New-Object System.Windows.Forms.Label
$Label33j.Text = "UNISCI FILE"
$Label33j.Font = "Verdana, 11"
$Label33j.ForeColor = "#ffffff"
$Label33j.BackColor = "#391754"
$Label33j.Location = New-Object System.Drawing.Point(10,170)
$Label33j.Size = New-Object System.Drawing.Size (105,20)
$PanelT33.Controls.Add($Label33j)

# File selection
$Label331j = New-Object System.Windows.Forms.Label
$Label331j.Text = "Cartella output"
$Label331j.Font = "Verdana, 11"
$Label331j.Location = New-Object System.Drawing.Point(10,200)
$Label331j.AutoSize = $true
$PanelT33.Controls.Add($Label331j)

$ButtonFJ = New-Object System.Windows.Forms.Button
$ButtonFJ.Location = New-Object System.Drawing.Point(135,195)
$ButtonFJ.Size = New-Object System.Drawing.Size(120,30)
$ButtonFJ.Text = "CARTELLA"
$ButtonFJ.Font = "Verdana, 10"
$ButtonFJ.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonFJ)

$Label3FJ = New-Object System.Windows.Forms.Label
$Label3FJ.Font = "Verdana, 9"
$Label3FJ.Location = New-Object System.Drawing.Point(260,202)
$Label3FJ.Size = New-Object System.Drawing.Size (480,18)
$Label3FJ.AutoEllipsis = $true
$Label3FJ.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3FJ)

$ButtonFJ.Add_Click({
    $folderJoin = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderJoin.ShowDialog() | Out-Null
    $selectedPathJ = $folderJoin.SelectedPath
    $Label3FJ.Text = "$($selectedPathJ)\File_total"
})

# First folder selection
$Label332j = New-Object System.Windows.Forms.Label
$Label332j.Text = "1° file da unire"
$Label332j.Font = "Verdana, 11"
$Label332j.Location = New-Object System.Drawing.Point(10,235)
$Label332j.AutoSize = $true
$Label332j.Visible = $true
$PanelT33.Controls.Add($Label332j)

$ButtonJa = New-Object System.Windows.Forms.Button
$ButtonJa.Location = New-Object System.Drawing.Point(145,230)
$ButtonJa.Size = New-Object System.Drawing.Size(120,30)
$ButtonJa.Text = "FILE 1"
$ButtonJa.Font = "Verdana, 10"
$ButtonJa.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonJa)

$Label3Ja = New-Object System.Windows.Forms.Label
$Label3Ja.Font = "Verdana, 9"
$Label3Ja.Location = New-Object System.Drawing.Point(275,237)
$Label3Ja.Size = New-Object System.Drawing.Size (280,18)
$Label3Ja.AutoEllipsis = $true
$Label3Ja.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3Ja)

Function File12 ($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Please Select File"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = “All files (*.*)| *.*”
    If ($OpenFileDialog.ShowDialog() -eq "Cancel") {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file!", "Error", 0, 
        [System.Windows.Forms.MessageBoxIcon]::Exclamation) | Out-Null # to avoid the "ok" message to show up
    }
    $Global:SelectedFile12 = $OpenFileDialog.SafeFileName
    $Global:SelectedPath12 = $OpenFileDialog.FileName
    Return $SelectedPath12
} 

$ButtonJa.Add_Click({
   $Label3Ja.Text = File12
})

# Second folder selection
$Label333j = New-Object System.Windows.Forms.Label
$Label333j.Text = "2° file da unire"
$Label333j.Font = "Verdana, 11"
$Label333j.Location = New-Object System.Drawing.Point(10,270)
$Label333j.AutoSize = $true
$Label333j.Visible = $true
$PanelT33.Controls.Add($Label333j)

$ButtonJb = New-Object System.Windows.Forms.Button
$ButtonJb.Location = New-Object System.Drawing.Point(145,265)
$ButtonJb.Size = New-Object System.Drawing.Size(120,30)
$ButtonJb.Text = "FILE 2"
$ButtonJb.Font = "Verdana, 10"
$ButtonJb.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonJb)

$Label3Jb = New-Object System.Windows.Forms.Label
$Label3Jb.Font = "Verdana, 9"
$Label3Jb.Location = New-Object System.Drawing.Point(275,272)
$Label3Jb.Size = New-Object System.Drawing.Size (280,18)
$Label3Jb.AutoEllipsis = $true
$Label3Jb.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3Jb)

Function File22 ($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Please Select File"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = “All files (*.*)| *.*”
    If ($OpenFileDialog.ShowDialog() -eq "Cancel") {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file!", "Error", 0, 
        [System.Windows.Forms.MessageBoxIcon]::Exclamation) | Out-Null # to avoid the "ok" message to show up
    }
    $Global:SelectedFile22 = $OpenFileDialog.SafeFileName
    $Global:SelectedPath22 = $OpenFileDialog.FileName
    Return $SelectedPath22
}

$ButtonJb.Add_Click({
    $Label3Jb.Text = File22 
})

# Set labels tooltips
$tooltip3 = New-Object System.Windows.Forms.ToolTip
$tooltip3.SetToolTip($Label3FJ, "...\File_total")

# Join execution section
$ButtonJ = New-Object System.Windows.Forms.Button
$ButtonJ.Location = New-Object System.Drawing.Point(585,235)
$ButtonJ.Size = New-Object System.Drawing.Size(130,30)
$ButtonJ.Text = "UNISCI!"
$ButtonJ.Font = "Verdana, 11"
$ButtonJ.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonJ)

$textBox3JS = New-Object System.Windows.Forms.TextBox
$textBox3JS.Location = New-Object System.Drawing.Point(585,270)
$textBox3JS.Size = New-Object System.Drawing.Size (130,30)
$textBox3JS.Multiline = $true
$textBox3JS.Font = "Verdana, 11"
$textBox3JS.BackColor = "#08243f"
$textBox3JS.ForeColor = "#ffffff"
$PanelT33.Controls.Add($textBox3JS)

$ButtonJ.Add_Click({
    $textBox3JS.Text =  Get-Content -Encoding Byte ($SelectedPath12), $($SelectedPath22) | Set-Content $Label3FJ.Text -Encoding Byte
    if ($? -match "True") {
        $textBox3JS.Text = "Fatto"
    } else {
        $textBox3JS.Text = "ERRORE!"
    }
})

# Bit inversion section

$Label33i = New-Object System.Windows.Forms.Label
$Label33i.Text = "INVERTI 0 E 1"
$Label33i.Font = "Verdana, 11"
$Label33i.ForeColor = "#ffffff"
$Label33i.BackColor = "#391754"
$Label33i.Location = New-Object System.Drawing.Point(10,330)
$Label33i.Size = New-Object System.Drawing.Size (115,20)
$PanelT33.Controls.Add($Label33i)

# File selection
$Label331i = New-Object System.Windows.Forms.Label
$Label331i.Text = "File da editare"
$Label331i.Font = "Verdana, 11"
$Label331i.Location = New-Object System.Drawing.Point(10,360)
$Label331i.AutoSize = $true
$PanelT33.Controls.Add($Label331i)

$ButtonI = New-Object System.Windows.Forms.Button
$ButtonI.Location = New-Object System.Drawing.Point(130,355)
$ButtonI.Size = New-Object System.Drawing.Size(120,30)
$ButtonI.Text = "FILE"
$ButtonI.Font = "Verdana, 10"
$ButtonI.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonI)

$Label3i = New-Object System.Windows.Forms.Label
$Label3i.Font = "Verdana, 9"
$Label3i.Location = New-Object System.Drawing.Point(260,362)
$Label3i.Size = New-Object System.Drawing.Size(480,18)
$Label3i.AutoEllipsis = $true
$Label3i.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3i)

Function FileI ($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Please Select File"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = “All files (*.*)| *.*”
    If ($OpenFileDialog.ShowDialog() -eq "Cancel") {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file!", "Error", 0, 
        [System.Windows.Forms.MessageBoxIcon]::Exclamation) | Out-Null # to avoid the "ok" message to show up
    }
    $Global:SelectedFileI = $OpenFileDialog.SafeFileName
    $Global:SelectedPathI = $OpenFileDialog.FileName
    Return $SelectedPathI
} 

$ButtonI.Add_Click({
    $Label3i.Text = FileI
})

# Destination folder selection
$Label332i = New-Object System.Windows.Forms.Label
$Label332i.Text = "Destinazione"
$Label332i.Font = "Verdana, 11"
$Label332i.Location = New-Object System.Drawing.Point(10,395)
$Label332i.AutoSize = $true
$Label332i.Visible = $true
$PanelT33.Controls.Add($Label332i)

$ButtonFi = New-Object System.Windows.Forms.Button
$ButtonFi.Location = New-Object System.Drawing.Point(130,390)
$ButtonFi.Size = New-Object System.Drawing.Size(120,30)
$ButtonFi.Text = "CARTELLA"
$ButtonFi.Font = "Verdana, 10"
$ButtonFi.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonFi)

$Label3Fi = New-Object System.Windows.Forms.Label
$Label3Fi.Font = "Verdana, 9"
$Label3Fi.Location = New-Object System.Drawing.Point(260,397)
$Label3Fi.Size = New-Object System.Drawing.Size(280,18)
$Label3Fi.AutoEllipsis = $true
$Label3Fi.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3Fi)

$ButtonFi.Add_Click({
    $folderBrowserI = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowserI.ShowDialog() | Out-Null
    $selectedPathI = $folderBrowserI.SelectedPath
    if (!$selectedPathI) {
        $Label3Fi.Text = "$HOME"
    } else {
        $Label3Fi.Text = "$($selectedPathI)\File_inverted"
    }
})

# Set labels tooltips
$tooltipi = New-Object System.Windows.Forms.ToolTip
$tooltipi.SetToolTip($Label3Fi, "...\File_inverted")

# Invert execution section
$ButtonFI = New-Object System.Windows.Forms.Button
$ButtonFI.Location = New-Object System.Drawing.Point(550,390)
$ButtonFI.Size = New-Object System.Drawing.Size(130,30)
$ButtonFI.Text = "INVERTI!"
$ButtonFI.Font = "Verdana, 11"
$ButtonFI.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonFI)

$textBox3FI = New-Object System.Windows.Forms.TextBox
$textBox3FI.Location = New-Object System.Drawing.Point(690,390)
$textBox3FI.Size = New-Object System.Drawing.Size(50,30)
$textBox3FI.Multiline = $true
$textBox3FI.Font = "Verdana, 11"
$textBox3FI.BackColor = "#08243f"
$textBox3FI.ForeColor = "#ffffff"
$PanelT33.Controls.Add($textBox3FI)

$ButtonFI.Add_Click({
    $textBox3FI.Text = ""
    if ($Label3Fi.Text -eq "") {
        $Label3Fi.Text = "$HOME\File_inverted"    
    }
    if (!$SelectedPathI) {
        $textBox3FI.Text = "NO!"
        return
    }
    $stream = New-Object System.IO.FileStream($Label3Fi.Text, [System.IO.FileMode]::Create)
    Get-Content -Path "$($SelectedPathI)" -Encoding Byte | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0').Replace('0', 'x').Replace('1', '0').Replace('x', '1') } | ForEach-Object { [Convert]::ToByte($_, 2) } | ForEach-Object { $stream.WriteByte($_) }
    $stream.Close()
    if ($? -match "True") {
        $textBox3FI.Text = "OK"
    } else {
        $textBox3FI.Text = "NO!"
    }
})

# Bitshift section

$Label33s = New-Object System.Windows.Forms.Label
$Label33s.Text = "BITSHIFT CIRCOLARE A SX"
$Label33s.Font = "Verdana, 11"
$Label33s.ForeColor = "#ffffff"
$Label33s.BackColor = "#391754"
$Label33s.Location = New-Object System.Drawing.Point(10,450)
$Label33s.Size = New-Object System.Drawing.Size (215,20)
$PanelT33.Controls.Add($Label33s)

# File selection
$Label331s = New-Object System.Windows.Forms.Label
$Label331s.Text = "File da editare"
$Label331s.Font = "Verdana, 11"
$Label331s.Location = New-Object System.Drawing.Point(10,480)
$Label331s.AutoSize = $true
$PanelT33.Controls.Add($Label331s)

$ButtonS = New-Object System.Windows.Forms.Button
$ButtonS.Location = New-Object System.Drawing.Point(130,475)
$ButtonS.Size = New-Object System.Drawing.Size(120,30)
$ButtonS.Text = "FILE"
$ButtonS.Font = "Verdana, 10"
$ButtonS.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonS)

$Label3s = New-Object System.Windows.Forms.Label
$Label3s.Font = "Verdana, 9"
$Label3s.Location = New-Object System.Drawing.Point(260,482)
$Label3s.Size = New-Object System.Drawing.Size(280,18)
$Label3s.AutoEllipsis = $true
$Label3s.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3s)

Function FileS ($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Please Select File"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = “All files (*.*)| *.*”
    If ($OpenFileDialog.ShowDialog() -eq "Cancel") {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file!", "Error", 0, 
        [System.Windows.Forms.MessageBoxIcon]::Exclamation) | Out-Null # to avoid the "ok" message to show up
    }
    $Global:SelectedFileS = $OpenFileDialog.SafeFileName
    $Global:SelectedPathS = $OpenFileDialog.FileName
    Return $SelectedFileS
} 

$ButtonS.Add_Click({
    $Label3s.Text = FileS
})

# Destination folder selection
$Label332s = New-Object System.Windows.Forms.Label
$Label332s.Text = "Destinazione"
$Label332s.Font = "Verdana, 11"
$Label332s.Location = New-Object System.Drawing.Point(10,515)
$Label332s.AutoSize = $true
$Label332s.Visible = $true
$PanelT33.Controls.Add($Label332s)

$ButtonFs = New-Object System.Windows.Forms.Button
$ButtonFs.Location = New-Object System.Drawing.Point(130,510)
$ButtonFs.Size = New-Object System.Drawing.Size(120,30)
$ButtonFs.Text = "CARTELLA"
$ButtonFs.Font = "Verdana, 10"
$ButtonFs.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonFs)

$Label3Fs = New-Object System.Windows.Forms.Label
$Label3Fs.Font = "Verdana, 9"
$Label3Fs.Location = New-Object System.Drawing.Point(260,517)
$Label3Fs.Size = New-Object System.Drawing.Size(280,18)
$Label3Fs.AutoEllipsis = $true
$Label3Fs.BackColor = "#101c28"
$PanelT33.Controls.Add($Label3Fs)

$ButtonFs.Add_Click({
    $folderBrowserSh = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowserSh.ShowDialog() | Out-Null
    $selectedPathSh = $folderBrowserSh.SelectedPath
    $Label3Fs.Text = "$($selectedPathSh)\File_shifted"
})

# Set labels tooltips
$tooltips = New-Object System.Windows.Forms.ToolTip
$tooltips.SetToolTip($Label3Fs, "...\File_shifted")

# Invert execution section
$ButtonSh = New-Object System.Windows.Forms.Button
$ButtonSh.Location = New-Object System.Drawing.Point(550,510)
$ButtonSh.Size = New-Object System.Drawing.Size(130,30)
$ButtonSh.Text = "SHIFTA!"
$ButtonSh.Font = "Verdana, 11"
$ButtonSh.BackColor = "#101c28"
$PanelT33.Controls.Add($ButtonSh)

$textBox3Sb = New-Object System.Windows.Forms.TextBox
$textBox3Sb.Location = New-Object System.Drawing.Point(690,510)
$textBox3Sb.Size = New-Object System.Drawing.Size(50,30)
$textBox3Sb.Multiline = $true
$textBox3Sb.Font = "Verdana, 11"
$textBox3Sb.BackColor = "#08243f"
$textBox3Sb.ForeColor = "#ffffff"
$PanelT33.Controls.Add($textBox3Sb)

$Label3Fbb = New-Object System.Windows.Forms.Label
$Label3Fbb.Font = "Verdana, 11"
$Label3Fbb.Location = New-Object System.Drawing.Point(550,482)
$Label3Fbb.Size = New-Object System.Drawing.Size(140,18)
$Label3Fbb.Text = "Posti da shiftare:"
$PanelT33.Controls.Add($Label3Fbb)

#Add a drop-down list
$ComboBox = New-Object System.Windows.Forms.ComboBox
$ComboBox.Width = 50
$ComboBox.BackColor = "#1d1e25"
$ComboBox.ForeColor = "#ffffff"
$ComboBox.Font = "Verdana, 11"
$bits = 1..7 | ForEach-Object { $ComboBox.Items.Add($_) }
$ComboBox.Location = New-Object System.Drawing.Point(690,480)
$panelT33.Controls.Add($ComboBox)

$ButtonSh.Add_Click({
    $textBox3Sb.Text = ""
    if ($Label3Fs.Text -eq "") {
        $Label3Fs.Text = "$($HOME)\File_shifted"
    }
    function Rotate-BitsLeft {
              param (
              [byte]$value,
              [int]$shift
              )
              $shift %= 8
              [byte]((($value -shl $shift) -bor ($value -shr (8 - $shift))) -band 0xFF)
              }
              $inputFile = $SelectedPathS
              $inputBytes = [System.IO.File]::ReadAllBytes($inputFile)
              $leftshift = $ComboBox.SelectedItem
              $rotatedBytes = foreach ($byte in $inputBytes) {
              Rotate-BitsLeft $byte $leftshift
              }
              $outputFile = "$($Label3Fs.Text)"
              [System.IO.File]::WriteAllBytes($outputFile, $rotatedBytes)
    if ($? -match "True") {
        $textBox3Sb.Text = "OK"
    } else {
        $textBox3Sb.Text = "NO!"
    }
})



### P A N E L  4

# Create Label for PANEL 4
$LabelT34 = New-Object System.Windows.Forms.Label
$LabelT34.Text = " SICUREZZA"
$LabelT34.Font = "Verdana, 11"
$LabelT34.Location = New-Object System.Drawing.Point(0,145)
$LabelT34.ForeColor = "#ebed31"
$LabelT34.BackColor = "#434c56"
$LabelT34.Size = New-Object System.Drawing.Size(145,20)
$PanelT3.Controls.Add($LabelT34)

# Create Panel
$PanelT34 = New-Object System.Windows.Forms.Panel
$PanelT34.Location = New-Object System.Drawing.Point(145,15)
$PanelT34.Size = New-Object System.Drawing.Size(900,590)
$PanelT34.BackColor = "#434c56"
$PanelT3.Controls.Add($PanelT34)

# Create a Label to signal when the Panel is selected
$Label3_4 = New-Object System.Windows.Forms.Label
$Label3_4.Text = "►"
$Label3_4.Font = "Verdana, 24"
$Label3_4.Location = New-Object System.Drawing.Point(125,-10)
$Label3_4.AutoSize = $true
$Label3_4.ForeColor = "#ebed31"
$Label3_4.Visible = $false
$LabelT34.Controls.Add($Label3_4)

# Hash file section

$Label34h = New-Object System.Windows.Forms.Label
$Label34h.Text = "CALCOLA HASH"
$Label34h.Font = "Verdana, 11"
$Label34h.ForeColor = "#ffffff"
$Label34h.BackColor = "#391754"
$Label34h.Location = New-Object System.Drawing.Point(10,10)
$Label34h.Size = New-Object System.Drawing.Size (125,20)
$PanelT34.Controls.Add($Label34h)

# File selection
$Label341 = New-Object System.Windows.Forms.Label
$Label341.Text = "Scegli file"
$Label341.Font = "Verdana, 11"
$Label341.Location = New-Object System.Drawing.Point(10,40)
$Label341.AutoSize = $true
$PanelT34.Controls.Add($Label341)

$ButtonF = New-Object System.Windows.Forms.Button
$ButtonF.Location = New-Object System.Drawing.Point(100,35)
$ButtonF.Size = New-Object System.Drawing.Size(120,30)
$ButtonF.Text = "FILE"
$ButtonF.Font = "Verdana, 10"
$ButtonF.BackColor = "#101c28"
$PanelT34.Controls.Add($ButtonF)

$Label3Fc = New-Object System.Windows.Forms.Label
$Label3Fc.Font = "Verdana, 9"
$Label3Fc.Location = New-Object System.Drawing.Point(225,42)
$Label3Fc.Size = New-Object System.Drawing.Size(285,18)
$Label3Fc.AutoEllipsis = $true
$Label3Fc.BackColor = "#101c28"
$PanelT34.Controls.Add($Label3Fc)

Function FileH ($InitialDirectory)
{
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Please Select File"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.filter = “All files (*.*)| *.*”
    If ($OpenFileDialog.ShowDialog() -eq "Cancel") {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file!", "Error", 0, 
        [System.Windows.Forms.MessageBoxIcon]::Exclamation) | Out-Null # to avoid the "ok" message to show up
    }
    $Global:SelectedFileH = $OpenFileDialog.SafeFileName
    $Global:SelectedPathH = $OpenFileDialog.FileName
    Return $SelectedFileH
} 

$ButtonF.Add_Click({
    $Label3Fc.Text = FileH   
})

$Label3d = New-Object System.Windows.Forms.Label
$Label3d.Font = "Verdana, 11"
$Label3d.Location = New-Object System.Drawing.Point(550,40)
$Label3d.Size = New-Object System.Drawing.Size(100,18)
$Label3d.Text = "Scegli hash:"
$PanelT34.Controls.Add($Label3d)

#Add a drop-down list
$ComboBox = New-Object System.Windows.Forms.ComboBox
$ComboBox.Width = 90
$ComboBox.BackColor = "#1d1e25"
$ComboBox.ForeColor = "#ffffff"
$ComboBox.Font = "Verdana, 11"
$LIST = "MD5","RIPEMD160","SHA1","SHA256","SHA384","SHA512" | ForEach-Object { $ComboBox.Items.Add($_) }
$ComboBox.Location = New-Object System.Drawing.Point(650,37)
$panelT34.Controls.Add($ComboBox)

# Hash execution
$ButtonFH = New-Object System.Windows.Forms.Button
$ButtonFH.Location = New-Object System.Drawing.Point(10,75)
$ButtonFH.Size = New-Object System.Drawing.Size(130,30)
$ButtonFH.Text = "HASH"
$ButtonFH.Font = "Verdana, 11"
$ButtonFH.BackColor = "#101c28"
$PanelT34.Controls.Add($ButtonFH)

$textBox3FH = New-Object System.Windows.Forms.TextBox
$textBox3FH.Location = New-Object System.Drawing.Point(150,75)
$textBox3FH.Size = New-Object System.Drawing.Size(590,30)
$textBox3FH.Multiline = $true
$textBox3FH.Font = "Verdana, 11"
$textBox3FH.BackColor = "#08243f"
$textBox3FH.ForeColor = "#ffffff"
$PanelT34.Controls.Add($textBox3FH)

$ButtonFH.Add_Click({
    $textBox3FH.Text = ""
    try {
        $getHash = Get-FileHash -Path "$($SelectedPathH)" -Algorithm $ComboBox.SelectedItem | Select-Object Hash
        $textBox3FH.Text = $getHash.hash
    } catch {
        $textBox3FH.Text = "ERRORE!"
    }
})

# Password section

$Label34p = New-Object System.Windows.Forms.Label
$Label34p.Text = "CREA PASSWORD"
$Label34p.Font = "Verdana, 11"
$Label34p.ForeColor = "#ffffff"
$Label34p.BackColor = "#391754"
$Label34p.Location = New-Object System.Drawing.Point(10,140)
$Label34p.Size = New-Object System.Drawing.Size (140,20)
$PanelT34.Controls.Add($Label34p)

# Lenght selection
$Label342 = New-Object System.Windows.Forms.Label
$Label342.Text = "Lunghezza:"
$Label342.Font = "Verdana, 11"
$Label342.Location = New-Object System.Drawing.Point(10,172)
$Label342.AutoSize = $true
$PanelT34.Controls.Add($Label342)

#Add a drop-down list
$ComboBoxP = New-Object System.Windows.Forms.ComboBox
$ComboBoxP.Width = 50
$ComboBoxP.BackColor = "#1d1e25"
$ComboBoxP.ForeColor = "#ffffff"
$ComboBoxP.Font = "Verdana, 11"
$pslenght = 5..20 | ForEach-Object { $ComboBoxP.Items.Add($_) }
$ComboBoxP.Location = New-Object System.Drawing.Point(110,170)
$panelT34.Controls.Add($ComboBoxP)

$ButtonP = New-Object System.Windows.Forms.Button
$ButtonP.Location = New-Object System.Drawing.Point(190,167)
$ButtonP.Size = New-Object System.Drawing.Size(130,30)
$ButtonP.Text = "GENERA"
$ButtonP.Font = "Verdana, 11"
$ButtonP.BackColor = "#101c28"
$PanelT34.Controls.Add($ButtonP)

$ButtonP.Add_Click({
    if (!$ComboBoxP.SelectedItem) {
        return
    }
    $pswdl = $ComboBoxP.SelectedItem
    $chmin = [char](Get-Random -Minimum 97 -Maximum 122)
    $chmai = [char](Get-Random -Minimum 65 -Maximum 90)
    $cnum = [char](Get-Random -Minimum 48 -Maximum 57)
    $chsim = [char](Get-Random -Minimum 33 -Maximum 47)
    $pswd = -join($chmin,$chmai,$chnum,$chsim | Sort-Object {Get-Random})
    do {$ch = [char](Get-Random -Minimum 33 -Maximum 125)
        $pswd += $ch
    } until ($pswd.length -eq $pswdl)
    $pswd = -join($pswd | Sort-Object {Get-Random})
    $textBox3P.text = $pswd | Out-String
})

$textBox3P = New-Object System.Windows.Forms.TextBox
$textBox3P.Location = New-Object System.Drawing.Point(330,167)
$textBox3P.Size = New-Object System.Drawing.Size(410,30)
$textBox3P.Multiline = $true
$textBox3P.Font = "Verdana, 11"
$textBox3P.BackColor = "#08243f"
$textBox3P.ForeColor = "#ffffff"
$PanelT34.Controls.Add($textBox3P)

# Defender section

$Label34d = New-Object System.Windows.Forms.Label
$Label34d.Text = "DEFENDER"
$Label34d.Font = "Verdana, 11"
$Label34d.ForeColor = "#ffffff"
$Label34d.BackColor = "#391754"
$Label34d.Location = New-Object System.Drawing.Point(10,230)
$Label34d.Size = New-Object System.Drawing.Size (90,20)
$PanelT34.Controls.Add($Label34d)

# Lenght selection
$Label342 = New-Object System.Windows.Forms.Label
$Label342.Text = "Apri Windows Security"
$Label342.Font = "Verdana, 11"
$Label342.Location = New-Object System.Drawing.Point(10,262)
$Label342.AutoSize = $true
$PanelT34.Controls.Add($Label342)

$ButtonD = New-Object System.Windows.Forms.Button
$ButtonD.Location = New-Object System.Drawing.Point(210,257)
$ButtonD.Size = New-Object System.Drawing.Size(130,30)
$ButtonD.Text = "APRI"
$ButtonD.Font = "Verdana, 11"
$ButtonD.BackColor = "#101c28"
$PanelT34.Controls.Add($ButtonD)

$ButtonD.Add_Click({
    start windowsdefender:
})

# Online scan section

$Label34o = New-Object System.Windows.Forms.Label
$Label34o.Text = "ONLINE SCAN"
$Label34o.Font = "Verdana, 11"
$Label34o.ForeColor = "#ffffff"
$Label34o.BackColor = "#391754"
$Label34o.Location = New-Object System.Drawing.Point(10,320)
$Label34o.Size = New-Object System.Drawing.Size (115,20)
$PanelT34.Controls.Add($Label34o)

$Label34o = New-Object System.Windows.Forms.Label
$Label34o.Text = "Apri malware scanner online:"
$Label34o.Font = "Verdana, 11"
$Label34o.Location = New-Object System.Drawing.Point(10,352)
$Label34o.AutoSize = $true
$PanelT34.Controls.Add($Label34o)

$ButtonO1 = New-Object System.Windows.Forms.Button
$ButtonO1.Location = New-Object System.Drawing.Point(270,347)
$ButtonO1.Size = New-Object System.Drawing.Size(130,30)
$ButtonO1.Text = "Virus Total"
$ButtonO1.Font = "Verdana, 11"
$ButtonO1.BackColor = "#101c28"
$PanelT34.Controls.Add($ButtonO1)

$ButtonO1.Add_Click({
    Start-Process "https://www.virustotal.com/gui/home/upload"
})

$ButtonO2 = New-Object System.Windows.Forms.Button
$ButtonO2.Location = New-Object System.Drawing.Point(440,347)
$ButtonO2.Size = New-Object System.Drawing.Size(130,30)
$ButtonO2.Text = "Filescan.io"
$ButtonO2.Font = "Verdana, 11"
$ButtonO2.BackColor = "#101c28"
$PanelT34.Controls.Add($ButtonO2)

$ButtonO2.Add_Click({
    Start-Process "https://www.filescan.io/scan"
})

$ButtonO3 = New-Object System.Windows.Forms.Button
$ButtonO3.Location = New-Object System.Drawing.Point(610,347)
$ButtonO3.Size = New-Object System.Drawing.Size(130,30)
$ButtonO3.Text = "HybridAnalysis"
$ButtonO3.Font = "Verdana, 11"
$ButtonO3.BackColor = "#101c28"
$PanelT34.Controls.Add($ButtonO3)

$ButtonO3.Add_Click({
    Start-Process "https://www.hybrid-analysis.com/"
})

# Sanitize section

$Label34s = New-Object System.Windows.Forms.Label
$Label34s.Text = "SANIFICA VOLUME (ATTENZIONE!)"
$Label34s.Font = "Verdana, 11"
$Label34s.ForeColor = "#ffffff"
$Label34s.BackColor = "#391754"
$Label34s.Location = New-Object System.Drawing.Point(10,415)
$Label34s.Size = New-Object System.Drawing.Size (275,20)
$PanelT34.Controls.Add($Label34s)

$Label343 = New-Object System.Windows.Forms.Label
$Label343.Text = "Con questa funzione si CANCELLA TUTTO IL CONTENUTO del volume, lo si FORMATTA al
medesimo file system (FAT, NTFS, etc.) e si SOVRASCRIVE tutto lo spazio con dati random
(usando il comando 'cipher/w:'), così da rendere più difficile il recupero dei dati."
$Label343.Font = "Verdana, 11"
$Label343.Location = New-Object System.Drawing.Point(10,440)
$Label343.AutoSize = $true
$PanelT34.Controls.Add($Label343)

$Label344 = New-Object System.Windows.Forms.Label
$Label344.Text = "Scegli un volume:"
$Label344.Font = "Verdana, 11"
$Label344.Location = New-Object System.Drawing.Point(10,508)
$Label344.AutoSize = $true
$PanelT34.Controls.Add($Label344)

#Add a drop-down list
$ComboBoxV = New-Object System.Windows.Forms.ComboBox
$ComboBoxV.Width = 50
$ComboBoxV.BackColor = "#1d1e25"
$ComboBoxV.ForeColor = "#ffffff"
$ComboBoxV.Font = "Verdana, 11"
$vols = "D","E","F","G","H","I","J","K","L","M","N","O","P" | ForEach-Object { $ComboBoxV.Items.Add($_) }
$ComboBoxV.Location = New-Object System.Drawing.Point(155,502)
$panelT34.Controls.Add($ComboBoxV)

$ButtonV = New-Object System.Windows.Forms.Button
$ButtonV.Location = New-Object System.Drawing.Point(230,500)
$ButtonV.Size = New-Object System.Drawing.Size(145,30)
$ButtonV.Text = "PULISCI!"
$ButtonV.Font = "Verdana, 11"
$ButtonV.BackColor = "#101c28"
$PanelT34.Controls.Add($ButtonV)

$Label344 = New-Object System.Windows.Forms.Label
$Label344.Text = "(Si aprirà un terminale; la pulizia richiederà tempo)"
$Label344.Font = "Verdana, 10"
$Label344.Location = New-Object System.Drawing.Point(375,505)
$Label344.AutoSize = $true
$PanelT34.Controls.Add($Label344)

$textBox3V = New-Object System.Windows.Forms.TextBox
$textBox3V.Location = New-Object System.Drawing.Point(10,535)
$textBox3V.Size = New-Object System.Drawing.Size(720,30)
$textBox3V.Multiline = $true
$textBox3V.Font = "Verdana, 11"
$textBox3V.BackColor = "#08243f"
$textBox3V.ForeColor = "#ffffff"
$PanelT34.Controls.Add($textBox3V)

$ButtonV.Add_Click({
    $textBox3V.Text = ""
    if (!$ComboBoxV.SelectedItem) {
        $textBox3V.Text = "Nessun volume scelto"
        return
    }
    $confirmation = [System.Windows.Forms.MessageBox]::Show( "Vuoi davvero CANCELLARE TUTTO il contenuto del volume e sovrascriverlo con tutti 0, poi con tutti 1 e infine con dati random?", "Conferma comando", "YesNo", "Warning" )
    if ($confirmation -eq "Yes") {
      try {
      $volFS = get-volume $ComboBoxV.SelectedItem -ErrorAction Stop
      Format-Volume -DriveLetter $ComboBoxV.SelectedItem -FileSystem $volFS.FileSystemType -Force -Confirm:$false
      Start-Process -FilePath "cipher" -ArgumentList "/w:$($ComboBoxV.SelectedItem)\" -PassThru -Wait
      $textBox3V.Text = "Fatto"
      } catch {
        $textBox3V.Text = "Errore!"
      }
    }
})

# Add event handler to handle click events for the Labels
$Label_Click3 = {
    param($sender, $e)
    $clickedLabel = $sender
    if ($clickedLabel -eq $LabelT31) {
        $PanelT31.Visible = $true
        $PanelT32.Visible = $false
        $PanelT33.Visible = $false
        $PanelT34.Visible = $false
    } elseif ($clickedLabel -eq $LabelT32) {
        $PanelT31.Visible = $false
        $PanelT32.Visible = $true
        $PanelT33.Visible = $false
        $PanelT34.Visible = $false
    } elseif ($clickedLabel -eq $LabelT33) {
        $PanelT31.Visible = $false
        $PanelT32.Visible = $false
        $PanelT33.Visible = $true
        $PanelT34.Visible = $false
    } elseif ($clickedLabel -eq $LabelT34) {
        $PanelT31.Visible = $false
        $PanelT32.Visible = $false
        $PanelT33.Visible = $false
        $PanelT34.Visible = $true
    }
}

# Set the label indicator when its panel is active
$Label_ClickX3 = {
    param($sender, $e)
    $clickedLabel = $sender
    if ($clickedLabel -eq $LabelT31) {
        $Label3_1.Visible = $true
        $Label3_2.Visible = $false
        $Label3_3.Visible = $false
        $Label3_4.Visible = $false
    } elseif ($clickedLabel -eq $LabelT32) {
        $Label3_1.Visible = $false
        $Label3_2.Visible = $true
        $Label3_3.Visible = $false
        $Label3_4.Visible = $false
    } elseif ($clickedLabel -eq $LabelT33) {
        $Label3_1.Visible = $false
        $Label3_2.Visible = $false
        $Label3_3.Visible = $true
        $Label3_4.Visible = $false
    } elseif ($clickedLabel -eq $LabelT34) {
        $Label3_1.Visible = $false
        $Label3_2.Visible = $false
        $Label3_3.Visible = $false
        $Label3_4.Visible = $true
    }
}

# Assign the event handler to the Labels
$LabelT31.Add_Click($Label_Click3)
$LabelT32.Add_Click($Label_Click3)
$LabelT33.Add_Click($Label_Click3)
$LabelT34.Add_Click($Label_Click3)

$LabelT31.Add_Click($Label_ClickX3)
$LabelT32.Add_Click($Label_ClickX3)
$LabelT33.Add_Click($Label_ClickX3)
$LabelT34.Add_Click($Label_ClickX3)


###### S H E L L 

# Create Label for SHELL tab
$LabelTS = New-Object System.Windows.Forms.Label
$LabelTS.Text = "         SHELL"
$LabelTS.Font = [System.Drawing.Font]::new("Arial", 12, [System.Drawing.FontStyle]::Bold)
$LabelTS.Location = New-Object System.Drawing.Point(455,15)
$LabelTS.ForeColor = "#ffb91a"
$LabelTS.BackColor = "#696e72"
$LabelTS.Size = New-Object System.Drawing.Size(145,20)
$main_form.Controls.Add($LabelTS)

# Create SHELL tab
$PanelTS = New-Object System.Windows.Forms.Panel
$PanelTS.Location = New-Object System.Drawing.Point(5,35)
$PanelTS.Size = New-Object System.Drawing.Size(900,590)
$PanelTS.BackColor = "#696e72"
$main_form.Controls.Add($PanelTS)

# Add label to input box
$labelS = New-Object System.Windows.Forms.Label
$labelS.Location = New-Object System.Drawing.Point(10,15)
$labelS.Size = New-Object System.Drawing.Size(200,20)
$labelS.Text = 'Scrivi comando da eseguire'
$labelS.Font = "Verdana, 11"
$labelS.AutoSize = $true
$panelTS.Controls.Add($labelS)

$textBoxS = New-Object System.Windows.Forms.TextBox
$textBoxS.Location = New-Object System.Drawing.Point(10,39)
$textBoxS.Size = New-Object System.Drawing.Size(725,20)
$textBoxS.Font = "Verdana, 11"
$panelTS.Controls.Add($textBoxS)

#place the button on the form:
$Button0S = New-Object System.Windows.Forms.Button
$Button0S.Location = New-Object System.Drawing.Point(750,37)
$Button0S.Size = New-Object System.Drawing.Size(120,30)
$Button0S.Text = "ESEGUI"
$Button0S.Font = "Verdana, 11"
$Button0S.BackColor = "#512178"
$panelTS.Controls.Add($Button0S)

#set the output multiline box
$TextBox0S = New-Object System.Windows.Forms.TextBox
$TextBox0S.Multiline = $true
$TextBox0S.ScrollBars = "Both"
$TextBox0S.Size = New-Object System.Drawing.Size(860,500)
$textBox0S.Font = "Verdana, 10.5"
$TextBox0S.BackColor = "#08243f"
$TextBox0S.ForeColor = "#ffffff"
$TextBox0S.Location = New-Object System.Drawing.Point(10,80)
$panelTS.Controls.Add($TextBox0S)

#set the output in the textbox (using the user input from the previsous box) 
$Button0S.Add_Click({
    $TextBox0S.Text = "Attendere..."
    try {
        $TextBox0S.Text = iex($textBoxs.Text) | Out-String
    } catch {
        $TextBox0S.Text = "Inserire un comando valido"
    }
    $TextBox0S.Text = iex($textBoxs.Text) | Out-String
})

# Add event handler to handle click events for the tabs
$Label_Click = {
    param($sender, $e)
    $clickedLabel = $sender
    $PanelT = 
    if ($clickedLabel -eq $LabelT1) {
        $PanelT1.Visible = $true
        $PanelT2.Visible = $false
        $PanelT3.Visible = $false
        $PanelTS.Visible = $false
    } elseif ($clickedLabel -eq $LabelT2) {
        $PanelT1.Visible = $false
        $PanelT2.Visible = $true
        $PanelT3.Visible = $false
        $PanelTS.Visible = $false
    } elseif ($clickedLabel -eq $LabelT3) {
        $PanelT1.Visible = $false
        $PanelT2.Visible = $false
        $PanelT3.Visible = $true
        $PanelTS.Visible = $false
    } elseif ($clickedLabel -eq $LabelTS) {
        $PanelT1.Visible = $false
        $PanelT2.Visible = $false
        $PanelT3.Visible = $false
        $PanelTS.Visible = $true
    }
}

# Assign the event handler to the Labels
$LabelT1.Add_Click($Label_Click)
$LabelT2.Add_Click($Label_Click)
$LabelT3.Add_Click($Label_Click)
$LabelTS.Add_Click($Label_Click)


# Display the form
$main_form.ShowDialog() | Out-Null

# releases all resources held by any managed objects
$main_form.Dispose()