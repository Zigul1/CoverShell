# CoverShell
(*disponibile anche in versione italiana ![image](https://github.com/Zigul1/CoverShell/assets/157254375/019162ce-a988-4be8-9fbd-3c6dc37f9640)
 v. fondo pagina*)

CoverShell is a PowerShell graphical interface to run useful commands and scripts, so there's no need to remember them or copy/paste them from saved notes to the shell. It's made with Windows Form and can be expanded adding more tabs and panels.

Tested succesfully using **PowerShell 5.1** on **Windows 10 Pro**.


### USE

- Copy all the raw text of the script "CoverShell.ps1" and paste it in a new notepad file
- save it and give it a .ps1 extension
- set a compatible execution policy with the PowerShell command: `set-execution policy -scope CurrentUser RemoteSigned` (or use the "bypass" one)
- right-click on the file just created ("[name].ps1") and then left-click on "Run with PowerShell"
- the shell will appear for a moment, then it will minimize itself and you will see the GUI, in the background of already opened windows.

[optional]
- if you want to make it an executable file (.exe), you can use [PS2EXE](https://github.com/MScholtes/PS2EXE) or similar applications.



### TOOLS

There are commands for:
- gathering system information and diagnostics
- monitoring outputs, resources and performances
- doing host maintenance and basic troubleshooting
- checking network activities, getting reports, capturing traffic and simple resetting
- comparing files, checking folders content differences, searching for file duplicates and finding specific files
- splitting/joining file bitwise, inverting 0s and 1s, setting circular left bitshift
- checking files hash, generating passwords, using online malware scanners and sanitize volumes.



### SCREENSHOTS

![Screenshot1](https://github.com/Zigul1/CoverShell/assets/157254375/f23b3048-2bb4-4b2e-a392-a4d2d99a2ec4)

![Screenshot2](https://github.com/Zigul1/CoverShell/assets/157254375/f7e47b3f-b767-4c18-9107-9f514993f0a0)

![Screenshot3](https://github.com/Zigul1/CoverShell/assets/157254375/6e945749-c448-40d9-a87a-aeb245d8bc85)

![Screenshot4](https://github.com/Zigul1/CoverShell/assets/157254375/c37d6a48-cfd1-4876-9b0a-62846463e5c8)



## Anche in italiano! ![image](https://github.com/Zigul1/CoverShell/assets/157254375/66240214-9ee5-4829-8bee-1fd0fe72cc70)


CoverShell è un'interfaccia grafica per PowerShell per eseguire comandi e script utili, senza bisogno di ricordarli a memoria o copia-incollarli dagli appunti alla shell. Realizzato con Windows Form, può essere arricchito aggiungendo altri tab e pannelli.


### USO

- Copiare tutto il contenuto "raw" dello script "CoverShell-ita.ps1" e incollarlo in un nuovo documento di testo
- salvarlo e dargli come estensione .ps1
- impostare una execution policy adeguata usando il comando PowerShell `set-execution policy -scope CurrentUser RemoteSigned` (oppure usare quella "bypass")
- cliccare con il destro sul file appena creato ("[nome].ps1") e poi con il sinistro su "Esegui con PowerShell"
- la shell comparirà per un momento, poi si ridurrà ad icona e comparirà la GUI, in background rispetto alle finestre già aperte.

[opzionale]
- per renderlo un eseguibile (.exe) è possibile usare [PS2EXE](https://github.com/MScholtes/PS2EXE) o applicazioni simili.


### STRUMENTI

Ci sono comandi per:
- raccogliere informazioni e diagnostica di sistema 
- monitorare *output*, risorse e *performance*
- fare manutenzione all'*host* e *troubleshooting* di base
- controllare attività di rete, ottenere *report*, catturare traffico e fare un *reset* basilare
- confrontare *file*, controllare differenze di contenuto fra cartelle, cercare *file* duplicati e trovare specifici *file*
- dividere/unire *file* al livello di *bit*, invertire 0 e 1, attuare rotazione circolare dei *bit* verso sinistra
- controllare l'*hash* dei *file*, generare *password*, ricorrere a *scanner online* per controllo *malware* e sanificare volumi.

