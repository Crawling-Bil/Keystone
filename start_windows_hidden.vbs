Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
folder = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = folder
shell.Run "cmd /c .venv\Scripts\pythonw.exe run.py", 0, False
WScript.Sleep 1800
shell.Run "http://127.0.0.1:8002", 1, False
