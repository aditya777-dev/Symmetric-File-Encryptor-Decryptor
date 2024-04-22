# Symmetric-File-Encryptor-Decryptor

> use this code by first converting it into an executable file and running it as an application to avoid others from accessing the source code
>
> any file type can be encrypted and will be encrypted into a '.bin' format

# To convert this file into an executable
1. install PyInstaller

> ' pip install pyinstaller==5.13.2 '

> use this specific version to avoid error: win32ctypes.pywin32.pywintypes.error: (225, 'BeginUpdateResourceW', 'Operation did not complete successfully because the file contains a virus or potentially unwanted software.')

2. use this command to convert python file to an executable

> ' python -m PyInstaller --noconsole --onefile symmetric-file-encryptor-decryptor.py '

> ' --noconsole ' supresses console output to maintain stealth of the application

> ' --onefile ' creates a single executable file of the code rather than an entire folder; this might raise an alert for windows defender and it will not allow the execution of the file
 
> this process may take some time

> after completion, the application file (symmetric-file-encryptor-decryptor.exe) will be available in 'dist' folder
