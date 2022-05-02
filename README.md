# Project Title

LFI Hunter

## Description

A Local File Inclusion finder.

## Getting Started

### Executing program

* With python3 for UNIX
```
python3 lfi_hunter.py -u 'http://lfi.location/example.php?parameter=' -w unix.txt -os win -o output.txt
```
* With python3 for Windows
```
python3 lfi_hunter.py -u 'http://lfi.location/example.php?parameter=' -w win.txt -os win -o output.txt
```

## Help

For help menu:
```
python3 lfi_hunter.py -h
```

## Disclaimer
All the code provided on this repository is for educational/research purposes only. Any actions and/or activities related to the material contained within this repository is solely your responsibility. The misuse of the code in this repository can result in criminal charges brought against the persons in question. Author will not be held responsible in the event any criminal charges be brought against any individuals misusing the code in this repository to break the law.