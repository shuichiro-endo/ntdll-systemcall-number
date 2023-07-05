# ntdll systemcall number
get system call number that functions of ntdll.dll call

## Installation
### Install dependencies
- visual studio community (Desktop development with C++)
    1. install Desktop development with C++

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/ntdll-systemcall-number.git
```
2. run x64 Native Tools Command Prompt for VS 2022
3. build
```
cd ntdll-systemcall-number
compile.bat
```

## Usage
```
usage        : main.exe [-f (read data from C:\windows\system32\ntdll.dll)] [-h (help)]
example      : main.exe
             : main.exe -f
```
- if you want to read data from loaded ntdll.dll on memory
```
main.exe
```
- if you want to read data from C:\windows\system32\ntdll.dll (if EDR hooks functions of ntdll.dll)
```
main.exe -f
```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/ntdll-systemcall-number/blob/main/LICENSE) file for details.
