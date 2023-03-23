# Overview
Provides a pattern showing how [jose-jwt](https://github.com/dvsekhvalnov/jose-jwt) can be updated to support the family of `ECDH-ES-*` key management algorithms on all platforms (Linux and Windows).

# Usage

## Linux
On my PC which is Windows, I used WSL2 to run this command on Ubuntu. 
```shell
dotnet run -f net6.0
```
Output
```
Running on Unix 5.10.102.1
Derived Key #2 = d33muATOW7cEBggxhYr+8ZeKtNgFNh8inXomWnkQDFo=
```

## Windows
```shell
dotnet run -f net6.0-windows
```
Output
```
Running on Microsoft Windows NT 10.0.19045.0
Derived Key #1 = d33muATOW7cEBggxhYr+8ZeKtNgFNh8inXomWnkQDFo=
Derived Key #2 = d33muATOW7cEBggxhYr+8ZeKtNgFNh8inXomWnkQDFo=
```
