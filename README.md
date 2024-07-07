# 下载和编译
nginx
源码下载地址：https://nginx.org/en/download.html
下载文件：nginx-1.26.1.tar.gz

编译环境：Ubuntu 20.04.4 LTS
编辑环境：win11，vscode
```shell
# configure 生成适配操作系统的文件，在 objs 目录下
./configure --prefix=/home/chuwei/gitcode/len_nginx/build
make
make install
```

# 报错解决
`
the HTTP rewrite module requires the PCRE library
sudo apt-get install libpcre3 libpcre3-dev
`


# Makefile 说明
执行configure后在objs文件夹生成主体Makefile文件。
```shell
# CC: CC是一个Makefile变量，用CC = cc定义和赋值，用$(CC)取它的值，cc是一个符号链接，通常指向gcc
# which cc 输出 ：/usr/bin/cc
CC =	cc

# CFLAGS	该变量通常用于指定C语言的编译器选项
# -pipe     使用管道代替临时文件  
# -O		等于同 -O1，优化生成的目标文件
# -W	 	用于开启编译器警告
# -Wall		启用大部分警告信息 
# -Wpointer-arith	当在算术表达式中使用函数指针时给出警告
# -Wno-unused-parameter		消除未使用参数告警
# -Werror                   所有的警告都当作是错误
# -g		可执行程序包含调试信息，可以使用gdb
CFLAGS =  -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g 
CPP =	cc -E
LINK =	$(CC)

# ALL_INCS	指定Nginx通用头文件所在目录
# -I		表示将后缀文件夹作为寻找头文件的目录
ALL_INCS = -I src/core \
	-I src/event \
	-I src/event/modules \
	-I src/event/quic \
	-I src/os/unix \
	-I objs \
	-I src/http \
	-I src/http/modules

# CORE_DEPS		指定Nginx核心代码依赖头文件路径
CORE_DEPS = src/core/nginx.h \
	src/core/ngx_config.h \
	src/core/ngx_core.h \
	src/core/ngx_log.h \
	src/core/ngx_palloc.h \
	...
	objs/ngx_auto_config.h

# CORE_INCS	指定Nginx核心代码头文件所在目录
CORE_INCS = -I src/core \
	-I src/event \
	-I src/event/modules \
	-I src/event/quic \
	-I src/os/unix \
	-I objs

# HTTP_DEPS	指定http依赖头文件
HTTP_DEPS = src/http/ngx_http.h \
	src/http/ngx_http_request.h \
    ...
	src/http/ngx_http_upstream_round_robin.h \
	src/http/modules/ngx_http_ssi_filter_module.h

# HTTP_INCS 指定http保护头文件目录
HTTP_INCS = -I src/http \
	-I src/http/modules

# [目标]:[依赖]	[命令]
# [目标]	目标顶格写，后面是冒号
# [依赖]	依赖是用来产生目标的原材料
# [命令]	命令前面一定是Tab，命令就是要生成那个目标需要做的动作

# build:	make 时执行的目标
# binary:	生成二进制可执行文件
# modules:	生成模块
# manpage:	生成man手册相关，nginx.8

# 例如，执行make编译时，进入目标build，再进入目标binary，再进入目标objs/nginx
# 生成目标objs/nginx需要依赖以下objs/src/core/nginx.o等文件
# $(LINK) 后面是要执行的命令，-o指定生成目标文件objs/nginx
build:	binary modules manpage

binary:	objs/nginx

objs/nginx:	objs/src/core/nginx.o \
	objs/src/core/ngx_log.o \
	objs/src/core/ngx_palloc.o \
	...
	objs/ngx_modules.o

	$(LINK) -o objs/nginx \
	objs/src/core/nginx.o \
	objs/src/core/ngx_log.o \
	objs/src/core/ngx_palloc.o \
	...
	objs/ngx_modules.o \
	-ldl -lpthread -lcrypt -lpcre -lz \
	-Wl,-E
	

modules:
# $(CC) -c 编译文件，生成目标文件objs/ngx_modules.o
objs/ngx_modules.o:	$(CORE_DEPS) \
	objs/ngx_modules.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/ngx_modules.o \
		objs/ngx_modules.c

    ...

```