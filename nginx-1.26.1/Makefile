
default:	build

clean:
	rm -rf Makefile objs

.PHONY:	default clean

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/chuwei/gitcode/len_nginx/build/sbin/nginx -t

	kill -USR2 `cat /home/chuwei/gitcode/len_nginx/build/logs/nginx.pid`
	sleep 1
	test -f /home/chuwei/gitcode/len_nginx/build/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/chuwei/gitcode/len_nginx/build/logs/nginx.pid.oldbin`

.PHONY:	build install modules upgrade
