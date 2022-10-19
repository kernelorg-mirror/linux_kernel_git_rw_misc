$(obj)/eprog_user_blob.o: $(obj)/eprog_user
$(obj)/eprog_user: $(srctree)/drivers/misc/embedded_prog/gohello/hello.go
	# TODO: Add support for cross builds
	go build -o $(obj)/eprog_user $(srctree)/drivers/misc/embedded_prog/gohello/hello.go

obj-$(CONFIG_EMBEDDED_PROG) += eprog.o
eprog-objs += eprog_kern.o eprog_user_blob.o
