# Patch细节

## shellcode:

patch前：
![](https://upload-images.jianshu.io/upload_images/5808046-a3abba53b042da07.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


patch后：
![](https://upload-images.jianshu.io/upload_images/5808046-a13349cc784810db.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

```
函数：void *mmap(void *start,size_t length,int prot,int flags,int fd,off_t offsize); 
参数start：指向欲映射的内存起始地址，通常设为 NULL，代表让系统自动选定地址，映射成功后返回该地址。

参数length：代表将文件中多大的部分映射到内存。

参数prot：映射区域的保护方式。可以为以下几种方式的组合：
PROT_EXEC 映射区域可被执行
PROT_READ 映射区域可被读取
PROT_WRITE 映射区域可被写入
PROT_NONE 映射区域不能存取


#define PROT_READ	0x1		/* Page can be read.  */
#define PROT_WRITE	0x2		/* Page can be written.  */
#define PROT_EXEC	0x4		/* Page can be executed.  */
#define PROT_NONE	0x0		/* Page can not be accessed.  */
#define PROT_GROWSDOWN	0x01000000	/* Extend change to start of
					   growsdown vma (mprotect only).  */
```

## fastbin attach（double free）:
patch前：
![](https://upload-images.jianshu.io/upload_images/5808046-30bb76e71d9beb6e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


patch后：
![](https://upload-images.jianshu.io/upload_images/5808046-99e33c566ef96f4b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## Format string bug
patch前：
![](https://upload-images.jianshu.io/upload_images/5808046-98b409adda057582.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


patch后：
![](https://upload-images.jianshu.io/upload_images/5808046-219b5e2efa3d6ac5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)