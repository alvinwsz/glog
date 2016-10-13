
glog
====

在[golang/glog](https://github.com/golang/glog)的基础上做了如下修改，适应我自己的需求。

## 修改的地方:
1. `-log_to=std,file`

   日志输出目标，std表示输出到console，file表示输出到文件，两者都指定则同时输出到console和文件，未指定则默认是file

2. `-log_file=filename`

   如果指定输出到文件，则指定log文件名，未指定则默认为`<program>.log`

3. `-log_dir=xxx`

   log文件保存路径，未指定则默认是系统TEMP目录

4. `-v=<level>`

   指定日志等级为DEBUG、INFO、WARN、ERROR、FATAL其中之一，日志级别由低到高，日志等级>=Level的日志才能输出，指定DEBUG表示所有调用打印日志的方法都会打出，指定FATAL则表示只有致命错误才打印日志并退出。未指定则默认是FATAL，调试时可指定DEBUG，release运行时可指定INFO

   设置日志级别的方法为：`glog.SetLevel(glog.DEBUG) `

5. `-vm=pattern:level,pattern:level`

   为特定文件指定日志等级，帮助调试。其中pattern可以是具体文件名（不带路径，无.go后缀）或者`glob`模式，level为日志等级

   在某些情况下，比如调试某个特定模块，需要关闭该模块之外的所有log：

   `-v=FATAL -vm=file1:DEBUG,file2:DEBUG`

6. `-log_backtrace_at=file:line`

   在log到指定文件指定行打印stack back trace，帮助调试。其中，file为不带路径不带.go后缀的文件名，line为行号

7. `-log_daily=true`

   按日期每天切割日志文件，指定为false则按大小（`-log_size`指定）切割，未指定默认为true

8. `-log_size=<size>`

   指定切割文件大小，size单位是MB，如果超过大小则创建新的log文件

9. `-log_flush=10`

   设置刷新缓冲区时间，单位是秒，默认是30s

   ​	


##使用示例 
```
func main() {
    //初始化命令行参数
    flag.Parse()
    //退出时调用，确保日志写入文件中
    defer glog.Flush()

	// 如下是用户未做设定时的默认参数：
	// 输出到系统TEMP目录，文件名为“<program>.log.<host>.<user>.yyyymmdd-hhmmss.pid”，为防止文件过大，采取每天创建新的log文件，但始终创建符号链接文件“<program>.log”到最新的log文件
	// 默认输出级别是DEBUG，也就是所有级别信息都输出
	// 后台flush缓冲数据到文件的时间间隔是30s

    //一般在测试环境下设置输出等级为DEBUG，线上环境设置为INFO
    
    glog.Info("test")
    glog.Warn("test")
    glog.Error("test")
    
    glog.Infof("test %d", 1)
    glog.Warnf("test %d", 2)
    glog.Errorf("test %d", 3)
 }
 
//假设编译后的可执行程序名为demo,运行时指定log_dir参数将日志文件保存到特定的目录，同时输出到控制台
// ./demo -log_dir=./log -v=INFO -log_to=std,file 
```
