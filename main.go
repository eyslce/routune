package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/eyslce/clash/config"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/hub"
	"github.com/eyslce/clash/hub/executor"
	"github.com/eyslce/clash/log"

	"go.uber.org/automaxprocs/maxprocs"
)

var (
	flagset            map[string]bool // 存储已设置的命令行标志
	version            bool            // 显示版本信息的标志
	testConfig         bool            // 测试配置文件的标志
	homeDir            string          // 配置目录路径
	configFile         string          // 配置文件路径
	externalUI         string          // 外部 UI 目录路径
	externalController string          // 外部控制器地址
	secret             string          // RESTful API 的密钥
)

// init 函数用于初始化命令行参数
func init() {
	// 定义命令行参数
	flag.StringVar(&homeDir, "d", "", "set configuration directory")
	flag.StringVar(&configFile, "f", "", "specify configuration file")
	flag.StringVar(&externalUI, "ext-ui", "", "override external ui directory")
	flag.StringVar(&externalController, "ext-ctl", "", "override external controller address")
	flag.StringVar(&secret, "secret", "", "override secret for RESTful API")
	flag.BoolVar(&version, "v", false, "show current version of clash")
	flag.BoolVar(&testConfig, "t", false, "test configuration and exit")
	flag.Parse() // 解析命令行参数

	// 将已设置的命令行标志存入 map
	flagset = map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		flagset[f.Name] = true
	})
}

// main 函数是程序的入口点
func main() {
	// 设置最大 GOMAXPROCS，忽略日志输出
	maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))
	// 如果设置了 -v 标志，则打印版本信息并退出
	if version {
		fmt.Printf("Clash %s %s %s with %s %s\n", C.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), C.BuildTime)
		return
	}

	// 处理配置目录路径
	if homeDir != "" {
		// 如果 homeDir 不是绝对路径，则转换为绝对路径
		if !filepath.IsAbs(homeDir) {
			currentDir, _ := os.Getwd()
			homeDir = filepath.Join(currentDir, homeDir)
		}
		C.SetHomeDir(homeDir) // 设置全局配置目录
	}

	// 处理配置文件路径
	if configFile != "" {
		// 如果 configFile 不是绝对路径，则转换为绝对路径
		if !filepath.IsAbs(configFile) {
			currentDir, _ := os.Getwd()
			configFile = filepath.Join(currentDir, configFile)
		}
		C.SetConfig(configFile) // 设置全局配置文件路径
	} else {
		// 如果未指定配置文件，则使用默认路径
		configFile := filepath.Join(C.Path.HomeDir(), C.Path.Config())
		C.SetConfig(configFile)
	}

	// 初始化配置目录
	if err := config.Init(C.Path.HomeDir()); err != nil {
		log.Fatalln("Initial configuration directory error: %s", err.Error())
	}

	// 如果设置了 -t 标志，则测试配置文件并退出
	if testConfig {
		if _, err := executor.Parse(); err != nil {
			log.Errorln(err.Error())
			fmt.Printf("configuration file %s test failed\n", C.Path.Config())
			os.Exit(1) // 配置测试失败，退出码为 1
		}
		fmt.Printf("configuration file %s test is successful\n", C.Path.Config())
		return // 配置测试成功，正常退出
	}

	var options []hub.Option // hub 的选项列表
	// 根据命令行参数设置 hub 选项
	if flagset["ext-ui"] {
		options = append(options, hub.WithExternalUI(externalUI))
	}
	if flagset["ext-ctl"] {
		options = append(options, hub.WithExternalController(externalController))
	}
	if flagset["secret"] {
		options = append(options, hub.WithSecret(secret))
	}

	// 解析并启动 hub
	if err := hub.Parse(options...); err != nil {
		log.Fatalln("Parse config error: %s", err.Error())
	}

	// 创建一个信号通道，用于接收中断和终止信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh // 阻塞程序，直到接收到信号
}
