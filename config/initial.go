package config

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/eyslce/clash/component/mmdb"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/log"
)

// downloadMMDB 函数从指定的URL下载MMDB文件并保存到给定的路径。
// 目前硬编码从jsdelivr CDN下载GeoIP2-CN的Country.mmdb文件。
func downloadMMDB(path string) (err error) {
	resp, err := http.Get("https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/Country.mmdb")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}

// InitMMDB 函数负责初始化MMDB (GeoIP数据库) 文件。
// 它会检查MMDB文件是否存在，如果不存在则下载。
// 还会验证现有的MMDB文件是否有效，如果无效则删除并重新下载。
func InitMMDB() error {
	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		log.Infoln("Can't find MMDB, start download")
		if err := downloadMMDB(C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't download MMDB: %s", err.Error())
		}
	}

	if !mmdb.Verify() {
		log.Warnln("MMDB invalid, remove and download")
		if err := os.Remove(C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't remove invalid MMDB: %s", err.Error())
		}

		if err := downloadMMDB(C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't download MMDB: %s", err.Error())
		}
	}

	return nil
}

// Init 函数用于准备Clash运行所需的必要文件和目录。
// 它接收一个表示配置目录路径的字符串参数。
// 主要工作包括：
// 1. 创建配置目录 (如果不存在)。
// 2. 创建一个初始的config.yaml配置文件 (如果不存在)，包含一个默认的mixed-port设置。
// 3. 初始化MMDB文件 (调用InitMMDB)。
// Init prepare necessary files
func Init(dir string) error {
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %s", C.Path.Config(), err.Error())
		}
		f.Write([]byte(`mixed-port: 7890`))
		f.Close()
	}

	// initial mmdb
	if err := InitMMDB(); err != nil {
		return fmt.Errorf("can't initial MMDB: %w", err)
	}
	return nil
}
