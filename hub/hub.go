package hub

import (
	"github.com/eyslce/routune/config"
	"github.com/eyslce/routune/hub/executor"
	"github.com/eyslce/routune/hub/route"
)

type Option func(*config.Config)

func WithExternalUI(externalUI string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalUI = externalUI
	}
}

func WithExternalController(externalController string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalController = externalController
	}
}

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.General.Secret = secret
	}
}

// Parse call at the beginning of routune
// Parse 函数在 routune 启动时调用，用于解析配置并应用。
// 它接收一系列 Option 函数作为参数，这些函数可以修改加载的配置。
func Parse(options ...Option) error {
	// 首先，尝试解析配置文件。
	cfg, err := executor.Parse()
	if err != nil {
		// 如果解析失败，返回错误。
		return err
	}

	// 遍历所有传入的 Option 函数，并将其应用于配置。
	// Option 函数允许在加载配置后对其进行修改，例如设置外部 UI 路径或控制器地址。
	for _, option := range options {
		option(cfg)
	}

	// 如果配置中指定了 ExternalUI 路径，则设置 UI 路径。
	if cfg.General.ExternalUI != "" {
		route.SetUIPath(cfg.General.ExternalUI)
	}

	// 如果配置中指定了 ExternalController 地址，则启动路由服务。
	// 这通常用于启动一个 HTTP 服务器来提供 API 接口。
	if cfg.General.ExternalController != "" {
		go route.Start(cfg.General.ExternalController, cfg.General.Secret)
	}

	// 应用最终的配置。
	// force 参数为 true，表示强制应用配置。
	executor.ApplyConfig(cfg, true)
	return nil
}
