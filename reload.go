package main

import (
	"fmt"
	"strings"

	ghdns "github.com/esrrhs/gohome/dns"
)

// domainReloader 是热重载分流规则所需的 resolver 能力子集，
// *ghdns.StandardResolver 天然满足；抽成接口以便用 fake 单测编排逻辑。
type domainReloader interface {
	// Update*Domains 全量替换用户自定义规则（内置直连默认始终保留）
	UpdateDirectDomains(domains []string)
	UpdateProxyDomains(domains []string)
	LoadDirectDomainFile(filePath string) (int, error)
	LoadProxyDomainFile(filePath string) (int, error)
	ReloadGeoIPDatabase(filePath string) error
	ClearCache()
}

// 编译期保证真实 resolver 可热重载
var _ domainReloader = (*ghdns.StandardResolver)(nil)

// reloadConfig 是 SIGHUP 处理：重新打开日志文件（外部 logrotate rename
// 友好）并全量重载分流域名表与 GeoIP，过程中不中断任何在途连接、
// 不重建监听。任一步失败都继续执行其余步骤并聚合错误返回——
// 一个坏文件不应让日志 reopen 或另一张表的更新被跳过。
func reloadConfig(lw *rotatingWriter, rl domainReloader, directFile, proxyFile, geoipFile string) (string, error) {
	var errs []string

	// 1. 日志文件切到新 inode（logrotate: rename 旧文件 + SIGHUP）
	if lw != nil {
		if err := lw.Reopen(); err != nil {
			errs = append(errs, fmt.Sprintf("reopen log file: %v", err))
		}
	}

	// 2. 域名表全量重载：LoadFromFile 是追加语义，必须先 Reset 用户
	// 规则（Update*Domains(nil) 保留 gohome 内置直连默认）再加载，
	// 否则"从文件里删掉的域名"无法失效。未配置文件的表完全不触碰。
	var directN, proxyN int
	rulesChanged := false
	if rl != nil {
		if directFile != "" {
			rl.UpdateDirectDomains(nil)
			n, err := rl.LoadDirectDomainFile(directFile)
			if err != nil {
				errs = append(errs, fmt.Sprintf("load direct domains: %v", err))
			}
			directN = n
			rulesChanged = true
		}
		if proxyFile != "" {
			rl.UpdateProxyDomains(nil)
			n, err := rl.LoadProxyDomainFile(proxyFile)
			if err != nil {
				errs = append(errs, fmt.Sprintf("load proxy domains: %v", err))
			}
			proxyN = n
			rulesChanged = true
		}
		// 3. GeoIP 库重新打开（文件可能已被替换）
		if geoipFile != "" {
			if err := rl.ReloadGeoIPDatabase(geoipFile); err != nil {
				errs = append(errs, fmt.Sprintf("reload geoip: %v", err))
			}
			rulesChanged = true
		}
		// 4. 规则确有更新时清 DNS 缓存：让新规则对后续查询立即生效，
		// 而不是等旧缓存条目自然过期；纯日志 reopen 不清缓存。
		if rulesChanged {
			rl.ClearCache()
		}
	}

	summary := fmt.Sprintf("reload complete: direct domains=%d, proxy domains=%d", directN, proxyN)
	if geoipFile != "" {
		summary += ", geoip reloaded"
	}
	if len(errs) > 0 {
		return summary, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return summary, nil
}
