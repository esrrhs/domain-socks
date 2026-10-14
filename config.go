package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// config 是从 key=value 文件读入的默认值集合。它必须在 flag 定义之前
// 加载：文件里的键作为各 flag 的 default 注入，命令行显式传参时由
// flag 包自动覆盖，天然实现"命令行 > 配置文件 > 内置默认"三级优先。
// -config 本身只认命令行，不允许从文件嵌套引用。
type config struct {
	path string
	vals map[string]string
	// errs 收集类型非法的值；统一在 validate 阶段报错，
	// 避免路由器上"密码里多个空格配置静默失效"这类事故。
	errs []string
}

// scanConfigPath 在 flag.Parse 之前手工扫描参数找出 -config。
// 支持 "-config p"、"-config=p"、"--config=p" 三种形态。
func scanConfigPath(args []string) (string, error) {
	for i, a := range args {
		switch {
		case a == "-config" || a == "--config":
			if i+1 >= len(args) {
				return "", fmt.Errorf("-config requires a file path")
			}
			return args[i+1], nil
		case strings.HasPrefix(a, "-config="):
			return strings.TrimPrefix(a, "-config="), nil
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config="), nil
		}
	}
	return "", nil
}

// loadConfig 预扫描 -config 并读取解析文件；没有 -config 时返回只带
// 空值的 config（所有取值走内置默认）。
func loadConfig(args []string) (*config, error) {
	path, err := scanConfigPath(args)
	if err != nil {
		return nil, err
	}
	c := &config{path: path, vals: map[string]string{}}
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	vals, err := parseConfigFile(data)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.vals = vals
	return c, nil
}

// parseConfigFile 解析 UTF-8 文本：每行 `key=value`（等号两侧空白忽略，
// 值内部空格保留），支持 `#` 整行注释与可选的 `-`/`--` 键前缀；
// 空行忽略，重复键后写覆盖前写。value 可含 `=`（只按第一个等号切分）。
func parseConfigFile(data []byte) (map[string]string, error) {
	cfg := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; sc.Scan(); line++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		s = strings.TrimPrefix(s, "--")
		s = strings.TrimPrefix(s, "-")
		key, val, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key=value, got %q", line, sc.Text())
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		cfg[key] = strings.TrimSpace(val)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Has 报告文件里是否给了该键（用于互斥校验：listen 出现在文件里
// 等同于命令行显式给了 -listen）。
func (c *config) Has(name string) bool {
	_, ok := c.vals[name]
	return ok
}

// String 返回值或默认值。
func (c *config) String(name, def string) string {
	if v, ok := c.vals[name]; ok {
		return v
	}
	return def
}

// Bool 返回布尔值；非法字面量记入 errs 并回退默认值。
func (c *config) Bool(name string, def bool) bool {
	v, ok := c.vals[name]
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		c.errs = append(c.errs, fmt.Sprintf("%s: invalid bool %q", name, v))
		return def
	}
	return b
}

// Int 返回整数值；非法字面量同 Bool。
func (c *config) Int(name string, def int) int {
	v, ok := c.vals[name]
	if !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		c.errs = append(c.errs, fmt.Sprintf("%s: invalid int %q", name, v))
		return def
	}
	return n
}

// validate 在 flag 全部定义后调用：拼写错误/不存在的键与类型非法的
// 值都必须立刻失败——静默忽略配置项在代理场景等于流量走向失控。
func (c *config) validate() error {
	if len(c.errs) > 0 {
		return fmt.Errorf("config %s: %s", c.path, c.errs[0])
	}
	var unknown []string
	for k := range c.vals {
		if flag.Lookup(k) == nil {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("config %s: unknown option(s): %s", c.path, strings.Join(unknown, ", "))
	}
	return nil
}
