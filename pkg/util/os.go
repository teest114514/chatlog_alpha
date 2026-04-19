package util

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/rs/zerolog/log"
)

// FindFilesWithPatterns 在指定目录下查找匹配多个正则表达式的文件
// directory: 要搜索的目录路径
// patterns: 正则表达式模式列表
// recursive: 是否递归搜索子目录
// 返回匹配的文件路径列表和可能的错误
func FindFilesWithPatterns(directory string, pattern string, recursive bool) ([]string, error) {
	// 编译所有正则表达式
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("无效的正则表达式 '%s': %v", pattern, err)
	}

	// 检查目录是否存在
	dirInfo, err := os.Stat(directory)
	if err != nil {
		return nil, fmt.Errorf("无法访问目录 '%s': %v", directory, err)
	}
	if !dirInfo.IsDir() {
		return nil, fmt.Errorf("'%s' 不是一个目录", directory)
	}

	// 存储匹配的文件路径
	var matchedFiles []string

	// 创建文件系统
	fsys := os.DirFS(directory)

	// 遍历文件系统
	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// 如果是目录且不递归，则跳过子目录
		if d.IsDir() {
			if !recursive && path != "." {
				return fs.SkipDir
			}
			return nil
		}

		// 检查文件名是否匹配任何一个正则表达式
		if re.MatchString(d.Name()) {
			// 添加完整路径到结果列表
			fullPath := filepath.Join(directory, path)
			matchedFiles = append(matchedFiles, fullPath)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("遍历目录时出错: %v", err)
	}

	return matchedFiles, nil
}

func DefaultWorkDir(account string) string {
	if len(account) == 0 {
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(os.ExpandEnv("${HOME}"), "Documents", "chatlog")
		default:
			return filepath.Join(os.ExpandEnv("${HOME}"), "chatlog")
		}
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.ExpandEnv("${HOME}"), "Documents", "chatlog", account)
	default:
		return filepath.Join(os.ExpandEnv("${HOME}"), "chatlog", account)
	}
}

func GetDirSize(dir string) string {
	var size int64
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			size += info.Size()
		}
		return nil
	})
	return ByteCountSI(size)
}

func ByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// PrepareDir ensures that the specified directory path exists.
// If the directory does not exist, it attempts to create it.
func PrepareDir(path string) error {
	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	} else if !stat.IsDir() {
		log.Debug().Msgf("%s is not a directory", path)
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}
