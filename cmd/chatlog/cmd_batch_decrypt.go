package chatlog

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
	"github.com/spf13/cobra"
)

var (
	batchDecryptCmd = &cobra.Command{
		Use:     "batch-decrypt",
		Short:   "批量解密已存在的.dat图片文件",
		Long:    `扫描指定目录下的所有.dat文件，并批量解密保存为普通图片格式`,
		Example: `chatlog batch-decrypt --data-dir "/Users/lee/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx" --data-key "66363764393236353832316536663530" --platform darwin --version 4`,
		Run:     BatchDecrypt,
	}

	// 批量解密参数
	batchDataDir     string
	batchDataKey     string
	batchImgKey      string
	batchPlatform    string
	batchVersion     int
	batchRecursive   bool
	batchDryRun      bool
	batchConcurrency int
)

func init() {
	rootCmd.AddCommand(batchDecryptCmd)

	// 必需参数
	batchDecryptCmd.Flags().StringVar(&batchDataDir, "data-dir", "", "微信数据目录路径")
	batchDecryptCmd.Flags().StringVar(&batchDataKey, "data-key", "", "数据密钥")
	batchDecryptCmd.Flags().StringVar(&batchImgKey, "img-key", "", "图片密钥")
	batchDecryptCmd.Flags().StringVar(&batchPlatform, "platform", "darwin", "平台 (darwin)")
	batchDecryptCmd.Flags().IntVar(&batchVersion, "version", 4, "微信版本 (3/4)")

	// 可选参数
	batchDecryptCmd.Flags().BoolVar(&batchRecursive, "recursive", true, "递归扫描子目录")
	batchDecryptCmd.Flags().BoolVar(&batchDryRun, "dry-run", false, "仅显示将要处理的文件，不实际解密")
	batchDecryptCmd.Flags().IntVar(&batchConcurrency, "concurrency", 4, "并发处理数量")

	// 标记必需参数
	batchDecryptCmd.MarkFlagRequired("data-dir")
	batchDecryptCmd.MarkFlagRequired("data-key")
}

func BatchDecrypt(cmd *cobra.Command, args []string) {
	// 验证参数
	if batchDataDir == "" {
		log.Error().Msg("data-dir is required")
		return
	}
	if batchDataKey == "" {
		log.Error().Msg("data-key is required")
		return
	}

	// 设置图片密钥（如果提供）
	if batchImgKey != "" {
		dat2img.SetAesKey(batchImgKey)
		log.Info().Str("img_key", batchImgKey).Msg("使用提供的图片密钥")
	} else {
		// 如果没有提供图片密钥，尝试使用数据密钥
		dat2img.SetAesKey(batchDataKey)
		log.Info().Str("data_key", batchDataKey).Msg("使用数据密钥作为图片密钥")
	}

	// 设置XOR密钥（微信4.x版本）
	if batchVersion == 4 {
		log.Info().Msg("扫描并设置XOR密钥...")
		_, err := dat2img.ScanAndSetXorKey(batchDataDir)
		if err != nil {
			log.Warn().Err(err).Msg("设置XOR密钥失败，将使用默认值")
		}
	}

	log.Info().
		Str("data_dir", batchDataDir).
		Str("platform", batchPlatform).
		Int("version", batchVersion).
		Bool("recursive", batchRecursive).
		Bool("dry_run", batchDryRun).
		Int("concurrency", batchConcurrency).
		Msg("开始批量解密")

	// 扫描.dat文件
	datFiles, err := scanDatFiles(batchDataDir, batchRecursive)
	if err != nil {
		log.Error().Err(err).Msg("扫描.dat文件失败")
		return
	}

	if len(datFiles) == 0 {
		log.Info().Msg("未找到任何.dat文件")
		return
	}

	log.Info().Int("count", len(datFiles)).Msg("找到.dat文件")

	// 执行批量解密
	startTime := time.Now()
	stats := processBatchDecrypt(datFiles, batchConcurrency, batchDryRun)
	duration := time.Since(startTime)

	// 输出统计信息
	log.Info().
		Int("total", stats.Total).
		Int("success", stats.Success).
		Int("failed", stats.Failed).
		Int("skipped", stats.Skipped).
		Dur("duration", duration).
		Msg("批量解密完成")

	if stats.Failed > 0 {
		log.Warn().Int("failed_count", stats.Failed).Msg("部分文件解密失败，请检查日志")
	}
}

// 扫描.dat文件
func scanDatFiles(dataDir string, recursive bool) ([]string, error) {
	var datFiles []string

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录
		if info.IsDir() {
			return nil
		}

		// 检查是否为.dat文件
		if strings.HasSuffix(strings.ToLower(path), ".dat") {
			datFiles = append(datFiles, path)
		}

		return nil
	}

	if recursive {
		err := filepath.Walk(dataDir, walkFunc)
		if err != nil {
			return nil, err
		}
	} else {
		entries, err := os.ReadDir(dataDir)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".dat") {
				datFiles = append(datFiles, filepath.Join(dataDir, entry.Name()))
			}
		}
	}

	return datFiles, nil
}

// 批量解密统计信息
type BatchStats struct {
	Total   int
	Success int
	Failed  int
	Skipped int
}

// 处理批量解密
func processBatchDecrypt(datFiles []string, concurrency int, dryRun bool) BatchStats {
	stats := BatchStats{
		Total: len(datFiles),
	}

	// 创建信号量控制并发
	semaphore := make(chan struct{}, concurrency)
	results := make(chan BatchResult, len(datFiles))

	// 启动工作协程
	for _, datFile := range datFiles {
		go func(file string) {
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			result := processSingleFile(file, dryRun)
			results <- result
		}(datFile)
	}

	// 收集结果
	for i := 0; i < len(datFiles); i++ {
		result := <-results
		switch result.Status {
		case "success":
			stats.Success++
		case "failed":
			stats.Failed++
		case "skipped":
			stats.Skipped++
		}

		// 输出进度
		if (i+1)%10 == 0 || i == len(datFiles)-1 {
			log.Info().
				Int("processed", i+1).
				Int("total", len(datFiles)).
				Int("success", stats.Success).
				Int("failed", stats.Failed).
				Int("skipped", stats.Skipped).
				Msg("批量解密进度")
		}
	}

	return stats
}

// 单个文件处理结果
type BatchResult struct {
	File   string
	Status string // success, failed, skipped
	Error  error
}

// 处理单个文件
func processSingleFile(datFile string, dryRun bool) BatchResult {
	// 生成输出文件路径
	outputPath := strings.TrimSuffix(datFile, filepath.Ext(datFile))

	// 检查是否已存在解密文件
	extensions := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp4"}
	for _, ext := range extensions {
		if _, err := os.Stat(outputPath + ext); err == nil {
			return BatchResult{
				File:   datFile,
				Status: "skipped",
			}
		}
	}

	if dryRun {
		log.Debug().Str("file", datFile).Msg("将处理文件")
		return BatchResult{
			File:   datFile,
			Status: "success",
		}
	}

	// 读取.dat文件
	data, err := os.ReadFile(datFile)
	if err != nil {
		return BatchResult{
			File:   datFile,
			Status: "failed",
			Error:  err,
		}
	}

	// 解密文件
	decryptedData, ext, err := dat2img.Dat2Image(data)
	if err != nil {
		log.Debug().Err(err).Str("file", datFile).Msg("解密失败")
		return BatchResult{
			File:   datFile,
			Status: "failed",
			Error:  err,
		}
	}

	// 保存解密后的文件
	outputPath = outputPath + "." + ext
	err = os.WriteFile(outputPath, decryptedData, 0644)
	if err != nil {
		return BatchResult{
			File:   datFile,
			Status: "failed",
			Error:  err,
		}
	}

	log.Debug().
		Str("dat_file", datFile).
		Str("output_file", outputPath).
		Str("format", ext).
		Int("size", len(decryptedData)).
		Msg("文件解密成功")

	return BatchResult{
		File:   datFile,
		Status: "success",
	}
}
