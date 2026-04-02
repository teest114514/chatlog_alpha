package http

import (
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/xuri/excelize/v2"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/pkg/util"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
	"github.com/sjzar/chatlog/pkg/util/silk"
)

// EFS holds embedded file system data for static assets.
//
//go:embed static
var EFS embed.FS

func (s *Service) initRouter() {
	s.initBaseRouter()
	s.initMediaRouter()
	s.initAPIRouter()
	s.initMCPRouter()
}

func (s *Service) initBaseRouter() {
	staticDir, _ := fs.Sub(EFS, "static")

	s.router.StaticFS("/static", http.FS(staticDir))
	s.router.StaticFileFS("/favicon.ico", "./favicon.ico", http.FS(staticDir))
	s.router.StaticFileFS("/", "./index.htm", http.FS(staticDir))

	s.router.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	s.router.NoRoute(s.NoRoute)
}

func (s *Service) initMediaRouter() {
	s.router.GET("/image/*key", func(c *gin.Context) { s.handleMedia(c, "image") })
	s.router.GET("/video/*key", func(c *gin.Context) { s.handleMedia(c, "video") })
	s.router.GET("/file/*key", func(c *gin.Context) { s.handleMedia(c, "file") })
	s.router.GET("/voice/*key", func(c *gin.Context) { s.handleMedia(c, "voice") })
	s.router.GET("/data/*path", s.handleMediaData)
}

func (s *Service) initAPIRouter() {
	api := s.router.Group("/api/v1", s.checkDBStateMiddleware())
	{
		api.GET("/chatlog", s.handleChatlog)
		api.GET("/contact", s.handleContacts)
		api.GET("/chatroom", s.handleChatRooms)
		api.GET("/session", s.handleSessions)
		api.GET("/sns", s.handleSNS)
		api.GET("/db", s.handleGetDBs)
		api.GET("/db/tables", s.handleGetDBTables)
		api.GET("/db/data", s.handleGetDBTableData)
		api.GET("/db/query", s.handleExecuteSQL)
		api.POST("/cache/clear", s.handleClearCache)
	}
}

func (s *Service) initMCPRouter() {
	s.router.Any("/mcp", func(c *gin.Context) {
		s.mcpStreamableServer.ServeHTTP(c.Writer, c.Request)
	})
	s.router.Any("/sse", func(c *gin.Context) {
		s.mcpSSEServer.ServeHTTP(c.Writer, c.Request)
	})
	s.router.Any("/message", func(c *gin.Context) {
		s.mcpSSEServer.ServeHTTP(c.Writer, c.Request)
	})
}

// NoRoute handles 404 Not Found errors. If the request URL starts with "/api"
// or "/static", it responds with a JSON error. Otherwise, it redirects to the root path.
func (s *Service) NoRoute(c *gin.Context) {
	path := c.Request.URL.Path
	switch {
	case strings.HasPrefix(path, "/api"), strings.HasPrefix(path, "/static"):
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
	default:
		c.Header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
		c.Redirect(http.StatusFound, "/")
	}
}

func (s *Service) handleChatlog(c *gin.Context) {

	q := struct {
		Time    string `form:"time"`
		Talker  string `form:"talker"`
		Sender  string `form:"sender"`
		Keyword string `form:"keyword"`
		Limit   int    `form:"limit"`
		Offset  int    `form:"offset"`
		Format  string `form:"format"`
	}{}

	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}

	var err error
	start, end, ok := util.TimeRangeOf(q.Time)
	if !ok {
		errors.Err(c, errors.InvalidArg("time"))
		return
	}
	if q.Limit < 0 {
		q.Limit = 0
	}

	if q.Offset < 0 {
		q.Offset = 0
	}

	messages, err := s.db.GetMessages(start, end, q.Talker, q.Sender, q.Keyword, q.Limit, q.Offset)
	if err != nil {
		errors.Err(c, err)
		return
	}

	// Populate md5->path cache for media files
	s.populateMD5PathCache(messages)
	s.enrichMessages(messages)

	switch strings.ToLower(q.Format) {
	case "chatlab":
		talkerName := q.Talker
		if len(messages) > 0 {
			// Try to find a non-empty TalkerName from messages
			for _, m := range messages {
				if m.TalkerName != "" {
					talkerName = m.TalkerName
					break
				}
			}
		}

		chatLabData := model.ConvertToChatLab(messages, q.Talker, talkerName)
		c.JSON(http.StatusOK, chatLabData)
	case "csv":
		c.Writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s_%s.csv", q.Talker, start.Format("2006-01-02"), end.Format("2006-01-02")))
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		csvWriter := csv.NewWriter(c.Writer)
		csvWriter.Write([]string{"MessageID", "Time", "SenderName", "Sender", "TalkerName", "Talker", "Content"})
		for _, m := range messages {
			csvWriter.Write(m.CSV(c.Request.Host))
		}
		csvWriter.Flush()
	case "xlsx", "excel":
		f := excelize.NewFile()
		defer func() {
			if err := f.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close excel file")
			}
		}()
		// Create a new sheet.
		index, err := f.NewSheet("Sheet1")
		if err != nil {
			errors.Err(c, err)
			return
		}
		// Set value of a cell.
		headers := []string{"MessageID", "Time", "SenderName", "Sender", "TalkerName", "Talker", "Content"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue("Sheet1", cell, header)
		}
		for i, m := range messages {
			row := m.CSV(c.Request.Host)
			for j, val := range row {
				cell, _ := excelize.CoordinatesToCellName(j+1, i+2)
				f.SetCellValue("Sheet1", cell, val)
			}
		}
		f.SetActiveSheet(index)
		// Set headers
		c.Writer.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s_%s.xlsx", q.Talker, start.Format("2006-01-02"), end.Format("2006-01-02")))
		if err := f.Write(c.Writer); err != nil {
			errors.Err(c, err)
			return
		}
	case "json":
		// json
		for _, m := range messages {
			if m.Content == "" {
				m.Content = m.PlainTextContent()
			}
		}
		c.JSON(http.StatusOK, messages)
	default:
		// plain text
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		for _, m := range messages {
			// format=text 时，不传入 host，只显示 [图片] 等标签，保持简洁
			c.Writer.WriteString(m.PlainText(strings.Contains(q.Talker, ","), util.PerfectTimeFormat(start, end), ""))
			c.Writer.WriteString("\n")
			c.Writer.Flush()
		}
	}
}

func (s *Service) handleContacts(c *gin.Context) {

	q := struct {
		Keyword string `form:"keyword"`
		Limit   int    `form:"limit"`
		Offset  int    `form:"offset"`
		Format  string `form:"format"`
	}{}

	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}

	list, err := s.db.GetContacts(q.Keyword, q.Limit, q.Offset)
	if err != nil {
		errors.Err(c, err)
		return
	}

	format := strings.ToLower(q.Format)
	switch format {
	case "json":
		// json
		c.JSON(http.StatusOK, list)
	case "xlsx", "excel":
		f := excelize.NewFile()
		defer func() {
			if err := f.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close excel file")
			}
		}()
		index, err := f.NewSheet("Contacts")
		if err != nil {
			errors.Err(c, err)
			return
		}
		headers := []string{"UserName", "Alias", "Remark", "NickName"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue("Contacts", cell, header)
		}
		for i, contact := range list.Items {
			row := []interface{}{contact.UserName, contact.Alias, contact.Remark, contact.NickName}
			for j, val := range row {
				cell, _ := excelize.CoordinatesToCellName(j+1, i+2)
				f.SetCellValue("Contacts", cell, val)
			}
		}
		f.SetActiveSheet(index)
		c.Writer.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Writer.Header().Set("Content-Disposition", "attachment; filename=contacts.xlsx")
		if err := f.Write(c.Writer); err != nil {
			errors.Err(c, err)
			return
		}
	default:
		// csv
		if format == "csv" {
			// 浏览器访问时，会下载文件
			c.Writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		} else {
			c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		c.Writer.WriteString("UserName,Alias,Remark,NickName\n")
		for _, contact := range list.Items {
			c.Writer.WriteString(fmt.Sprintf("%s,%s,%s,%s\n", contact.UserName, contact.Alias, contact.Remark, contact.NickName))
		}
		c.Writer.Flush()
	}
}

func (s *Service) handleChatRooms(c *gin.Context) {

	q := struct {
		Keyword string `form:"keyword"`
		Limit   int    `form:"limit"`
		Offset  int    `form:"offset"`
		Format  string `form:"format"`
	}{}

	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}

	list, err := s.db.GetChatRooms(q.Keyword, q.Limit, q.Offset)
	if err != nil {
		errors.Err(c, err)
		return
	}
	format := strings.ToLower(q.Format)
	switch format {
	case "json":
		// json
		c.JSON(http.StatusOK, list)
	case "xlsx", "excel":
		f := excelize.NewFile()
		defer func() {
			if err := f.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close excel file")
			}
		}()
		index, err := f.NewSheet("ChatRooms")
		if err != nil {
			errors.Err(c, err)
			return
		}
		headers := []string{"Name", "Remark", "NickName", "Owner", "UserCount"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue("ChatRooms", cell, header)
		}
		for i, chatRoom := range list.Items {
			row := []interface{}{chatRoom.Name, chatRoom.Remark, chatRoom.NickName, chatRoom.Owner, len(chatRoom.Users)}
			for j, val := range row {
				cell, _ := excelize.CoordinatesToCellName(j+1, i+2)
				f.SetCellValue("ChatRooms", cell, val)
			}
		}
		f.SetActiveSheet(index)
		c.Writer.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Writer.Header().Set("Content-Disposition", "attachment; filename=chatrooms.xlsx")
		if err := f.Write(c.Writer); err != nil {
			errors.Err(c, err)
			return
		}
	default:
		// csv
		if format == "csv" {
			// 浏览器访问时，会下载文件
			c.Writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		} else {
			c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		c.Writer.WriteString("Name,Remark,NickName,Owner,UserCount\n")
		for _, chatRoom := range list.Items {
			c.Writer.WriteString(fmt.Sprintf("%s,%s,%s,%s,%d\n", chatRoom.Name, chatRoom.Remark, chatRoom.NickName, chatRoom.Owner, len(chatRoom.Users)))
		}
		c.Writer.Flush()
	}
}

func (s *Service) handleSessions(c *gin.Context) {

	q := struct {
		Keyword string `form:"keyword"`
		Limit   int    `form:"limit"`
		Offset  int    `form:"offset"`
		Format  string `form:"format"`
	}{}

	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}

	sessions, err := s.db.GetSessions(q.Keyword, q.Limit, q.Offset)
	if err != nil {
		errors.Err(c, err)
		return
	}
	format := strings.ToLower(q.Format)
	switch format {
	case "csv":
		c.Writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		c.Writer.WriteString("UserName,NOrder,NickName,Content,NTime\n")
		for _, session := range sessions.Items {
			c.Writer.WriteString(fmt.Sprintf("%s,%d,%s,%s,%s\n", session.UserName, session.NOrder, session.NickName, strings.ReplaceAll(session.Content, "\n", "\\n"), session.NTime))
		}
		c.Writer.Flush()
	case "xlsx", "excel":
		f := excelize.NewFile()
		defer func() {
			if err := f.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close excel file")
			}
		}()
		index, err := f.NewSheet("Sessions")
		if err != nil {
			errors.Err(c, err)
			return
		}
		headers := []string{"UserName", "NOrder", "NickName", "Content", "NTime"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue("Sessions", cell, header)
		}
		for i, session := range sessions.Items {
			row := []interface{}{session.UserName, session.NOrder, session.NickName, session.Content, session.NTime}
			for j, val := range row {
				cell, _ := excelize.CoordinatesToCellName(j+1, i+2)
				f.SetCellValue("Sessions", cell, val)
			}
		}
		f.SetActiveSheet(index)
		c.Writer.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Writer.Header().Set("Content-Disposition", "attachment; filename=sessions.xlsx")
		if err := f.Write(c.Writer); err != nil {
			errors.Err(c, err)
			return
		}
	case "json":
		// json
		c.JSON(http.StatusOK, sessions)
	default:
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()
		for _, session := range sessions.Items {
			c.Writer.WriteString(session.PlainText(120))
			c.Writer.WriteString("\n")
		}
		c.Writer.Flush()
	}
}

func (s *Service) handleMedia(c *gin.Context, _type string) {
	key := strings.TrimPrefix(c.Param("key"), "/")
	if key == "" {
		errors.Err(c, errors.InvalidArg(key))
		return
	}

	keys := util.Str2List(key, ",")
	if len(keys) == 0 {
		errors.Err(c, errors.InvalidArg(key))
		return
	}

	var _err error
	for _, k := range keys {
		if strings.Contains(k, "/") {
			if absolutePath, err := s.findPath(_type, k); err == nil {
				c.Redirect(http.StatusFound, "/data/"+absolutePath)
				return
			}
		}
		media, err := s.db.GetMedia(_type, k)
		if err != nil {
			// Fallback 1: try to find path from md5->path cache
			if cachedPath := s.getMD5FromCache(k); cachedPath != "" {
				// Try to find the actual file with different suffixes
				if absolutePath := s.tryFindFileWithSuffixes(cachedPath); absolutePath != "" {
					if _type == "image" {
						s.handleImageFile(c, absolutePath)
						return
					}
					c.Redirect(http.StatusFound, "/data/"+cachedPath)
					return
				}
			}

			// Fallback 2: try to find file by md5 in msg/attach directory
			if _type == "image" && !strings.Contains(k, "/") {
				if foundPath := s.findImageByMD5(k); foundPath != "" {
					// Process the found image file
					s.handleImageFile(c, foundPath)
					return
				}
			}

			_err = err
			continue
		}
		if c.Query("info") != "" {
			c.JSON(http.StatusOK, media)
			return
		}
		switch media.Type {
		case "voice":
			s.HandleVoice(c, media.Data)
			return
		case "image":
			s.handleImageFile(c, filepath.Join(s.conf.GetDataDir(), media.Path))
			return
		default:
			if resolvedPath, err := s.findPath(_type, media.Path); err == nil {
				c.Redirect(http.StatusFound, "/data/"+resolvedPath)
				return
			}
			c.Redirect(http.StatusFound, "/data/"+media.Path)
			return
		}
	}

	if _err != nil {
		errors.Err(c, _err)
		return
	}
}

func (s *Service) findPath(_type string, key string) (string, error) {
	absolutePath := filepath.Join(s.conf.GetDataDir(), key)
	if _, err := os.Stat(absolutePath); err == nil {
		return key, nil
	}
	switch _type {
	case "image":
		for _, candidate := range s.imagePathCandidates(key) {
			testPath := filepath.Join(s.conf.GetDataDir(), candidate)
			if _, err := os.Stat(testPath); err == nil {
				return candidate, nil
			}
		}
	case "video":
		for _, suffix := range []string{".mp4", "_thumb.jpg"} {
			if _, err := os.Stat(absolutePath + suffix); err == nil {
				return key + suffix, nil
			}
		}
	}
	return "", errors.ErrMediaNotFound
}

// findImageByMD5 searches for an image file by MD5 in the msg/attach directory
// It tries different suffixes: _h.dat, .dat, _t.dat
func (s *Service) findImageByMD5(md5 string) string {
	dataDir := s.conf.GetDataDir()
	attachDir := filepath.Join(dataDir, "msg", "attach")

	// Check if attach directory exists
	if _, err := os.Stat(attachDir); os.IsNotExist(err) {
		return ""
	}

	var foundPath string

	// Walk through the attach directory to find files matching the md5
	err := filepath.Walk(attachDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip directories we can't access
			if os.IsPermission(err) {
				return filepath.SkipDir
			}
			return err
		}

		// Stop if we already found a file
		if foundPath != "" {
			return io.EOF
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file name contains the md5
		baseName := strings.ToLower(filepath.Base(path))
		if !strings.Contains(baseName, strings.ToLower(md5)) {
			return nil
		}

		// Check if it's a .dat file
		if !strings.HasSuffix(baseName, ".dat") {
			return nil
		}

		// Try to read and verify the file
		if _, err := os.Stat(path); err == nil {
			foundPath = path
			return io.EOF
		}

		return nil
	})

	// If we found io.EOF, it means we found the file
	if err == io.EOF && foundPath != "" {
		return foundPath
	}

	return ""
}

// getMD5FromCache retrieves path from md5->path cache
func (s *Service) getMD5FromCache(md5 string) string {
	s.md5PathMu.RLock()
	defer s.md5PathMu.RUnlock()

	if path, ok := s.md5PathCache[md5]; ok {
		log.Debug().Str("md5", md5).Str("path", path).Msg("Cache hit for md5")
		return path
	}

	log.Debug().Str("md5", md5).Msg("Cache miss for md5")
	return ""
}

func (s *Service) imagePathCandidates(basePath string) []string {
	candidates := []string{basePath}
	if filepath.Ext(basePath) != "" {
		return candidates
	}

	candidates = append(candidates,
		basePath+".jpg",
		basePath+".png",
		basePath+".gif",
		basePath+".jpeg",
		basePath+".bmp",
		basePath+"_t",
		basePath+"_t.jpg",
		basePath+"_t.png",
		basePath+"_t.gif",
		basePath+"_t.jpeg",
		basePath+"_t.bmp",
		basePath+"_h.dat",
		basePath+".dat",
		basePath+"_t.dat",
	)
	return candidates
}

func (s *Service) resolveExistingImagePath(basePath string) string {
	for _, candidate := range s.imagePathCandidates(basePath) {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// tryFindFileWithSuffixes tries common media suffixes for cached paths.
func (s *Service) tryFindFileWithSuffixes(basePath string) string {
	dataDir := s.conf.GetDataDir()

	for _, candidate := range s.imagePathCandidates(basePath) {
		testPath := filepath.Join(dataDir, candidate)
		if _, err := os.Stat(testPath); err == nil {
			log.Debug().Str("path", testPath).Msg("Found image candidate")
			return testPath
		}
	}

	for _, suffix := range []string{".mp4", "_thumb.jpg"} {
		testPath := filepath.Join(dataDir, basePath+suffix)
		if _, err := os.Stat(testPath); err == nil {
			log.Debug().Str("path", testPath).Str("suffix", suffix).Msg("Found video candidate")
			return testPath
		}
	}

	log.Debug().Str("basePath", basePath).Msg("File not found with any suffix")
	return ""
}

// populateMD5PathCache populates the md5->path cache from messages
func (s *Service) populateMD5PathCache(messages []*model.Message) {
	s.md5PathMu.Lock()
	defer s.md5PathMu.Unlock()

	for _, msg := range messages {
		if msg.Contents == nil {
			continue
		}

		// Only cache for image, video, and file types
		if msg.Type != model.MessageTypeImage &&
			msg.Type != model.MessageTypeVideo &&
			msg.Type != model.MessageTypeVoice {
			continue
		}

		// Get md5 from contents
		md5Value, md5Ok := msg.Contents["md5"].(string)
		if !md5Ok || md5Value == "" {
			continue
		}

		// Get path from contents
		pathValue, pathOk := msg.Contents["path"].(string)
		if pathOk && pathValue != "" {
			s.md5PathCache[md5Value] = pathValue
			log.Debug().Str("md5", md5Value).Str("path", pathValue).Msg("Cached md5->path mapping")
		}
	}
}

// handleImageFile processes an image file, handling decryption if it's a .dat file or file without extension
func (s *Service) handleImageFile(c *gin.Context, absolutePath string) {
	if resolvedPath := s.resolveExistingImagePath(absolutePath); resolvedPath != "" {
		absolutePath = resolvedPath
	}

	// Check if the file needs decryption (either .dat extension or no extension)
	needsDecryption := strings.HasSuffix(strings.ToLower(absolutePath), ".dat") ||
		filepath.Ext(absolutePath) == ""

	// If it doesn't need decryption, redirect to the data handler
	if !needsDecryption {
		relativePath := strings.TrimPrefix(absolutePath, s.conf.GetDataDir())
		relativePath = strings.TrimPrefix(relativePath, string(filepath.Separator))
		c.Redirect(http.StatusFound, "/data/"+relativePath)
		return
	}

	// Determine the base path for converted files
	var outputPath string
	if filepath.Ext(absolutePath) == "" {
		// No extension, use the path as is
		outputPath = absolutePath
	} else {
		// Has .dat extension, remove it
		outputPath = strings.TrimSuffix(absolutePath, filepath.Ext(absolutePath))
	}

	var newRelativePath string
	relativePathBase := strings.TrimPrefix(outputPath, s.conf.GetDataDir())
	relativePathBase = strings.TrimPrefix(relativePathBase, string(filepath.Separator))

	// Check if a converted file already exists
	for _, ext := range []string{".jpg", ".png", ".gif", ".jpeg", ".bmp"} {
		if _, err := os.Stat(outputPath + ext); err == nil {
			newRelativePath = relativePathBase + ext
			break
		}
	}

	// If a converted file is found, redirect to it immediately
	if newRelativePath != "" {
		c.Redirect(http.StatusFound, "/data/"+newRelativePath)
		return
	}

	// Try to decrypt and convert the file
	b, err := os.ReadFile(absolutePath)
	if err != nil {
		// If file doesn't exist or can't be read, fallback to redirect
		relativePath := strings.TrimPrefix(absolutePath, s.conf.GetDataDir())
		relativePath = strings.TrimPrefix(relativePath, string(filepath.Separator))
		c.Redirect(http.StatusFound, "/data/"+relativePath)
		return
	}

	out, ext, err := dat2img.Dat2Image(b)
	if err != nil {
		// If decryption fails, fallback to serving the file as-is
		relativePath := strings.TrimPrefix(absolutePath, s.conf.GetDataDir())
		relativePath = strings.TrimPrefix(relativePath, string(filepath.Separator))
		c.Redirect(http.StatusFound, "/data/"+relativePath)
		return
	}

	// Save the decrypted file
	s.saveDecryptedFile(absolutePath, out, ext)

	// Build the new relative path and redirect
	newRelativePath = relativePathBase + "." + ext
	c.Redirect(http.StatusFound, "/data/"+newRelativePath)
}

func (s *Service) handleMediaData(c *gin.Context) {
	relativePath := filepath.Clean(c.Param("path"))

	absolutePath := filepath.Join(s.conf.GetDataDir(), relativePath)

	if _, err := os.Stat(absolutePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "File not found",
		})
		return
	}

	ext := strings.ToLower(filepath.Ext(absolutePath))
	switch {
	case ext == ".dat", ext == "":
		// Try to decrypt .dat files or files without extension
		s.HandleDatFile(c, absolutePath)
	default:
		// 直接返回文件
		c.File(absolutePath)
	}

}

func (s *Service) HandleDatFile(c *gin.Context, path string) {

	b, err := os.ReadFile(path)
	if err != nil {
		errors.Err(c, err)
		return
	}
	out, ext, err := dat2img.Dat2Image(b)
	if err != nil {
		// If decryption fails, check if this is a file without extension
		// If so, try to return it as-is
		if filepath.Ext(path) == "" {
			// Try to detect the file type and return appropriately
			http.DetectContentType(b)
			c.Data(http.StatusOK, http.DetectContentType(b), b)
			return
		}

		// For .dat files that fail to decrypt, return error
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "Failed to parse .dat file",
			"reason": err.Error(),
			"path":   path,
		})
		return
	}

	// Save decrypted file to local disk
	if s.conf.GetSaveDecryptedMedia() {
		s.saveDecryptedFile(path, out, ext)
	}

	switch ext {
	case "jpg", "jpeg":
		c.Data(http.StatusOK, "image/jpeg", out)
	case "png":
		c.Data(http.StatusOK, "image/png", out)
	case "gif":
		c.Data(http.StatusOK, "image/gif", out)
	case "bmp":
		c.Data(http.StatusOK, "image/bmp", out)
	case "mp4":
		c.Data(http.StatusOK, "video/mp4", out)
	default:
		c.Data(http.StatusOK, "image/jpg", out)
		// c.File(path)
	}
}

func (s *Service) HandleVoice(c *gin.Context, data []byte) {
	out, err := silk.Silk2MP3(data)
	if err != nil {
		c.Data(http.StatusOK, "audio/silk", data)
		return
	}
	c.Data(http.StatusOK, "audio/mp3", out)
}

// saveDecryptedFile saves the decrypted media file to local disk
func (s *Service) saveDecryptedFile(datPath string, data []byte, ext string) {
	// Generate target file path: replace .dat with actual extension
	outputPath := strings.TrimSuffix(datPath, filepath.Ext(datPath)) + "." + ext

	// Check if file already exists to avoid duplicate writes
	if _, err := os.Stat(outputPath); err == nil {
		return
	}

	// Write file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		log.Error().
			Err(err).
			Str("dat_path", datPath).
			Str("output_path", outputPath).
			Msg("Failed to save decrypted file")
		return
	}

	log.Debug().
		Str("dat_path", datPath).
		Str("output_path", outputPath).
		Str("format", ext).
		Int("size", len(data)).
		Msg("Decrypted file saved successfully")
}

func (s *Service) handleClearCache(c *gin.Context) {
	dataDir := s.conf.GetDataDir()
	if dataDir == "" {
		errors.Err(c, fmt.Errorf("data directory not configured"))
		return
	}

	deletedCount := 0

	err := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil // Skip directories
		}

		ext := strings.ToLower(filepath.Ext(path))
		// List of generated extensions
		generatedExts := map[string]struct{}{
			".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".bmp": {}, ".mp4": {},
		}

		if _, isGenerated := generatedExts[ext]; isGenerated {
			baseName := strings.TrimSuffix(path, ext)
			// Check for corresponding .dat file. WeChat can use various suffixes.
			datSuffixes := []string{".dat", "_h.dat", "_t.dat"}
			for _, datSuffix := range datSuffixes {
				datPath := baseName + datSuffix
				if _, statErr := os.Stat(datPath); statErr == nil {
					// Found a corresponding .dat file, so this is a cached file.
					if removeErr := os.Remove(path); removeErr == nil {
						deletedCount++
					} else {
						log.Warn().Err(removeErr).Str("path", path).Msg("Failed to remove cached file")
					}
					// Once we find a .dat pair and delete, no need to check other suffixes
					return nil
				}
			}
		}
		return nil
	})

	if err != nil {
		errors.Err(c, fmt.Errorf("failed to walk data directory: %w", err))
		return
	}

	log.Info().Int("count", deletedCount).Msg("Cleared decrypted file cache")
	c.JSON(http.StatusOK, gin.H{
		"message":      "Cache cleared successfully",
		"deletedCount": deletedCount,
	})
}

func (s *Service) handleGetDBs(c *gin.Context) {
	dbs, err := s.db.GetDecryptedDBs()
	if err != nil {
		errors.Err(c, err)
		return
	}
	c.JSON(http.StatusOK, dbs)
}

func (s *Service) handleGetDBTables(c *gin.Context) {
	group := c.Query("group")
	file := c.Query("file")

	if group == "" || file == "" {
		errors.Err(c, errors.InvalidArg("group or file"))
		return
	}

	tables, err := s.db.GetTables(group, file)
	if err != nil {
		errors.Err(c, err)
		return
	}
	c.JSON(http.StatusOK, tables)
}

func (s *Service) handleGetDBTableData(c *gin.Context) {
	group := c.Query("group")
	file := c.Query("file")
	table := c.Query("table")
	keyword := c.Query("keyword")
	limitStr := c.DefaultQuery("limit", "20")
	offsetStr := c.DefaultQuery("offset", "0")
	format := strings.ToLower(c.Query("format"))

	if group == "" || file == "" || table == "" {
		errors.Err(c, errors.InvalidArg("group, file or table"))
		return
	}

	limit := 20
	offset := 0
	fmt.Sscanf(limitStr, "%d", &limit)
	fmt.Sscanf(offsetStr, "%d", &offset)

	// If exporting, fetch all matching rows (ignore pagination if user wants all? or respect pagination?)
	// Usually export means "export all matching".
	if format == "csv" || format == "xlsx" || format == "excel" {
		limit = -1 // No limit
		offset = 0
	}

	data, err := s.db.GetTableData(group, file, table, limit, offset, keyword)
	if err != nil {
		errors.Err(c, err)
		return
	}

	if format == "csv" || format == "xlsx" || format == "excel" {
		s.exportData(c, data, format, table)
		return
	}

	c.JSON(http.StatusOK, data)
}

func (s *Service) handleExecuteSQL(c *gin.Context) {
	group := c.Query("group")
	file := c.Query("file")
	query := c.Query("sql")
	format := strings.ToLower(c.Query("format"))

	if group == "" || file == "" || query == "" {
		errors.Err(c, errors.InvalidArg("group, file or sql"))
		return
	}

	data, err := s.db.ExecuteSQL(group, file, query)
	if err != nil {
		errors.Err(c, err)
		return
	}

	if format == "csv" || format == "xlsx" || format == "excel" {
		s.exportData(c, data, format, "query_result")
		return
	}

	c.JSON(http.StatusOK, data)
}

func (s *Service) exportData(c *gin.Context, data []map[string]interface{}, format string, filename string) {
	if len(data) == 0 {
		c.String(http.StatusOK, "")
		return
	}

	// Extract headers
	var headers []string
	for k := range data[0] {
		headers = append(headers, k)
	}
	// Sort headers for consistency
	// sort.Strings(headers) // We need sort package

	if format == "csv" {
		c.Writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", filename))
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Flush()

		w := csv.NewWriter(c.Writer)
		w.Write(headers)
		for _, row := range data {
			var record []string
			for _, h := range headers {
				val := row[h]
				if val == nil {
					record = append(record, "")
				} else {
					record = append(record, fmt.Sprintf("%v", val))
				}
			}
			w.Write(record)
		}
		w.Flush()
	} else {
		// Excel
		f := excelize.NewFile()
		defer func() {
			if err := f.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close excel file")
			}
		}()

		sheet := "Sheet1"
		index, _ := f.NewSheet(sheet)

		// Write headers
		for i, h := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue(sheet, cell, h)
		}

		// Write data
		for r, row := range data {
			for cIdx, h := range headers {
				val := row[h]
				cell, _ := excelize.CoordinatesToCellName(cIdx+1, r+2)
				f.SetCellValue(sheet, cell, val)
			}
		}

		f.SetActiveSheet(index)
		c.Writer.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.xlsx", filename))
		if err := f.Write(c.Writer); err != nil {
			log.Error().Err(err).Msg("Failed to write excel file")
		}
	}
}

func (s *Service) handleSNS(c *gin.Context) {
	q := struct {
		Username string `form:"username"`
		Limit    int    `form:"limit"`
		Offset   int    `form:"offset"`
		Format   string `form:"format"`
	}{}

	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}

	if q.Limit < 0 {
		q.Limit = 0
	}
	if q.Offset < 0 {
		q.Offset = 0
	}

	format := strings.ToLower(q.Format)

	// 原始格式需要直接从数据库查询 XML
	if format == "raw" {
		s.handleSNSRaw(c, q.Username, q.Limit, q.Offset)
		return
	}

	data, err := s.db.GetSNSTimeline(q.Username, q.Limit, q.Offset)
	if err != nil {
		errors.Err(c, err)
		return
	}

	switch format {
	case "csv", "xlsx", "excel":
		s.exportData(c, data, format, "sns_timeline")
	case "json":
		c.JSON(http.StatusOK, data)
	default:
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		for _, item := range data {
			// 格式化输出
			if createTimeStr, ok := item["create_time_str"].(string); ok {
				c.Writer.WriteString(fmt.Sprintf("📅 %s\n", createTimeStr))
			}
			if nickname, ok := item["nickname"].(string); ok && nickname != "" {
				c.Writer.WriteString(fmt.Sprintf("👤 %s\n", nickname))
			}
			if contentDesc, ok := item["content_desc"].(string); ok && contentDesc != "" {
				c.Writer.WriteString(fmt.Sprintf("💬 %s\n", contentDesc))
			}
			if location, ok := item["location"].(map[string]interface{}); ok {
				c.Writer.WriteString("📍 ")
				if poiName, ok := location["poi_name"].(string); ok && poiName != "" {
					c.Writer.WriteString(poiName)
					if poiAddress, ok := location["poi_address"].(string); ok && poiAddress != "" {
						c.Writer.WriteString(fmt.Sprintf(" (%s)", poiAddress))
					}
				} else if city, ok := location["city"].(string); ok && city != "" {
					c.Writer.WriteString(city)
				}
				c.Writer.WriteString("\n")
			}
			if contentType, ok := item["content_type"].(string); ok {
				switch contentType {
				case "image":
					if mediaList, ok := item["media_list"].([]interface{}); ok {
						c.Writer.WriteString(fmt.Sprintf("🖼️ 图片 (%d张)\n", len(mediaList)))
					}
				case "video":
					if mediaList, ok := item["media_list"].([]interface{}); ok && len(mediaList) > 0 {
						if media, ok := mediaList[0].(map[string]interface{}); ok {
							if duration, ok := media["duration"].(string); ok && duration != "" {
								c.Writer.WriteString(fmt.Sprintf("🎬 视频 (%s)\n", duration))
							} else {
								c.Writer.WriteString("🎬 视频\n")
							}
						}
					}
				case "article":
					if article, ok := item["article"].(map[string]interface{}); ok {
						if title, ok := article["title"].(string); ok {
							c.Writer.WriteString(fmt.Sprintf("📰 文章: %s\n", title))
						}
						if url, ok := article["url"].(string); ok {
							c.Writer.WriteString(fmt.Sprintf("   %s\n", url))
						}
					}
				case "finder":
					if feed, ok := item["finder_feed"].(map[string]interface{}); ok {
						if nickname, ok := feed["nickname"].(string); ok {
							c.Writer.WriteString(fmt.Sprintf("📺 视频号: %s\n", nickname))
						}
						if desc, ok := feed["desc"].(string); ok && desc != "" {
							c.Writer.WriteString(fmt.Sprintf("   %s\n", desc))
						}
					}
				}
			}
			c.Writer.WriteString(strings.Repeat("=", 80) + "\n\n")
			c.Writer.Flush()
		}
	}
}

// handleSNSRaw 处理原始格式输出（返回原始 XML）
func (s *Service) handleSNSRaw(c *gin.Context, username string, limit, offset int) {
	// 获取 wechatdb.DB
	db := s.db.GetDB()
	if db == nil {
		errors.Err(c, fmt.Errorf("database not available"))
		return
	}

	// 获取数据库列表
	dbs, err := db.GetDBs()
	if err != nil {
		errors.Err(c, err)
		return
	}

	snsDBs, ok := dbs["sns"]
	if !ok || len(snsDBs) == 0 {
		errors.Err(c, fmt.Errorf("SNS database not found"))
		return
	}

	// 使用第一个 sns 数据库文件
	snsFile := snsDBs[0]

	// 构建查询
	query := "SELECT tid, user_name, content FROM SnsTimeLine"

	if username != "" {
		// 转义单引号以防止 SQL 注入
		username = strings.ReplaceAll(username, "'", "''")
		query += fmt.Sprintf(" WHERE user_name = '%s'", username)
	}

	query += " ORDER BY tid DESC"

	// 执行查询（使用 ExecuteSQL）
	result, err := db.ExecuteSQL("sns", snsFile, query)
	if err != nil {
		errors.Err(c, err)
		return
	}

	// 手动处理分页（因为 ExecuteSQL 不支持 LIMIT/OFFSET）
	if offset > 0 || limit > 0 {
		if offset >= len(result) {
			result = []map[string]interface{}{}
		} else {
			result = result[offset:]
			if limit > 0 && limit < len(result) {
				result = result[:limit]
			}
		}
	}

	c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Flush()

	for _, item := range result {
		// 输出原始格式
		if tid, ok := item["tid"]; ok {
			c.Writer.WriteString(fmt.Sprintf("TID: %v\n", tid))
		}
		if userName, ok := item["user_name"]; ok {
			c.Writer.WriteString(fmt.Sprintf("UserName: %v\n", userName))
		}
		if content, ok := item["content"]; ok {
			c.Writer.WriteString(fmt.Sprintf("Content (XML):\n%v\n", content))
		}
		c.Writer.WriteString(strings.Repeat("-", 80) + "\n\n")
		c.Writer.Flush()
	}
}
