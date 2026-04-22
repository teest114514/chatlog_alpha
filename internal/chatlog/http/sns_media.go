package http

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
)

const snsVideoDecryptWindow = 128 * 1024

func (s *Service) handleSNSMediaProxy(c *gin.Context) {
	rawURL := strings.TrimSpace(c.Query("url"))
	if rawURL == "" {
		errors.Err(c, errors.InvalidArg("url"))
		return
	}
	key := strings.TrimSpace(c.Query("key"))
	if key == "" || key == "0" {
		key = s.getSNSMediaKeyFromCache(rawURL)
	}

	data, contentType, err := s.downloadAndDecryptSNSMedia(c.Request.Context(), rawURL, key)
	if err != nil {
		errors.Err(c, err)
		return
	}
	c.Header("Content-Type", contentType)
	c.Header("Cache-Control", "public, max-age=86400")
	c.Data(http.StatusOK, contentType, data)
}

func (s *Service) downloadAndDecryptSNSMedia(ctx context.Context, rawURL, key string) ([]byte, string, error) {
	cachePath := s.snsMediaCachePath(rawURL, key)
	if cachePath != "" {
		if data, err := os.ReadFile(cachePath); err == nil && len(data) > 0 {
			return data, detectSNSMime(data, ""), nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", errors.InvalidArg("url")
	}
	req.Header.Set("User-Agent", "MicroMessenger Client")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", errors.OpenFileFailed(rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, "", errors.QueryFailed(fmt.Sprintf("sns media http status %d", resp.StatusCode), nil)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", errors.ReadFileFailed(rawURL, err)
	}
	if len(data) == 0 {
		return nil, "", errors.QueryFailed("empty sns media response", nil)
	}

	data, contentType, err := s.decryptSNSMedia(ctx, data, key, resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", err
	}

	if cachePath != "" {
		if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err == nil {
			if writeErr := os.WriteFile(cachePath, data, 0o644); writeErr != nil {
				log.Warn().Err(writeErr).Str("path", cachePath).Msg("write sns media cache failed")
			}
		}
	}
	return data, contentType, nil
}

func (s *Service) decryptSNSMedia(ctx context.Context, data []byte, key, fallbackContentType string) ([]byte, string, error) {
	rawMime := detectSNSMimeStrict(data)
	if strings.HasPrefix(rawMime, "image/") {
		return data, rawMime, nil
	}

	if strings.TrimSpace(key) == "" {
		if strings.HasPrefix(rawMime, "video/") {
			return data, rawMime, nil
		}
		return nil, "", errors.QueryFailed("sns media decrypt key missing", nil)
	}
	seed, err := strconv.ParseUint(strings.TrimSpace(key), 10, 64)
	if err != nil {
		return nil, "", errors.QueryFailed("invalid sns media decrypt key", err)
	}

	// 先按图片全量 XOR 尝试。实测朋友圈图片同样优先使用 reversed keystream。
	imageModes := []bool{true, false}
	for _, reversed := range imageModes {
		imgDec := make([]byte, len(data))
		copy(imgDec, data)
		stream, streamErr := s.getKeystreamPreferWASM(ctx, key, len(imgDec), reversed)
		if streamErr != nil {
			isaac := newISAAC64(seed)
			stream = isaac.generateKeystream(len(imgDec))
			if reversed {
				reverseBytes(stream)
			}
		}
		for i := range imgDec {
			imgDec[i] ^= stream[i]
		}
		imgMime := detectSNSMime(imgDec, "")
		if strings.HasPrefix(imgMime, "image/") {
			return imgDec, imgMime, nil
		}
	}

	// 再按视频头部窗口 XOR 尝试。
	videoDec := make([]byte, len(data))
	copy(videoDec, data)
	window := len(videoDec)
	if window > snsVideoDecryptWindow {
		window = snsVideoDecryptWindow
	}
	stream, streamErr := s.getKeystreamPreferWASM(ctx, key, window, true)
	if streamErr != nil {
		isaac := newISAAC64(seed)
		stream = isaac.generateKeystream(window)
		reverseBytes(stream)
	}
	for i := 0; i < window; i++ {
		videoDec[i] ^= stream[i]
	}
	videoMime := detectSNSMime(videoDec, "")
	if strings.HasPrefix(videoMime, "video/") {
		return videoDec, videoMime, nil
	}

	return nil, "", errors.QueryFailed("sns media decrypt failed", nil)
}

func (s *Service) getKeystreamPreferWASM(ctx context.Context, key string, size int, reverse bool) ([]byte, error) {
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("missing key")
	}
	mode := "raw"
	if reverse {
		mode = "reversed"
	}
	stream, err := s.getSNSWasmKeystream(ctx, key, size, mode)
	if err == nil && len(stream) == size {
		return stream, nil
	}
	return nil, err
}

func detectSNSMime(buf []byte, fallback string) string {
	if strict := detectSNSMimeStrict(buf); strict != "" {
		return strict
	}
	if strings.Contains(strings.ToLower(fallback), "image/") || strings.Contains(strings.ToLower(fallback), "video/") {
		return fallback
	}
	return "application/octet-stream"
}

func detectSNSMimeStrict(buf []byte) string {
	if len(buf) >= 3 && buf[0] == 0xff && buf[1] == 0xd8 && buf[2] == 0xff {
		return "image/jpeg"
	}
	if len(buf) >= 8 && buf[0] == 0x89 && buf[1] == 0x50 && buf[2] == 0x4e && buf[3] == 0x47 {
		return "image/png"
	}
	if len(buf) >= 6 && string(buf[:6]) == "GIF87a" || len(buf) >= 6 && string(buf[:6]) == "GIF89a" {
		return "image/gif"
	}
	if len(buf) >= 12 && string(buf[:4]) == "RIFF" && string(buf[8:12]) == "WEBP" {
		return "image/webp"
	}
	if len(buf) >= 12 && string(buf[4:8]) == "ftyp" {
		head := strings.ToLower(string(buf[8:minIntLocal(len(buf), 32)]))
		if strings.Contains(head, "heic") || strings.Contains(head, "heix") || strings.Contains(head, "hevc") || strings.Contains(head, "mif1") {
			return "image/heic"
		}
		return "video/mp4"
	}
	return ""
}

func fixSNSURL(rawURL, token string, isVideo bool) string {
	fixed := strings.TrimSpace(rawURL)
	if fixed == "" {
		return ""
	}
	fixed = strings.Replace(fixed, "http://", "https://", 1)
	if !isVideo {
		fixed = strings.ReplaceAll(fixed, "/150?", "/0?")
		if strings.HasSuffix(fixed, "/150") {
			fixed = strings.TrimSuffix(fixed, "/150") + "/0"
		}
	}
	if token == "" || strings.Contains(fixed, "token=") {
		return fixed
	}
	if isVideo {
		parts := strings.SplitN(fixed, "?", 2)
		if len(parts) == 2 {
			return parts[0] + "?token=" + url.QueryEscape(token) + "&idx=1&" + parts[1]
		}
		return fixed + "?token=" + url.QueryEscape(token) + "&idx=1"
	}
	connector := "?"
	if strings.Contains(fixed, "?") {
		connector = "&"
	}
	return fixed + connector + "token=" + url.QueryEscape(token) + "&idx=1"
}

func (s *Service) enrichSNSPostMedia(c *gin.Context, post *model.SNSPost) []gin.H {
	mediaEnabled := strings.TrimSpace(c.DefaultQuery("media", "1")) != "0"
	replace := strings.TrimSpace(c.DefaultQuery("replace", "1")) != "0"
	result := make([]gin.H, 0, len(post.MediaList))
	for _, media := range post.MediaList {
		isVideo := media.Type == "video"
		rawURL := fixSNSURL(media.URL, media.Token, isVideo)
		rawThumb := fixSNSURL(media.ThumbURL, media.Token, false)
		item := gin.H{
			"type":      media.Type,
			"url":       rawURL,
			"thumb":     rawThumb,
			"token":     media.Token,
			"key":       media.Key,
			"md5":       media.MD5,
			"enc_idx":   media.EncIdx,
			"width":     media.Width,
			"height":    media.Height,
			"duration":  media.Duration,
			"raw_url":   rawURL,
			"raw_thumb": rawThumb,
		}
		s.rememberSNSMediaKey(rawURL, media.Key)
		s.rememberSNSMediaKey(rawThumb, media.Key)
		if mediaEnabled {
			proxyURL := s.buildSNSMediaProxyURL(c, rawURL, media.Key)
			proxyThumb := s.buildSNSMediaProxyURL(c, rawThumb, media.Key)
			item["proxy_url"] = proxyURL
			item["proxy_thumb_url"] = proxyThumb
			item["resolved_url"] = proxyURL
			item["resolved_thumb_url"] = proxyThumb
			if replace {
				if proxyURL != "" {
					item["url"] = proxyURL
				}
				if proxyThumb != "" {
					item["thumb"] = proxyThumb
				}
			}
		}

		if media.LivePhoto != nil {
			liveURL := fixSNSURL(media.LivePhoto.URL, media.LivePhoto.Token, true)
			liveThumb := fixSNSURL(media.LivePhoto.ThumbURL, media.LivePhoto.Token, false)
			live := gin.H{
				"url":       liveURL,
				"thumb":     liveThumb,
				"token":     media.LivePhoto.Token,
				"key":       media.LivePhoto.Key,
				"enc_idx":   media.LivePhoto.EncIdx,
				"raw_url":   liveURL,
				"raw_thumb": liveThumb,
			}
			s.rememberSNSMediaKey(liveURL, media.LivePhoto.Key)
			s.rememberSNSMediaKey(liveThumb, media.LivePhoto.Key)
			if mediaEnabled {
				proxyURL := s.buildSNSMediaProxyURL(c, liveURL, media.LivePhoto.Key)
				proxyThumb := s.buildSNSMediaProxyURL(c, liveThumb, media.LivePhoto.Key)
				live["proxy_url"] = proxyURL
				live["proxy_thumb_url"] = proxyThumb
				live["resolved_url"] = proxyURL
				live["resolved_thumb_url"] = proxyThumb
				if replace {
					if proxyURL != "" {
						live["url"] = proxyURL
					}
					if proxyThumb != "" {
						live["thumb"] = proxyThumb
					}
				}
			}
			item["live_photo"] = live
		}

		result = append(result, item)
	}
	return result
}

func (s *Service) buildSNSMediaProxyURL(c *gin.Context, rawURL, key string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	params := url.Values{}
	params.Set("url", rawURL)
	if strings.TrimSpace(key) != "" {
		params.Set("key", key)
	}
	host := strings.TrimSpace(c.Request.Host)
	if host == "" {
		host = strings.TrimSpace(s.conf.GetHTTPAddr())
	}
	if host == "" {
		return ""
	}
	return "http://" + host + "/api/v1/sns/media/proxy?" + params.Encode()
}

func (s *Service) snsMediaCachePath(rawURL, key string) string {
	base := strings.TrimSpace(s.conf.GetWorkDir())
	if base == "" {
		base = strings.TrimSpace(s.conf.GetDataDir())
	}
	if base == "" {
		return ""
	}
	sum := md5.Sum([]byte(rawURL + "|" + key))
	return filepath.Join(base, ".chatlog_sns_cache", hex.EncodeToString(sum[:])+".bin")
}

func normalizeSNSMediaURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Fragment = ""
	return u.String()
}

func (s *Service) rememberSNSMediaKey(rawURL, key string) {
	key = strings.TrimSpace(key)
	if key == "" || key == "0" {
		return
	}
	normalized := normalizeSNSMediaURL(rawURL)
	if normalized == "" {
		return
	}
	s.snsMediaKeyMu.Lock()
	s.snsMediaKeyCache[normalized] = key
	s.snsMediaKeyMu.Unlock()
}

func (s *Service) getSNSMediaKeyFromCache(rawURL string) string {
	normalized := normalizeSNSMediaURL(rawURL)
	if normalized == "" {
		return ""
	}
	s.snsMediaKeyMu.RLock()
	key := strings.TrimSpace(s.snsMediaKeyCache[normalized])
	s.snsMediaKeyMu.RUnlock()
	return key
}

// isaac64 is a local fallback implementation aligned to the known
// WeChat Channels/SNS decryption behavior. The upstream reference
// prefers the official WASM path for exact compatibility.
type isaac64 struct {
	mm      [256]uint64
	randrsl [256]uint64
	aa      uint64
	bb      uint64
	cc      uint64
	randcnt int
}

func newISAAC64(seed uint64) *isaac64 {
	i := &isaac64{}
	i.randrsl[0] = seed
	i.init(true)
	return i
}

func (i *isaac64) init(flag bool) {
	const golden uint64 = 0x9e3779b97f4a7c15
	a, b, c, d := golden, golden, golden, golden
	e, f, g, h := golden, golden, golden, golden
	mix := func() {
		a -= e
		f ^= h >> 9
		h += a
		b -= f
		g ^= a << 9
		a += b
		c -= g
		h ^= b >> 23
		b += c
		d -= h
		a ^= c << 15
		c += d
		e -= a
		b ^= d >> 14
		d += e
		f -= b
		c ^= e << 20
		e += f
		g -= c
		d ^= f >> 17
		f += g
		h -= d
		e ^= g << 14
		g += h
	}
	for n := 0; n < 4; n++ {
		mix()
	}
	for idx := 0; idx < 256; idx += 8 {
		if flag {
			a += i.randrsl[idx]
			b += i.randrsl[idx+1]
			c += i.randrsl[idx+2]
			d += i.randrsl[idx+3]
			e += i.randrsl[idx+4]
			f += i.randrsl[idx+5]
			g += i.randrsl[idx+6]
			h += i.randrsl[idx+7]
		}
		mix()
		i.mm[idx], i.mm[idx+1], i.mm[idx+2], i.mm[idx+3] = a, b, c, d
		i.mm[idx+4], i.mm[idx+5], i.mm[idx+6], i.mm[idx+7] = e, f, g, h
	}
	if flag {
		for idx := 0; idx < 256; idx += 8 {
			a += i.mm[idx]
			b += i.mm[idx+1]
			c += i.mm[idx+2]
			d += i.mm[idx+3]
			e += i.mm[idx+4]
			f += i.mm[idx+5]
			g += i.mm[idx+6]
			h += i.mm[idx+7]
			mix()
			i.mm[idx], i.mm[idx+1], i.mm[idx+2], i.mm[idx+3] = a, b, c, d
			i.mm[idx+4], i.mm[idx+5], i.mm[idx+6], i.mm[idx+7] = e, f, g, h
		}
	}
	i.isaac()
	i.randcnt = 256
}

func (i *isaac64) isaac() {
	i.cc++
	i.bb += i.cc
	for idx := 0; idx < 256; idx++ {
		x := i.mm[idx]
		switch idx & 3 {
		case 0:
			i.aa ^= (i.aa << 21) ^ ^uint64(0)
		case 1:
			i.aa ^= i.aa >> 5
		case 2:
			i.aa ^= i.aa << 12
		case 3:
			i.aa ^= i.aa >> 33
		}
		i.aa += i.mm[(idx+128)&255]
		y := i.mm[(x>>3)&255] + i.aa + i.bb
		i.mm[idx] = y
		i.bb = i.mm[(y>>11)&255] + x
		i.randrsl[idx] = i.bb
	}
}

func (i *isaac64) next() uint64 {
	if i.randcnt == 0 {
		i.isaac()
		i.randcnt = 256
	}
	i.randcnt--
	return i.randrsl[i.randcnt]
}

func (i *isaac64) generateKeystream(size int) []byte {
	out := make([]byte, size)
	fullBlocks := size / 8
	for block := 0; block < fullBlocks; block++ {
		v := i.next()
		base := block * 8
		out[base+0] = byte(v >> 56)
		out[base+1] = byte(v >> 48)
		out[base+2] = byte(v >> 40)
		out[base+3] = byte(v >> 32)
		out[base+4] = byte(v >> 24)
		out[base+5] = byte(v >> 16)
		out[base+6] = byte(v >> 8)
		out[base+7] = byte(v)
	}
	if rem := size % 8; rem > 0 {
		v := i.next()
		base := fullBlocks * 8
		tmp := [8]byte{
			byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
		}
		copy(out[base:], tmp[:rem])
	}
	return out
}

func reverseBytes(buf []byte) {
	for left, right := 0, len(buf)-1; left < right; left, right = left+1, right-1 {
		buf[left], buf[right] = buf[right], buf[left]
	}
}

func minIntLocal(a, b int) int {
	if a < b {
		return a
	}
	return b
}
