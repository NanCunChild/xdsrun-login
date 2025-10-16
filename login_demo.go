// main.go
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// --- 请在这里配置你的信息 ---
const (
	username     = "23009100014" // 你的学号
	password     = "300910"      // 你的校园网密码
	domain       = ""            // 运营商后缀, 校园网为空"", 电信"@dx", 联通"@lt", 移动"@yd"
	portalHost   = "https://w.xidian.edu.cn"
	acID         = "8"
	customB64ABC = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)

// --- 程序主要逻辑 ---
func main() {
	fmt.Println("=== 深澜校园网认证流程 [终极调试版] ===")
	fmt.Println("将分步执行，并打印详细网络日志...")

	fullUsername := username + domain
	fmt.Printf("\n[配置检查] 使用的完整用户名: '%s'\n", fullUsername)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	waitForEnter()
	userIP := getIpAddress(client)
	fmt.Printf("[结果] 步骤 1: 成功获取内网 IP: %s\n", userIP)

	waitForEnter()
	token := getChallengeToken(client, userIP, fullUsername)
	fmt.Printf("[结果] 步骤 2: 成功获取 Token (Challenge): %s\n", token)

	waitForEnter()
	hmd5 := calculateHmacMD5(password, token)
	fmt.Printf("[结果] 步骤 3: 计算 HMAC-MD5 完成: %s\n", hmd5)

	waitForEnter()
	info := encodeUserInfo(userIP, token, fullUsername)
	fmt.Printf("[结果] 步骤 4: 加密生成 info 字段完成: %s...\n", info[:50])

	waitForEnter()
	chksum := calculateChecksum(token, userIP, hmd5, info, fullUsername)
	fmt.Printf("[结果] 步骤 5: 计算 SHA1 chksum 完成: %s\n", chksum)

	waitForEnter()
	fmt.Println("\n--- 步骤 6: 发起最终登录请求 ---")
	finalLogin(client, userIP, token, hmd5, info, chksum, fullUsername)
}

// ================================================================================= //
//                            魔改版 XXTEA 核心实现 (JS翻译)                           //
// ================================================================================= //

// s 函数将字符串转为 uint32 切片 (little-endian)
func s(data string, includeLength bool) []uint32 {
	n := len(data)
	// 用空字节填充，确保长度是4的倍数
	paddedData := []byte(data)
	if n%4 != 0 {
		paddedData = append(paddedData, make([]byte, 4-n%4)...)
	}

	v := make([]uint32, len(paddedData)/4)
	for i := 0; i < len(paddedData); i += 4 {
		v[i>>2] = uint32(paddedData[i]) |
			uint32(paddedData[i+1])<<8 |
			uint32(paddedData[i+2])<<16 |
			uint32(paddedData[i+3])<<24
	}

	if includeLength {
		v = append(v, uint32(n))
	}
	return v
}

// l 函数将 uint32 切片转回字符串
func l(data []uint32) string {
	byteData := make([]byte, len(data)*4)
	for i := 0; i < len(data); i++ {
		byteData[i*4+0] = byte(data[i] & 0xff)
		byteData[i*4+1] = byte(data[i] >> 8 & 0xff)
		byteData[i*4+2] = byte(data[i] >> 16 & 0xff)
		byteData[i*4+3] = byte(data[i] >> 24 & 0xff)
	}
	return string(byteData)
}

// srunXXTEAEncrypt 实现了JS代码中魔改的XXTEA加密算法
func srunXXTEAEncrypt(data string, key string) []byte {
	v := s(data, true)
	k := s(key, false)

	if len(k) < 4 {
		k = append(k, make([]uint32, 4-len(k))...)
	}

	n := uint32(len(v) - 1)
	if n < 1 {
		return []byte(l(v))
	}

	z := v[n]
	y := v[0]
	delta := uint32(0x9E3779B9) // TEA算法标准魔数
	q := 6 + 52/(n+1)
	var sum uint32 = 0

	for q > 0 {
		sum += delta
		e := (sum >> 2) & 3
		var p uint32
		for p = 0; p < n; p++ {
			y = v[p+1]
			// 这是与标准XXTEA不同的魔改MX函数
			m := (z>>5 ^ y<<2) + (y>>3 ^ z<<4 ^ (sum ^ y)) + (k[(p&3)^e] ^ z)
			v[p] += m
			z = v[p]
		}
		y = v[0]
		m := (z>>5 ^ y<<2) + (y>>3 ^ z<<4 ^ (sum ^ y)) + (k[(p&3)^e] ^ z)
		v[n] += m
		z = v[n]
		q--
	}

	return []byte(l(v))
}

// ================================================================================= //
//                             各认证步骤的实现函数                                   //
// ================================================================================= //

func getIpAddress(client *http.Client) string {
	fmt.Println("\n--- 步骤 1: 获取 IP 地址 ---")
	req, _ := http.NewRequest("GET", portalHost+"/srun_portal_pc?ac_id="+acID, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	printRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("步骤 1 请求失败: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("步骤 1 读取响应失败: %v", err)
	}
	printResponse(resp, bodyBytes)

	re := regexp.MustCompile(`ip\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"`)
	matches := re.FindStringSubmatch(string(bodyBytes))
	if len(matches) < 2 {
		log.Fatalf("步骤 1 在页面中未找到 IP 地址")
	}
	return matches[1]
}

func getChallengeToken(client *http.Client, userIP string, fullUsername string) string {
	fmt.Println("\n--- 步骤 2: 获取 Token (Challenge) ---")

	callback := fmt.Sprintf("jQuery11240%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000)
	apiURL := fmt.Sprintf("%s/cgi-bin/get_challenge?callback=%s&username=%s&ip=%s&_=%d", portalHost, callback, url.QueryEscape(fullUsername), userIP, time.Now().UnixMilli())

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	printRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("步骤 2 请求失败: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("步骤 2 读取响应失败: %v", err)
	}
	printResponse(resp, bodyBytes)

	jsonStr := string(bodyBytes)
	jsonStr = strings.TrimPrefix(jsonStr, callback+"(")
	jsonStr = strings.TrimSuffix(jsonStr, ")")

	var challengeResponse struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &challengeResponse); err != nil {
		log.Fatalf("步骤 2 解析 JSON 失败: %v", err)
	}
	if challengeResponse.Challenge == "" {
		log.Fatalf("步骤 2 获取到的 challenge 为空！")
	}
	return challengeResponse.Challenge
}

func calculateHmacMD5(data, key string) string {
	fmt.Println("\n--- 步骤 3: 计算 HMAC-MD5 ---")
	h := hmac.New(md5.New, []byte(key))
	h.Write([]byte(data))
	result := hex.EncodeToString(h.Sum(nil))
	fmt.Printf("[调试] HMAC-MD5 输入: (数据: '%s', 密钥: '%s')\n", data, key)
	return result
}

func encodeUserInfo(userIP, token string, fullUsername string) string {
	fmt.Println("\n--- 步骤 4: 使用魔改 XXTEA 加密 info 字段 ---")
	userInfo := map[string]string{
		"username": fullUsername,
		"password": password,
		"ip":       userIP,
		"acid":     acID,
		"enc_ver":  "srun_bx1",
	}
	jsonData, err := json.Marshal(userInfo)
	if err != nil {
		log.Fatalf("步骤 4 JSON 序列化失败: %v", err)
	}
	fmt.Printf("[调试] 待加密的JSON: %s\n", string(jsonData))
	fmt.Printf("[调试] 使用的密钥 (Token): %s\n", token)

	encryptedData := srunXXTEAEncrypt(string(jsonData), token)
	fmt.Printf("[调试] XXTEA 输出 (原始字节): %x\n", encryptedData)

	customEncoder := base64.NewEncoding(customB64ABC)
	b64EncodedData := customEncoder.EncodeToString(encryptedData)
	fmt.Printf("[调试] 自定义Base64编码后: %s\n", b64EncodedData)

	return "{SRBX1}" + b64EncodedData
}

func calculateChecksum(token, userIP, hmd5, info string, fullUsername string) string {
	fmt.Println("\n--- 步骤 5: 计算 SHA1 chksum ---")
	var builder strings.Builder
	builder.WriteString(token)
	builder.WriteString(fullUsername)
	builder.WriteString(token)
	builder.WriteString(hmd5)
	builder.WriteString(token)
	builder.WriteString(acID)
	builder.WriteString(token)
	builder.WriteString(userIP)
	builder.WriteString(token)
	builder.WriteString("200")
	builder.WriteString(token)
	builder.WriteString("1")
	builder.WriteString(token)
	builder.WriteString(info)

	longStr := builder.String()
	fmt.Printf("[调试] 用于计算SHA1的长字符串 (截断显示): %.80s...\n", longStr)

	h := sha1.New()
	h.Write([]byte(longStr))
	return hex.EncodeToString(h.Sum(nil))
}

func finalLogin(client *http.Client, userIP, token, hmd5, info, chksum string, fullUsername string) {
	params := url.Values{}
	params.Set("callback", fmt.Sprintf("jQuery11240%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000))
	params.Set("action", "login")
	params.Set("username", fullUsername)
	params.Set("password", "{MD5}"+hmd5)
	params.Set("os", "Windows 10")
	params.Set("name", "Windows")
	params.Set("double_stack", "0")
	params.Set("chksum", chksum)
	params.Set("info", info)
	params.Set("ac_id", acID)
	params.Set("ip", userIP)
	params.Set("n", "200")
	params.Set("type", "1")
	params.Set("_", fmt.Sprintf("%d", time.Now().UnixMilli()))

	finalURL := portalHost + "/cgi-bin/srun_portal?" + params.Encode()
	req, _ := http.NewRequest("GET", finalURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	printRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("步骤 6 请求失败: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("步骤 6 读取响应失败: %v", err)
	}

	printResponse(resp, bodyBytes)
	fmt.Println("\n🎉 验证流程执行完毕！请检查最后一步的响应是否包含 'error\":\"ok' 或 'suc_msg'。")
}

// ================================================================================= //
//                                 辅助调试函数                                      //
// ================================================================================= //

func waitForEnter() {
	fmt.Print("\n>>> 按 Enter 进入下一步...\n")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func printRequest(req *http.Request) {
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		log.Println("无法Dump请求:", err)
		return
	}
	fmt.Println("---------- 发送请求 ----------")
	fmt.Println(string(dump))
	fmt.Println("-----------------------------")
}

func printResponse(resp *http.Response, body []byte) {
	dump, err := httputil.DumpResponse(resp, false) // false表示不包含body
	if err != nil {
		log.Println("无法Dump响应:", err)
		return
	}
	fmt.Println("---------- 收到响应 ----------")
	fmt.Println(string(dump))
	fmt.Println("--- 响应体 ---")
	fmt.Println(string(body))
	fmt.Println("-----------------------------")
}
