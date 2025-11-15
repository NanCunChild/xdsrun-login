// main.go
package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	acID         = "8"
	customB64ABC = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)

var servers = []string{"https://w.xidian.edu.cn", "https://10.255.44.33"}

// ================================================================================= //
//                                    主程序入口                                      //
// ================================================================================= //

func main() {
	usernameFlag := flag.String("u", "", "您的账号 (学号)")
	passwordFlag := flag.String("p", "", "您的校园网密码")
	domainFlag := flag.String("d", "", "运营商后缀, 如 @dx, @lt, @yd (默认为校园网)")
	statusFlag := flag.Bool("s", false, "查询在线状态 (此模式下无需-u和-p)")
	timeoutFlag := flag.Int("to", 10, "超时时间(秒)") // 考虑是否需要
	flag.Parse()

	client := createClient(true)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutFlag)*time.Second)
	defer cancel()

	// 如果带有 -s 参数，则执行状态查询
	if *statusFlag {
		checkStatus(ctx, client)
	} else {
		// 检查登录模式下参数是否完整
		if *usernameFlag == "" || *passwordFlag == "" {
			fmt.Println("错误: 登录模式下必须提供 -u (账号) 和 -p (密码) 参数。")
			fmt.Println("用法示例: ./xdsrun -u 你的学号 -p '你的密码'")
			os.Exit(1)
		}
		performLogin(ctx, client, *usernameFlag, *passwordFlag, *domainFlag)
	}
}

func createClient(skipVerify bool) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipVerify,
		},
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
}

// ================================================================================= //
//                                 主要业务流程                                      //
// ================================================================================= //

// performLogin 执行完整的登录流程
func performLogin(ctx context.Context, client *http.Client, username, password, domain string) {
	fullUsername := username + domain
	type result struct {
		host   string
		userIP string
		err    error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(servers))

	for _, host := range servers {
		go func(host string) {
			select {
			case <-ctx.Done():
				results <- result{host: host, err: ctx.Err()}
				return
			default:
			}

			userIP, err := getIpAddress(ctx, client, host)
			if err != nil {
				results <- result{host: host, err: err}
				return
			}
			token, err := getChallengeToken(ctx, client, host, userIP, fullUsername)
			if err != nil {
				results <- result{host: host, err: err}
				return
			}
			hmd5 := calculateHmacMD5(password, token)
			info := encodeUserInfo(userIP, fullUsername, password, token)
			chksum := calculateChecksum(token, userIP, hmd5, info, fullUsername)
			err = finalLogin(ctx, client, host, userIP, hmd5, info, chksum, fullUsername)
			results <- result{host: host, userIP: userIP, err: err}
		}(host)
	}

	successFound := false
	for i := 0; i < len(servers); i++ {
		r := <-results
		if r.err == nil && !successFound {
			fmt.Printf("[OK] 登录到 %q 成功！ IP %q 目前已授权！\n", r.host, r.userIP)
			cancel()
			return
		} else {
			fmt.Printf("host %s failed: %v\n", r.host, r.err)
		}
	}

	fmt.Println("错误: 所有服务器均尝试失败，请检查网络。")
}

// checkStatus 执行在线状态查询流程
func checkStatus(ctx context.Context, client *http.Client) {
	var success bool
	for _, host := range servers {
		fmt.Printf("正在尝试连接服务器: %s ...\n", host)

		userIP, err := getIpAddress(ctx, client, host)
		if err != nil {
			fmt.Printf("从 %s 获取IP失败: %v\n", host, err)
			continue
		}

		// 构造查询URL
		callback := fmt.Sprintf("jQuery11240%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000)
		apiURL := fmt.Sprintf("%s/cgi-bin/rad_user_info?callback=%s&ip=%s&_=%d", host, callback, userIP, time.Now().UnixMilli())

		respBody, err := makeRequest(ctx, client, apiURL)
		if err != nil {
			fmt.Printf("向 %s 查询状态失败: %v\n", host, err)
			continue
		}

		// 解析JSONP响应
		jsonStr := strings.TrimPrefix(string(respBody), callback+"(")
		jsonStr = strings.TrimSuffix(jsonStr, ")")

		var statusInfo map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &statusInfo); err != nil {
			fmt.Printf("解析来自 %s 的状态信息失败: %v\n", host, err)
			continue
		}

		// 检查并打印状态
		if errStr, ok := statusInfo["error"].(string); ok && errStr == "ok" {
			fmt.Println("--- 当前在线状态 ---")
			fmt.Printf("账号: %v\n", statusInfo["user_name"])
			fmt.Printf("姓名: %v\n", statusInfo["real_name"])
			fmt.Printf("已用流量: %.2f MB\n", statusInfo["sum_bytes"].(float64)/(1024*1024))
			fmt.Printf("已用时长: %.2f 分钟\n", statusInfo["sum_seconds"].(float64)/60)
			fmt.Printf("账户余额: %.2f\n", statusInfo["user_balance"].(float64))
			fmt.Printf("当前IP: %v\n", statusInfo["online_ip"])
			fmt.Println("--------------------")
		} else {
			fmt.Printf("当前未登录或状态异常。服务器消息: %v\n", statusInfo["error_msg"])
		}

		success = true
		break
	}
	if !success {
		log.Fatal("错误: 所有服务器均尝试失败，请检查是否已正确连接到校园网。")
	}
}

// ================================================================================= //
//                            核心认证与加密函数 (已验证)                            //
// ================================================================================= //

func getIpAddress(ctx context.Context, client *http.Client, host string) (string, error) {
	body, err := makeRequest(ctx, client, host+"/srun_portal_pc?ac_id="+acID)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`ip\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return "", errors.New("在页面中未找到 IP 地址")
	}
	return matches[1], nil
}

func getChallengeToken(ctx context.Context, client *http.Client, host, userIP, fullUsername string) (string, error) {
	callback := fmt.Sprintf("jQuery11240%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000)
	apiURL := fmt.Sprintf("%s/cgi-bin/get_challenge?callback=%s&username=%s&ip=%s&_=%d",
		host, callback, url.QueryEscape(fullUsername), userIP, time.Now().UnixMilli())
	body, err := makeRequest(ctx, client, apiURL)
	if err != nil {
		return "", err
	}

	jsonStr := strings.TrimPrefix(string(body), callback+"(")
	jsonStr = strings.TrimSuffix(jsonStr, ")")

	var res struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &res); err != nil {
		return "", fmt.Errorf("解析JSON失败: %w", err)
	}
	if res.Challenge == "" {
		return "", errors.New("获取到的 challenge 为空")
	}
	return res.Challenge, nil
}

func finalLogin(ctx context.Context, client *http.Client, host, userIP, hmd5, info, chksum, fullUsername string) error {
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

	finalURL := host + "/cgi-bin/srun_portal?" + params.Encode()
	body, err := makeRequest(ctx, client, finalURL)
	if err != nil {
		return err
	}

	if !strings.Contains(string(body), "\"error\":\"ok\"") && !strings.Contains(string(body), "\"suc_msg\":\"login_ok\"") {
		return fmt.Errorf("登录失败，服务器响应: %s", string(body))
	}
	return nil
}

func calculateHmacMD5(data, key string) string {
	h := hmac.New(md5.New, []byte(key))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func encodeUserInfo(userIP, fullUsername, password, token string) string {
	userInfo := map[string]string{
		"username": fullUsername,
		"password": password,
		"ip":       userIP,
		"acid":     acID,
		"enc_ver":  "srun_bx1",
	}
	jsonData, _ := json.Marshal(userInfo)
	encryptedData := srunXXTEAEncrypt(string(jsonData), token)
	customEncoder := base64.NewEncoding(customB64ABC)
	b64EncodedData := customEncoder.EncodeToString(encryptedData)
	return "{SRBX1}" + b64EncodedData
}

func calculateChecksum(token, userIP, hmd5, info string, fullUsername string) string {
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
	h := sha1.New()
	h.Write([]byte(builder.String()))
	return hex.EncodeToString(h.Sum(nil))
}

// 西电深澜系统使用了魔改的XXTEA加密
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
	z, y, delta, q := v[n], v[0], uint32(0x9E3779B9), 6+52/(n+1)
	var sum uint32 = 0
	for q > 0 {
		sum += delta
		e := (sum >> 2) & 3
		var p uint32
		for p = 0; p < n; p++ {
			y = v[p+1]
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
func s(data string, includeLength bool) []uint32 {
	n := len(data)
	paddedData := []byte(data)
	if n%4 != 0 {
		paddedData = append(paddedData, make([]byte, 4-n%4)...)
	}
	v := make([]uint32, len(paddedData)/4)
	for i := 0; i < len(paddedData); i += 4 {
		v[i>>2] = uint32(paddedData[i]) | uint32(paddedData[i+1])<<8 | uint32(paddedData[i+2])<<16 | uint32(paddedData[i+3])<<24
	}
	if includeLength {
		v = append(v, uint32(n))
	}
	return v
}
func l(data []uint32) string {
	byteData := make([]byte, len(data)*4)
	for i, val := range data {
		byteData[i*4+0] = byte(val & 0xff)
		byteData[i*4+1] = byte(val >> 8 & 0xff)
		byteData[i*4+2] = byte(val >> 16 & 0xff)
		byteData[i*4+3] = byte(val >> 24 & 0xff)
	}
	return string(byteData)
}

// ================================================================================= //
//                                    辅助工具函数                                     //
// ================================================================================= //

func makeRequest(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("服务器返回非 200 状态码: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
