package rpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"

	"github.com/sammy007/monero-stratum/pool"
)

type RPCClient struct {
	sync.RWMutex
	sickRate         int64
	successRate      int64
	Accepts          int64
	Rejects          int64
	LastSubmissionAt int64
	FailsCount       int64
	Url              *url.URL
	login            string
	password         string
	Name             string
	sick             bool
	client           *http.Client
}

type GetBlockTemplateReply struct {
	Blob           string `json:"blocktemplate_blob"`
	Difficulty     int64  `json:"difficulty"`
	ReservedOffset int    `json:"reserved_offset"`
	Height         int64  `json:"height"`
	PrevHash       string `json:"prev_hash"`
}

type JSONRpcResp struct {
	Id     *json.RawMessage       `json:"id"`
	Result *json.RawMessage       `json:"result"`
	Error  map[string]interface{} `json:"error"`
}

func NewRPCClient(cfg *pool.Upstream) (*RPCClient, error) {
	rawUrl := fmt.Sprintf("http://%s:%v/json_rpc", cfg.Host, cfg.Port)
	url, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	rpcClient := &RPCClient{Name: cfg.Name, Url: url, login: cfg.Login, password: cfg.Password}
	timeout, _ := time.ParseDuration(cfg.Timeout)
	rpcClient.client = &http.Client{
		Timeout: timeout,
	}
	return rpcClient, nil
}

func (r *RPCClient) GetBlockTemplate(reserveSize int, address string) (*GetBlockTemplateReply, error) {
	params := map[string]interface{}{"reserve_size": reserveSize, "wallet_address": address}
	rpcResp, err := r.doPost(r.Url.String(), "getblocktemplate", params)
	var reply *GetBlockTemplateReply
	if err != nil {
		return nil, err
	}
	if rpcResp.Result != nil {
		err = json.Unmarshal(*rpcResp.Result, &reply)
	}
	return reply, err
}

func (r *RPCClient) SubmitBlock(hash string) (*JSONRpcResp, error) {
	return r.doPost(r.Url.String(), "submitblock", []string{hash})
}

func digestParts(resp *http.Response) map[string]string {
	result := map[string]string{}
	if len(resp.Header["Www-Authenticate"]) > 0 {
		wantedHeaders := []string{"nonce", "realm", "qop"}
		responseHeaders := strings.Split(resp.Header["Www-Authenticate"][0], ",")
		for _, r := range responseHeaders {
			for _, w := range wantedHeaders {
				if strings.Contains(r, w) {
					result[w] = strings.Split(r, `"`)[1]
				}
			}
		}
	}
	return result
}

func getMD5(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getCnonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)[:16]
}

func getDigestAuthrization(digestParts map[string]string) string {
	d := digestParts
	ha1 := getMD5(d["username"] + ":" + d["realm"] + ":" + d["password"])
	ha2 := getMD5(d["method"] + ":" + d["uri"])
	nonceCount := 00000001
	cnonce := getCnonce()
	response := getMD5(fmt.Sprintf("%s:%s:%v:%s:%s:%s", ha1, d["nonce"], nonceCount, cnonce, d["qop"], ha2))
	authorization := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc="%v", qop="%s", response="%s"`,
		d["username"], d["realm"], d["nonce"], d["uri"], cnonce, nonceCount, d["qop"], response)
	return authorization
}

func (r *RPCClient) doPost(url, method string, params interface{}) (*JSONRpcResp, error) {
	jsonReq := map[string]interface{}{"jsonrpc": "2.0", "id": 0, "method": method, "params": params}
	data, _ := json.Marshal(jsonReq)

	req1, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req1.Header.Set("Content-Length", (string)(len(data)))
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := r.client.Do(req1)
	defer resp1.Body.Close()

	digestParts := digestParts(resp1)
	digestParts["uri"] = url
	digestParts["method"] = "POST"
	digestParts["username"] = r.login
	digestParts["password"] = r.password
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Set("Content-Length", (string)(len(data)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", getDigestAuthrization(digestParts))

	resp, err := r.client.Do(req)
	if err != nil {
		r.markSick()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, errors.New(resp.Status)
	}

	var rpcResp *JSONRpcResp
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	if err != nil {
		r.markSick()
		return nil, err
	}
	if rpcResp.Error != nil {
		r.markSick()
		return nil, errors.New(rpcResp.Error["message"].(string))
	}
	return rpcResp, err
}

func (r *RPCClient) Check(reserveSize int, address string) (bool, error) {
	_, err := r.GetBlockTemplate(reserveSize, address)
	if err != nil {
		return false, err
	}
	r.markAlive()
	return !r.Sick(), nil
}

func (r *RPCClient) Sick() bool {
	r.RLock()
	defer r.RUnlock()
	return r.sick
}

func (r *RPCClient) markSick() {
	r.Lock()
	if !r.sick {
		atomic.AddInt64(&r.FailsCount, 1)
	}
	r.sickRate++
	r.successRate = 0
	if r.sickRate >= 5 {
		r.sick = true
	}
	r.Unlock()
}

func (r *RPCClient) markAlive() {
	r.Lock()
	r.successRate++
	if r.successRate >= 5 {
		r.sick = false
		r.sickRate = 0
		r.successRate = 0
	}
	r.Unlock()
}
