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
	"io"
	"io/ioutil"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"encoding/base64"
	"strconv"

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

/*
 Parse Authorization header from the http.Request. Returns a map of
 auth parameters or nil if the header is not a valid parsable Digest
 auth header.
*/
func DigestAuthParams(r *http.Response) map[string]string {
	s := strings.SplitN(r.Header.Get("Www-Authenticate"), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	result := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.Trim(parts[0], "\" ")] = strings.Trim(parts[1], "\" ")
	}
	return result
}
func RandomKey() string {
	k := make([]byte, 45)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}

/*
 H function for MD5 algorithm (returns a lower-case hex MD5 digest)
*/
func H(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return hex.EncodeToString(digest.Sum(nil))
}

func getAuthHeader(username, password string, resp *http.Response) (string) {
	var authorization map[string]string = DigestAuthParams(resp)
	realmHeader := authorization["realm"]
	qopHeader := authorization["qop"]
	nonceHeader := authorization["nonce"]
	//opaqueHeader := authorization["opaque"]
	algorithm := authorization["algorithm"]
	realm := realmHeader
	// A1
	h := md5.New()
	A1 := fmt.Sprintf("%s:%s:%s", username, realm, password)
	io.WriteString(h, A1)
	HA1 := hex.EncodeToString(h.Sum(nil))

	// A2
	h = md5.New()
	A2 := fmt.Sprintf("POST:%s", "/json_rpc")
	io.WriteString(h, A2)
	HA2 := hex.EncodeToString(h.Sum(nil))
	nc := "00000001"
	// response
	cnonce := RandomKey()
	response := H(strings.Join([]string{HA1, nonceHeader, nc, cnonce, qopHeader, HA2}, ":"))

	// now make header
	AuthHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=%s, nc=%s, cnonce="%s", algorithm="%s"`,
		username, realmHeader, nonceHeader, "/json_rpc", response, qopHeader, nc, cnonce, algorithm)
	return AuthHeader
}

func (r *RPCClient) doPost(url, method string, params interface{}) (*JSONRpcResp, error) {
	jsonReq := map[string]interface{}{"jsonrpc": "2.0", "id": 0, "method": method, "params": params}
	data, _ := json.Marshal(jsonReq)
	req1, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req1.Header.Set("Content-Length", strconv.Itoa(len(data)))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Accept", "application/json")
	resp1, err := r.client.Do(req1)
	io.Copy(ioutil.Discard, resp1.Body)
	resp1.Body.Close()
	authHeader := getAuthHeader(r.login, r.password, resp1)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Set("Content-Length", strconv.Itoa(len(data)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	req.Header.Set("Authorization", authHeader)
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
