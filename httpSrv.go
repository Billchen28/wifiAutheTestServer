
package main;
    
/**
 * wifi中间商合作服务端测试程序
 * @author jiubiaochen
 *
 */

    import (
        "net/http"
            "bytes"
            "crypto/aes"
            "crypto/cipher"
            "encoding/base64"
            "fmt"
            "io/ioutil"
            "net/url"
            "encoding/json"
            "strings"
            "strconv"
    )

    var (
        gNeedAuthe = true//全局标记当前是否返回需要认证
        gNetworkOk = true//网络是否可用
        gKey = "0123456789abcdef0123456789abcd12"//中间商合作认证的加密密钥
        gProtalBody = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>mmgr</title></head><body><h1>mmgr</h1></body></html>"
        gNetworkOkBody = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>mmgr</title></head><body><h1>not need Authe.</h1></body></html>"
    )
    
    /**
    处理鉴权请求
    **/
    func say(w http.ResponseWriter, req *http.Request) {
        if req.Method == "POST" {
            result, _:= ioutil.ReadAll(req.Body)
            req.Body.Close()
            fmt.Printf("%s\n", result)
            valueTable,_ := url.ParseQuery(string(result));
            params := valueTable["params"]//解释拿到鉴权参数
            if params != nil {
                respont := proceParams(string(params[0]))//根据鉴权参数进行处理
                if respont != nil {
                     w.Write(respont)
                 } else {
                    w.Write([]byte("proceParams fail."))
                 }
            } else {
                w.Write([]byte("params not FOUND."))
            }
        } else {
            w.Write([]byte("only support POST method."))
        }
    }

    func normal(w http.ResponseWriter, req *http.Request) {
         w.Write([]byte(gNetworkOkBody))
    }

    func reset(w http.ResponseWriter, req *http.Request) {
        gNeedAuthe = true
        w.Write([]byte("reset finish."))
    }

    func networkcheck(w http.ResponseWriter, req *http.Request) {
        if gNeedAuthe {
            http.Redirect(w, req, "/wifiprotal", 302)
        } else {
            if gNetworkOk {
                normal(w, req);
            } else {
                http.Error(w, "network not avilable", 500)
            }
            
        }  
    }

//鉴权处理函数
    func proceParams(params string) []byte {
        data, _ := base64.StdEncoding.DecodeString(params)
        if data != nil {
            //解密
            desc := AesDecrypt(data, []byte(gKey))
             if desc != nil {
                var f interface{}
                json.Unmarshal(desc, &f)//
                m := f.(map[string]interface{})
                for k, v := range m {
                switch vv := v.(type) {
                    case string:
                        fmt.Println(k, "is string", vv)
                    case int:
                        fmt.Println(k, "is int", vv)
                    case float64:
                        fmt.Println(k,"is float64",vv)
                    case []interface{}:
                        fmt.Println(k, "is an array:")
                        for i, u := range vv {
                            fmt.Println(i, u)
                        }
                    default:
                        fmt.Println(k, "is of a type I don't know how to handle")
                    }
                }
                session_id := m["session_id"]
                if session_id != nil {
                   return getResponeData(1, session_id.(float64), "http://m.qq.com")
                }
             }
        }
        return nil
    }

    func getResponeData(api_code float64, session_id float64, ad_url string) []byte {
        result := make(map[string]interface{})
        result["api_code"] = api_code
        result["session_id"] = session_id
        result["ad_url"] = ad_url
        b, _ := json.Marshal(result)
        crypted := AesEncrypt(string(b), gKey)
        gNeedAuthe = false;
        return []byte(base64.StdEncoding.EncodeToString(crypted))
    }

    func config(w http.ResponseWriter, req *http.Request) {
        valueTable,_ := url.ParseQuery(req.RequestURI)
        key := valueTable["key"]
        var buffer bytes.Buffer
        if key != nil && len(key[0]) == 32 {
            buffer.WriteString("key=")
            gKey = key[0]
            buffer.WriteString(gKey)
        } else if key != nil && len(key) > 0 {
            buffer.WriteString("key=")
            gKey = key[0]
            buffer.WriteString(gKey)
            buffer.WriteString(" is not legal")
            buffer.WriteString(strconv.Itoa(len(gKey)))
        }
        buffer.WriteString("\n")
        protalbody := valueTable["protalbody"]
        if protalbody != nil && len(protalbody) > 0 {
            buffer.WriteString("protalbody=")
            v,_ := url.QueryUnescape(protalbody[0])
            gProtalBody = v
            buffer.WriteString(gProtalBody)
        }
        buffer.WriteString("\n")
        networkokbody := valueTable["networkokbody"]
        if networkokbody != nil && len(networkokbody) > 0 {
            buffer.WriteString("networkokbody=")
            v,_ := url.QueryUnescape(networkokbody[0])
            gNetworkOkBody = v
            buffer.WriteString(gNetworkOkBody)
        }
        buffer.WriteString("\n")
        networkok := valueTable["networkok"]
        if networkok != nil && len(networkok) > 0 {
            buffer.WriteString("networkok=")
            networkok_val := networkok[0]
            if strings.Compare(networkok_val, "true") == 0 {
                gNetworkOk = true
            } else {
                gNetworkOk = false
            }
            buffer.WriteString(networkok_val)
        }
        buffer.WriteString("\n")
        needProtal := valueTable["needprotal"]
        if needProtal != nil && len(needProtal) > 0 {
            buffer.WriteString("needProtal=")
            needProtal_val := needProtal[0]
            if strings.Compare(needProtal_val, "true") == 0 {
                gNeedAuthe = true
            } else {
                gNeedAuthe = false
            }
            buffer.WriteString(needProtal_val)
        }
        buffer.WriteString("\n")
        w.Write(buffer.Bytes())
    }

    func setnetwork(w http.ResponseWriter, req *http.Request) {
        gNeedAuthe = false;
        w.Write([]byte("reset finish."))
    }

    func wifiprotal(w http.ResponseWriter, req *http.Request) {
        fmt.Println("wifiprotal")
        fmt.Println(gProtalBody)
        w.Write([]byte(gProtalBody))
    }

    func main() {
        http.Handle("/reset",http.HandlerFunc(reset));
        http.Handle("/setnetwork",http.HandlerFunc(setnetwork));
        http.Handle("/networkcheck",http.HandlerFunc(networkcheck));
        http.Handle("/wifiprotal",http.HandlerFunc(wifiprotal));
        http.Handle("/handle",http.HandlerFunc(say));
        http.Handle("/config",http.HandlerFunc(config));
        http.ListenAndServe(":8001", nil);
        select{};
    }
    
func AesDecrypt(crypted, key []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        fmt.Println("err is:", err)
    }
    blockMode := NewECBDecrypter(block)
    origData := make([]byte, len(crypted))
    blockMode.CryptBlocks(origData, crypted)
    origData = PKCS5UnPadding(origData)
//    fmt.Println("source is :", origData, string(origData))
    return origData
}

func AesEncrypt(src, key string) []byte {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        fmt.Println("key error1", err)
    }
    if src == "" {
        fmt.Println("plain content empty")
    }
    ecb := NewECBEncrypter(block)
    content := []byte(src)
    content = PKCS5Padding(content, block.BlockSize())
    crypted := make([]byte, len(content))
    ecb.CryptBlocks(crypted, content)
    return crypted
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
    length := len(origData)
    // 去掉最后一个字节 unpadding 次
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}

type ecb struct {
    b         cipher.Block
    blockSize int
}

func newECB(b cipher.Block) *ecb {
    return &ecb{
        b:         b,
        blockSize: b.BlockSize(),
    }
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
    return (*ecbEncrypter)(newECB(b))
}
func (x *ecbEncrypter) BlockSize() int { return x.blockSize }
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("crypto/cipher: input not full blocks")
    }
    if len(dst) < len(src) {
        panic("crypto/cipher: output smaller than input")
    }
    for len(src) > 0 {
        x.b.Encrypt(dst, src[:x.blockSize])
        src = src[x.blockSize:]
        dst = dst[x.blockSize:]
    }
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
    return (*ecbDecrypter)(newECB(b))
}
func (x *ecbDecrypter) BlockSize() int { return x.blockSize }
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("crypto/cipher: input not full blocks")
    }
    if len(dst) < len(src) {
        panic("crypto/cipher: output smaller than input")
    }
    for len(src) > 0 {
        x.b.Decrypt(dst, src[:x.blockSize])
        src = src[x.blockSize:]
        dst = dst[x.blockSize:]
    }
}
