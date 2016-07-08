
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
    )

    var (
        gNeedAuthe = true//全局标记当前是否返回需要认证
        gKey = "0123456789abcdef"//中间商合作认证的加密密钥
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
         w.Write([]byte("not need Authe."))
    }

    func reset(w http.ResponseWriter, req *http.Request) {
        gNeedAuthe = true
        w.Write([]byte("reset finish."))
    }

    func networkcheck(w http.ResponseWriter, req *http.Request) {
        if gNeedAuthe {
            fmt.Println("networkcheck NeedAuthe")
            http.Redirect(w, req, "http://m.qq.com", 302)
        } else {
            normal(w, req);
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

    func main() {
        http.Handle("/reset",http.HandlerFunc(reset));
        http.Handle("/networkcheck",http.HandlerFunc(networkcheck));
        http.Handle("/handle",http.HandlerFunc(say));
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
