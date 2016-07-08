
package main;
    
    import (
        "net/http"
		    "bytes"
			"crypto/aes"
			"crypto/cipher"
			"encoding/base64"
			"fmt"
			"strings"
			"io/ioutil"
            "net/url"
            "encoding/json"
    )

    var (
        gNeedAuthe = true
        gKey = "0123456789abcdef"
    )
	
    func say(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" {
			result, _:= ioutil.ReadAll(req.Body)
			req.Body.Close()
			fmt.Printf("%s\n", result)
            valueTable,_ := url.ParseQuery(string(result));
            params := valueTable["params"]
            if params != nil {
                respont := proceParams(string(params[0]))
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

    func needAuthe(w http.ResponseWriter, req *http.Request) {
         w.Write([]byte("Need authe."))
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

    func proceParams(params string) []byte {
    	data, _ := base64.StdEncoding.DecodeString(params)
    	fmt.Println(len(data))
        if data != nil {
            desc := AesDecrypt(data, []byte(gKey))
            if desc != nil {
		 		fmt.Println(string(desc))
			}
             // if desc != nil {
             //    var f interface{}
             //    json.Unmarshal(desc, &f)
             //    m := f.(map[string]interface{})
             //    for k, v := range m {
             //    switch vv := v.(type) {
             //        case string:
             //            fmt.Println(k, "is string", vv)
             //        case int:
             //            fmt.Println(k, "is int", vv)
             //        case float64:
             //            fmt.Println(k,"is float64",vv)
             //        case []interface{}:
             //            fmt.Println(k, "is an array:")
             //            for i, u := range vv {
             //                fmt.Println(i, u)
             //            }
             //        default:
             //            fmt.Println(k, "is of a type I don't know how to handle")
             //        }
             //    }
             //    session_id := m["session_id"]
             //    if session_id != nil {
             //       return getResponeData(1, session_id.(int), "http://m.qq.com")
             //    }
             //}
        }
        return nil
    }

    func getResponeData(api_code int, session_id int, ad_url string) []byte {
        result := make(map[string]interface{})
        result["api_code"] = api_code
        result["session_id"] = session_id
        result["ad_url"] = ad_url
        b, _ := json.Marshal(result)
        crypted := AesEncrypt(string(b), gKey)
        return []byte(Base64UrlSafeEncode(crypted))
    }

    func main() {
        http.Handle("/reset",http.HandlerFunc(reset));
        http.Handle("/networkcheck",http.HandlerFunc(networkcheck));
        http.Handle("/needAuthe",http.HandlerFunc(needAuthe));
        http.Handle("/handle",http.HandlerFunc(say));
        http.ListenAndServe(":8001", nil);
        select{};
    }
	
func Base64URLDecode(data string) ([]byte, error) {
    var missing = (4 - len(data)%4) % 4
    data += strings.Repeat("=", missing)
    res, err := base64.URLEncoding.DecodeString(data)
    fmt.Println("  decodebase64urlsafe is :", string(res), err)
    return base64.URLEncoding.DecodeString(data)
}

func Base64UrlSafeEncode(source []byte) string {
    // Base64 Url Safe is the same as Base64 but does not contain '/' and '+' (replaced by '_' and '-') and trailing '=' are removed.
    bytearr := base64.StdEncoding.EncodeToString(source)
    safeurl := strings.Replace(string(bytearr), "/", "_", -1)
    safeurl = strings.Replace(safeurl, "+", "-", -1)
    safeurl = strings.Replace(safeurl, "=", "", -1)
    return safeurl
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
    // 普通base64编码加密 区别于urlsafe base64
    fmt.Println("base64 result:", base64.StdEncoding.EncodeToString(crypted))

    fmt.Println("base64UrlSafe result:", Base64UrlSafeEncode(crypted))
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



// package main

// import (
// //    "encoding/json"
// 	"net/url"
//     "fmt"
// )

// func main() {
// 	valueTable,_ := url.ParseQuery("params=abcdef&extra=123456");
// 	for k, v := range valueTable {
// 		fmt.Println(k, "=", v)
// 	}
// }

// func main() {	
// 	result := make(map[string]interface{})
// 	result["api_code"] = 1
// 	result["session_id"] = 123123
// 	result["ad_url"] = "http://m.qqq.com"
// 	b, _ := json.Marshal(result)
// 	fmt.Println(string(b))
	
// 	var f interface{}
// 	json.Unmarshal(b, &f)
// 	m := f.(map[string]interface{})
// 	fmt.Println(m["group_id"])
// 	for k, v := range m {
//     switch vv := v.(type) {
// 		case string:
// 			fmt.Println(k, "is string", vv)
// 		case int:
// 			fmt.Println(k, "is int", vv)
// 		case float64:
// 			fmt.Println(k,"is float64",vv)
// 		case []interface{}:
// 			fmt.Println(k, "is an array:")
// 			for i, u := range vv {
// 				fmt.Println(i, u)
// 			}
// 		default:
// 			fmt.Println(k, "is of a type I don't know how to handle")
// 		}
// 	}
// }
