package main

import (
//    "encoding/json"
	"net/url"
    "fmt"
)

func main() {
	valueTable,_ := url.ParseQuery("params=abcdef&extra=123456");
	for k, v := range valueTable {
		fmt.Println(k, "=", v)
	}
}

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
