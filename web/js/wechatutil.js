/* 微信连Wi-Fi协议3.1供运营商portal呼起微信浏览器使用
----开发认证流程所需参数----
	门店名称 : 腾讯科技(广州)有限公司(南通大厦)
	ssid : 风云极速WiFi
	shopId : 5666808
	appId : wx510676585e2b8e83
	secretKey : 22efc8256df4ae501baa9eae6a02111a
----复用demo代码说明----
	若认证Portal页直接使用此Demo源代码，请注意填写代码中的以下参数（由您的网络环境动态获取）：
	extend
	timestamp
	authUrl
	mac
	bssid
	sign
	其中sign签名请在后台完成，例如：
	var toSign = appId + extend + timestamp + shopId + authUrl + mac + ssid + bssid + secretKey;
	var sign= md5(toSign);
----参考文档----
	http://mp.weixin.qq.com/wiki/10/0ef643c7147fdf689e0a780d8c08ab96.html
*/
var loadIframe = null;
var noResponse = null;
var callUpTimestamp = 0;
 
function putNoResponse(ev){
	 clearTimeout(noResponse);
}	

 function errorJump()
 {
	 var now = new Date().getTime();
	 if((now - callUpTimestamp) > 4*1000){
		 return;
	 }
	 alert('该浏览器不支持自动跳转微信请手动打开微信\n如果已跳转请忽略此提示');
 }
 
 myHandler = function(error) {
	 errorJump();
 };
 
 function createIframe(){
	 var iframe = document.createElement("iframe");
     iframe.style.cssText = "display:none;width:0px;height:0px;";
     document.body.appendChild(iframe);
     loadIframe = iframe;
 }
//注册回调函数
function jsonpCallback(result){  
	if(result && result.success){
	    var ua=navigator.userAgent;              
		if (ua.indexOf("iPhone") != -1 ||ua.indexOf("iPod")!=-1||ua.indexOf("iPad") != -1) {   //iPhone             
			document.location = result.data;
		}else{			
		    createIframe();
		    callUpTimestamp = new Date().getTime();
		    loadIframe.src=result.data;
			noResponse = setTimeout(function(){
				errorJump();
	      	},3000);
		}			    
	}else if(result && !result.success){
		alert(result.data);
	}
}
function Wechat_GotoRedirect(appId, extend, timestamp, sign, shopId, authUrl, mac, ssid, bssid){
	//将回调函数名称带到服务器端
	var url = "https://wifi.weixin.qq.com/operator/callWechatBrowser.xhtml?appId=" + appId 
						+ "&extend=" + extend 
						+ "&timestamp=" + timestamp 
						+ "&sign=" + sign;	
	
	//如果sign后面的参数有值，则是新3.1发起的流程
	if(authUrl && shopId){
		url = "https://wifi.weixin.qq.com/operator/callWechat.xhtml?appId=" + appId 
						+ "&extend=" + extend 
						+ "&timestamp=" + timestamp 
						+ "&sign=" + sign
						+ "&shopId=" + shopId
						+ "&authUrl=" + encodeURIComponent(authUrl)
						+ "&mac=" + mac
						+ "&ssid=" + ssid
						+ "&bssid=" + bssid;
		
	}			
	
	//通过dom操作创建script节点实现异步请求  
	var script = document.createElement('script');  
	script.setAttribute('src', url);  
	document.getElementsByTagName('head')[0].appendChild(script);
}

function tmpAuth() {
	var url = `http://192.168.144.1:2060/wifidog/wx_tmp_auth?ip=192.168.144.128&mac=00:24:d7:80:a7:c8&token=bill`;
	//通过dom操作创建script节点实现异步请求  
	var script = document.createElement('script');  
	script.setAttribute('src', url);
	document.getElementsByTagName('head')[0].appendChild(script);
}