# tampermonkey-CryptoHook
对在window上的常见第三方加密库 Hook

功能比较鸡肋, 如题 只能对window下的第三方库Hook.

* debug: debug是否开启
* prohibit_arr: 不希望被打印的方法
 
Hook_.debug = true;  
Hook_.prohibit_arr = ["enc.Latin1.parse", "enc.Utf8.parse", "getRandomValues"];

![1png](https://user-images.githubusercontent.com/87036071/234781250-c1148f63-e7ec-4bf8-9aeb-2373be7c47d3.png)
