import { Gateway } from "./gateway.js"

let connected
const connectedPromise = new Promise(r => connected = r)
let failed
const failedPromise = new Promise(r => failed = r)
const gateway = new Gateway({
    host: '',//中枢网关的ip 不要加协议头，就纯数字ip
    protocols: ['passcode'],
}, function () {
    //连接码，打开米家app，点击中枢网关，点击中枢功能获得
    this.setPasscode('')
}, connected, failed)
await Promise.any([failedPromise, connectedPromise])
//获取所有全局变量
for (let i = 0; i < 1; i++) {
    //measure time
    const start = performance.now()
    console.log(await gateway.callAPI('getVarList', {
        scope: 'global'
    }, 5000))
    console.log(performance.now() - start)
}

//想要执行某个功能，就打开米家自动化极客版那个网页，然后给callAPI这个函数打断点，看那个功能对应的请求参数是怎么写的