import d from "elliptic"
import u from 'node-forge'
import { BN as c } from 'bn.js'
import _r from 'node:zlib'


export class p {
    #w
    #E
    #I
    #C
    #S
    #A
    #T
    #N
    #_
    #B = !1
    #k = !1
    #R = !1
    #L = !1
    #M = !1
    constructor(e) {
        if ('server' !== e.role && 'client' !== e.role)
            throw new TypeError('role must be "client" or "server"')
        if ('string' != typeof e.secret)
            throw new TypeError('secret must be a string')
            ; (this.#w = e.role),
                (this.#E = 'client' === this.#w ? 'server' : 'client')
        let t = new TextEncoder()
            ; (this.#S = new c(t.encode(e.secret))),
                (this.#I = 'secp256k1'),
                (this.#C = 22)
    }
    writeRoundOne() {
        if (this.#B)
            throw new Error('Reusing failed ECJPAKE context is insecure.')
        if (this.#k || this.#L || this.#M) throw new Error('Wrong step')
        this.#k = !0

        const e = new d.ec(this.#I)
        this.#A = e.genKeyPair()
        const t = this.#x(
            this.#I,
            e.g,
            this.#A.getPublic(),
            this.#A.getPrivate(),
            this.#w
        )
        this.#T = e.genKeyPair()
        const r = this.#x(
            this.#I,
            e.g,
            this.#T.getPublic(),
            this.#T.getPrivate(),
            this.#w
        ),
            i = this.#D(this.#A.getPublic()),
            n = this.#D(this.#T.getPublic()),
            s = this.#P(t),
            o = this.#P(r),
            a = new Uint8Array(i.length + s.length + n.length + o.length)
        let u = 0
        return (
            a.set(i, u),
            (u += i.length),
            a.set(s, u),
            (u += s.length),
            a.set(n, u),
            (u += n.length),
            a.set(o, u),
            (u += o.length),
            a
        )
    }
    readRoundOne(e) {
        if (this.#B)
            throw new Error('Reusing failed ECJPAKE context is insecure.')
        if (this.#R || this.#L || this.#M) throw new Error('Wrong step')
        this.#R = !0
        const t = new d.ec(this.#I)
        let r = 0
        const i = e[r]
        r++
        const n = e.slice(r, r + i)
            ; (r += i), (this.#N = t.keyFromPublic(n).getPublic())
        const s = e[r],
            o = 1 + s + 1 + e[r + 1 + s],
            a = e.slice(r, r + o)
        r += o
        const u = this.#U(a)
        if (!this.#O(this.#I, t.g, this.#N, u.V, u.r, this.#E))
            throw ((this.#B = !0), new Error('ECJPAKE round one failed'))
        const c = e[r]
        r++
        const p = e.slice(r, r + c)
            ; (r += c), (this.#_ = t.keyFromPublic(p).getPublic())
        const f = e[r],
            l = 1 + f + 1 + e[r + 1 + f],
            h = e.slice(r, r + l)
        r += l
        const g = this.#U(h)
        if (!this.#O(this.#I, t.g, this.#_, g.V, g.r, this.#E))
            throw ((this.#B = !0), new Error('ECJPAKE round one failed'))
    }
    writeRoundTwo() {
        if (this.#B)
            throw new Error('Reusing failed ECJPAKE context is insecure.')
        if (this.#L || !this.#k || !this.#R) throw new Error('Wrong step')
        this.#L = !0
        const e = new d.ec(this.#I)
        let t = this.#A.getPublic().add(this.#N).add(this.#_)
        e.g = t
        const r = u.random.getBytesSync(16)
        let i = new Uint8Array(16)
        for (let u = 0; u < r.length; u++) i[u] = r.charCodeAt(u)
        let n = new c(i)
        if (null === e.n || void 0 === e.n) throw new Error('EC error')
        n = n.mul(e.n).add(this.#S)
        let s,
            o = this.#T.getPrivate().mul(n).umod(e.n),
            a = t.mul(o),
            p = this.#x(this.#I, t, a, o, this.#w),
            f = this.#V(),
            l = this.#D(a),
            h = this.#P(p),
            g = 0
        return (
            'server' === this.#w
                ? ((s = new Uint8Array(f.length + l.length + h.length)),
                    s.set(f, g),
                    (g += f.length))
                : (s = new Uint8Array(l.length + h.length)),
            s.set(l, g),
            (g += l.length),
            s.set(h, g),
            (g += h.length),
            s
        )
    }
    readRoundTwo(e) {
        if (this.#B)
            throw new Error('Reusing failed ECJPAKE context is insecure.')
        if (this.#M || !this.#k || !this.#R) throw new Error('Wrong step')
        this.#M = !0
        const t = new d.ec(this.#I)
        let r = this.#A.getPublic().add(this.#T.getPublic()).add(this.#N),
            i = 0
        'client' === this.#w && (i += 3)
        const n = e[i]
        i++
        const s = e.slice(i, i + n)
        i += n
        let o = t.keyFromPublic(s).getPublic()
        const a = e[i],
            p = 1 + a + 1 + e[i + 1 + a],
            f = e.slice(i, i + p)
        i += p
        const l = this.#U(f)
        if (!this.#O(this.#I, r, o, l.V, l.r, this.#E))
            throw ((this.#B = !0), new Error('ECJPAKE round two failed'))
        const h = u.random.getBytesSync(16)
        let g = new Uint8Array(16)
        for (let u = 0; u < h.length; u++) g[u] = h.charCodeAt(u)
        let y = new c(g)
        if (null === t.n || void 0 === t.n) throw new Error('EC error')
        y = y.mul(t.n).add(this.#S)
        let m = this.#T.getPrivate().mul(y).umod(t.n),
            v = o.add(this.#_.mul(m).neg()).mul(this.#T.getPrivate())
        const b = u.md.sha256.create()
        b.update(String.fromCharCode(...v.getX().toArray('be', 32)), 'raw')
        const w = b.digest().bytes(32)
        let E = new Uint8Array(32)
        for (let u = 0; u < w.length; u++) E[u] = w.charCodeAt(u)
        return E
    }
    #K(e) {
        let t = new Uint8Array(69)
        t.fill(0)
        let r = new DataView(t.buffer)
        r.setUint32(0, 65, !1), r.setUint8(4, 4)
        const i = new Uint8Array(e.getX().toArray('be', 32)),
            n = new Uint8Array(e.getY().toArray('be', 32))
        return t.set(i, 5), t.set(n, 37), t
    }
    #D(e) {
        let t = new Uint8Array(66)
        t.fill(0)
        let r = new DataView(t.buffer)
        r.setUint8(0, 65), r.setUint8(1, 4)
        const i = new Uint8Array(e.getX().toArray('be', 32)),
            n = new Uint8Array(e.getY().toArray('be', 32))
        return t.set(i, 2), t.set(n, 34), t
    }
    #V() {
        let e = new Uint8Array(3)
        return (e[0] = 3), new DataView(e.buffer).setUint16(1, this.#C, !1), e
    }
    #z(e, t, r, i, n) {
        const s = this.#K(e),
            o = this.#K(t),
            a = this.#K(r)
        const d = new TextEncoder().encode(i),
            p = new Uint8Array(4)
        new DataView(p.buffer).setUint32(0, d.length, !1)
        let f = new Uint8Array(
            s.length + o.length + a.length + p.length + d.length
        )
        f.fill(0)
        let l = 0
        f.set(s, l),
            (l += s.length),
            f.set(o, l),
            (l += o.length),
            f.set(a, l),
            (l += a.length),
            f.set(p, l),
            (l += p.length),
            f.set(d, l),
            (l += d.length)
        const h = u.md.sha256.create()
        h.update(String.fromCharCode(...f), 'raw')
        const g = h.digest().toHex()
        let y = new c(g, 'hex', 'be')
        return (y = y.umod(n)), y
    }
    #x(e, t, r, i, n) {
        const s = new d.ec(e)
        s.g = t
        let o = s.genKeyPair()
        if (null === s.n || void 0 === s.n) throw new Error('EC error')
        let a = this.#z(s.g, o.getPublic(), r, n, s.n),
            u = o.getPrivate().sub(a.mul(i)).umod(s.n)
        return { V: o.getPublic(), r: u }
    }
    #P(e) {
        const t = new Uint8Array(99)
        return (
            t.fill(0),
            t.set(this.#D(e.V), 0),
            (t[66] = 32),
            t.set(e.r.toArray('be', 32), 67),
            t
        )
    }
    #U(e) {
        if (!(e instanceof Uint8Array))
            throw new TypeError(
                'ZKPArray should be an Uint8Array with length===99'
            )
        const t = new d.ec(this.#I),
            r = e[0],
            i = t.keyFromPublic(e.slice(1, 1 + r)).getPublic(),
            n = e[1 + r]
        return { V: i, r: new c(e.slice(1 + r + 1, 1 + r + 1 + n)) }
    }
    #O(e, t, r, i, n, s) {
        const o = new d.ec(e)
        if (((o.g = t), null === o.n || void 0 === o.n))
            throw new Error('EC error')
        let a = this.#z(t, i, r, s, o.n)
        return r.mul(a).add(t.mul(n)).eq(i)
    }
}
const Br = {
    compress(e) {
        let t = _r.deflateRawSync(new Uint8Array(e))
            , r = new ArrayBuffer(4 + t.length);
        new DataView(r).setUint32(0, e.byteLength, !0);
        let i = new Uint8Array(r);
        return i.set(t, 4),
            i.buffer
    },
    decompress: e => _r.inflateRawSync(new Uint8Array(e.slice(4))).buffer
};
function l(e) {
    let t = new Uint8Array(e.length());
    for (let r = 0; r < t.length; r++)
        t[r] = e.at(r);
    return t
}
export class h {
    #$
    #j
    #H
    #G = 1
    #W = 0
    constructor(e, t) {
        if (!(e instanceof Uint8Array) || 16 !== e?.length)
            throw new TypeError("key's length is not 16")
        if (!(t instanceof Uint8Array) || 8 !== t.length)
            throw new TypeError("salt's length is not 8")
            ; (this.#$ = u.cipher.createCipher('AES-GCM', u.util.createBuffer(e))),
                (this.#j = u.cipher.createDecipher(
                    'AES-GCM',
                    u.util.createBuffer(e)
                )),
                (this.#H = t)
    }
    encrypt(e) {
        if (this.#G > 4294967295) throw new Error('self counter overflow')
        const t = this.#G++,
            r = new Uint8Array(12)
        r.set(this.#H, 0)
        if (
            (new DataView(r.buffer).setUint32(8, t, !0),
                this.#$.start({ iv: u.util.createBuffer(r), tagLength: 128 }),
                this.#$.update(u.util.createBuffer(e)),
                !this.#$.finish())
        )
            throw new Error('forge encryption error')
        const i = l(this.#$.output),
            n = l(this.#$.mode.tag)
        let s = new Uint8Array(4 + i.length + n.length)
        return (
            new DataView(s.buffer).setUint32(0, t, !0),
            s.set(i, 4),
            s.set(n, 4 + i.length),
            s.buffer
        )
    }
    decrypt(e) {
        let t = new DataView(e).getUint32(0, !0)
        if (t <= this.#W) throw new Error('Replay attack!')
        this.#W = t
        const r = new Uint8Array(e.slice(4, e.byteLength - 16)),
            i = new Uint8Array(e.slice(4 + r.length)),
            n = new Uint8Array(12)
        n.set(this.#H)
        if (
            (new DataView(n.buffer).setUint32(8, t, !0),
                this.#j.start({
                    iv: u.util.createBuffer(n),
                    tagLength: 128,
                    tag: u.util.createBuffer(i),
                }),
                this.#j.update(u.util.createBuffer(r)),
                !this.#j.finish())
        )
            throw new Error('authentication or decryption failed')
        return l(this.#j.output).buffer
    }
}
class kr extends Error {
    static ERROR_CODE = {
        PARSE_ERROR: -32700,
        INVALID_REQUEST: -32600,
        METHOD_NOT_FOUND: -32601,
        INVALID_PARAMS: -32602,
        INTERNAL_ERROR: -32603,
    }
    constructor(e, t = kr.ERROR_CODE.INTERNAL_ERROR) {
        super(e), (this.code = t)
    }
}
class Rr {
    static DATA_TYPE = {
        PROTOCOL_LIST: 1,
        SELECTED_PROTOCOL: 2,
        SESSION_KEY_EXCHANGE: 3,
        ERROR: 4,
        DATA: 5,
        SERVER_PUB_KEY: 16,
        ECJPAKE_ROUND_ONE: 32,
        ECJPAKE_ROUND_TWO: 33,
    }
    static CIPHER_STEPS = {
        QR: [
            { name: 'ecdh peer pub', timeout: 6e4 },
            { name: 'key exchange', timeout: 5e3 },
        ],
        passcode: [
            { name: 'set passcode', timeout: 6e4 },
            { name: 'ecjpake round one', timeout: 5e3 },
            { name: 'ecjpake round two', timeout: 5e3 },
            { name: 'key exchange', timeout: 5e3 },
        ],
    }
    #Q
    #Z
    #X
    #Y
    #J
    #ee = void 0
    #te = -1
    #re
    #ie
    #ne = !1
    #se = 0
    #oe = new Map()
    #ae = new Map()
    constructor(e, f, connectedResolve, failedResolve) {
        this.onRequestPasscode = f
        this.onSecureSessionEstablish = () => {
            console.log('connected')
            connectedResolve()
        }
        this.onSecureSessionError = () => {
            console.log('failed')
            failedResolve()
        }
        const t = `ws://${e.host}${e.path ?? '/centrallinkws/'}`
            ; (this.#Q = new WebSocket(t)),
                this.#Q.addEventListener('open', (t) => {
                    this.#ue(e.protocols)
                }),
                this.#Q.addEventListener('close', (e) => {
                    this.close()
                }),
                this.#Q.addEventListener('close', (e) => {
                    this.close()
                }),
                this.#Q.addEventListener('message', async (e) => {
                    if ('string' == typeof e.data)
                        throw new Error('Central link does not accpet ws text data')
                    this.#ce(await e.data.arrayBuffer())
                })
    }
    close() {
        this.#de(),
            (this.#ne = !1),
            (this.#ie = void 0),
            (this.#re = void 0),
            this.#Q.close(),
            this.onClose?.()
    }
    onClose = () => { }
    onRequestPasscode = () => { }
    setPasscode(e) {
        try {
            this.#pe('set passcode', 'passcode'),
                (this.#Y = new p({ role: 'client', secret: e }))
            const t = this.#Y.writeRoundOne()
            let r = new Uint8Array(1 + t.length)
                ; (r[0] = Rr.DATA_TYPE.ECJPAKE_ROUND_ONE),
                    r.set(t, 1),
                    this.#Q.send(r.buffer)
        } catch (t) {
            throw (this.#de(), this.#fe(), this.onSecureSessionError?.(), t)
        }
    }
    onDisplayPubKey = (e, t, r) => { }
    onSecureSessionEstablish = () => {
        // console.log('connected')
    }
    onSecureSessionError = () => { 
        
    }
    async callAPI(e, t, r = 5e3) {
        try {
            if (!this.#ne) throw new Error('secure session not established')
            const i = this.#le(),
                n = `${i}`
            let s = { resolve: void 0, reject: void 0, timeoutHandle: void 0 },
                o = new Promise((e, t) => {
                    ; (s.resolve = e), (s.reject = t)
                })
            return (
                this.#he({
                    jsonrpc: '2.0',
                    id: i,
                    method: `/api/${e}`,
                    params: t,
                }),
                this.#oe.set(n, s),
                (s.timeoutHandle = setTimeout(() => {
                    s.reject(new Error('Timeout')), this.#oe.delete(n)
                }, r)),
                await o
            )
        } catch (i) {
            throw new kr(i?.message ?? `${i}`, i?.code)
        }
    }
    registerAPI(e, t) {
        this.#ae.set(`/api/${e}`, { func: t })
    }
    unregisterAPI(e) {
        this.#ae.delete(`/api/${e}`)
    }
    sendPush(e, t) {
        try {
            if (!this.#ne) throw new Error('seucre session not established')
            this.#he({
                jsonrpc: '2.0',
                id: this.#le(),
                method: `/push/${e}`,
                params: t,
            })
        } catch (r) { }
    }
    registerPush(e, t) {
        this.#ae.set(`/push/${e}`, { isPushHandler: !0, func: t })
    }
    unregisterPush(e) {
        this.#ae.delete(`/push/${e}`)
    }
    async #ce(e) {
        switch (new DataView(e).getUint8(0)) {
            case Rr.DATA_TYPE.DATA:
                {
                    if (!this.#ne) throw new Error('Secure sesison not established')
                    const r = this.#ie.decrypt(e.slice(1)),
                        i = Br.decompress(r),
                        n = JSON.parse(new TextDecoder().decode(i))
                    if ('number' != typeof n.id)
                        throw new Error('Invalid json rpc id')
                    if ('result' in n) {
                        const e = `${n.id}`
                        let r = this.#oe.get(e)
                        if (void 0 !== r) {
                            try {
                                clearTimeout(r.timeoutHandle)
                            } catch (t) { }
                            r.resolve(n.result)
                        }
                        this.#oe.delete(e)
                    } else if ('error' in n) {
                        const e = `${n.id}`
                        let r = this.#oe.get(e)
                        if (void 0 !== r) {
                            try {
                                clearTimeout(r.timeoutHandle)
                            } catch (t) { }
                            r.reject(n.error)
                        }
                        this.#oe.delete(e)
                    } else if ('method' in n) {
                        let e = this.#ae.get(n.method)
                        if (void 0 === e) break
                        if (e.isPushHandler) e.func(n.params)
                        else {
                            let r = { jsonrpc: '2.0', id: n.id }
                            try {
                                r.result = (await e.func(n.params)) ?? {}
                            } catch (t) {
                                r.error = {
                                    code: t?.code ?? kr.ERROR_CODE.INTERNAL_ERROR,
                                    message: t?.message ?? `${t}`,
                                }
                            }
                            this.#he(r)
                        }
                    }
                }
                break
            case Rr.DATA_TYPE.SELECTED_PROTOCOL:
                try {
                    let t = JSON.parse(new TextDecoder().decode(e.slice(1)))
                    this.#ge(t.protocol),
                        'QR' === t.protocol
                            ? ((this.#X = new f()),
                                this.onDisplayPubKey(
                                    this.#X.writeSelfPub().buffer,
                                    t.params.did,
                                    t.params.id
                                ))
                            : 'passcode' === t.protocol && this.onRequestPasscode()
                } catch (t) {
                    throw (this.#de(), this.#fe(), this.onSecureSessionError?.(), t)
                }
                break
            case Rr.DATA_TYPE.SERVER_PUB_KEY:
                try {
                    this.#pe('ecdh peer pub', 'QR')
                    const t = this.#X.readPeerPub(new Uint8Array(e.slice(1)))
                    this.#ye(t)
                } catch (t) {
                    throw (this.#de(), this.#fe(), this.onSecureSessionError?.(), t)
                }
                break
            case Rr.DATA_TYPE.ECJPAKE_ROUND_ONE:
                try {
                    this.#pe('ecjpake round one', 'passcode'),
                        this.#Y.readRoundOne(new Uint8Array(e.slice(1)))
                    const t = this.#Y.writeRoundTwo()
                    let r = new Uint8Array(1 + t.length)
                        ; (r[0] = Rr.DATA_TYPE.ECJPAKE_ROUND_TWO),
                            r.set(t, 1),
                            this.#Q.send(r.buffer)
                } catch (t) {
                    throw (this.#de(), this.#fe(), this.onSecureSessionError?.(), t)
                }
                break
            case Rr.DATA_TYPE.ECJPAKE_ROUND_TWO:
                try {
                    this.#pe('ecjpake round two', 'passcode')
                    const t = this.#Y.readRoundTwo(new Uint8Array(e.slice(1)))
                    this.#ye(t)
                } catch (t) {
                    throw (this.#de(), this.#fe(), this.onSecureSessionError?.(), t)
                }
                break
            case Rr.DATA_TYPE.SESSION_KEY_EXCHANGE:
                try {
                    this.#pe('key exchange')
                    const t = new Uint8Array(this.#J.decrypt(e.slice(1))),
                        r = t.slice(0, 16),
                        i = t.slice(16, 24)
                        ; (this.#ie = new h(r, i)),
                            this.#de(),
                            (this.#ne = !0),
                            this.onSecureSessionEstablish?.()
                } catch (t) {
                    throw (this.#de(), this.#fe(), this.onSecureSessionError?.(), t)
                }
                break
            case Rr.DATA_TYPE.ERROR:
                this.#de(), this.onSecureSessionError?.()
        }
    }
    #he(e) {
        if (!this.#ne) throw new Error('Secure session not established')
        let t = Br.compress(
            new TextEncoder().encode(JSON.stringify(e)).buffer
        ),
            r = this.#re.encrypt(t),
            i = new Uint8Array(1 + r.byteLength)
            ; (i[0] = Rr.DATA_TYPE.DATA),
                i.set(new Uint8Array(r), 1),
                this.#Q.send(i.buffer)
    }
    #fe() {
        let e = new Uint8Array(1)
            ; (e[0] = Rr.DATA_TYPE.ERROR), this.#Q.send(e.buffer)
    }
    #ue(e) {
        let t = new TextEncoder().encode(JSON.stringify(e)),
            r = new Uint8Array(1 + t.length)
            ; (r[0] = Rr.DATA_TYPE.PROTOCOL_LIST),
                r.set(t, 1),
                this.#Q.send(r.buffer),
                (this.#ee = setTimeout(() => {
                    this.#de(), this.onSecureSessionError?.()
                }, 5e3))
    }
    #ye(e) {
        const t = e.slice(0, 16),
            r = e.slice(16, 24)
        this.#J = new h(t, r)
        const i = crypto.getRandomValues(new Uint8Array(24)),
            n = i.slice(0, 16),
            s = i.slice(16, 24)
        this.#re = new h(n, s)
        const o = this.#J.encrypt(i.buffer)
        let a = new Uint8Array(1 + o.byteLength)
            ; (a[0] = Rr.DATA_TYPE.SESSION_KEY_EXCHANGE),
                a.set(new Uint8Array(o), 1),
                this.#Q.send(a.buffer)
    }
    #de() {
        try {
            clearTimeout(this.#ee)
        } catch (e) { }
        ; (this.#Z = void 0),
            (this.#te = -1),
            (this.#Y = void 0),
            (this.#X = void 0),
            (this.#J = void 0)
    }
    #ge(e) {
        if ((this.#de(), void 0 === Rr.CIPHER_STEPS[e]))
            throw new Error(`${e} is not a valid cipher`)
            ; (this.#Z = e),
                (this.#te = -1),
                (this.#ee = setTimeout(() => {
                    this.#de(), this.onSecureSessionError?.()
                }, Rr.CIPHER_STEPS[e][0].timeout))
    }
    #pe(e, t) {
        try {
            if (void 0 === this.#Z)
                throw new Error('Not in a key exchange session')
            t = t ?? this.#Z
            if (void 0 === Rr.CIPHER_STEPS[t])
                throw new Error(`${t} is not a valid cipher`)
            if ((this.#te++, Rr.CIPHER_STEPS[t][this.#te].name !== e))
                throw new Error(
                    `Wrong step ${e}, should be ${Rr.CIPHER_STEPS[t][this.#te].name
                    }`
                )
            try {
                clearTimeout(this.#ee)
            } catch (r) { }
            void 0 !== Rr.CIPHER_STEPS[t][this.#te + 1] &&
                (this.#ee = setTimeout(() => {
                    this.#de(), this.onSecureSessionError?.()
                }, Rr.CIPHER_STEPS[t][this.#te + 1].timeout))
        } catch (r) {
            throw (this.#de(), r)
        }
    }
    #le() {
        let e = this.#se
        return (this.#se = (this.#se + 1) % 4294967295), e
    }
}
export { Rr as Gateway }