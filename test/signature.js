function Ya(e, t) {
    const n = []
      , i = ~~(t / 8)
      , o = t % 8;
    for (let a = 0, s = e.length; a < s; a++)
        n[a] = (e[(a + i) % s] << o & 255) + (e[(a + i + 1) % s] >>> 8 - o & 255);
    return n
}
function Bo(e, t) {
    const n = [];
    for (let i = e.length - 1; i >= 0; i--)
        n[i] = (e[i] ^ t[i]) & 255;
    return n
}
function d0(e, t) {
    const n = [];
    for (let i = e.length - 1; i >= 0; i--)
        n[i] = e[i] & t[i] & 255;
    return n
}
function zS(e, t) {
    const n = [];
    for (let i = e.length - 1; i >= 0; i--)
        n[i] = (e[i] | t[i]) & 255;
    return n
}
function Nu(e, t) {
    const n = [];
    let i = 0;
    for (let o = e.length - 1; o >= 0; o--) {
        const a = e[o] + t[o] + i;
        a > 255 ? (i = 1,
        n[o] = a & 255) : (i = 0,
        n[o] = a & 255)
    }
    return n
}
function e0e(e) {
    const t = [];
    for (let n = e.length - 1; n >= 0; n--)
        t[n] = ~e[n] & 255;
    return t
}
function t0e(e) {
    return Bo(Bo(e, Ya(e, 9)), Ya(e, 17))
}
function n0e(e) {
    return Bo(Bo(e, Ya(e, 15)), Ya(e, 23))
}
function r0e(e, t, n, i) {
    return i >= 0 && i <= 15 ? Bo(Bo(e, t), n) : zS(zS(d0(e, t), d0(e, n)), d0(t, n))
}
function i0e(e, t, n, i) {
    return i >= 0 && i <= 15 ? Bo(Bo(e, t), n) : zS(d0(e, t), d0(e0e(e), n))
}
function o0e(e, t) {
    const n = []
      , i = [];
    for (let b = 0; b < 16; b++) {
        const _ = b * 4;
        n.push(t.slice(_, _ + 4))
    }
    for (let b = 16; b < 68; b++)
        n.push(Bo(Bo(n0e(Bo(Bo(n[b - 16], n[b - 9]), Ya(n[b - 3], 15))), Ya(n[b - 13], 7)), n[b - 6]));
    for (let b = 0; b < 64; b++)
        i.push(Bo(n[b], n[b + 4]));
    const o = [121, 204, 69, 25]
      , a = [122, 135, 157, 138];
    let s = e.slice(0, 4), u = e.slice(4, 8), f = e.slice(8, 12), y = e.slice(12, 16), m = e.slice(16, 20), v = e.slice(20, 24), r = e.slice(24, 28), d = e.slice(28, 32), c, p, h, g;
    for (let b = 0; b < 64; b++) {
        const _ = b >= 0 && b <= 15 ? o : a;
        c = Ya(Nu(Nu(Ya(s, 12), m), Ya(_, b)), 7),
        p = Bo(c, Ya(s, 12)),
        h = Nu(Nu(Nu(r0e(s, u, f, b), y), p), i[b]),
        g = Nu(Nu(Nu(i0e(m, v, r, b), d), c), n[b]),
        y = f,
        f = Ya(u, 9),
        u = s,
        s = h,
        d = r,
        r = Ya(v, 19),
        v = m,
        m = t0e(g)
    }
    return Bo([].concat(s, u, f, y, m, v, r, d), e)
}
function a0e(e) {
    let t = e.length * 8
      , n = t % 512;
    n = n >= 448 ? 512 - n % 448 - 1 : 448 - n - 1;
    const i = new Array((n - 7) / 8);
    for (let f = 0, y = i.length; f < y; f++)
        i[f] = 0;
    const o = [];
    t = t.toString(2);
    for (let f = 7; f >= 0; f--)
        if (t.length > 8) {
            const y = t.length - 8;
            o[f] = parseInt(t.substr(y), 2),
            t = t.substr(0, y)
        } else
            t.length > 0 ? (o[f] = parseInt(t, 2),
            t = "") : o[f] = 0;
    const a = [].concat(e, [128], i, o)
      , s = a.length / 64;
    let u = [115, 128, 22, 111, 73, 20, 178, 185, 23, 36, 66, 215, 218, 138, 6, 0, 169, 111, 48, 188, 22, 49, 56, 170, 227, 141, 238, 77, 176, 251, 14, 78];
    for (let f = 0; f < s; f++) {
        const y = 64 * f
          , m = a.slice(y, y + 64);
        u = o0e(u, m)
    }
    return u
}
function s0e(e) {
    return e.map(t => (t = t.toString(16),
    t.length === 1 ? "0" + t : t)).join("")
}
function l0e(e) {
    const t = [];
    for (let n = 0, i = e.length; n < i; n++) {
        const o = e.codePointAt(n);
        if (o <= 127)
            t.push(o);
        else if (o <= 2047)
            t.push(192 | o >>> 6),
            t.push(128 | o & 63);
        else if (o <= 55295 || o >= 57344 && o <= 65535)
            t.push(224 | o >>> 12),
            t.push(128 | o >>> 6 & 63),
            t.push(128 | o & 63);
        else if (o >= 65536 && o <= 1114111)
            n++,
            t.push(240 | o >>> 18 & 28),
            t.push(128 | o >>> 12 & 63),
            t.push(128 | o >>> 6 & 63),
            t.push(128 | o & 63);
        else
            throw t.push(o),
            new Error("input is not supported")
    }
    return t
}
function u0e(e) {
    return e = typeof e == "string" ? l0e(e) : Array.prototype.slice.call(e),
    s0e(a0e(e))
}
function go(e) {
    var output = u0e(e);
    std.puts(output);
}