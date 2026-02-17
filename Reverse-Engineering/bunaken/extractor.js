function w() {
    let n = ["WR0tF8oezmkl", "toString", "W603xSol", "1tlHJnY", "1209923ghGtmw", "text", "13820KCwBPf", "byteOffset", "40xRjnfn", "Cfa9", "bNaXh8oEW6OiW5FcIq", "alues", "lXNdTmoAgqS0pG", "D18RtemLWQhcLConW5a", "nCknW4vfbtX+", "WOZcIKj+WONdMq", "FCk1cCk2W7FcM8kdW4y", "a8oNWOjkW551fSk2sZVcNa", "yqlcTSo9xXNcIY9vW7dcS8ky", "from", "iSoTxCoMW6/dMSkXW7PSW4xdHaC", "c0ZcS2NdK37cM8o+mW", "377886jVoqYx", "417805ESwrVS", "7197AxJyfv", "cu7cTX/cMGtdJSowmSk4W5NdVCkl", "W7uTCqXDf0ddI8kEFW", "write", "encrypt", "ted", "xHxdQ0m", "byteLength", "6CCilXQ", "304OpHfOi", "set", "263564pSWjjv", "subtle", "945765JHdYMe", "SHA-256", "Bu7dQfxcU3K", "getRandomV"];
    return w = function() {
        return n
    }, w()
}

function l(n, r) {
    return n = n - 367, w()[n]
}
var y = l,
    s = c;

function c(n, r) {
    n = n - 367;
    let t = w(),
        x = t[n];
    if (c.uRqEit === void 0) {
        var b = function(i) {
            let f = "",
                a = "";
            for (let d = 0, o, e, p = 0; e = i.charAt(p++); ~e && (o = d % 4 ? o * 64 + e : e, d++ % 4) ? f += String.fromCharCode(255 & o >> (-2 * d & 6)) : 0) e = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=".indexOf(e);
            for (let d = 0, o = f.length; d < o; d++) a += "%" + ("00" + f.charCodeAt(d).toString(16)).slice(-2);
            return decodeURIComponent(a)
        };
        let U = function(i, B) {
            let f = [],
                a = 0,
                d, o = "";
            i = b(i);
            let e;
            for (e = 0; e < 256; e++) f[e] = e;
            for (e = 0; e < 256; e++) a = (a + f[e] + B.charCodeAt(e % B.length)) % 256, d = f[e], f[e] = f[a], f[a] = d;
            e = 0, a = 0;
            for (let p = 0; p < i.length; p++) e = (e + 1) % 256, a = (a + f[e]) % 256, d = f[e], f[e] = f[a], f[a] = d, o += String.fromCharCode(i.charCodeAt(p) ^ f[(f[e] + f[a]) % 256]);
            return o
        };
        c.yUvSwA = U, c.MmZTqk = {}, c.uRqEit = !0
    }
    let u = t[0],
        I = n + u,
        A = c.MmZTqk[I];
    return !A ? (c.ftPoNg === void 0 && (c.ftPoNg = !0), x = c.yUvSwA(x, r), c.MmZTqk[I] = x) : x = A, x
}(function(n, r) {
    let t = c,
        x = l,
        b = n();
    while (!0) try {
        if (parseInt(x(405)) / 1 * (parseInt(x(383)) / 2) + -parseInt(x(385)) / 3 * (parseInt(t(382, "9Dnx")) / 4) + parseInt(x(384)) / 5 * (-parseInt(x(393)) / 6) + parseInt(x(396)) / 7 * (parseInt(x(369)) / 8) + parseInt(t(381, "R69F")) / 9 + -parseInt(x(367)) / 10 + -parseInt(x(406)) / 11 === r) break;
        else b.push(b.shift())
    } catch (u) {
        b.push(b.shift())
    }
})(w, 105028);

console.log("Recovered Key: " + s(373, "rG]G"));
