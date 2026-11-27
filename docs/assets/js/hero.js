/*
 * Mirage landing hero — the mirage diamond in raw WebGL: a rotating
 * octahedron wireframe, a flat-shaded inner octahedron at 55%, and ~180
 * dust points in depth fog. Token colors; one static frame under reduced
 * motion; pauses when hidden or scrolled out; no WebGL / lost context →
 * static mark (.hero-no-webgl), never recovered.
 */
(function () {
  "use strict";

  var SPIN = 0.06, SWAY = 0.3, SWAY_AMP = 0.05, INNER = 0.55, EYE_Z = 6.2,
      DUST = 180, STATIC_T = 17.3, FOG = [6, 10.5];

  var hero = document.querySelector(".hero");
  if (!hero) return; // no hero here (404): done

  var canvas = document.createElement("canvas");
  canvas.className = "hero-canvas";
  canvas.setAttribute("aria-hidden", "true");

  var ctxOpts = { alpha: true, antialias: true, depth: false };
  var gl = canvas.getContext("webgl2", ctxOpts) || canvas.getContext("webgl", ctxOpts) ||
           canvas.getContext("experimental-webgl", ctxOpts);
  if (!gl) {
    hero.classList.add("hero-no-webgl");
    console.warn("mirage hero: no WebGL");
    return;
  }

  // Shaders (GLSL ES 1.00 — runs on WebGL1 and 2).
  var VS_LINE = `
  attribute vec3 aPos;
  uniform mat4 uVP, uModel;
  uniform float uScale;
  varying float vDist;
  void main() {
    vec4 cp = uVP * (uModel * vec4(aPos * uScale, 1.0));
    vDist = cp.w;
    gl_Position = cp;
  }`;
  var FS_LINE = `
  precision mediump float;
  uniform vec4 uColor;
  uniform vec2 uFog;
  varying float vDist;
  void main() {
    float a = uColor.a * (1.0 - smoothstep(uFog.x, uFog.y, vDist));
    gl_FragColor = vec4(uColor.rgb, a);
  }`;
  var VS_FACE = `
  attribute vec3 aPos, aNrm;
  uniform mat4 uVP, uModel;
   uniform float uScale;
  varying float vDist;
  varying vec3 vNrm;
  void main() {
    vec4 cp = uVP * (uModel * vec4(aPos * uScale, 1.0));
    vDist = cp.w;
    vNrm = (uModel * vec4(aNrm, 0.0)).xyz;
    gl_Position = cp;
  }`;
  var FS_FACE = `
  precision mediump float;
  uniform vec4 uColor;
  uniform vec3 uBg;
  uniform vec2 uFog;
  varying float vDist;
  varying vec3 vNrm;
  void main() {
    float lit = 0.35 + 0.65 * max(dot(normalize(vNrm), vec3(0.4, 0.7, 0.55)), 0.0);
    float fog = smoothstep(uFog.x, uFog.y, vDist);
    gl_FragColor = vec4(mix(uColor.rgb * lit, uBg, fog), uColor.a * (1.0 - 0.9 * fog));
  }`;
  var VS_POINT = `
  attribute vec4 aPos;
  uniform mat4 uVP;
  uniform float uTime, uDpr;
  varying float vDist, vMix, vA;
  void main() {
    float s = aPos.w;
    vec3 p = aPos.xyz;
    p.x += 0.16 * sin(uTime * 0.10 + s * 6.2832);
    p.y += 0.12 * sin(uTime * 0.07 + s * 12.566);
    p.z += 0.10 * sin(uTime * 0.05 + s * 25.133);
    vec4 cp = uVP * vec4(p, 1.0);
    vDist = cp.w;
    vMix = step(0.5, fract(s * 7.31));
    vA = (0.7 + 0.3 * sin(uTime * 0.5 + s * 40.0)) * (0.30 + 0.45 * s);
    gl_PointSize = clamp(26.0 / max(cp.w, 0.1), 1.0, 7.0) * uDpr;
    gl_Position = cp;
  }`;
  var FS_POINT = `
  precision mediump float;
  uniform vec3 uColA, uColB;
  uniform vec2 uFog;
  varying float vDist, vMix, vA;
  void main() {
    vec2 q = gl_PointCoord * 2.0 - 1.0;
    float r2 = dot(q, q);
    if (r2 > 1.0) discard;
    float a = vA * (1.0 - r2) * (1.0 - smoothstep(uFog.x, uFog.y, vDist));
    gl_FragColor = vec4(mix(uColA, uColB, vMix), a);
  }`;

  // GL uniform aliases.
  var uM = gl.uniformMatrix4fv.bind(gl), u1 = gl.uniform1f.bind(gl),
      u4 = gl.uniform4f.bind(gl), u2v = gl.uniform2fv.bind(gl),
      u3v = gl.uniform3fv.bind(gl);

  function compile(type, src) {
    var s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
  }
  function program(vs, fs, us, as) {
    var v = compile(gl.VERTEX_SHADER, vs), f = compile(gl.FRAGMENT_SHADER, fs),
        p = gl.createProgram(), u = {}, a = {}, i;
    if (!v || !f) return null;
    gl.attachShader(p, v);
    gl.attachShader(p, f);
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) return null;
    for (i = 0; i < us.length; i++) u[us[i]] = gl.getUniformLocation(p, us[i]);
    for (i = 0; i < as.length; i++) a[as[i]] = gl.getAttribLocation(p, as[i]);
    return { p: p, u: u, a: a };
  }

  var LP = program(VS_LINE, FS_LINE, ["uVP","uModel","uScale","uColor","uFog"], ["aPos"]);
  var FP = program(VS_FACE, FS_FACE, ["uVP","uModel","uScale","uColor","uBg","uFog"], ["aPos","aNrm"]);
  var DP = program(VS_POINT, FS_POINT, ["uVP","uTime","uDpr","uColA","uColB","uFog"], ["aPos"]);
  if (!LP || !FP || !DP) {
    hero.classList.add("hero-no-webgl");
    return;
  }

  function buffer(data) {
    var b = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, b);
    gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
    return b;
  }
  function attr(p, name, buf, size, stride, off) {
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.enableVertexAttribArray(p.a[name]);
    gl.vertexAttribPointer(p.a[name], size, gl.FLOAT, false, stride, off);
  }

  // Octahedron: 6 vertices, 12 edges (skip the 3 opposite pairs).
  var V = [[1,0,0],[-1,0,0],[0,1,0],[0,-1,0],[0,0,1],[0,0,-1]], lineData = [], i, j;
  for (i = 0; i < 6; i++) for (j = i + 1; j < 6; j++)
    if ((i >> 1) !== (j >> 1))
      lineData.push(V[i][0],V[i][1],V[i][2],V[j][0],V[j][1],V[j][2]);
  var lineBuf = buffer(new Float32Array(lineData));

  // Inner faceted octahedron: 8 triangles, one flat normal per face.
  var faceData = [], sx, sy, sz, l;
  for (sx = -1; sx <= 1; sx += 2) for (sy = -1; sy <= 1; sy += 2) for (sz = -1; sz <= 1; sz += 2) {
    l = Math.hypot(sx, sy, sz);
    faceData.push(sx,0,0,sx/l,sy/l,sz/l, 0,sy,0,sx/l,sy/l,sz/l, 0,0,sz,sx/l,sy/l,sz/l);
  }
  var faceBuf = buffer(new Float32Array(faceData));

  // Dust: depth-spread positions, seed in component 4.
  var dustData = new Float32Array(DUST * 4), k;
  for (k = 0; k < DUST; k++) {
    dustData[k*4] = (Math.random()*2-1)*4.2;
    dustData[k*4+1] = (Math.random()*2-1)*2.4;
    dustData[k*4+2] = (Math.random()*2-1)*3.4-0.5;
    dustData[k*4+3] = Math.random();
  }
  var dustBuf = buffer(dustData);

  // Palette: design tokens, re-read on theme change.
  function parseColor(v, fb) {
    var m = /^#([0-9a-f]{6})$/i.exec(String(v || "").trim()), h;
    if (!m) return fb;
    h = m[1];
    return [parseInt(h.slice(0,2),16)/255, parseInt(h.slice(2,4),16)/255, parseInt(h.slice(4,6),16)/255];
  }
  var pal = {};
  function readPalette() {
    var cs = getComputedStyle(document.documentElement);
    pal.accent = parseColor(cs.getPropertyValue("--accent"), [0.27,0.84,0.77]);
    pal.strong = parseColor(cs.getPropertyValue("--accent-strong"), [0.44,0.94,0.87]);
    pal.faint = parseColor(cs.getPropertyValue("--faint"), [0.37,0.44,0.54]);
    pal.bg = parseColor(cs.getPropertyValue("--bg"), [0.04,0.06,0.10]);
  }
  readPalette();

  // Column-major mat4 helpers.
  function persp(fov, asp, n, f) {
    var t = 1/Math.tan(fov/2), nf = 1/(n-f);
    return new Float32Array([t/asp,0,0,0, 0,t,0,0, 0,0,(f+n)*nf,-1, 0,0,2*f*n*nf,0]);
  }
  function lookAt(ex, ey, ez) { // eye→origin, up (0,1,0)
    var zl = Math.hypot(ex, ey, ez) || 1, zx=ex/zl, zy=ey/zl, zz=ez/zl,
        xl = Math.hypot(zz, zx) || 1, xx = zz/xl, xz = -zx/xl,
        yx = zy*xz, yy = zz*xx - zx*xz, yz = -zy*xx;
    return new Float32Array([
      xx,yx,zx,0, 0,yy,zy,0, xz,yz,zz,0,
      -(xx*ex+xz*ez), -(yx*ex+yy*ey+yz*ez), -(zx*ex+zy*ey+zz*ez), 1]);
  }
  function rotX(a) { var c=Math.cos(a), s=Math.sin(a);
    return new Float32Array([1,0,0,0, 0,c,s,0, 0,-s,c,0, 0,0,0,1]); }
  function rotY(a) { var c=Math.cos(a), s=Math.sin(a);
    return new Float32Array([c,0,-s,0, 0,1,0,0, s,0,c,0, 0,0,0,1]); }
  function mul(a, b) {
    var o = new Float32Array(16), c, r;
    for (c = 0; c < 4; c++) for (r = 0; r < 4; r++)
      o[c*4+r] = a[r]*b[c*4] + a[4+r]*b[c*4+1] + a[8+r]*b[c*4+2] + a[12+r]*b[c*4+3];
    return o;
  }

  var proj = null, dpr = 1;

  function draw(t) {
    if (!proj) return;
    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    var model = mul(rotX(Math.sin(t*SWAY)*SWAY_AMP), rotY(t*SPIN)),
        vp = mul(proj, lookAt(px, py, EYE_Z)), F = FP, L = LP, D = DP;

    // inner faceted octahedron: flat-shaded, very subtle fill
    gl.useProgram(F.p);
    uM(F.u.uVP, false, vp);
    uM(F.u.uModel, false, model);
    u1(F.u.uScale, INNER);
    u4(F.u.uColor, pal.accent[0], pal.accent[1], pal.accent[2], 0.06);
    u3v(F.u.uBg, pal.bg);
    u2v(F.u.uFog, FOG);
    attr(F, "aPos", faceBuf, 3, 24, 0);
    attr(F, "aNrm", faceBuf, 3, 24, 12);
    gl.blendFuncSeparate(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA, gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
    gl.drawArrays(gl.TRIANGLES, 0, 24);
    gl.disableVertexAttribArray(F.a.aNrm);

    // wireframes, additive: inner then outer
    gl.useProgram(L.p);
    uM(L.u.uVP, false, vp);
    uM(L.u.uModel, false, model);
    u2v(L.u.uFog, FOG);
    attr(L, "aPos", lineBuf, 3, 12, 0);
    gl.blendFuncSeparate(gl.SRC_ALPHA, gl.ONE, gl.ONE, gl.ONE);
    u1(L.u.uScale, INNER);
    u4(L.u.uColor, pal.strong[0], pal.strong[1], pal.strong[2], 0.5);
    gl.drawArrays(gl.LINES, 0, 24);
    u1(L.u.uScale, 1);
    u4(L.u.uColor, pal.accent[0], pal.accent[1], pal.accent[2], 0.42);
    gl.drawArrays(gl.LINES, 0, 24);

    // dust: additive round sprites, drifting in the shader
    gl.useProgram(D.p);
    uM(D.u.uVP, false, vp);
    u1(D.u.uTime, t);
    u1(D.u.uDpr, dpr);
    u2v(D.u.uFog, FOG);
    u3v(D.u.uColA, pal.accent);
    u3v(D.u.uColB, pal.faint);
    attr(D, "aPos", dustBuf, 4, 16, 0);
    gl.drawArrays(gl.POINTS, 0, DUST);
  }

  function resize() {
    var w = canvas.clientWidth, h = canvas.clientHeight;
    if (!w || !h) return;
    dpr = Math.min(window.devicePixelRatio || 1, 1.75);
    var fw = Math.round(w*dpr), fh = Math.round(h*dpr);
    if (canvas.width !== fw || canvas.height !== fh) { canvas.width = fw; canvas.height = fh; }
    gl.viewport(0, 0, fw, fh);
    proj = persp(38*Math.PI/180, w/h, 0.1, 40);
    if (!running) draw(t);
  }

  // Loop + pause conditions.
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  var t = reduced.matches ? STATIC_T : 0;
  var running = false, raf = 0, last = 0, inView = true, lost = false;
  var px = 0, py = 0, tx = 0, ty = 0;

  function frame(now) {
    if (!running) { raf = 0; return; }
    var dt = Math.min(Math.max(now - last, 0), 50) / 1000;
    last = now;
    t += dt;
    px += (tx - px) * 0.04;
    py += (ty - py) * 0.04;
    draw(t);
    raf = requestAnimationFrame(frame);
  }
  function setRunning(on) {
    var want = !!on && !reduced.matches && !lost && inView && !document.hidden && !!proj;
    if (want === running) return;
    running = want;
    if (want) { last = performance.now(); raf = requestAnimationFrame(frame); }
    else if (raf) { cancelAnimationFrame(raf); raf = 0; }
  }

  // Context loss: stop, static mark. No recovery.
  canvas.addEventListener("webglcontextlost", function (e) {
    e.preventDefault();
    lost = true;
    setRunning(false);
    canvas.remove();
    if (rz) rz.disconnect();
    if (io) io.disconnect();
    if (themeObs) themeObs.disconnect();
    hero.classList.add("hero-no-webgl");
  }, false);
  document.addEventListener("visibilitychange", function () { setRunning(!document.hidden); });

  var io = new IntersectionObserver(function (en) {
    inView = en[0].isIntersecting;
    setRunning(inView);
  }, { threshold: 0 });
  io.observe(hero);

  var themeObs = new MutationObserver(function () {
    readPalette();
    if (!running) draw(t); // keep a paused frame in the right colors
  });
  themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

  // Parallax: fine pointers only, eased toward ±0.35 units.
  if (window.matchMedia("(pointer: fine)").matches && !reduced.matches) {
    window.addEventListener("pointermove", function (e) {
      tx = (e.clientX / window.innerWidth * 2 - 1) * 0.35;
      ty = (1 - e.clientY / window.innerHeight * 2) * 0.35;
    }, { passive: true });
  }

  // Mount.
  hero.insertBefore(canvas, hero.firstChild);
  gl.disable(gl.DEPTH_TEST);
  gl.enable(gl.BLEND);

  var rz = new ResizeObserver(resize);
  rz.observe(canvas);
  resize(); // first sizing + first frame
  setRunning(true);
})();
