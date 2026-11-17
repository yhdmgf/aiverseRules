/* 滑动人机验证（本地自实现，无第三方库/无 CDN/无内联脚本，兼容 CSP default-src 'self'）
   接口：
     GET  /api/captcha/challenge -> { id, bg }   bg 为缺口目标相对位置（0~1）
     POST /api/captcha/verify    -> { id, x }    成功 { ok:true, token }，失败 { ok:false }
   暴露：
     window.getCaptchaToken() -> 当前已通过的 token（未通过返回 ''）
     window.resetCaptcha()    -> 重新拉取 challenge 并重置滑块
*/
(function () {
  'use strict';

  var HANDLE = 44; // 滑块把手宽度（px），需与 style.css 一致

  var box = document.getElementById('captcha-box');
  var puzzleEl = document.getElementById('captcha-puzzle');
  var gapEl = document.getElementById('captcha-gap');
  var pieceEl = document.getElementById('captcha-piece');
  var trackEl = document.getElementById('captcha-track');
  var fillEl = document.getElementById('captcha-fill');
  var handleEl = document.getElementById('captcha-handle');
  var hintEl = document.getElementById('captcha-hint');
  var statusEl = document.getElementById('captcha-status');
  var refreshBtn = document.getElementById('captcha-refresh');

  var token = '';
  var challengeId = '';
  var totpRequired = false; // 服务端是否已配置 TOTP（challenge 下发）
  var bg = 0;
  var dragging = false;
  var startX = 0;
  var verified = false;

  // 把手可动最大行程（px）
  function maxX() {
    return Math.max(1, (trackEl.clientWidth || 1) - HANDLE);
  }

  // 拼图块中心跟随把手实际像素位置，确保"拼图块中心 == 缺口中心"时提交的 x == 缺口 bg。
  // 统一坐标系：元素中心相对轨道宽度的比例（与 CSS 的 left百分比 + translateX(-50%) 一致）。
  function setPiece(p) {
    p = Math.max(0, Math.min(1, p));
    var trackW = trackEl.clientWidth || 1;
    var handleX = maxX() * p;      // 把手左边缘（px）
    handleEl.style.left = handleX + 'px';
    fillEl.style.width = (handleX + HANDLE) + 'px';
    var pieceCenter = handleX + HANDLE / 2;   // 拼图块中心跟随把手
    pieceEl.style.left = (pieceCenter / trackW * 100) + '%';
  }

  function setVerifiedUI() {
    box.classList.add('is-verified');
    hintEl.textContent = '验证通过';
    setStatus('✓ 验证通过', 'ok');
  }

  function setStatus(text, kind) {
    statusEl.textContent = text;
    statusEl.className = 'captcha-status' + (kind ? ' captcha-status-' + kind : '');
    statusEl.hidden = false;
  }

  function clearStatus() {
    statusEl.textContent = '';
    statusEl.hidden = true;
  }

  function resetSlider() {
    verified = false;
    token = '';
    box.classList.remove('is-verified');
    box.classList.remove('is-dragging');
    handleEl.style.left = '0px';
    fillEl.style.width = HANDLE + 'px';
    setPiece(0);
    hintEl.textContent = '按住滑块拖动，对齐缺口';
  }

  function renderChallenge(data) {
    challengeId = data.id || '';
    bg = typeof data.bg === 'number' ? data.bg : 0;
    totpRequired = !!data.totp_required;
    gapEl.style.left = (bg * 100) + '%';
    resetSlider();
  }

  function refreshChallenge() {
    token = '';
    challengeId = '';
    box.classList.remove('is-verified');
    clearStatus();
    return fetch('/api/captcha/challenge', { credentials: 'same-origin' })
      .then(function (res) {
        if (!res.ok) { throw new Error('获取验证码失败 (' + res.status + ')'); }
        return res.json();
      })
      .then(function (data) {
        renderChallenge(data || {});
      })
      .catch(function (err) {
        setStatus(err.message || '获取验证码失败，请点“换一个”重试', 'err');
      });
  }

  function verify(x) {
    return fetch('/api/captcha/verify', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: challengeId, x: x })
    }).then(function (res) {
      if (!res.ok) { throw new Error('验证失败 (' + res.status + ')'); }
      return res.json();
    });
  }

  function onDown(e) {
    if (verified) { return; }
    if (!challengeId) { refreshChallenge(); return; }
    dragging = true;
    startX = (e.touches ? e.touches[0].clientX : e.clientX);
    box.classList.add('is-dragging');
    e.preventDefault();
  }

  function onMove(e) {
    if (!dragging) { return; }
    var clientX = (e.touches ? e.touches[0].clientX : e.clientX);
    var dx = clientX - startX;
    var x = Math.max(0, Math.min(maxX(), dx));
    var p = x / maxX();
    setPiece(p);
    if (e.cancelable) { e.preventDefault(); }
  }

  function onUp() {
    if (!dragging) { return; }
    dragging = false;
    box.classList.remove('is-dragging');

    var trackW = trackEl.clientWidth || 1;
    var handleLeft = parseFloat(handleEl.style.left || '0');
    // 提交"拼图块中心相对轨道宽度"的比例，与后端缺口 bg 同一定义
    var x = (handleLeft + HANDLE / 2) / trackW;

    verify(x).then(function (data) {
      if (data && data.ok && data.token) {
        verified = true;
        token = data.token;
        setVerifiedUI();
      } else {
        setStatus('验证未通过，请重试', 'err');
        refreshChallenge();
      }
    }).catch(function (err) {
      setStatus(err.message || '验证失败，请重试', 'err');
      refreshChallenge();
    });
  }

  handleEl.addEventListener('mousedown', onDown);
  handleEl.addEventListener('touchstart', onDown, { passive: false });
  document.addEventListener('mousemove', onMove);
  document.addEventListener('touchmove', onMove, { passive: false });
  document.addEventListener('mouseup', onUp);
  document.addEventListener('touchend', onUp);
  document.addEventListener('touchcancel', onUp);

  refreshBtn.addEventListener('click', function () {
    refreshChallenge();
  });

  window.getCaptchaToken = function () {
    return verified ? token : '';
  };
  // 服务端是否要求动态码（未配置 TOTP 密钥时为 false，前端不强制）
  window.isTOTPRequired = function () {
    return totpRequired;
  };
  window.resetCaptcha = function () {
    refreshChallenge();
  };

  refreshChallenge();
})();
