/* 算术人机验证（本地自实现，无第三方库/无 CDN/无内联脚本，兼容 CSP default-src 'self'）
   接口：
     GET  /api/captcha/challenge -> { id, question, totp_required }   question 为算术题（如 "7+5"）
     POST /api/captcha/verify    -> { id, answer }                    成功 { ok:true, token }，失败 { ok:false }
   暴露：
     window.getCaptchaToken() -> 当前已通过的 token（未通过返回 ''）
     window.resetCaptcha()    -> 重新拉取题目并清空输入
     window.isTOTPRequired()  -> 服务端是否已配置 TOTP（未配置时前端不强制动态码）
*/
(function () {
  'use strict';

  var box = document.getElementById('captcha-box');
  var questionEl = document.getElementById('captcha-question');
  var answerEl = document.getElementById('captcha-answer');
  var statusEl = document.getElementById('captcha-status');
  var refreshBtn = document.getElementById('captcha-refresh');

  var token = '';
  var challengeId = '';
  var totpRequired = false; // 服务端是否已配置 TOTP（challenge 下发）
  var verified = false;

  function setStatus(text, kind) {
    statusEl.textContent = text;
    statusEl.className = 'captcha-status' + (kind ? ' captcha-status-' + kind : '');
    statusEl.hidden = false;
  }

  function clearStatus() {
    statusEl.textContent = '';
    statusEl.hidden = true;
  }

  function setVerifiedUI() {
    box.classList.add('is-verified');
    questionEl.textContent = '✓ 已通过';
    answerEl.disabled = true;
    setStatus('验证通过', 'ok');
  }

  function resetUI() {
    verified = false;
    token = '';
    box.classList.remove('is-verified');
    answerEl.value = '';
    answerEl.disabled = false;
  }

  function renderChallenge(data) {
    challengeId = (data && data.id) || '';
    totpRequired = !!(data && data.totp_required);
    resetUI();
    questionEl.textContent = (data && data.question) ? data.question + ' = ?' : '加载失败，请点“换一个”';
    clearStatus();
  }

  function refreshChallenge() {
    token = '';
    challengeId = '';
    box.classList.remove('is-verified');
    answerEl.disabled = false;
    clearStatus();
    questionEl.textContent = '加载中…';
    return fetch('/api/captcha/challenge', { credentials: 'same-origin' })
      .then(function (res) {
        if (!res.ok) { throw new Error('获取验证题失败 (' + res.status + ')'); }
        return res.json();
      })
      .then(function (data) {
        renderChallenge(data || {});
        if (!verified) { answerEl.focus(); }
      })
      .catch(function (err) {
        questionEl.textContent = '加载失败';
        setStatus(err.message || '获取验证题失败，请点“换一个”重试', 'err');
      });
  }

  function verify() {
    if (verified) { return Promise.resolve(); }
    if (!challengeId) { return refreshChallenge(); }
    var answer = answerEl.value.trim();
    if (!/^\d+$/.test(answer)) {
      setStatus('请输入算式结果（数字）', 'err');
      answerEl.focus();
      return Promise.resolve();
    }
    return fetch('/api/captcha/verify', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: challengeId, answer: answer })
    }).then(function (res) {
      if (!res.ok) { throw new Error('验证失败 (' + res.status + ')'); }
      return res.json();
    }).then(function (data) {
      if (data && data.ok && data.token) {
        verified = true;
        token = data.token;
        setVerifiedUI();
      } else {
        setStatus('答案不对，已换一题，请重试', 'err');
        refreshChallenge();
      }
    }).catch(function (err) {
      setStatus(err.message || '验证失败，请重试', 'err');
      refreshChallenge();
    });
  }

  // 输入框回车即校验
  answerEl.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !verified) {
      e.preventDefault();
      verify();
    }
  });
  // 重新输入时清掉错误提示
  answerEl.addEventListener('input', function () {
    if (!verified) { clearStatus(); }
  });

  refreshBtn.addEventListener('click', refreshChallenge);

  window.getCaptchaToken = function () {
    return verified ? token : '';
  };
  window.isTOTPRequired = function () {
    return totpRequired;
  };
  window.resetCaptcha = function () {
    refreshChallenge();
  };

  refreshChallenge();
})();
