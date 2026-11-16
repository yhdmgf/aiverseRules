/* 插件商店审核后台前端逻辑（原生 JS，无框架依赖） */
(function () {
  'use strict';

  // 已审核状态集合
  var DONE = { approved: true, rejected: true };

  var state = {
    tab: 'pending', // pending | done
    items: [],
    rejectId: null
  };

  // ---------- DOM ----------
  var loginView = document.getElementById('login-view');
  var adminView = document.getElementById('admin-view');
  var loginForm = document.getElementById('login-form');
  var loginError = document.getElementById('login-error');
  var loginBtn = document.getElementById('login-btn');
  var logoutBtn = document.getElementById('logout-btn');
  var currentUser = document.getElementById('current-user');
  var listEl = document.getElementById('list');
  var countPending = document.getElementById('count-pending');
  var countDone = document.getElementById('count-done');

  // ---------- API 封装 ----------
  function api(path, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    opts.headers = opts.headers || {};
    if (opts.body && typeof opts.body !== 'string') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(path, opts).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var err = new Error(data.error || ('请求失败 (' + res.status + ')'));
          err.status = res.status;
          throw err;
        }
        return data;
      });
    });
  }

  // ---------- 视图切换 ----------
  function showLogin() {
    loginView.hidden = false;
    adminView.hidden = true;
  }
  function showAdmin(user) {
    loginView.hidden = true;
    adminView.hidden = false;
    currentUser.textContent = user ? ('当前用户：' + user) : '';
  }

  // ---------- 启动：探测登录态 ----------
  function bootstrap() {
    api('/api/queue').then(function () {
      showAdmin('');
      load();
    }).catch(function () {
      showLogin();
    });
  }

  // ---------- 登录/退出 ----------
  loginForm.addEventListener('submit', function (e) {
    e.preventDefault();
    loginError.hidden = true;
    loginBtn.disabled = true;
    var username = document.getElementById('login-user').value.trim();
    var password = document.getElementById('login-pass').value;
    api('/api/login', { method: 'POST', body: { username: username, password: password } })
      .then(function (data) {
        showAdmin(data.user || username);
        load();
      })
      .catch(function (err) {
        loginError.textContent = err.message;
        loginError.hidden = false;
      })
      .finally(function () {
        loginBtn.disabled = false;
        document.getElementById('login-pass').value = '';
      });
  });

  logoutBtn.addEventListener('click', function () {
    api('/api/logout', { method: 'POST' }).finally(function () {
      showLogin();
    });
  });

  // ---------- 数据加载与渲染 ----------
  function load() {
    listEl.innerHTML = '<p class="muted loading">加载中…</p>';
    return api('/api/queue').then(function (data) {
      state.items = data.items || [];
      render();
    }).catch(function (err) {
      if (err.status === 401) { showLogin(); return; }
      listEl.innerHTML = '<p class="error">' + escapeHtml(err.message) + '</p>';
    });
  }

  function render() {
    var pending = state.items.filter(function (it) { return it.status === 'pending'; });
    var done = state.items.filter(function (it) { return DONE[it.status]; });
    countPending.textContent = pending.length;
    countDone.textContent = done.length;

    var shown = state.tab === 'pending' ? pending : done;
    if (!shown.length) {
      listEl.innerHTML = '<p class="empty">暂无' + (state.tab === 'pending' ? '待审核' : '已审核') + '插件</p>';
      return;
    }
    listEl.innerHTML = '';
    shown.forEach(function (it) {
      listEl.appendChild(renderItem(it));
    });
  }

  function renderItem(it) {
    var el = document.createElement('div');
    el.className = 'item';

    var head = document.createElement('div');
    head.className = 'item-head';
    head.innerHTML =
      '<span class="item-title">' + escapeHtml(it.name || it.id) + '</span>' +
      '<span class="status status-' + it.status + '">' + statusText(it.status) + '</span>';
    el.appendChild(head);

    var meta = document.createElement('div');
    meta.className = 'item-meta';
    meta.innerHTML =
      '<span class="item-id">' + escapeHtml(it.id) + '</span>' +
      '<span>v' + escapeHtml(it.version || '') + '</span>' +
      '<span>上传者：' + escapeHtml(it.uploader || 'anonymous') + '</span>' +
      '<span>' + formatTime(it.uploaded_at) + '</span>' +
      (it.size ? '<span>' + formatSize(it.size) + '</span>' : '');
    el.appendChild(meta);

    // 已拒绝时展示原因
    if (it.status === 'rejected' && it.reject_reason) {
      var rb = document.createElement('div');
      rb.className = 'reason-box';
      rb.textContent = '拒绝原因：' + it.reject_reason;
      el.appendChild(rb);
    }
    // 已审核时展示审核人
    if (DONE[it.status] && it.reviewed_by) {
      var rev = document.createElement('div');
      rev.className = 'item-meta';
      rev.innerHTML = '<span>审核人：' + escapeHtml(it.reviewed_by) + '</span>' +
        '<span>' + formatTime(it.reviewed_at) + '</span>';
      el.appendChild(rev);
    }

    // 待审核才显示操作按钮
    if (it.status === 'pending') {
      var actions = document.createElement('div');
      actions.className = 'item-actions';
      var approveBtn = mkBtn('通过并发布', 'btn btn-approve');
      var rejectBtn = mkBtn('拒绝', 'btn btn-danger');
      approveBtn.addEventListener('click', function () { approve(it.id, approveBtn, rejectBtn); });
      rejectBtn.addEventListener('click', function () { openReject(it); });
      actions.appendChild(approveBtn);
      actions.appendChild(rejectBtn);
      el.appendChild(actions);
    }
    return el;
  }

  function mkBtn(text, cls) {
    var b = document.createElement('button');
    b.className = cls;
    b.textContent = text;
    return b;
  }

  // ---------- 操作 ----------
  function approve(id, approveBtn, rejectBtn) {
    if (!confirm('确认通过并发布插件 ' + id + ' 到商店仓库？')) return;
    approveBtn.disabled = true;
    rejectBtn.disabled = true;
    approveBtn.textContent = '发布中…';
    api('/api/approve', { method: 'POST', body: { id: id } })
      .then(function (data) {
        alert(data.message || '发布成功');
        load();
      })
      .catch(function (err) {
        alert('发布失败：' + err.message);
        approveBtn.disabled = false;
        rejectBtn.disabled = false;
        approveBtn.textContent = '通过并发布';
      });
  }

  var rejectDialog = document.getElementById('reject-dialog');
  var rejectForm = document.getElementById('reject-form');
  var rejectReason = document.getElementById('reject-reason');
  var rejectTarget = document.getElementById('reject-target');

  function openReject(it) {
    state.rejectId = it.id;
    rejectTarget.textContent = it.id + ' v' + (it.version || '');
    rejectReason.value = '';
    if (typeof rejectDialog.showModal === 'function') {
      rejectDialog.showModal();
    } else {
      rejectDialog.setAttribute('open', '');
    }
  }

  document.getElementById('reject-cancel').addEventListener('click', function () {
    rejectDialog.close ? rejectDialog.close() : rejectDialog.removeAttribute('open');
  });

  rejectForm.addEventListener('submit', function (e) {
    e.preventDefault();
    var id = state.rejectId;
    var reason = rejectReason.value.trim();
    api('/api/reject', { method: 'POST', body: { id: id, reason: reason } })
      .then(function () {
        rejectDialog.close ? rejectDialog.close() : rejectDialog.removeAttribute('open');
        load();
      })
      .catch(function (err) {
        alert('拒绝失败：' + err.message);
      });
  });

  // ---------- tabs ----------
  Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (tab) {
    tab.addEventListener('click', function () {
      Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (t) {
        t.classList.remove('active');
      });
      tab.classList.add('active');
      state.tab = tab.getAttribute('data-tab');
      render();
    });
  });

  // ---------- 工具 ----------
  function statusText(s) {
    return { pending: '待审核', approved: '已通过', rejected: '已拒绝' }[s] || s;
  }
  function formatTime(ts) {
    if (!ts) return '';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString('zh-CN');
  }
  function formatSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  bootstrap();
})();
