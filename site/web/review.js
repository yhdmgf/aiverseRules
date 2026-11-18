/* 插件商店审核后台前端逻辑（原生 JS，无框架依赖） */
(function () {
  'use strict';

  // 已审核状态集合
  var DONE = { approved: true, rejected: true };

  var state = {
    tab: 'all', // all | pending | done | audit | security | stats
    items: [],
    published: [],
    rejectId: null,
    unpublishId: null,
    unpublishVersion: null,
    // 搜索/筛选
    search: { q: '', status: '', from: '', to: '' },
    searchTimer: null,
    // 批量勾选（存插件 id）
    selected: [],
    // 包内容预览
    previewId: null,
    previewTree: null,
    previewPath: null,
    // IP 黑名单
    banned: []
  };

  // ---------- DOM ----------
  var loginView = document.getElementById('login-view');
  var adminView = document.getElementById('admin-view');
  var loginForm = document.getElementById('login-form');
  var loginError = document.getElementById('login-error');
  var loginBtn = document.getElementById('login-btn');
  var logoutBtn = document.getElementById('logout-btn');
  var listEl = document.getElementById('list');
  var auditListEl = document.getElementById('audit-list');
  var statsListEl = document.getElementById('stats-list');
  var authorsPanel = document.getElementById('authors-panel');
  var authorsListEl = document.getElementById('authors-list');
  var authorSearchForm = document.getElementById('author-search-form');
  var authorSearchInput = document.getElementById('author-search');
  var allListEl = document.getElementById('all-list');
  var countPending = document.getElementById('count-pending');
  var countDone = document.getElementById('count-done');
  var countAll = document.getElementById('count-all');
  // 新增：搜索 / 批量 / 预览 / 安全
  var searchBar = document.getElementById('search-bar');
  var selectAllEl = document.getElementById('select-all');
  var searchForm = document.getElementById('search-form');
  var searchQ = document.getElementById('search-q');
  var searchStatus = document.getElementById('search-status');
  var searchFrom = document.getElementById('search-from');
  var searchTo = document.getElementById('search-to');
  var batchResultEl = document.getElementById('batch-result');
  var batchBar = document.getElementById('batch-bar');
  var batchCount = document.getElementById('batch-count');
  var previewPanel = document.getElementById('preview-panel');
  var previewTarget = document.getElementById('preview-target');
  var previewManifest = document.getElementById('preview-manifest');
  var previewTreeEl = document.getElementById('preview-tree');
  var previewPathEl = document.getElementById('preview-file-path');
  var previewContentEl = document.getElementById('preview-content');
  var previewStatus = document.getElementById('preview-status');
  var previewSaveBtn = document.getElementById('preview-save');
  var securityPanel = document.getElementById('security-panel');
  var banForm = document.getElementById('ban-form');
  var banTableWrap = document.getElementById('ban-table-wrap');

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
          err.data = data;
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
  }

  // ---------- 启动：探测登录态 ----------
  function bootstrap() {
    api('/api/published').then(function () {
      showAdmin('');
      loadPublished();
    }).catch(function () {
      showLogin();
    });
  }

  // ---------- 登录/退出 ----------
  loginForm.addEventListener('submit', function (e) {
    e.preventDefault();
    loginError.hidden = true;

    var username = document.getElementById('login-user').value.trim();
    var password = document.getElementById('login-pass').value;
    var totp = document.getElementById('login-totp').value.trim();
    var captchaToken = (window.getCaptchaToken ? window.getCaptchaToken() : '');

    // 前端预校验：算术验证已通过；动态码仅当服务端要求时校验 6 位
    var totpRequired = !!(window.isTOTPRequired && window.isTOTPRequired());
    if (totpRequired && !/^\d{6}$/.test(totp)) {
      loginError.textContent = '请输入 6 位数字动态码';
      loginError.hidden = false;
      document.getElementById('login-totp').focus();
      return;
    }
    if (!captchaToken) {
      var ansVal = document.getElementById('captcha-answer').value.trim();
      loginError.textContent = ansVal
        ? '答案已填，请点“确认”完成人机验证'
        : '请先完成人机验证（填算式结果后点“确认”）';
      loginError.hidden = false;
      return;
    }

    loginBtn.disabled = true;
    api('/api/login', {
      method: 'POST',
      body: {
        username: username,
        password: password,
        totp: totp,
        captcha_token: captchaToken
      }
    })
      .then(function (data) {
        var ok = document.getElementById('login-success');
        ok.textContent = '✓ 登录成功，正在进入审核后台…';
        ok.hidden = false;
        setTimeout(function () {
          showAdmin(data.user || username);
          loadPublished();
        }, 700);
      })
      .catch(function (err) {
        var raw = err && err.data ? err.data : {};
        if (raw.locked) {
          var mins = lockedMinutes(raw.locked_until);
          loginError.textContent = '账号已锁定，请 ' + mins + ' 分钟后再试';
        } else {
          loginError.textContent = err.message;
        }
        loginError.hidden = false;
        var msg = err && err.message ? err.message : '';
        // 按错误类型只清对应字段，不清全部，方便用户只改错的那项重试。
        // 人机验证 token 在密码/动态码错误时保持有效（后端仅校验不消费），所以保留“已通过”状态。
        if (msg.indexOf('动态码') !== -1) {
          // 动态码错：仅清动态码，保留密码与人机验证
          document.getElementById('login-totp').value = '';
          document.getElementById('login-totp').focus();
        } else if (msg.indexOf('密码') !== -1 || msg.indexOf('用户名') !== -1) {
          // 用户名/密码错：仅清密码（用户名保留便于重试），保留人机验证与动态码
          document.getElementById('login-pass').value = '';
          document.getElementById('login-pass').focus();
        } else if (msg.indexOf('人机验证') !== -1 || msg.indexOf('验证码') !== -1) {
          // 人机验证未通过：重置算术题
          if (window.resetCaptcha) { window.resetCaptcha(); }
        } else {
          // 其他未知错误：保守清空密码与动态码，保留人机验证
          document.getElementById('login-pass').value = '';
          document.getElementById('login-totp').value = '';
        }
      })
      .finally(function () {
        setTimeout(function () { loginBtn.disabled = false; }, 700);
      });
  });

  // 计算锁定剩余分钟（至少 1）
  function lockedMinutes(rfc3339) {
    var t = rfc3339 ? new Date(rfc3339).getTime() : NaN;
    if (isNaN(t)) { return 1; }
    var diff = Math.ceil((t - Date.now()) / 60000);
    return diff > 0 ? diff : 1;
  }

  logoutBtn.addEventListener('click', function () {
    if (!window.confirm('确定退出登录吗？')) { return; }
    api('/api/logout', { method: 'POST' }).finally(function () {
      showLogin();
      var ok = document.getElementById('login-success');
      if (ok) {
        ok.textContent = '✓ 已退出登录';
        ok.hidden = false;
      }
    });
  });

  // ---------- 数据加载与渲染 ----------
  function loadPublished() {
    showContainer('all');
    allListEl.innerHTML = '<p class="muted loading">加载中…</p>';
    return api('/api/published').then(function (data) {
      state.published = data.items || [];
      countAll.textContent = state.published.length;
      renderPublished();
    }).catch(function (err) {
      if (err.status === 401) { showLogin(); return; }
      countAll.textContent = '0';
      allListEl.innerHTML = '<p class="error">' + escapeHtml(err.message) + '</p>';
    });
  }

  function renderPublished() {
    var items = state.published;
    if (!items.length) {
      allListEl.innerHTML = '<p class="empty">暂无已发布插件</p>';
      return;
    }
    allListEl.innerHTML = '';
    items.forEach(function (it) {
      allListEl.appendChild(renderPublishedItem(it));
    });
  }

  function renderPublishedItem(it) {
    var el = document.createElement('div');
    el.className = 'item';

    var head = document.createElement('div');
    head.className = 'item-head';
    head.innerHTML =
      '<span class="item-title">' + escapeHtml(it.name_zh || it.id) + '</span>' +
      '<span class="status status-approved">已发布</span>';
    el.appendChild(head);

    var meta = document.createElement('div');
    meta.className = 'item-meta';
    meta.innerHTML =
      '<span class="item-id">' + escapeHtml(it.id) + '</span>' +
      '<span>v' + escapeHtml(it.version || '') + '</span>' +
      '<span>作者：' + escapeHtml(it.author || 'anonymous') + '</span>' +
      (it.tags && it.tags.length ? '<span>' + escapeHtml(it.tags.join(' / ')) + '</span>' : '') +
      '<span>' + formatTime(it.last_update) + '</span>';
    el.appendChild(meta);

    if (it.description_zh) {
      var desc = document.createElement('div');
      desc.className = 'reason-box';
      desc.textContent = it.description_zh;
      el.appendChild(desc);
    }

    var actions = document.createElement('div');
    actions.className = 'item-actions';
    var downloadBtn = mkBtn('下载', 'btn btn-ghost');
    var unpublishBtn = mkBtn('下架', 'btn btn-danger');
    downloadBtn.addEventListener('click', function () { downloadPublished(it, downloadBtn); });
    unpublishBtn.addEventListener('click', function () { openUnpublish(it); });
    actions.appendChild(downloadBtn);
    actions.appendChild(unpublishBtn);
    el.appendChild(actions);
    return el;
  }

  // ---------- 下载已发布包（同源 cookie，浏览器直接下载） ----------
  function downloadPublished(it, btn) {
    if (btn) { btn.disabled = true; btn.textContent = '下载中…'; }
    var a = document.createElement('a');
    a.href = '/api/published-download?id=' + encodeURIComponent(it.id) +
      '&version=' + encodeURIComponent(it.version || '');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // 无法探测下载成败，延时恢复按钮
    setTimeout(function () {
      if (btn) { btn.disabled = false; btn.textContent = '下载'; }
    }, 1500);
  }

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
      updateBatchBar();
      updateSelectAll();
      return;
    }
    listEl.innerHTML = '';
    shown.forEach(function (it) {
      listEl.appendChild(renderItem(it));
    });
    updateBatchBar();
    updateSelectAll();
  }

  function renderItem(it) {
    var selectable = it.status === 'pending';
    var el = document.createElement('div');
    el.className = 'item' + (selectable ? ' selectable' : '') +
      (selectable && state.selected.indexOf(it.id) !== -1 ? ' selected' : '');
    if (selectable) { el.setAttribute('data-id', it.id); }

    // 批量勾选（仅待审核）：左侧 checkbox
    if (selectable) {
      var selWrap = document.createElement('div');
      selWrap.className = 'item-select';
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'item-checkbox';
      cb.checked = state.selected.indexOf(it.id) !== -1;
      cb.setAttribute('aria-label', '选择 ' + it.id);
      cb.addEventListener('change', function () {
        toggleSelect(it.id, cb.checked);
      });
      selWrap.appendChild(cb);
      el.appendChild(selWrap);
    }

    var body = document.createElement('div');
    body.className = 'item-body';
    el.appendChild(body);

    var head = document.createElement('div');
    head.className = 'item-head';
    head.innerHTML =
      '<span class="item-title">' + escapeHtml(it.name || it.id) + '</span>' +
      '<span class="status status-' + it.status + '">' + statusText(it.status) + '</span>' +
      // 更新包标记：放在状态 badge 之后，用内联样式区分（style.css 无 status-update 类）
      (it.is_update
        ? '<span class="status status-update" style="background:linear-gradient(120deg,#3451b2,#5a79e0);">更新</span>'
        : '');
    body.appendChild(head);

    var meta = document.createElement('div');
    meta.className = 'item-meta';
    meta.innerHTML =
      '<span class="item-id">' + escapeHtml(it.id) + '</span>' +
      '<span>v' + escapeHtml(it.version || '') + '</span>' +
      '<span>上传者：' + escapeHtml(it.uploader || 'anonymous') + '</span>' +
      '<span>' + formatTime(it.uploaded_at) + '</span>' +
      (it.size ? '<span>' + formatSize(it.size) + '</span>' : '');
    // 更新包且已知旧版本时展示版本变化 v旧 → v新
    if (it.is_update && it.old_version) {
      meta.innerHTML +=
        '<span style="color:var(--brand,#3451b2);">v' + escapeHtml(it.old_version) +
        ' → v' + escapeHtml(it.version || '') + '</span>';
    }
    body.appendChild(meta);

    // 已拒绝时展示原因
    if (it.status === 'rejected' && it.reject_reason) {
      var rb = document.createElement('div');
      rb.className = 'reason-box';
      rb.textContent = '拒绝原因：' + it.reject_reason;
      body.appendChild(rb);
    }
    // 已审核时展示审核人
    if (DONE[it.status] && it.reviewed_by) {
      var rev = document.createElement('div');
      rev.className = 'item-meta';
      rev.innerHTML = '<span>审核人：' + escapeHtml(it.reviewed_by) + '</span>' +
        '<span>' + formatTime(it.reviewed_at) + '</span>';
      body.appendChild(rev);
    }

    // 待审核才显示操作按钮
    if (it.status === 'pending') {
      var actions = document.createElement('div');
      actions.className = 'item-actions';
      var isUpdate = !!it.is_update;
      var approveBtn = mkBtn(isUpdate ? '更新并发布' : '通过并发布', 'btn btn-approve');
      var rejectBtn = mkBtn('拒绝', 'btn btn-danger');
      var downloadBtn = mkBtn('下载', 'btn btn-ghost');
      var inspectBtn = mkBtn('查看内容', 'btn btn-ghost');
      approveBtn.addEventListener('click', function () { approve(it, approveBtn, rejectBtn); });
      rejectBtn.addEventListener('click', function () { openReject(it); });
      downloadBtn.addEventListener('click', function () { downloadPending(it.id, downloadBtn); });
      inspectBtn.addEventListener('click', function () { togglePreview(it, inspectBtn); });
      actions.appendChild(approveBtn);
      actions.appendChild(rejectBtn);
      actions.appendChild(downloadBtn);
      actions.appendChild(inspectBtn);
      // 更新包：对比差异
      if (isUpdate) {
        var diffBtn = mkBtn('对比差异', 'btn btn-ghost');
        diffBtn.addEventListener('click', function () { openDiff(it, diffBtn); });
        actions.appendChild(diffBtn);
      }
      body.appendChild(actions);
    }
    // 已通过（发布过）的插件提供下架入口
    if (it.status === 'approved') {
      var pubActions = document.createElement('div');
      pubActions.className = 'item-actions';
      var unpublishBtn = mkBtn('下架', 'btn btn-danger');
      unpublishBtn.addEventListener('click', function () { openUnpublish(it); });
      pubActions.appendChild(unpublishBtn);
      body.appendChild(pubActions);
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
  // it 为完整 item：用 it.is_update / it.version 区分首次发布与版本更新
  function approve(it, approveBtn, rejectBtn) {
    var id = it.id;
    var isUpdate = !!it.is_update;
    var version = it.version || '';
    var confirmText = isUpdate
      ? '确认将插件 ' + id + ' 更新到 v' + version + ' 并发布？将替换仓库中旧版本。'
      : '确认通过并发布插件 ' + id + ' 到商店仓库？';
    if (!confirm(confirmText)) return;
    var busyText = isUpdate ? '更新中…' : '发布中…';
    var resetText = isUpdate ? '更新并发布' : '通过并发布';
    approveBtn.disabled = true;
    rejectBtn.disabled = true;
    approveBtn.textContent = busyText;
    api('/api/approve', { method: 'POST', body: { id: id } })
      .then(function (data) {
        alert(data.message || (isUpdate ? '更新发布成功' : '发布成功'));
        load();
      })
      .catch(function (err) {
        alert((isUpdate ? '更新失败：' : '发布失败：') + err.message);
        approveBtn.disabled = false;
        rejectBtn.disabled = false;
        approveBtn.textContent = resetText;
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

  // ---------- 下载待审核包（便于快速测试） ----------
  function downloadPending(id, btn) {
    if (btn) { btn.disabled = true; btn.textContent = '下载中…'; }
    // 走同源 cookie，直接浏览器下载
    var a = document.createElement('a');
    a.href = '/api/pending-download?id=' + encodeURIComponent(id);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // 无法探测下载成败，延时恢复按钮
    setTimeout(function () {
      if (btn) { btn.disabled = false; btn.textContent = '下载'; }
    }, 1500);
  }

  // ---------- 下架插件 ----------
  var unpublishDialog = document.getElementById('unpublish-dialog');
  var unpublishForm = document.getElementById('unpublish-form');
  var unpublishTarget = document.getElementById('unpublish-target');

  function openUnpublish(it) {
    state.unpublishId = it.id;
    state.unpublishVersion = it.version || '';
    unpublishTarget.textContent = it.id + (it.version ? ' v' + it.version : '');
    if (typeof unpublishDialog.showModal === 'function') {
      unpublishDialog.showModal();
    } else {
      unpublishDialog.setAttribute('open', '');
    }
  }

  document.getElementById('unpublish-cancel').addEventListener('click', function () {
    unpublishDialog.close ? unpublishDialog.close() : unpublishDialog.removeAttribute('open');
  });

  unpublishForm.addEventListener('submit', function (e) {
    e.preventDefault();
    var id = state.unpublishId;
    var version = state.unpublishVersion;
    var body = { id: id };
    if (version) { body.version = version; }
    var confirmBtn = document.getElementById('unpublish-confirm');
    confirmBtn.disabled = true;
    confirmBtn.textContent = '下架中…';
    api('/api/unpublish', { method: 'POST', body: body })
      .then(function (data) {
        unpublishDialog.close ? unpublishDialog.close() : unpublishDialog.removeAttribute('open');
        alert(data.message || '已下架');
        // 从哪个视图下架就从哪里刷新（“全部”视图直接重拉 index）
        if (state.tab === 'all') { loadPublished(); } else { load(); }
      })
      .catch(function (err) {
        alert('下架失败：' + err.message);
      })
      .finally(function () {
        confirmBtn.disabled = false;
        confirmBtn.textContent = '确认下架';
      });
  });

  // ---------- 上传插件（后台上传入口，需登录；multipart 提交，不走 api() 以免被强设 JSON Content-Type） ----------
  var uploadDialog = document.getElementById('upload-dialog');
  var uploadForm = document.getElementById('upload-form');
  var uploadFileEl = document.getElementById('upload-file');
  var uploadStatus = document.getElementById('upload-status');

  document.getElementById('upload-btn').addEventListener('click', function () {
    uploadStatus.hidden = true;
    uploadForm.reset();
    if (typeof uploadDialog.showModal === 'function') {
      uploadDialog.showModal();
    } else {
      uploadDialog.setAttribute('open', '');
    }
  });

  document.getElementById('upload-cancel').addEventListener('click', function () {
    uploadDialog.close ? uploadDialog.close() : uploadDialog.removeAttribute('open');
  });

  uploadForm.addEventListener('submit', function (e) {
    e.preventDefault();
    var file = uploadFileEl.files && uploadFileEl.files[0];
    if (!file) { alert('请选择插件包（.zip）'); return; }
    var submitBtn = document.getElementById('upload-submit');
    submitBtn.disabled = true;
    submitBtn.textContent = '上传中…';
    uploadStatus.hidden = false;
    uploadStatus.textContent = '正在上传，请稍候…';

    var fd = new FormData();
    fd.append('file', file);
    var uploader = (document.getElementById('upload-uploader').value || '').trim();
    if (uploader) { fd.append('uploader', uploader); }

    // multipart 上传：不设 Content-Type，让浏览器自动带 boundary
    fetch('/api/upload', { method: 'POST', credentials: 'same-origin', body: fd })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (!res.ok) {
            var err = new Error(data.error || ('上传失败 (' + res.status + ')'));
            throw err;
          }
          return data;
        });
      })
      .then(function (data) {
        uploadDialog.close ? uploadDialog.close() : uploadDialog.removeAttribute('open');
        alert((data && data.message) || '上传成功，已进入待审核队列');
        // 先刷新队列数据（拉取含新包的 /api/queue），再切到待审核 tab 查看刚上传的包。
        // 不先 load() 的话 state.items 还是旧数据，新包不会出现在待审核列表里。
        load().then(function () {
          var pendingTab = document.querySelector('.tab[data-tab="pending"]');
          if (pendingTab) { pendingTab.click(); }
        });
      })
      .catch(function (err) {
        uploadStatus.textContent = '上传失败：' + err.message;
      })
      .finally(function () {
        submitBtn.disabled = false;
        submitBtn.textContent = '提交上传';
      });
  });

  // ---------- tabs ----------
  // 容器：全部已发布 / 插件列表 / 审计日志 / 安全（IP 黑名单）/ 下载统计，随 tab 切换显隐。
  function showContainer(which) {
    allListEl.hidden = which !== 'all';
    listEl.hidden = which !== 'list';
    auditListEl.hidden = which !== 'audit';
    securityPanel.hidden = which !== 'security';
    statsListEl.hidden = which !== 'stats';
    authorsPanel.hidden = which !== 'authors';
    // 搜索/筛选栏仅 pending / done 列表显示
    if (searchBar) { searchBar.hidden = which !== 'list'; }
  }

  Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (tab) {
    tab.addEventListener('click', function () {
      Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (t) {
        t.classList.remove('active');
      });
      tab.classList.add('active');
      state.tab = tab.getAttribute('data-tab');
      closePreview();
      clearSelection();
      clearBatchResult();
      if (state.tab === 'all') {
        showContainer('all');
        loadPublished();
      } else if (state.tab === 'audit') {
        showContainer('audit');
        loadAudit();
      } else if (state.tab === 'security') {
        showContainer('security');
        loadBanned();
      } else if (state.tab === 'stats') {
        showContainer('stats');
        loadStats();
      } else if (state.tab === 'authors') {
        showContainer('authors');
        loadAuthors();
      } else {
        showContainer('list');
        runSearch();
      }
    });
  });

  // ---------- 审计日志 ----------
  function loadAudit() {
    auditListEl.innerHTML = '<p class="muted loading">加载中…</p>';
    api('/api/audit?limit=200').then(function (data) {
      renderAudit(data.items || []);
    }).catch(function (err) {
      if (err.status === 401) { showLogin(); return; }
      auditListEl.innerHTML = '<p class="error">' + escapeHtml(err.message) + '</p>';
    });
  }

  function renderAudit(items) {
    if (!items.length) {
      auditListEl.innerHTML = '<p class="empty">暂无审计记录</p>';
      return;
    }
    auditListEl.innerHTML = '';
    items.forEach(function (ev) {
      var el = document.createElement('div');
      el.className = 'item';
      var head = document.createElement('div');
      head.className = 'item-head';
      head.innerHTML =
        '<span class="item-title">' + escapeHtml(auditEventText(ev.event)) + '</span>' +
        '<span class="status ' + (ev.result === 'fail' ? 'status-rejected' : 'status-approved') + '">'
          + escapeHtml(ev.result === 'fail' ? '失败' : '成功') + '</span>';
      el.appendChild(head);
      var meta = document.createElement('div');
      meta.className = 'item-meta';
      meta.innerHTML =
        '<span>操作者：' + escapeHtml(ev.user || '—') + '</span>' +
        '<span>IP：' + escapeHtml(ev.ip || '—') + '</span>' +
        (ev.target ? '<span>目标：' + escapeHtml(ev.target) + '</span>' : '') +
        '<span>' + formatTime(ev.time) + '</span>';
      el.appendChild(meta);
      if (ev.detail) {
        var d = document.createElement('div');
        d.className = 'reason-box';
        d.textContent = ev.detail;
        el.appendChild(d);
      }
      auditListEl.appendChild(el);
    });
  }

  function auditEventText(e) {
    return {
      login: '登录',
      login_failed: '登录失败',
      approve: '审核通过并发布',
      reject: '审核拒绝',
      unpublish: '下架插件'
    }[e] || e;
  }

  // ---------- 下载量统计 ----------
  function loadStats() {
    statsListEl.innerHTML = '<p class="muted loading">加载中…</p>';
    api('/api/stats').then(function (data) {
      renderStats(data);
    }).catch(function (err) {
      if (err.status === 401) { showLogin(); return; }
      statsListEl.innerHTML = '<p class="error">' + escapeHtml(err.message) + '</p>';
    });
  }

  function renderStats(data) {
    var items = data.items || [];
    var head = '<p class="muted">' + escapeHtml(data.note || '近似值') +
      ' · 生成于 ' + formatTime(data.generated) + '</p>';
    if (data.stale) {
      head += '<p class="muted">当前为缓存数据（实时获取失败）</p>';
    }
    if (!items.length) {
      statsListEl.innerHTML = head + '<p class="empty">暂无已发布插件</p>';
      return;
    }
    var html = head;
    items.forEach(function (st) {
      var title = st.name_zh || st.id || st.file;
      var sub = st.id ? st.id + (st.version ? ' v' + st.version : '') : '';
      html +=
        '<div class="item">' +
          '<div class="item-head">' +
            '<span class="item-title">' + escapeHtml(title) + '</span>' +
            '<span class="status status-approved">' + st.unique_ips + ' 独立IP</span>' +
          '</div>' +
          '<div class="item-meta">' +
            (sub ? '<span>' + escapeHtml(sub) + '</span>' : '') +
            '<span>总下载：' + st.total + ' 次</span>' +
            (st.last_at ? '<span>最近：' + formatTime(st.last_at) + '</span>' : '') +
          '</div>' +
        '</div>';
    });
    statsListEl.innerHTML = html;
  }

  // ---------- 搜索/筛选（仅 pending / done） ----------
  function searchParams() {
    return {
      q: (searchQ.value || '').trim(),
      status: state.tab === 'done' ? (searchStatus.value || '') : 'pending',
      from: searchFrom.value || '',
      to: searchTo.value || ''
    };
  }
  function hasFilter(p) {
    return !!(p.q || p.from || p.to || (state.tab === 'done' && p.status));
  }
  function buildSearchQuery(p) {
    var parts = [];
    if (p.q) { parts.push('q=' + encodeURIComponent(p.q)); }
    if (p.status) { parts.push('status=' + encodeURIComponent(p.status)); }
    if (p.from) { parts.push('from=' + encodeURIComponent(p.from)); }
    if (p.to) { parts.push('to=' + encodeURIComponent(p.to)); }
    return parts.length ? '?' + parts.join('&') : '';
  }
  // pending 列表固定待审核；done 列表无筛选时拉全部再本地分；有筛选走 /api/queue/search
  function runSearch() {
    listEl.innerHTML = '<p class="muted loading">加载中…</p>';
    var p = searchParams();
    var req;
    if (state.tab === 'pending' || !hasFilter(p)) {
      req = api('/api/queue');
    } else {
      req = api('/api/queue/search' + buildSearchQuery(p));
    }
    return req.then(function (data) {
      var items = data.items || [];
      if (state.tab === 'pending') {
        state.items = items;
        render();
      } else if (!hasFilter(p)) {
        state.items = items;
        render();
      } else {
        listEl.innerHTML = '';
        if (!items.length) {
          listEl.innerHTML = '<p class="empty">没有符合条件的插件</p>';
        } else {
          items.forEach(function (it) { listEl.appendChild(renderItem(it)); });
        }
        updateBatchBar();
        updateSelectAll();
      }
    }).catch(function (err) {
      if (err.status === 401) { showLogin(); return; }
      listEl.innerHTML = '<p class="error">' + escapeHtml(err.message) + '</p>';
    });
  }

  function onSearchInput() {
    if (state.searchTimer) { clearTimeout(state.searchTimer); }
    state.searchTimer = setTimeout(function () {
      state.searchTimer = null;
      runSearch();
    }, 300);
  }

  if (searchForm) {
    searchForm.addEventListener('submit', function (e) {
      e.preventDefault();
      if (state.searchTimer) { clearTimeout(state.searchTimer); state.searchTimer = null; }
      runSearch();
    });
    // 实时过滤（debounce 300ms）；日期变化也重拉
    searchQ.addEventListener('input', onSearchInput);
    searchStatus.addEventListener('change', runSearch);
    searchFrom.addEventListener('change', runSearch);
    searchTo.addEventListener('change', runSearch);
  }

  // ---------- 批量操作 ----------
  function toggleSelect(id, checked) {
    var i = state.selected.indexOf(id);
    if (checked && i === -1) { state.selected.push(id); }
    if (!checked && i !== -1) { state.selected.splice(i, 1); }
    var item = listEl.querySelector('.item[data-id="' + cssEscape(id) + '"]');
    if (item) { item.classList.toggle('selected', checked); }
    updateBatchBar();
    updateSelectAll();
  }

  function setSelectAll(checked) {
    state.selected = [];
    var boxes = listEl.querySelectorAll('.item-checkbox');
    Array.prototype.forEach.call(boxes, function (cb) {
      cb.checked = checked;
      var wrap = cb.closest('.item');
      if (wrap) {
        wrap.classList.toggle('selected', checked);
        var id = wrap.getAttribute('data-id');
        if (checked && id && state.selected.indexOf(id) === -1) { state.selected.push(id); }
      }
    });
    updateBatchBar();
  }

  function updateSelectAll() {
    if (!selectAllEl) { return; }
    var boxes = listEl.querySelectorAll('.item-checkbox');
    if (!boxes.length) { selectAllEl.checked = false; selectAllEl.disabled = !boxes.length; return; }
    selectAllEl.disabled = false;
    var all = true;
    Array.prototype.forEach.call(boxes, function (cb) { if (!cb.checked) { all = false; } });
    selectAllEl.checked = all;
  }

  function updateBatchBar() {
    if (!batchBar) { return; }
    var n = state.selected.length;
    batchBar.hidden = !(state.tab === 'pending' && n > 0);
    batchCount.textContent = '已选 ' + n + ' 项';
  }

  function clearSelection() {
    state.selected = [];
    if (selectAllEl) { selectAllEl.checked = false; }
    updateBatchBar();
  }

  function clearBatchResult() {
    if (batchResultEl) { batchResultEl.hidden = true; batchResultEl.textContent = ''; }
  }

  function showBatchResult(text) {
    if (!batchResultEl) { return; }
    batchResultEl.textContent = text;
    batchResultEl.hidden = false;
  }

  // select-all checkbox
  if (selectAllEl) {
    selectAllEl.addEventListener('change', function () { setSelectAll(selectAllEl.checked); });
  }

  function renderBatchResult(data) {
    var ok = (data.succeeded || []).length;
    var fail = (data.failed || []).length;
    var text = '成功 ' + ok + ' 项';
    if (fail) {
      text += '，失败 ' + fail + ' 项：' + (data.failed || []).map(function (f) {
        return f.id + (f.error ? '（' + f.error + '）' : '');
      }).join('，');
    }
    showBatchResult(text);
  }

  var batchDialog = document.getElementById('batch-dialog');
  var batchForm = document.getElementById('batch-form');
  var batchTarget = document.getElementById('batch-target');
  var batchReason = document.getElementById('batch-reason');

  function batchAction(action) {
    var ids = state.selected.slice();
    if (!ids.length) { alert('请先勾选待审核插件'); return; }
    if (action === 'approve') {
      if (!confirm('确认批量通过并发布所选 ' + ids.length + ' 个插件？')) { return; }
      doBatch(action, ids, '');
    } else {
      batchTarget.textContent = '将对所选 ' + ids.length + ' 个插件写入拒绝原因';
      batchReason.value = '';
      if (typeof batchDialog.showModal === 'function') { batchDialog.showModal(); }
      else { batchDialog.setAttribute('open', ''); }
    }
  }

  function doBatch(action, ids, reason) {
    var approveBtn = document.getElementById('batch-approve');
    var rejectBtn = document.getElementById('batch-reject');
    if (approveBtn) { approveBtn.disabled = true; }
    if (rejectBtn) { rejectBtn.disabled = true; }
    api('/api/queue/batch', {
      method: 'POST',
      body: { action: action, ids: ids, reason: reason }
    }).then(function (data) {
      renderBatchResult(data);
      clearSelection();
      return runSearch();
    }).catch(function (err) {
      alert('批量操作失败：' + err.message);
    }).finally(function () {
      if (approveBtn) { approveBtn.disabled = false; }
      if (rejectBtn) { rejectBtn.disabled = false; }
    });
  }

  if (document.getElementById('batch-approve')) {
    document.getElementById('batch-approve').addEventListener('click', function () { batchAction('approve'); });
  }
  if (document.getElementById('batch-reject')) {
    document.getElementById('batch-reject').addEventListener('click', function () { batchAction('reject'); });
  }
  if (document.getElementById('batch-cancel')) {
    document.getElementById('batch-cancel').addEventListener('click', function () {
      batchDialog.close ? batchDialog.close() : batchDialog.removeAttribute('open');
    });
  }
  if (batchForm) {
    batchForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var reason = batchReason.value.trim();
      if (!reason) { alert('请填写拒绝原因'); batchReason.focus(); return; }
      var ids = state.selected.slice();
      batchDialog.close ? batchDialog.close() : batchDialog.removeAttribute('open');
      doBatch('reject', ids, reason);
    });
  }

  // ---------- 待审核包内容预览 + 编辑 ----------
  function closePreview() {
    state.previewId = null;
    state.previewTree = null;
    state.previewPath = null;
    if (previewPanel) { previewPanel.hidden = true; }
  }

  function togglePreview(it, btn) {
    if (state.previewId === it.id && previewPanel && !previewPanel.hidden) {
      closePreview();
      return;
    }
    state.previewId = it.id;
    state.previewTree = null;
    state.previewPath = null;
    previewPanel.hidden = false;
    previewTarget.textContent = it.id + (it.version ? ' v' + it.version : '');
    previewManifest.textContent = '加载中…';
    previewTreeEl.innerHTML = '<p class="tree-empty">加载中…</p>';
    previewPathEl.textContent = '选择左侧文件查看内容';
    previewContentEl.value = '';
    previewContentEl.disabled = true;
    previewSaveBtn.disabled = true;
    previewStatus.hidden = true;
    btn.disabled = true;
    api('/api/inspect?id=' + encodeURIComponent(it.id))
      .then(function (data) {
        state.previewTree = buildTree(data.files || []);
        previewManifest.textContent = describeManifest(data.manifest);
        renderTree();
      })
      .catch(function (err) {
        if (err.status === 401) { showLogin(); return; }
        previewTreeEl.innerHTML = '<p class="tree-empty error">' + escapeHtml(err.message) + '</p>';
        previewManifest.textContent = '';
      })
      .finally(function () { btn.disabled = false; });
  }

  function describeManifest(m) {
    if (!m) { return ''; }
    var parts = [];
    if (m.id) { parts.push('id：' + m.id); }
    if (m.version) { parts.push('版本：v' + m.version); }
    if (m.name || m.name_zh) { parts.push('名称：' + (m.name_zh || m.name)); }
    if (m.author) { parts.push('作者：' + m.author); }
    if (m.permissions && m.permissions.length) { parts.push('权限：' + m.permissions.join(' / ')); }
    return parts.length ? '清单：' + parts.join(' · ') : '';
  }

  // 把扁平 files [{path,size,isDir,isText}] 组成目录树
  function buildTree(files) {
    var root = { name: '', path: '', isDir: true, children: [] };
    files.forEach(function (f) {
      var segs = String(f.path).split('/').filter(function (s) { return s.length; });
      var cur = root;
      segs.forEach(function (seg, idx) {
        var isLast = idx === segs.length - 1;
        var path = segs.slice(0, idx + 1).join('/');
        var isDir = isLast ? !!f.isDir : true;
        var node = { name: seg, path: path, isDir: isDir };
        if (isLast) {
          if (!isDir) {
            node.size = f.size || 0;
            node.isText = !!f.isText;
          }
        }
        if (isDir) { node.children = []; }
        var found = null;
        for (var k = 0; k < cur.children.length; k++) {
          if (cur.children[k].name === seg && !!cur.children[k].isDir === isDir) { found = cur.children[k]; break; }
        }
        if (found) {
          cur = found;
        } else {
          cur.children.push(node);
          cur = node;
        }
      });
    });
    sortTree(root);
    return root;
  }

  function sortTree(node) {
    if (!node.children) { return; }
    node.children.sort(function (a, b) {
      if (a.isDir !== b.isDir) { return a.isDir ? -1 : 1; }
      return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
    });
    node.children.forEach(sortTree);
  }

  function renderTree() {
    previewTreeEl.innerHTML = '';
    if (!state.previewTree || !state.previewTree.children.length) {
      previewTreeEl.innerHTML = '<p class="tree-empty">空包或无文件</p>';
      return;
    }
    state.previewTree.children.forEach(function (node) {
      previewTreeEl.appendChild(renderTreeNode(node, 0));
    });
  }

  function renderTreeNode(node, depth) {
    var wrap = document.createElement('div');
    wrap.style.paddingLeft = (depth * 16) + 'px';
    var row = document.createElement('button');
    row.type = 'button';
    row.className = 'tree-node ' + (node.isDir ? 'is-dir' : 'is-file') +
      (!node.isDir && !node.isText ? ' disabled' : '') +
      (!node.isDir && state.previewPath === node.path ? ' selected' : '');
    var icon = document.createElement('span');
    icon.className = 'tree-icon';
    icon.textContent = node.isDir ? '▸' : (node.isText ? '📄' : '⬛');
    var name = document.createElement('span');
    name.className = 'tree-name';
    name.textContent = node.name;
    name.title = node.path;
    row.appendChild(icon);
    row.appendChild(name);
    if (node.isDir) {
      if (node.children && node.children.length) {
        var cnt = document.createElement('span');
        cnt.className = 'tree-size';
        cnt.textContent = node.children.length + ' 项';
        row.appendChild(cnt);
      }
    } else {
      var sz = document.createElement('span');
      sz.className = 'tree-size';
      sz.textContent = formatSize(node.size || 0);
      row.appendChild(sz);
    }
    wrap.appendChild(row);
    if (node.isDir && node.children && node.children.length) {
      var childWrap = document.createElement('div');
      childWrap.className = 'tree-children';
      childWrap.hidden = true;
      node.children.forEach(function (child) {
        childWrap.appendChild(renderTreeNode(child, 0));
      });
      wrap.appendChild(childWrap);
      row.addEventListener('click', function () {
        childWrap.hidden = !childWrap.hidden;
        icon.textContent = childWrap.hidden ? '▸' : '▾';
      });
    } else if (!node.isDir) {
      if (node.isText) {
        row.addEventListener('click', function () { viewFile(node.path); });
      } else {
        row.title = '二进制文件，无法预览';
      }
    }
    return wrap;
  }

  function viewFile(path) {
    previewPathEl.textContent = path;
    previewContentEl.value = '加载中…';
    previewContentEl.disabled = true;
    previewSaveBtn.disabled = true;
    previewStatus.hidden = true;
    state.previewPath = path;
    api('/api/inspect/file?id=' + encodeURIComponent(state.previewId) +
      '&path=' + encodeURIComponent(path))
      .then(function (data) {
        previewContentEl.value = data.content || '';
        previewContentEl.disabled = false;
        previewSaveBtn.disabled = false;
        previewStatus.hidden = true;
        renderTree();
      })
      .catch(function (err) {
        if (err.status === 401) { showLogin(); return; }
        previewContentEl.value = '';
        previewContentEl.disabled = true;
        previewSaveBtn.disabled = true;
        previewStatus.textContent = err.message || '无法读取文件';
        previewStatus.className = 'preview-status error';
        previewStatus.hidden = false;
      });
  }

  if (previewSaveBtn) {
    previewSaveBtn.addEventListener('click', function () {
      var id = state.previewId;
      var path = state.previewPath;
      if (!id || !path) { alert('请先选择要编辑的文件'); return; }
      previewSaveBtn.disabled = true;
      previewSaveBtn.textContent = '保存中…';
      api('/api/inspect/edit', {
        method: 'POST',
        body: { id: id, path: path, content: previewContentEl.value }
      }).then(function (data) {
        previewStatus.textContent = data.message || '已修改并重新打包';
        previewStatus.className = 'preview-status ok';
        previewStatus.hidden = false;
      }).catch(function (err) {
        if (err.status === 401) { showLogin(); return; }
        previewStatus.textContent = '保存失败：' + err.message;
        previewStatus.className = 'preview-status error';
        previewStatus.hidden = false;
      }).finally(function () {
        previewSaveBtn.disabled = false;
        previewSaveBtn.textContent = '保存修改';
      });
    });
  }
  if (document.getElementById('preview-close')) {
    document.getElementById('preview-close').addEventListener('click', closePreview);
  }

  // ---------- 更新包对比 ----------
  var diffDialog = document.getElementById('diff-dialog');

  function openDiff(it, btn) {
    if (btn) { btn.disabled = true; }
    var body = document.getElementById('diff-body');
    document.getElementById('diff-target').textContent =
      it.id + (it.old_version ? '  v' + it.old_version + ' → v' + (it.version || '') : '');
    body.innerHTML = '<p class="muted">加载中…</p>';
    if (typeof diffDialog.showModal === 'function') { diffDialog.showModal(); }
    else { diffDialog.setAttribute('open', ''); }
    api('/api/diff?id=' + encodeURIComponent(it.id))
      .then(function (data) { body.innerHTML = renderDiff(data); })
      .catch(function (err) {
        if (err.status === 401) { showLogin(); return; }
        body.innerHTML = '<p class="error">' + escapeHtml(err.message) + '</p>';
      })
      .finally(function () { if (btn) { btn.disabled = false; } });
  }

  function renderDiff(data) {
    var html = '';
    if (data.oldVersion || data.newVersion) {
      html += '<p class="muted">版本：v' + escapeHtml(data.oldVersion || '?') +
        ' → v' + escapeHtml(data.newVersion || '?') + '</p>';
    }
    var mc = data.manifestChanges;
    if (mc && Object.keys(mc).length) {
      html += '<div class="diff-section"><h3>plugin.json 字段变化</h3><table class="diff-table">' +
        '<thead><tr><th>字段</th><th>旧值</th><th>新值</th></tr></thead><tbody>';
      Object.keys(mc).forEach(function (field) {
        var c = mc[field];
        html += '<tr><td class="field">' + escapeHtml(field) + '</td><td class="old">' +
          escapeHtml(c.old === undefined || c.old === null ? '（无）' : c.old) + '</td><td class="new">' +
          escapeHtml(c.new === undefined || c.new === null ? '（无）' : c.new) + '</td></tr>';
      });
      html += '</tbody></table></div>';
    }
    var fc = data.fileChanges || {};
    html += '<div class="diff-section"><h3>文件变化</h3>';
    html += '<h3 style="font-size:12.5px;color:var(--muted);">新增文件</h3>' +
      renderFileList(fc.added, 'diff-added', '+ ');
    html += '<h3 style="font-size:12.5px;color:var(--muted);">删除文件</h3>' +
      renderFileList(fc.removed, 'diff-removed', '- ');
    html += '<h3 style="font-size:12.5px;color:var(--muted);">修改文件</h3>' +
      renderFileList(fc.modified, 'diff-modified', '~ ');
    html += '</div>';
    return html;
  }

  function renderFileList(arr, cls, prefix) {
    if (!arr || !arr.length) { return '<p class="diff-none">无</p>'; }
    var html = '<ul class="diff-list">';
    arr.forEach(function (f) {
      html += '<li class="' + cls + '">' + escapeHtml(prefix + f) + '</li>';
    });
    return html + '</ul>';
  }

  if (document.getElementById('diff-cancel')) {
    document.getElementById('diff-cancel').addEventListener('click', function () {
      diffDialog.close ? diffDialog.close() : diffDialog.removeAttribute('open');
    });
  }

  // ---------- IP 黑名单（安全） ----------
  function loadBanned() {
    banTableWrap.innerHTML = '<p class="muted loading">加载中…</p>';
    api('/api/ipban').then(function (data) {
      state.banned = data.banned || [];
      renderBanned();
    }).catch(function (err) {
      if (err.status === 401) { showLogin(); return; }
      banTableWrap.innerHTML = '<p class="error">' + escapeHtml(err.message) + '</p>';
    });
  }

  function renderBanned() {
    var rows = state.banned;
    if (!rows.length) {
      banTableWrap.innerHTML = '<p class="empty">暂无封禁 IP</p>';
      return;
    }
    var html = '<table class="ban-table"><thead><tr>' +
      '<th>IP</th><th>封禁至</th><th>失败次数</th><th>最近失败</th><th>操作</th>' +
      '</tr></thead><tbody>';
    rows.forEach(function (r) {
      html += '<tr>' +
        '<td class="ip">' + escapeHtml(r.ip) + '</td>' +
        '<td>' + (r.until ? escapeHtml(formatTime(r.until)) : '永久') + '</td>' +
        '<td>' + escapeHtml(r.fails || 0) + '</td>' +
        '<td>' + (r.lastFail ? escapeHtml(formatTime(r.lastFail)) : '—') + '</td>' +
        '<td class="actions"></td></tr>';
    });
    banTableWrap.innerHTML = html + '</tbody></table>';
    // 解封按钮（textContent，避免 XSS）
    var btns = banTableWrap.querySelectorAll('td.actions');
    rows.forEach(function (r, idx) {
      var cell = btns[idx];
      if (!cell) { return; }
      var b = mkBtn('解封', 'btn btn-ghost');
      b.addEventListener('click', function () { unban(r.ip); });
      cell.appendChild(b);
    });
  }

  function showBanStatus(text, isError) {
    var el = document.getElementById('ban-status');
    if (!el) { return; }
    el.textContent = text;
    el.className = isError ? 'error' : 'ok';
    el.hidden = false;
  }

  function unban(ip) {
    if (!confirm('确认解封 ' + ip + '？')) { return; }
    api('/api/ipban/remove', { method: 'POST', body: { ip: ip } })
      .then(function (data) {
        showBanStatus(data.message || ('已解封 ' + ip), false);
        loadBanned();
      })
      .catch(function (err) {
        if (err.status === 401) { showLogin(); return; }
        showBanStatus('解封失败：' + err.message, true);
      });
  }

  if (banForm) {
    banForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var ip = document.getElementById('ban-ip').value.trim();
      var duration = document.getElementById('ban-duration').value;
      var reason = document.getElementById('ban-reason').value.trim();
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
        showBanStatus('请输入合法的 IPv4 地址', true);
        return;
      }
      var btn = document.getElementById('ban-submit');
      btn.disabled = true;
      btn.textContent = '封禁中…';
      api('/api/ipban/add', { method: 'POST', body: { ip: ip, duration: duration, reason: reason } })
        .then(function (data) {
          showBanStatus(data.message || ('已封禁 ' + ip), false);
          document.getElementById('ban-ip').value = '';
          document.getElementById('ban-reason').value = '';
          loadBanned();
        })
        .catch(function (err) {
          if (err.status === 401) { showLogin(); return; }
          showBanStatus('封禁失败：' + err.message, true);
        })
        .finally(function () {
          btn.disabled = false;
          btn.textContent = '封禁';
        });
    });
  }

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
  // 属性选择器转义（querySelector data-id 用）
  function cssEscape(s) {
    if (window.CSS && CSS.escape) { return CSS.escape(s); }
    return String(s).replace(/["\\]/g, '\\$&');
  }

  // ---------- 作者管理 ----------
  function loadAuthors(searchQuery) {
    authorsListEl.innerHTML = '<p class="muted loading">加载中…</p>';
    api('/api/authors').then(function (data) {
      var items = data.items || [];
      // 前端过滤
      if (searchQuery) {
        items = items.filter(function (item) {
          return item.author.toLowerCase().indexOf(searchQuery) !== -1;
        });
      }
      renderAuthors(items);
    }).catch(function (err) {
      if (err.status === 401) { showLogin(); return; }
      authorsListEl.innerHTML = '<p class="error">' + escapeHtml(err.message) + '</p>';
    });
  }

  function renderAuthors(items) {
    if (!items.length) {
      authorsListEl.innerHTML = '<p class="empty">暂无作者</p>';
      return;
    }
    var html = '<table class="data-table"><thead><tr>'
      + '<th>作者 ID</th>'
      + '<th>插件总数</th>'
      + '<th>已发布</th>'
      + '<th>待审核</th>'
      + '<th>最后上传时间</th>'
      + '<th>操作</th>'
      + '</tr></thead><tbody>';
    items.forEach(function (author) {
      var lastUpdate = author.last_update ? new Date(author.last_update).toLocaleString('zh-CN') : '-';
      html += '<tr>'
        + '<td><strong>' + escapeHtml(author.author) + '</strong></td>'
        + '<td>' + author.plugin_count + '</td>'
        + '<td>' + (author.published_count || 0) + '</td>'
        + '<td>' + (author.pending_count || 0) + '</td>'
        + '<td>' + lastUpdate + '</td>'
        + '<td>'
        + '<button class="btn btn-sm" data-author="' + escapeHtml(author.author) + '">查看插件</button> '
        + '<button class="btn btn-sm" data-rename="' + escapeHtml(author.author) + '">修改作者</button>'
        + '</td>'
        + '</tr>';
    });
    html += '</tbody></table>';
    authorsListEl.innerHTML = html;

    // 绑定"查看插件"按钮
    Array.prototype.forEach.call(authorsListEl.querySelectorAll('[data-author]'), function (btn) {
      btn.addEventListener('click', function () {
        var author = btn.getAttribute('data-author');
        viewAuthorPlugins(author);
      });
    });

    // 绑定"修改作者"按钮
    Array.prototype.forEach.call(authorsListEl.querySelectorAll('[data-rename]'), function (btn) {
      btn.addEventListener('click', function () {
        var oldAuthor = btn.getAttribute('data-rename');
        promptRenameAuthor(oldAuthor);
      });
    });
  }

  function promptRenameAuthor(oldAuthor) {
    var newAuthor = prompt('将作者 "' + oldAuthor + '" 改为：', oldAuthor);
    if (!newAuthor || newAuthor.trim() === '' || newAuthor.trim() === oldAuthor) {
      return;
    }
    if (!confirm('确认将作者 "' + oldAuthor + '" 改为 "' + newAuthor.trim() + '"？\n这将修改该作者的所有插件。')) {
      return;
    }
    renameAuthor(oldAuthor, newAuthor.trim());
  }

  function renameAuthor(oldAuthor, newAuthor) {
    api('/api/author/rename', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_author: oldAuthor, new_author: newAuthor })
    }).then(function (data) {
      alert('修改成功：' + data.message);
      loadAuthors();
    }).catch(function (err) {
      if (err.status === 401) { showLogin(); return; }
      alert('修改失败：' + err.message);
    });
  }

  function viewAuthorPlugins(author) {
    // 切换到"全部"tab，并按作者筛选
    var allTab = document.querySelector('[data-tab="all"]');
    if (allTab) { allTab.click(); }
    // 设置搜索框为作者名
    var searchInput = document.getElementById('search-q');
    if (searchInput) {
      searchInput.value = author;
      // 触发搜索
      setTimeout(function () {
        var searchForm = document.getElementById('search-form');
        if (searchForm) { searchForm.dispatchEvent(new Event('submit')); }
      }, 100);
    }
  }

  // 作者搜索
  if (authorSearchForm) {
    authorSearchForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var query = (authorSearchInput.value || '').trim().toLowerCase();
      loadAuthors(query);
    });
  }

  bootstrap();
})();
