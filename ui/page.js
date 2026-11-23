// 页面逻辑：只读本地 KV、通过任务队列触发后台签到。页面不直接请求 PT 站点，也不展示 Cookie 明文。
const $ = id => document.getElementById(id)
const STORAGE = { sites: 'sites', history: 'sign-history', config: 'sign-config', keepalive: 'keepalive-state' }
const CIRC = 2 * Math.PI * 82

let ctxRef = null
let sites = []
let history = {}
let config = {}
let running = false
let pollTimer = null
let clockTimer = null
let disposers = []
let hostSites = []
let keepalive = {}

function on(target, type, fn, options) {
  target.addEventListener(type, fn, options)
  disposers.push(() => target.removeEventListener(type, fn, options))
}

function dayKey(ts = Date.now()) {
  const d = new Date(ts)
  const p = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}
function fmtTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  const p = n => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}
function hostOf(url) {
  try { return new URL(url).hostname } catch { return url }
}
function statusText(status) {
  return {
    success: '签到成功', already: '今日已签', failed: '签到失败', unconfirmed: '待确认',
    manual: '需人工', 'manual-done': '已标记', skipped: '已跳过', pending: '待签到', off: '未启用',
  }[status] || '待签到'
}
function streakOf(dates, today = dayKey()) {
  const done = new Set(dates || [])
  const cursor = new Date(today + 'T12:00:00')
  if (!done.has(dayKey(cursor.getTime()))) cursor.setDate(cursor.getDate() - 1)
  let n = 0
  for (let i = 0; i < 3660; i++) {
    if (!done.has(dayKey(cursor.getTime()))) break
    n++
    cursor.setDate(cursor.getDate() - 1)
  }
  return n
}

function toast(message, kind = 'info') {
  const stack = $('toasts')
  const el = document.createElement('div')
  el.className = `toast ${kind}`
  el.innerHTML = `<span class="t-ico"></span><span>${escapeHtml(message)}</span>`
  stack.appendChild(el)
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 260) }, 3200)
}

// 把通知返回结构翻译成人话，失败要能看到原因，而不是静默吞掉。
function describeNotify(res, prefix) {
  if (!res) { toast(prefix + '：无返回结果', 'err'); return }
  if (res.error) { toast(prefix + '失败：' + res.error, 'err'); return }
  if (res.skipped) { toast(prefix + '：未发送（' + (res.reason || '未开启') + '）', 'info'); return }
  const deliveries = Array.isArray(res.deliveries) ? res.deliveries : []
  if (!deliveries.length) {
    toast(res.accepted ? prefix + '：宿主已接收（无渠道明细）' : prefix + '：宿主未接收', res.accepted ? 'ok' : 'err')
    return
  }
  const sent = deliveries.filter(d => d.status === 'sent')
  if (sent.length) {
    toast(prefix + '已送达：' + sent.map(d => d.channel).join('、'), 'ok')
  } else {
    const reasons = deliveries.map(d => {
      const why = { not_configured: '未配置', disabled: '已禁用', quiet_hours: '静默时段' }[d.reason] || d.reason || d.status
      return `${d.channel} ${why}`
    }).join('；')
    toast(prefix + '未送达：' + reasons, 'err')
  }
}

// 从 DIAN115 读取用户已配置的 PT 站点（凭据脱敏，只能拿到名称/地址）。
// 只读取列表，用于带入表单；不读取也不尝试还原任何 Cookie/凭据。
async function loadHostSites() {
  const ctx = ctxRef
  try {
    const res = await ctx.api.get('/api/pt/sites')
    const raw = (res && (res.items || res.data)) || res || []
    hostSites = (Array.isArray(raw) ? raw : [])
      .filter(s => s && (s.enabled !== false))
      .map(s => {
        let url = ''
        for (const key of ['url', 'base_url', 'baseUrl', 'site_url', 'siteUrl', 'homepage', 'home_url', 'address']) {
          if (s[key]) { url = String(s[key]).trim(); break }
        }
        return {
          id: s.id,
          name: String(s.name || s.site_name || s.siteName || ('#' + s.id)),
          url,
        }
      })
      .filter(s => s.id !== undefined && s.id !== null)
  } catch {
    hostSites = []
  }
  renderHostSites()
}

function renderHostSites() {
  const sel = $('host-site-select')
  if (!sel) return
  if (!hostSites.length) {
    sel.innerHTML = '<option value="">— 未读取到宿主站点 —</option>'
    const hint = $('import-hint')
    if (hint) hint.textContent = '宿主未返回可带入的 PT 站点，请在下方手动填写。'
    return
  }
  sel.innerHTML = '<option value="">— 选择一个站点 —</option>' + hostSites
    .map((s, i) => `<option value="${i}">${escapeHtml(s.name)}</option>`)
    .join('')
  const hint = $('import-hint')
  if (hint) hint.textContent = `已读取 ${hostSites.length} 个宿主站点。宿主不返回 Cookie，带入后请在下方补填该站签到 Cookie。`
}

async function load() {
  const ctx = ctxRef
  const [s, h, c, k] = await Promise.all([
    ctx.storage.get(STORAGE.sites).catch(() => []),
    ctx.storage.get(STORAGE.history).catch(() => ({})),
    ctx.storage.get(STORAGE.config).catch(() => ({})),
    ctx.storage.get(STORAGE.keepalive).catch(() => ({})),
  ])
  sites = Array.isArray(s) ? s : []
  history = h && typeof h === 'object' && !Array.isArray(h) ? h : {}
  config = c && typeof c === 'object' ? c : {}
  keepalive = k && typeof k === 'object' ? k : {}
  render()
  void loadHostSites()
}

function render() {
  const today = dayKey()
  const enabled = sites.filter(s => s.enabled)
  const doneToday = enabled.filter(s => (history[s.id]?.dates || []).includes(today)).length
  const total = enabled.length

  $('hero-done').textContent = String(doneToday)
  $('hero-total').textContent = String(total)
  $('chip-enabled').textContent = String(enabled.length)
  $('sites-count').textContent = String(sites.length)
  $('stat-sites').textContent = String(sites.length)
  $('stat-streak').innerHTML = `${Math.max(0, ...sites.map(s => streakOf(history[s.id]?.dates, today)))}<small> 天</small>`
  const month = today.slice(0, 7)
  let monthCount = 0, allCount = 0
  for (const entry of Object.values(history)) {
    const dates = entry?.dates || []
    allCount += dates.length
    monthCount += dates.filter(d => d.startsWith(month)).length
  }
  $('stat-total').textContent = String(allCount)
  $('stat-month').textContent = String(monthCount)

  const pct = total ? Math.round(doneToday / total * 100) : 0
  $('ring-percent').textContent = pct + '%'
  $('ring-value').style.strokeDashoffset = String(CIRC * (1 - pct / 100))
  $('hero-sub').textContent = !sites.length
    ? '添加一个 PT 站点，开启你的每日签到之旅。'
    : doneToday === total && total > 0
      ? '漂亮！今天所有站点都签到了 ✨'
      : `还有 ${total - doneToday} 个站点等待签到，点一下就搞定。`

  renderHeatmap()
  renderSites()
  renderTimeline()
  $('cfg-notify').checked = Boolean(config.notify)
  $('cfg-notify-fail').checked = Boolean(config.notifyOnFailureOnly)
  $('cfg-vision-enabled').checked = Boolean(config.visionEnabled)
  $('cfg-vision-url').value = config.visionURL || ''
  $('cfg-vision-key').value = config.visionKey || ''
  $('cfg-vision-model').value = config.visionModel || ''
  // 馒头到期预警：令牌回显（仅本机可见），状态摘要。
  $('ka-key').value = keepalive.apiKey || ''
  const ks = keepalive.state || {}
  if (ks.lastCheck) {
    const left = typeof ks.daysLeft === 'number' ? ` · 距删号线约 ${ks.daysLeft} 天` : ''
    $('ka-hint').textContent = `${ks.lastStatus || ''} · ${fmtTime(ks.lastCheck)}${ks.lastUser ? ' · ' + ks.lastUser : ''}${left}。${ks.lastDetail || ''}`
  } else if (keepalive.apiKey) {
    $('ka-hint').textContent = '令牌已保存，点「验证令牌」或「检查活跃状态」查看账号状态。'
  }
}

function renderHeatmap() {
  const grid = $('heatmap')
  grid.innerHTML = ''
  const labels = ['日', '一', '二', '三', '四', '五', '六']
  labels.forEach(l => {
    const cell = document.createElement('div')
    cell.className = 'heat-head'
    cell.textContent = l
    grid.appendChild(cell)
  })
  const today = new Date()
  today.setHours(12, 0, 0, 0)
  const mondayOffset = (today.getDay() + 6) % 7
  const start = new Date(today)
  start.setDate(start.getDate() - mondayOffset - 28)
  const counts = {}
  for (const entry of Object.values(history)) {
    for (const d of (entry?.dates || [])) counts[d] = (counts[d] || 0) + 1
  }
  const maxCount = Math.max(1, ...Object.values(counts))
  const todayStr = dayKey()
  for (let i = 0; i < 35; i++) {
    const d = new Date(start)
    d.setDate(start.getDate() + i)
    const key = dayKey(d.getTime())
    const n = counts[key] || 0
    const level = n === 0 ? 0 : n >= maxCount * .66 ? 3 : n >= maxCount * .33 ? 2 : 1
    const cell = document.createElement('div')
    cell.className = `heat-cell l${level}${key === todayStr ? ' today' : ''}`
    cell.textContent = d.getDate()
    cell.title = `${key}：签到 ${n} 个站点`
    grid.appendChild(cell)
  }
}

function renderSites() {
  const grid = $('site-grid')
  const today = dayKey()
  $('empty').hidden = sites.length > 0
  grid.innerHTML = ''
  sites.forEach((site, index) => {
    const entry = history[site.id] || {}
    const dates = entry.dates || []
    const signed = dates.includes(today)
    const last = entry.lastStatus
    const attention = last === 'failed' || last === 'unconfirmed' || last === 'manual'
    const status = !site.enabled ? 'off' : signed ? 'already' : attention ? last : 'pending'
    const card = document.createElement('article')
    card.className = 'site-card' + (site.enabled ? '' : ' is-off')
    card.style.animationDelay = (index * 45) + 'ms'
    const initial = escapeHtml(site.name.slice(0, 1).toUpperCase())
    card.innerHTML = `
      <div class="site-top">
        <div class="site-avatar">${initial}</div>
        <div class="site-id"><strong title="${escapeHtml(site.name)}">${escapeHtml(site.name)}</strong><small title="${escapeHtml(hostOf(site.url))}">${escapeHtml(hostOf(site.url))}${site.cookie ? '' : ' · <b class="miss-ck">缺 Cookie</b>'}</small></div>
        <span class="badge ${status}">${statusText(status)}</span>
      </div>
      <div class="site-meta">
        <div><small>连续</small><strong class="flame">${streakOf(dates, today)} 天</strong></div>
        <div><small>累计</small><strong>${entry.total || dates.length}</strong></div>
        <div><small>最近</small><strong style="font-size:12px">${fmtTime(entry.lastAt)}</strong></div>
      </div>
      <div class="site-actions">
        <button class="btn ${attention ? 'btn-secondary' : 'btn-primary'}" data-act="sign" data-id="${site.id}" ${running || !site.enabled ? 'disabled' : ''}>
          ${attention ? '重试确认' : signed ? '再次签到' : '立即签到'}
        </button>
        <label class="mini-toggle" title="启用/停用"><input type="checkbox" data-act="toggle" data-id="${site.id}" ${site.enabled ? 'checked' : ''}><i class="toggle"></i></label>
        ${!signed && site.enabled ? `<button class="icon-act" data-act="mark" data-id="${site.id}" title="我刚在浏览器手动签过了，标记今日完成" aria-label="标记已签"><svg viewBox="0 0 24 24"><path d="m5 13 4 4L19 7"/></svg></button>` : ''}
        <button class="icon-act" data-act="probe" data-id="${site.id}" title="诊断站点返回" aria-label="诊断"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6"/><path d="m20 20-4.5-4.5"/></svg></button>
        <button class="icon-act" data-act="edit" data-id="${site.id}" title="编辑" aria-label="编辑"><svg viewBox="0 0 24 24"><path d="m15 5 4 4M4 20l4-1 11-11-3-3L5 16z"/></svg></button>
        <button class="icon-act danger" data-act="del" data-id="${site.id}" title="删除" aria-label="删除"><svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v6M14 11v6"/></svg></button>
      </div>`
    grid.appendChild(card)
  })
}

function renderTimeline() {
  const list = $('timeline')
  list.innerHTML = ''
  const rows = []
  for (const site of sites) {
    const entry = history[site.id] || {}
    if (entry.lastAt) rows.push({ site, entry })
  }
  rows.sort((a, b) => (b.entry.lastAt || 0) - (a.entry.lastAt || 0))
  const top = rows.slice(0, 12)
  $('timeline-empty').hidden = top.length > 0
  for (const { site, entry } of top) {
    const li = document.createElement('li')
    li.innerHTML = `<span class="tl-dot ${entry.lastStatus || 'success'}"></span>
      <span class="tl-name">${escapeHtml(site.name)}</span>
      <span class="tl-detail">${escapeHtml(statusText(entry.lastStatus))}${entry.lastDetail ? ' · ' + escapeHtml(entry.lastDetail) : ''}</span>
      <span class="tl-time">${fmtTime(entry.lastAt)}</span>`
    list.appendChild(li)
  }
}

function openModal(site) {
  const editing = Boolean(site)
  $('modal-title').textContent = editing ? '编辑站点' : '添加站点'
  $('f-id').value = site?.id || ''
  $('f-host-id').value = site?.hostId ?? ''
  $('f-name').value = site?.name || ''
  $('f-url').value = site?.url || ''
  $('f-method').value = site?.method || 'GET'
  $('f-enabled').checked = site ? Boolean(site.enabled) : true
  $('f-cookie').value = ''
  $('f-cookie').placeholder = editing && site?.cookie ? '已保存Cookie，留空表示不修改' : '从浏览器复制的该站点 Cookie；留空表示不修改'
  $('f-ua').value = site?.userAgent || ''
  $('f-render').checked = Boolean(site?.render)
  $('f-bank').value = site?.quizBank || ''
  $('f-ai').checked = site ? site.aiAnswer !== false : true
  // 新建站点时预填 NexusPHP 站点的通用关键词，避免"签到成功却显示待确认"；用户可自行改写。
  $('f-success').value = (site?.successKeywords || []).join(', ') || (editing ? '' : '签到成功,已签到,连续签到,已获得')
  $('f-already').value = (site?.alreadyKeywords || []).join(', ') || (editing ? '' : '今天已经签过,今日已签,已经签到,重复签到')
  $('modal').hidden = false
  setTimeout(() => $('f-name').focus(), 30)
}
function closeModal() { $('modal').hidden = true }

async function saveSite(event) {
  event.preventDefault()
  const ctx = ctxRef
  const id = $('f-id').value
  const previous = sites.find(s => s.id === id) || {}
  const payload = {
    id: id || undefined,
    name: $('f-name').value.trim(),
    url: $('f-url').value.trim(),
    method: $('f-method').value,
    enabled: $('f-enabled').checked,
    cookie: $('f-cookie').value ? $('f-cookie').value.trim() : (previous.cookie || ''),
    userAgent: $('f-ua').value.trim(),
    render: $('f-render').checked,
    quizBank: $('f-bank').value.trim(),
    aiAnswer: $('f-ai').checked,
    successKeywords: $('f-success').value,
    alreadyKeywords: $('f-already').value,
    hostId: $('f-host-id').value !== '' ? $('f-host-id').value : (previous.hostId ?? ''),
  }
  try {
    // 页面按与后台一致的规则本地校验；后台执行签到时会再做一次同样的安全校验。
    const site = normalizeLocal(payload, previous)
    if (id) sites = sites.map(s => s.id === id ? { ...site, createdAt: previous.createdAt } : s)
    else sites.push(site)
    await ctx.storage.set(STORAGE.sites, sites)
    closeModal()
    await load()
    toast(id ? '站点已更新' : '站点已添加', 'ok')
  } catch (error) {
    toast(error?.message || '保存失败，请检查填写内容', 'err')
  }
}

// 与后台 normalizeSite 同规则的本地校验；页面不保存 Cookie 明文到 DOM 之外的任何地方。
function normalizeLocal(input, previous) {
  let url
  try { url = new URL(input.url) } catch { throw new Error('签到地址无效') }
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  if (url.protocol !== 'https:' || url.username || url.password || url.port
    || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/i.test(host)
    || /\.(?:local|localhost|internal|test|invalid|example|onion)$/.test(host)) {
    throw new Error('仅支持公网 HTTPS 域名，不能是内网地址、裸 IP 或带端口的链接')
  }
  const kw = v => String(v || '').split(/[,，\n]/).map(s => s.trim()).filter(Boolean).slice(0, 12)
  const cookie = String(input.cookie || '').trim()
  if (cookie.length > 8000 || /[\r\n]/.test(cookie)) throw new Error('Cookie 过长或含非法字符')
  const userAgent = String(input.userAgent || '').trim()
  if (userAgent.length > 300 || /[\r\n]/.test(userAgent)) throw new Error('User-Agent 过长或含非法字符')
  const quizBank = String(input.quizBank || '').replace(/\r\n/g, '\n').trim()
  if (quizBank.length > 8000 || quizBank.split('\n').length > 300) throw new Error('答题库过长：最多 300 行 / 8000 字符')
  // 提前挑出写不成「关键词 = 答案」的行，避免用户以为配好了却永远不命中。
  const badLines = quizBank.split('\n').map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !/=>|＝|=(?!=)/.test(l))
  if (badLines.length) throw new Error(`答题库有 ${badLines.length} 行缺「= 答案」：${badLines[0].slice(0, 24)}`)
  return {
    id: previous.id || ('site-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8)),
    name: String(input.name || '').slice(0, 40),
    url: url.href, host, method: input.method === 'POST' ? 'POST' : 'GET',
    cookie, userAgent, render: Boolean(input.render), quizBank,
    aiAnswer: input.aiAnswer === undefined ? true : Boolean(input.aiAnswer),
    successKeywords: kw(input.successKeywords), alreadyKeywords: kw(input.alreadyKeywords),
    enabled: Boolean(input.enabled), createdAt: previous.createdAt || Date.now(),
    hostId: input.hostId === '' || input.hostId === undefined ? null : input.hostId,
  }
}

// 任务提交被宿主拒绝时，把状态码翻成人话，别只丢一句 axios 原文。
function describeSubmitError(error) {
  const raw = String(error?.message || error || '')
  const matched = /(?:status code|状态码)\s*[:：]?\s*(\d{3})/i.exec(raw)
  const status = String(error?.status || error?.response?.status || (matched ? matched[1] : ''))
  if (status === '400') {
    return '宿主拒绝了任务提交（400）：可能有未核对的历史任务，先到宿主任务队列处理后再试'
  }
  if (status === '409') return '任务已被占用（409）：上一次签到还没结束，稍后再试'
  if (status === '401' || status === '403') return '宿主拒绝访问（' + status + '）：请重新登录 DIAN115'
  return raw || '任务提交失败'
}

// 批量贴 Cookie：Cookie 是站点级登录态，每站各自一份，但没必要一个个点开弹层。
// 左侧写站点名或域名都认，右侧整段都当 Cookie；匹配不到的行不写库，原样报出来。
function matchSiteKey(rawKey) {
  const key = String(rawKey || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/[/?#].*$/, '')
  if (!key) return null
  const exact = sites.find(site => site.name.toLowerCase() === key || hostOf(site.url).toLowerCase() === key)
  if (exact) return exact
  return sites.find(site => {
    const host = hostOf(site.url).toLowerCase()
    return host.includes(key) || key.includes(host) || site.name.toLowerCase().includes(key) || site.url.toLowerCase().includes(key)
  }) || null
}

function parseBulkCookie(text) {
  const rows = []
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const spaced = /\s+[=＝]\s+/.exec(line)
    let key = ''
    let cookie = ''
    if (spaced) {
      key = line.slice(0, spaced.index)
      cookie = line.slice(spaced.index + spaced[0].length)
    } else {
      const index = line.search(/[=＝]/)
      if (index < 0) { rows.push({ line, site: null, cookie: '' }); continue }
      key = line.slice(0, index)
      cookie = line.slice(index + 1)
    }
    rows.push({ line, key: key.trim(), cookie: cookie.trim(), site: matchSiteKey(key) })
  }
  return rows
}

function describeBulk() {
  const rows = parseBulkCookie($('bulk-text').value)
  const hit = rows.filter(row => row.site && row.cookie)
  const miss = rows.filter(row => !row.site || !row.cookie)
  $('bulk-hint').textContent = rows.length
    ? `将写入 ${hit.length} 个站点${hit.length ? '：' + hit.map(row => row.site.name).join('、') : ''}${miss.length ? ` ｜ ${miss.length} 行未匹配` : ''}`
    : '站点：—'
  return { rows, hit, miss }
}

function openBulkCookie() {
  if (!sites.length) { toast('先添加站点，再批量贴 Cookie', 'err'); return }
  $('bulk-text').value = ''
  describeBulk()
  $('bulk-modal').hidden = false
  setTimeout(() => $('bulk-text').focus(), 30)
}

async function saveBulkCookie() {
  const { hit, miss } = describeBulk()
  if (!hit.length) { toast('没有匹配到站点：右侧写的站点名或域名要和卡片上的一致', 'err'); return }
  try {
    for (const row of hit) {
      if (row.cookie.length > 8000) throw new Error(`「${row.site.name}」的 Cookie 超过 8000 字符`)
      if (/[\r\n]/.test(row.cookie)) throw new Error(`「${row.site.name}」的 Cookie 含换行`)
      sites = sites.map(site => site.id === row.site.id ? { ...site, cookie: row.cookie } : site)
    }
    await ctxRef.storage.set(STORAGE.sites, sites)
    $('bulk-modal').hidden = true
    await load()
    toast(`已更新 ${hit.length} 个站点的 Cookie${miss.length ? `，${miss.length} 行未匹配已忽略` : ''}`, 'ok')
  } catch (error) {
    toast(error?.message || '写入失败', 'err')
  }
}

function showProbe(report) {
  const chip = (label, on, warn) =>
    `<span class="probe-chip${on ? (warn ? ' warn' : ' on') : ''}">${escapeHtml(label)}</span>`
  const rows = [
    ['站点', report.name],
    ['请求地址', report.target],
    ['请求方式', report.method + (report.channel ? ' · ' + report.channel : '')],
    ['带上的 Cookie', report.hasCookie ? `${report.cookieCount || 0} 条` : '无'],
    ['HTTP 状态', report.status ? String(report.status) : '—'],
    ['最终地址', report.finalUrl || '—'],
    ['页面标题', report.title || '—'],
    ['页面大小', report.bytes ? report.bytes + ' 字符' : '—'],
    ['判定', report.verdict + (report.detail ? ' · ' + report.detail : '')],
    ['识别到的签到按钮', report.signinAction || '无'],
  ]
  const steps = Array.isArray(report.steps) ? report.steps : []
  const quizOptions = Array.isArray(report.quizOptions) ? report.quizOptions : []
  const keywords = Array.isArray(report.signinKeywords) ? report.signinKeywords : []
  const links = Array.isArray(report.signinLinks) ? report.signinLinks : []
  $('probe-body').innerHTML = `
    <dl class="probe-grid">${rows.map(([key, value]) =>
      `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd>`).join('')}</dl>
    <div class="probe-flag">
      ${chip(report.hasCookie ? '已带 Cookie' : '未带 Cookie', report.hasCookie, !report.hasCookie)}
      ${chip(report.render ? '仿真兜底已开' : '仅直连', report.render)}
      ${chip(report.challenged ? '命中 Cloudflare 拦截' : '未命中拦截页', report.challenged, report.challenged)}
      ${chip(report.redirectedLogin ? '被跳转到登录页' : '未跳登录页', report.redirectedLogin, report.redirectedLogin)}
      ${chip(report.loginForm ? '页面要求登录' : '无登录表单', report.loginForm, report.loginForm)}
      ${chip(report.loginEvidence ? '识别到登录态' : '未识别登录态', report.loginEvidence, !report.loginEvidence)}
      ${chip(report.signinEvidence ? '识别到签到回执' : '无签到回执', report.signinEvidence, !report.signinEvidence)}
      ${report.captcha ? chip('页面要求图形验证码', true, true) : ''}
      ${report.quizQuestion ? chip('识别到答题签到', true, true) : ''}
      ${report.signAction ? chip('页面仍有「签到」按钮', true, true) : ''}
    </div>
    ${report.quizQuestion ? `<div class="probe-quiz">
      <strong>题目</strong><p>${escapeHtml(report.quizQuestion)}</p>
      ${quizOptions.length ? `<strong>选项</strong><p>${quizOptions.map(o => escapeHtml(o)).join(' / ')}</p>` : ''}
      <strong>题库匹配</strong><p>${escapeHtml(report.quizHit || '无')}</p>
    </div>` : ''}
    ${report.captcha ? '<div class="probe-quiz warn"><p>图形验证码无法自动识别（插件不会把图片发往任何外部服务），这个站只能手动签到；签完点卡片上的 ✓ 标记今日完成。</p></div>' : ''}
    ${(keywords.length || links.length || report.homeAction) ? `<div class="probe-quiz">
      <strong>页面里的签到线索</strong>
      ${keywords.length ? `<ul class="probe-list">${keywords.map(k => `<li>${escapeHtml(k)}</li>`).join('')}</ul>` : ''}
      ${links.length ? `<p class="probe-dim">相关链接：</p><ul class="probe-list">${links.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul>` : ''}
      ${report.homeAction ? `<p class="probe-dim">首页可提交的入口：${escapeHtml(report.homeAction)}</p>` : ''}
      ${report.homeVerdict ? `<p class="probe-dim">首页判定：${escapeHtml(report.homeVerdict)}</p>` : ''}
    </div>` : ''}
    ${steps.length ? `<ol class="probe-steps">${steps.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ol>` : ''}
    <div class="probe-sample">${escapeHtml(report.sample || '（页面无可见文本）')}</div>
  `
  $('probe-modal').hidden = false
}

// 诊断：跑一次只读探测，把站点真实返回摊在界面上。
async function runProbe(siteId) {
  const site = sites.find(s => s.id === siteId)
  if (!site) return
  toast('正在诊断 ' + site.name + '…', 'info')
  try {
    const key = 'probe-' + String(siteId).slice(-8) + '-' + Date.now().toString(36)
    const runId = await ctxRef.tasks.run('signin', key, { manual: true, siteId, diagnose: true })
    const run = await waitRun(runId)
    const report = run?.result?.diagnose
    if (!report) {
      toast(run?.error?.message ? String(run.error.message).slice(0, 140) : '诊断没有返回结果', 'err')
      return
    }
    showProbe(report)
  } catch (error) {
    toast(describeSubmitError(error), 'err')
  }
}

async function runSign(siteId, retry = false) {
  if (running) return
  running = true
  $('sign-all').disabled = true
  document.querySelectorAll('[data-act="sign"]').forEach(b => b.disabled = true)
  toast(siteId ? '正在签到…' : '正在批量签到…', 'info')
  try {
    const key = 'manual:' + (siteId || 'all') + ':' + dayKey() + ':' + (retry ? 'r' + Date.now() : 'run')
    const input = { manual: true }
    if (siteId) input.siteId = siteId
    if (retry) input.retry = true
    const runId = await ctxRef.tasks.run('signin', key, input)
    const run = await waitRun(runId)
    await load()
    toast('签到任务已完成', 'ok')
    if (run?.result?.notification) {
      describeNotify(run.result.notification, '签到通知')
    }
  } catch (error) {
    toast(describeSubmitError(error), 'err')
  } finally {
    running = false
    $('sign-all').disabled = false
    document.querySelectorAll('[data-act="sign"]').forEach(b => b.disabled = false)
  }
}

// 验证码站只能人手动签：签完点一下标记，当天就不再重试，连续天数也不会断。
async function markDone(siteId) {
  const site = sites.find(s => s.id === siteId)
  if (!site) return
  try {
    const key = 'mark:' + siteId + ':' + dayKey() + ':' + Date.now().toString(36)
    const runId = await ctxRef.tasks.run('signin', key, { manual: true, siteId, markDone: true })
    const run = await waitRun(runId)
    if (run?.result?.marked) toast(`已标记「${site.name}」今天签到完成`, 'ok')
    else toast('标记失败：' + (run?.error?.message || '宿主未确认结果'), 'err')
    await load()
  } catch (error) {
    toast(describeSubmitError(error), 'err')
  }
}

function waitRun(runId) {  return new Promise((resolve, reject) => {
    let attempts = 0
    clearInterval(pollTimer)
    pollTimer = setInterval(async () => {
      if (ctxRef.signal?.aborted) { clearInterval(pollTimer); reject(new Error('已取消')); return }
      attempts++
      try {
        const run = await ctxRef.tasks.get(runId)
        const status = String(run?.status || '').toLowerCase()
        if (['success', 'succeeded', 'completed', 'done', 'failed', 'error', 'cancelled', 'canceled'].includes(status)) {
          clearInterval(pollTimer)
          if (['failed', 'error', 'cancelled', 'canceled'].includes(status) && run?.error) {
            toast(String(run.error?.message || run.error).slice(0, 120), 'err')
          }
          resolve(run)
        } else if (attempts > 120) {
          clearInterval(pollTimer); resolve(run)
        }
      } catch (e) {
        if (attempts > 120) { clearInterval(pollTimer); reject(e) }
      }
    }, 700)
  })
}

export function mount(ctx) {
  ctxRef = ctx
  // index.html 负责页面结构，这里只负责绑定行为；不做 DOM 搬迁以免丢失事件与动画。

  // 时钟
  const tick = () => {
    const d = new Date()
    $('clock').textContent = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
  }
  tick(); clockTimer = setInterval(tick, 30000)

  on($('add-site'), 'click', () => openModal(null))
  on($('empty-add'), 'click', () => openModal(null))
  on($('refresh'), 'click', () => { void load(); toast('数据已刷新', 'info') })
  on($('sign-all'), 'click', () => void runSign(null, false))
  on($('modal-close'), 'click', closeModal)
  on($('f-cancel'), 'click', closeModal)
  on($('site-form'), 'submit', saveSite)
  on($('modal'), 'click', e => { if (e.target === $('modal')) closeModal() })
  const closeProbe = () => { $('probe-modal').hidden = true }
  on($('probe-close'), 'click', closeProbe)
  on($('probe-ok'), 'click', closeProbe)
  on($('probe-modal'), 'click', e => { if (e.target === $('probe-modal')) closeProbe() })

  // 批量贴 Cookie：一次填完所有站点，不用逐张卡片点开。
  const closeBulk = () => { $('bulk-modal').hidden = true }
  on($('bulk-cookie'), 'click', openBulkCookie)
  on($('bulk-close'), 'click', closeBulk)
  on($('bulk-cancel'), 'click', closeBulk)
  on($('bulk-save'), 'click', () => void saveBulkCookie())
  on($('bulk-text'), 'input', describeBulk)
  on($('bulk-modal'), 'click', e => { if (e.target === $('bulk-modal')) closeBulk() })

  // 从 DIAN115 已配置站点带入：只带名称与地址，Cookie 由用户自行补填。
  on($('host-apply'), 'click', () => {
    const idx = Number($('host-site-select').value)
    const picked = hostSites[idx]
    if (!picked) { toast('请先选择一个宿主站点', 'err'); return }
    const currentName = $('f-name').value.trim()
    if (currentName && currentName !== ('#' + picked.id) && currentName !== picked.name && !confirm('带入会覆盖当前填写的名称与地址，继续？')) return
    $('f-name').value = picked.name
    $('f-host-id').value = String(picked.id)
    if (picked.url && !$('f-url').value.trim()) $('f-url').value = picked.url
    toast(`已带入「${picked.name}」，请补填签到地址与 Cookie`, 'ok')
    $('f-url').focus()
  })

  on($('site-grid'), 'click', async e => {
    const btn = e.target.closest('[data-act]')
    if (!btn || btn.dataset.act === 'toggle') return
    const id = btn.dataset.id
    const site = sites.find(s => s.id === id)
    if (btn.dataset.act === 'sign') {
      const last = history[id]?.lastStatus
      void runSign(id, last === 'failed' || last === 'unconfirmed' || last === 'manual')
    } else if (btn.dataset.act === 'mark') {
      if (!confirm(`确认「${site?.name}」今天已在浏览器里手动签到？标记后今天不再重试。`)) return
      await markDone(id)
    } else if (btn.dataset.act === 'edit') {
      openModal(site)
    } else if (btn.dataset.act === 'probe') {
      void runProbe(id)
    } else if (btn.dataset.act === 'del') {
      if (!confirm(`确定删除站点「${site?.name}」吗？签到历史会保留。`)) return
      sites = sites.filter(s => s.id !== id)
      await ctx.storage.set(STORAGE.sites, sites)
      await load()
      toast('站点已删除', 'ok')
    }
  })
  on($('site-grid'), 'change', async e => {
    const input = e.target.closest('[data-act="toggle"]')
    if (!input) return
    const site = sites.find(s => s.id === input.dataset.id)
    if (!site) return
    site.enabled = input.checked
    await ctx.storage.set(STORAGE.sites, sites)
    await load()
    toast(site.enabled ? '站点已启用' : '站点已停用', 'info')
  })
  on($('cfg-notify'), 'change', async e => { config.notify = e.target.checked; await ctx.storage.set(STORAGE.config, config) })
  on($('cfg-notify-fail'), 'change', async e => { config.notifyOnFailureOnly = e.target.checked; await ctx.storage.set(STORAGE.config, config) })
  on($('notify-test'), 'click', async () => {
    const btn = $('notify-test')
    btn.disabled = true
    try {
      const res = await ctx.notifications.send({
        title: 'PT 签到助手 · 测试通知',
        body: '**PT 签到助手**\n这是一条测试通知。\n收到就说明通知链路通畅。',
        format: 'markdown',
        level: 'info',
        dedupe_key: 'pt-signin:test:' + Date.now(),
      })
      describeNotify(res, '测试通知')
    } catch (error) {
      toast('测试通知失败：' + (error?.message || error), 'err')
    } finally { btn.disabled = false }
  })
  // 答题会复用宿主已配置的 AI：先让用户看清到底有没有可用提供商，别等签到那天才发现答不了。
  on($('ai-check'), 'click', async () => {
    const hint = $('ai-hint')
    try {
      const res = await ctx.api.get(`/api/extensions/v3/${ctx.id || 'local.pt-signin'}/ai/providers`)
      const list = Array.isArray(res?.providers) ? res.providers : []
      const picked = list.find(item => item.id === res?.default_provider_id) || list[0]
      hint.textContent = list.length
        ? `AI 可用于答题：${picked?.name || picked?.id || '已配置'}${picked?.model ? ' · ' + picked.model : ''}（共 ${list.length} 个提供商）`
        : '宿主还没有配置 AI 提供商：答题签到会改为把题目发通知给你'
    } catch (error) {
      hint.textContent = '读取 AI 提供商失败：' + (error?.message || error)
    }
  })
  // 视觉 AI 配置：只存本插件私有 KV，密钥不明文回显到界面之外的任何地方。
  on($('vision-save'), 'click', async () => {
    try {
      config.visionEnabled = $('cfg-vision-enabled').checked
      config.visionURL = $('cfg-vision-url').value.trim()
      config.visionKey = $('cfg-vision-key').value.trim()
      config.visionModel = $('cfg-vision-model').value.trim()
      await ctxRef.storage.set(STORAGE.config, config)
      $('vision-hint').textContent = '已保存。' + (config.visionEnabled ? '验证码自动识别已开启。' : '自动识别未开启。')
      toast('验证码识别设置已保存', 'ok')
    } catch (error) {
      toast('保存失败：' + (error?.message || error), 'err')
    }
  })
  on($('vision-test'), 'click', async () => {
    // 先把当前表单里的值存下来再测，避免用户填了没保存却点了测试。
    config.visionEnabled = $('cfg-vision-enabled').checked
    config.visionURL = $('cfg-vision-url').value.trim()
    config.visionKey = $('cfg-vision-key').value.trim()
    config.visionModel = $('cfg-vision-model').value.trim()
    if (!config.visionURL || !config.visionKey || !config.visionModel) {
      toast('请先填全接口地址、密钥和模型', 'err'); return
    }
    const btn = $('vision-test')
    btn.disabled = true
    $('vision-hint').textContent = '正在用测试图验证识图…'
    try {
      await ctxRef.storage.set(STORAGE.config, config)
      // 用一个不存在的站点 id 触发不到签到，因此走专门的 visionTest 输入。
      const key = 'visiontest:' + Date.now()
      const runId = await ctxRef.tasks.run('signin', key, { visionTest: true })
      const run = await waitRun(runId)
      const report = run?.result?.visionTest
      $('vision-hint').textContent = report
        ? (report.ok
          ? `识图成功：模型读出了「${report.text}」✅`
          : `识图失败：${report.error || '未知原因'}`)
        : ('测试无结果：' + (run?.error?.message || '请检查宿主任务队列'))
      toast(report?.ok ? '视觉 AI 识图正常' : '视觉 AI 识图失败', report?.ok ? 'ok' : 'err')
    } catch (error) {
      $('vision-hint').textContent = '测试失败：' + (error?.message || error)
      toast('测试失败：' + (error?.message || error), 'err')
    } finally { btn.disabled = false }
  })
  on($('notify-channels'), 'click', async () => {
    try {
      const list = await ctx.notifications.channels()
      const rows = (Array.isArray(list) ? list : []).map(c =>
        `${c.name || c.channel}：${c.deliverable ? '可发送' : ({ not_configured: '未配置', disabled: '已禁用', quiet_hours: '静默时段' }[c.reason] || '不可用')}`
      )
      $('notify-hint').textContent = rows.length ? '通知渠道 → ' + rows.join('；') : '宿主未配置任何通知渠道'
    } catch (error) {
      toast('读取通知渠道失败：' + (error?.message || error), 'err')
    }
  })

  // 馒头到期预警：令牌只存私有 KV；只读 profile 查询活跃状态，不刷新 lastBrowse（官方禁止第三方代刷）。
  on($('ka-save'), 'click', async () => {
    try {
      keepalive.apiKey = $('ka-key').value.trim()
      await ctxRef.storage.set(STORAGE.keepalive, keepalive)
      toast(keepalive.apiKey ? '馒头令牌已保存' : '馒头令牌已清空', 'ok')
      $('ka-hint').textContent = keepalive.apiKey ? '令牌已保存，点「验证令牌」确认可用。' : '尚未填写令牌。'
    } catch (error) {
      toast('保存失败：' + (error?.message || error), 'err')
    }
  })
  on($('ka-check'), 'click', async () => {
    const key = $('ka-key').value.trim()
    if (!key) { toast('请先填入 M-Team 的 api_key', 'err'); return }
    keepalive.apiKey = key
    try {
      await ctxRef.storage.set(STORAGE.keepalive, keepalive)
    } catch { /* 存储失败也继续验证，结果里会体现 */ }
    toast('正在验证令牌…', 'info')
    try {
      const runId = await ctxRef.tasks.run('keepalive', 'kacheck:' + Date.now(), { quiet: true })
      const run = await waitRun(runId)
      const r = run?.result || {}
      const hint = $('ka-hint')
      if (r.status && r.status !== 'failed') {
        hint.textContent = `令牌有效：${r.detail || ''}`
        toast('令牌验证通过', 'ok')
        void load()
      } else {
        hint.textContent = '验证失败：' + (r.detail || run?.error?.message || '未知原因')
        toast('令牌验证失败', 'err')
      }
    } catch (error) {
      toast('验证失败：' + (error?.message || error), 'err')
    }
  })
  on($('ka-run'), 'click', async () => {
    const key = $('ka-key').value.trim()
    if (!key) { toast('请先填入 M-Team 的 api_key', 'err'); return }
    keepalive.apiKey = key
    try {
      await ctxRef.storage.set(STORAGE.keepalive, keepalive)
    } catch { /* 存储失败也继续 */ }
    toast('正在检查活跃状态…', 'info')
    try {
      const runId = await ctxRef.tasks.run('keepalive', 'kacheck:' + Date.now(), { force: true })
      const run = await waitRun(runId)
      const r = run?.result || {}
      if (r.status && r.status !== 'failed') {
        $('ka-hint').textContent = r.detail || '检查完成'
        toast(r.status === 'danger' ? '账号已到删号线，请登录！' : r.status === 'warn' ? '账号临近删号线，请登录' : '账号状态正常', r.status === 'ok' ? 'ok' : 'info')
        void load()
      } else {
        $('ka-hint').textContent = '检查失败：' + (r.detail || run?.error?.message || '未知原因')
        toast('检查失败', 'err')
      }
    } catch (error) {
      toast('检查失败：' + (error?.message || error), 'err')
    }
  })

  let disposed = false
  function dispose() {
    if (disposed) return
    disposed = true
    clearInterval(clockTimer); clearInterval(pollTimer)
    ctx.signal?.removeEventListener('abort', dispose)
    disposers.forEach(fn => fn()); disposers = []
  }
  if (ctx.signal) {
    ctx.signal.addEventListener('abort', dispose)
    if (ctx.signal.aborted) dispose()
  }
  void load()
  return dispose
}

let started = false
function start() {
  if (!started && window.DIAN115Plugin) {
    started = true
    const ctx = window.DIAN115Plugin
    mount(ctx)
  }
}
window.addEventListener('dian115:ready', start, { once: true })
start()
