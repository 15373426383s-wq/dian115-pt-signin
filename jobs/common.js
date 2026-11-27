// 共享工具：站点配置校验、SSRF 防护、签到判定、历史统计。
// 红线：站点地址与 Cookie 由用户在页面自填，只存 ctx.storage；任何请求目标都必须是公网 HTTPS 域名。

export const KEYS = {
  sites: 'sites',
  history: 'sign-history',
  config: 'sign-config',
  keepalive: 'keepalive-state',
}

// 图形验证码自动识别：用户在插件页面自行填写视觉 AI 接口（OpenAI chat/completions 格式），
// 存插件私有 KV。插件不写死任何地址、不读取宿主配置或凭据；识别时只把验证码图片与一句提示
// 发往用户填写的这一个接口。这正是「自己接模型识别」：地址/密钥/模型都由用户决定。
export const VISION_DEFAULTS = {
  visionEnabled: false,
  visionURL: '',
  visionKey: '',
  visionModel: '',
}

// 校验并规范化视觉 AI 配置。地址由用户填写，支持：
//   - 公网 https 域名（最常见，如用户自己的中转）
//   - http://127.0.0.1:端口 或 http://本机局域网 IP:端口（用户在 NAS 上自建的本地网关）
// 拒绝裸公网 IP、带账号密码、路径里塞 query 混淆。密钥只留在该配置里，绝不写日志。
export function normalizeVisionAI(input) {
  const value = input && typeof input === 'object' ? input : {}
  const enabled = Boolean(value.visionEnabled)
  const url = String(value.visionURL || '').trim()
  const key = String(value.visionKey || '').trim()
  const model = String(value.visionModel || '').trim()
  if (!url && !key && !model) return { ...VISION_DEFAULTS }
  let parsed
  try { parsed = new URL(url) }
  catch { throw new PluginError('视觉 AI 接口地址无效，请填完整地址（含协议与端口，页面输入框有示例）。') }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '')
  const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1'
  const isPrivate = /^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  const publicDomain = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/i.test(host)
  if (parsed.username || parsed.password || !publicDomain && !isLoopback && !isPrivate) {
    throw new PluginError('视觉 AI 地址只能是公网 HTTPS 域名，或你本机的 127.0.0.1 / 局域网地址。')
  }
  if (parsed.protocol !== 'https:' && !isLoopback && !isPrivate) {
    throw new PluginError('公网视觉 AI 地址必须用 HTTPS；本机/局域网地址可用 HTTP。')
  }
  if (url.length > 500 || key.length > 500 || model.length > 100) {
    throw new PluginError('视觉 AI 配置过长。')
  }
  if (enabled && (!key || !model)) {
    throw new PluginError('启用验证码识别需要同时填写 API 密钥和模型名。')
  }
  return { visionEnabled: enabled, visionURL: parsed.href, visionKey: key, visionModel: model }
}

// 拼出 chat/completions 的实际地址：用户填 /v1 或 /v1/chat/completions 都能用。
export function visionChatURL(base) {
  const url = new URL(String(base || ''))
  if (/\/chat\/completions\/?$/i.test(url.pathname)) return url.href
  url.pathname = url.pathname.replace(/\/+$/, '') + '/chat/completions'
  url.search = ''
  url.hash = ''
  return url.href
}

// M-Team（馒头）保活：官方 API 域名写死，令牌只发往这里，绝不接受用户传入的任意域名。
export const MTEAM_API = 'https://api.m-team.io'

// 天空（HDSKY）图形验证码签到：站点 JS 走这几个固定接口，命中后交给半自动流程。
export const CAPTCHA_SITES = ['hdsky.my']

export function isCaptchaSite(site) {
  const host = String(site?.host || '').toLowerCase().replace(/^www\./, '')
  return CAPTCHA_SITES.includes(host) || site?.captchaMode === true
}

export class PluginError extends Error {
  constructor(message, status = 400) {
    super(message)
    this.status = status
  }
}

export function header(headers, name) {
  const key = Object.keys(headers || {}).find(item => item.toLowerCase() === name.toLowerCase())
  const value = key ? headers[key] : undefined
  return String(Array.isArray(value) ? value[0] || '' : value || '')
}

// 仅接受公网 HTTPS 域名：拒绝裸 IP、内网段、localhost、本地域名后缀、非标准端口、URL 内凭据。
export function safeSiteURL(value, base) {
  let url
  try { url = new URL(value, base) }
  catch { throw new PluginError('签到地址无效，请填写完整的 https 地址。') }
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  if (url.protocol !== 'https:' || url.username || url.password || url.port
    || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/i.test(host)
    || /\.(?:local|localhost|internal|test|invalid|example|onion)$/.test(host)
    || url.href.length > 2000) {
    throw new PluginError('签到地址不符合安全规则：仅支持公网 HTTPS 域名，不能是内网地址、裸 IP、本地域名或带端口/账号的链接。')
  }
  url.hash = ''
  return url
}

export function normalizeKeywords(value) {
  if (Array.isArray(value)) return value.map(item => String(item).trim()).filter(Boolean).slice(0, 12)
  if (typeof value !== 'string') return []
  return value.split(/[,，\n]/).map(item => item.trim()).filter(Boolean).slice(0, 12)
}

// 校验并规范化单个站点配置。cookie 为空是允许的（公开签到页），长度与字符受限，绝不写日志。
export function normalizeSite(input, previous = {}) {
  if (!input || typeof input !== 'object') throw new PluginError('站点配置无效。')
  const name = String(input.name ?? '').trim()
  if (!name || name.length > 40) throw new PluginError('站点名称需为 1–40 个字符。')
  const url = safeSiteURL(String(input.url ?? '').trim())
  const method = input.method === 'POST' ? 'POST' : 'GET'
  const cookie = String(input.cookie ?? '').trim()
  if (cookie.length > 8000 || /[\r\n]/.test(cookie)) throw new PluginError('Cookie 太长或含有非法换行。')
  // UA 由用户可选填写，与获取 Cookie 时的浏览器保持一致，避免站点按 UA 判定会话失效。
  const userAgent = String(input.userAgent ?? '').trim()
  if (userAgent.length > 300 || /[\r\n]/.test(userAgent)) throw new PluginError('User-Agent 太长或含有非法换行。')
  const success = normalizeKeywords(input.successKeywords)
  const already = normalizeKeywords(input.alreadyKeywords)
  // 答题库：用户自己维护的「题目关键词 = 答案」，只在本地拼装提交值，不联网、不外发。
  const quizBank = String(input.quizBank ?? '').replace(/\r\n/g, '\n').trim()
  if (quizBank.length > 8000 || quizBank.split('\n').length > 300) {
    throw new PluginError('答题库过长：最多 300 行 / 8000 字符。')
  }
  const id = typeof previous.id === 'string' && previous.id
    ? previous.id
    : 'site-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8)
  // JSON 接口签到：签到不是页面表单，而是网页 JS 调的一个 JSON 接口。
  // 接口地址与状态地址都必须是该站点自己的域名，否则拒绝保存（Cookie 不能外发）。
  const apiMode = Boolean(input.apiMode)
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  const sameHost = value => {
    const target = safeSiteURL(String(value || '').trim())
    if (target.hostname.toLowerCase().replace(/\.$/, '') !== host) {
      throw new PluginError('JSON 签到接口必须与站点同一域名。')
    }
    return target.href
  }
  const apiUrl = apiMode && input.apiUrl ? sameHost(input.apiUrl) : (apiMode ? url.origin + '/api/check-in' : '')
  const statusUrl = apiMode && input.statusUrl ? sameHost(input.statusUrl) : ''
  const apiBody = String(input.apiBody ?? '').trim()
  if (apiMode) {
    if (apiBody.length > 2000) throw new PluginError('签到请求体过长（最多 2000 字符）。')
    if (apiBody && !parseJsonBody(apiBody)) throw new PluginError('签到请求体必须是合法 JSON。')
  }
  return {
    id,
    name,
    url: url.href,
    host,
    method,
    cookie,
    userAgent,
    // JSON 接口签到（蜂巢这类新框架站）：按接口返回判，不走 HTML 页面判定。
    apiMode,
    apiUrl,
    apiBody: apiMode ? apiBody : '',
    statusUrl,
    statusPath: apiMode ? String(input.statusPath ?? '').trim().slice(0, 120) : '',
    // 浏览器仿真：Cloudflare/WAF 站点的直连请求会被拦，改用宿主渲染器带 Cookie 打开页面。
    render: Boolean(input.render),
    // 图形验证码半自动：插件取验证码图显示在页面，用户填码后插件提交（不 OCR、不外发）。
    captchaMode: Boolean(input.captchaMode),
    quizBank,
    // 题库没命中时是否让宿主 AI 来选答案（默认开：用户不必自己维护题库）。
    aiAnswer: input.aiAnswer === undefined ? true : Boolean(input.aiAnswer),
    successKeywords: success,
    alreadyKeywords: already,
    enabled: input.enabled === undefined ? true : Boolean(input.enabled),
    createdAt: previous.createdAt || Date.now(),
  }
}

// ===== CookieCloud 对接 =====
// 宿主「内置插件 → CookieCloud 服务器」保存了用户浏览器同步过来的站点 Cookie。
// 插件只按站点自己的域名读取，绝不读其它域，读到的 Cookie 仍只发往该站点本身。
// 用能力探测而非写死版本号：有 ctx.cookiecloud 方法就支持。旧宿主没有这个方法时返回 false，
// 签到自动回退到用户手填的 Cookie，不阻断。
export function supportsCookieCloud(ctx) {
  return typeof ctx?.cookiecloud === 'function'
}

// host 变体：站点可能记 ptskit.org、浏览器存的却是 www.ptskit.org（或反之），两个都读。
function cloudDomains(site) {
  const host = String(site?.host || '').toLowerCase().replace(/\.$/, '')
  if (!host) return []
  const list = [host]
  const other = host.startsWith('www.') ? host.slice(4) : 'www.' + host
  if (other.includes('.') && other !== host) list.push(other)
  return list
}

// 从 CookieCloud 读某个站点的 Cookie 对象数组（保留 Path/HttpOnly/Secure 属性）。
// 只取属于该站点宿主（含 www 变体）的 Cookie；读不到或宿主不支持时返回 []，绝不抛错。
export async function readCloudCookies(ctx, site) {
  if (!supportsCookieCloud(ctx)) return []
  const domains = cloudDomains(site)
  if (!domains.length) return []
  try {
    const snapshot = await ctx.cookiecloud('read', { domains })
    const cookies = Array.isArray(snapshot?.cookies) ? snapshot.cookies : []
    const allowed = new Set(domains)
    return cookies.filter(item => {
      if (!item || !item.name) return false
      const domain = String(item.domain || '').toLowerCase().replace(/^\./, '').replace(/\.$/, '')
      return allowed.has(domain)
    }).map(item => ({
      name: String(item.name),
      value: String(item.value ?? ''),
      domain: String(item.domain || domains[0]).replace(/^\./, ''),
      path: String(item.path || '/'),
      host_only: Boolean(item.host_only),
      secure: Boolean(item.secure),
      http_only: Boolean(item.http_only),
      ...(item.same_site ? { same_site: item.same_site } : {}),
      ...(Number.isFinite(item.expires_at) ? { expires_at: item.expires_at } : {}),
    }))
  } catch {
    return []
  }
}

// CookieCloud 的 Cookie 对象转成「name=value; ...」字符串，供明文头通道与界面预览使用。
export function cookiesToString(cookies) {
  return (Array.isArray(cookies) ? cookies : [])
    .filter(item => item && item.name)
    .map(item => `${item.name}=${item.value ?? ''}`)
    .join('; ')
}

export async function readSites(ctx) {
  const value = await ctx.storage.get(KEYS.sites)
  return Array.isArray(value) ? value : []
}

export async function writeSites(ctx, sites) {
  await ctx.storage.set(KEYS.sites, sites)
}

export async function readHistory(ctx) {
  const value = await ctx.storage.get(KEYS.history)
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

export async function readConfig(ctx) {
  const value = await ctx.storage.get(KEYS.config)
  return {
    ...(value || {}),
    // 通知默认开启；只有用户显式关掉才不发。
    notify: value?.notify !== false,
    notifyOnFailureOnly: Boolean(value?.notifyOnFailureOnly),
  }
}

export function dayKey(timestamp = Date.now()) {
  const date = new Date(timestamp)
  const pad = n => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}

// 用户关键词必须是「陈述句」，不能出自规则/奖励说明段落。
// 例：我堡签到页写着「连续签到 10 天后，每次签到额外获得 5 魔力值」，
// 命中「连续签到」就会被当成签到成功，而实际上那个页面还在等人机验证。
const RULE_CONTEXT = /(?:额外|額外|规则|規則|说明|說明|封顶|封頂|累积|累積|天后|可获得|可獲得|算作|视为|視為|不等|奖励说明)/
function includesAny(text, keywords) {
  const lower = text.toLowerCase()
  for (const word of keywords) {
    if (!word) continue
    const needle = String(word).toLowerCase()
    let at = lower.indexOf(needle)
    if (at < 0) continue
    // 同一关键词可能多处出现，任意一处落在陈述句里就算命中。
    let ok = false
    while (at >= 0) {
      const sentence = text.slice(Math.max(0, at - 30), at + needle.length + 30)
      if (!RULE_CONTEXT.test(sentence)) { ok = true; break }
      at = lower.indexOf(needle, at + needle.length)
    }
    if (ok) return word
  }
  return null
}

function safeChar(code) {
  return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : ''
}

export function decodeEntities(value) {
  const named = { nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }
  return String(value || '')
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => safeChar(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => safeChar(parseInt(dec, 10)))
    .replace(/&([a-z][a-z0-9]*);/gi, (whole, name) => named[String(name).toLowerCase()] ?? whole)
}

// 只保留页面可见内容：剔除 head、脚本、样式、模板、注释、隐藏元素（hidden/aria-hidden/type=hidden/
// display:none/visibility:hidden），对齐 AutoSignIn 的 visible_html，避免隐藏模板里的「签到成功」骗过判定。
// 判断一个标签的属性是否表示「隐藏」。必须按属性名精确判定：
// aria-hidden="false"、data-hidden、class="not-hidden" 都不是隐藏，
// 用 \bhidden\b 这种宽松写法会把它们连同容器里的签到回执一起删掉（憨憨就是这么被误判的）。
function isHiddenAttrs(attrs) {
  const a = String(attrs || '')
  if (/(?:^|\s)hidden(?:\s*=\s*(?:["']?hidden["']?)?)?(?=\s|\/?>|$)/i.test(a)) return true
  if (/(?:^|\s)aria-hidden\s*=\s*["']?true/i.test(a)) return true
  if (/(?:^|\s)type\s*=\s*["']?hidden/i.test(a)) return true
  if (/(?:^|\s)style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)/i.test(a)) return true
  return false
}

// 单页最多处理这么多字符。PT 站点首页动辄 200KB+，签到回执常在后半段，
// 截太小会把真实回执切掉（憨憨就是这个原因被判成「无回执」）。
export const MAX_HTML = 800000

// 顶层标签里不带文本语义的，直接跳过。
const VOID_TAGS = new Set(['br', 'img', 'input', 'meta', 'link', 'hr', 'source', 'track', 'wbr', 'area', 'base', 'col', 'embed', 'param'])

// 按标签栈扫描剔除隐藏容器。不能用一条非贪婪正则：`<html>…</html>` 会一口吞掉整页，
// 里面的 `<div hidden>` 就再也不会被检查到。
function stripHidden(html) {
  const source = String(html || '')
  const re = /<(\/?)([a-z][a-z0-9]*)\b([^>]*)>/gi
  let out = ''
  let cursor = 0
  let skipTag = ''
  let depth = 0
  let match
  while ((match = re.exec(source))) {
    const closing = match[1] === '/'
    const tag = match[2].toLowerCase()
    if (depth > 0) {
      if (tag === skipTag) {
        depth += closing ? -1 : 1
        if (depth === 0) skipTag = ''
      }
      cursor = re.lastIndex
      continue
    }
    if (!closing && isHiddenAttrs(match[3])) {
      out += source.slice(cursor, match.index)
      if (VOID_TAGS.has(tag) || /\/\s*>$/.test(match[0])) {
        cursor = re.lastIndex
        continue
      }
      skipTag = tag
      depth = 1
      cursor = re.lastIndex
    }
  }
  out += source.slice(cursor)
  return out
}

function sanitizeHTML(html) {
  let text = String(html || '').slice(0, MAX_HTML)
  text = text.replace(/<head\b[^>]*>[\s\S]*?<\/head\s*>/gi, ' ')
  text = text.replace(/<!--[\s\S]*?-->/g, ' ')
  text = text.replace(/<(script|style|template|noscript|textarea)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ')
  return stripHidden(text)
}

export function visibleText(html) {
  return decodeEntities(sanitizeHTML(html).replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim()
}

function attrValue(attrs, name) {
  const quoted = new RegExp('\\b' + name + '\\s*=\\s*(["\'])([\\s\\S]*?)\\1', 'i').exec(attrs || '')
  if (quoted) return decodeEntities(quoted[2])
  const bare = new RegExp('\\b' + name + '\\s*=\\s*([^\\s>]+)', 'i').exec(attrs || '')
  return bare ? decodeEntities(bare[1]) : ''
}

// 抽取页面里带文本的控件与短文本节点，供"按钮仍在等用户操作""页面提示尚未签到"等判定使用。
// 与 visibleText 用同一套剔除规则：隐藏模板、脚本、注释里的文字不算页面内容。
function elementLabels(html) {
  const source = sanitizeHTML(html)
  const list = []
  const inputRe = /<input\b([^>]*)>/gi
  let match
  while ((match = inputRe.exec(source))) {
    const value = attrValue(match[1], 'value')
    if (value) list.push({ tag: 'input', attrs: match[1] || '', label: value.replace(/\s+/g, '') })
  }
  const pairRe = /<(a|button|label|span|div|td|li|p|strong|b|h1|h2|h3|form)\b([^>]*)>([\s\S]{0,120}?)<\/\1\s*>/gi
  while ((match = pairRe.exec(source))) {
    const inner = decodeEntities(String(match[3]).replace(/<[^>]*>/g, '')).replace(/\s+/g, '').trim()
    if (inner) list.push({ tag: match[1].toLowerCase(), attrs: match[2] || '', label: inner })
  }
  return list
}

// 判定"是否被弹回登录页"：只认真正的密码输入框。
// 不能用"登录"二字做判断——NexusPHP 页脚/导航/「上次登录时间」都含该词，会误杀有效 Cookie。
export function hasLoginForm(html) {
  return /<input\b[^>]*\btype\s*=\s*["']?password/i.test(String(html || ''))
}

// HTTP 状态语义化：403 访问被拒、429 频率受限、5xx 站点故障。
export function httpFailure(status) {
  if (status === 403 || status === 401) return '访问被拒绝（HTTP ' + status + '），检查 Cookie 或站点防护'
  if (status === 429) return '访问频率受限（HTTP 429），稍后再试'
  if (status >= 500) return '站点服务异常（HTTP ' + status + '）'
  return '站点返回 HTTP ' + status
}

// Cloudflare / WAF 拦截页识别：命中即说明请求没真正打到站点业务页，不能当作签到结果。
const CHALLENGE_MARKERS = [
  /just a moment/i,
  /checking your browser/i,
  /^attention required/i,
  /cf-browser-verification/i,
  /cf_chl_opt/i,
  /__cf_chl_/i,
  /enable javascript and cookies to continue/i,
  /verify you are human/i,
  /ddos protection by/i,
]

export function underChallenge(html, headers) {
  if (String(header(headers, 'cf-mitigated') || '').trim()) return true
  const text = String(html || '').slice(0, MAX_HTML)
  if (!text.trim()) return false
  const title = (/<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(text) || [])[1] || ''
  return CHALLENGE_MARKERS.some(re => re.test(title) || re.test(text.slice(0, 4000)))
}

// 请求被站点踹到登录页：即使登录页是 JS 渲染、没有 password 输入框，也能一眼认出凭据没生效。
// 只看最终地址，不误伤正文里出现 logo/demo 之类关键词的页面。
export function loginRedirected(response) {
  const finalUrl = String(response && response.url || '')
  if (!finalUrl) return false
  return /\/login(?:\.php)?(?:[/?#]|$)/i.test(finalUrl) || /[?&]returnto=/i.test(finalUrl)
}

// 登录态证据：存在退出/登出控件，或 NexusPHP 的用户中心入口。隐藏模板与登录表单不算。
export function hasLoginEvidence(html) {
  const source = String(html || '')
  if (!source.trim() || hasLoginForm(source)) return false
  if (/<[a-z][^>]*\b(?:href|action|formaction|data-url|onclick|lay-on)\s*=\s*["'][^"']*\b(?:logout|logoff|signout)\b/i.test(source)) {
    return true
  }
  const logoutLabels = new Set(['退出登录', '退出登錄', '登出', 'logout', 'signout'])
  for (const item of elementLabels(source)) {
    if (item.tag !== 'form' && logoutLabels.has(item.label.toLowerCase())) return true
  }
  // NexusPHP：登录后才有 userdetails.php / usercp.php 入口。
  if (/\b(?:userdetails|usercp)\.php\b/i.test(source)) return true
  return /(?:欢迎回来|歡迎回來)/.test(visibleText(source))
}

// 明确的失败凭据：出现即否决成功。
const SIGNIN_NEGATIVE = /(?:签到|簽到)(?:失败|失敗|未成功)|(?:未|没有|沒有)(?:签到|簽到)成功|签到出错/
// 页面仍在提示"尚未签到"
const UNSIGNED_NODE = /^(?:您|你)?(?:今天|今日)?(?:尚未|还未|還未|未|没有|沒有)(?:签到|簽到)[！!。.]?$/
// 站点明说"今天已经签到过"：NexusPHP 的标准台词（中文「您今天已经签到过了」/英文 already attend）。
// 这是「今天已签」而不是「本次刚刚签成功」，单独识别才能让通知分组说实话。
const ALREADY_TEXT = /(?:您|你)(?:今天|今日)?(?:已经|已)(?:签[过過]?到|簽[过過]?到)(?:过|過)?了?|(?:今天|今日)(?:已经|已)(?:签[过過]?到|簽[过過]?到)(?:过|過)?[到的]?了?|对不起[，,]?您今天已经签到过|already attend/i
// 明确的完成回执（含 NexusPHP 的"连续N天，今日获得N魔力值"）
const SIGNED_EXACT = /^(?:签到成功|簽到成功|(?:今日|今天)(?:已签到|已簽到|已经签到|已經簽到)|已经打卡|已經打卡)[✓✔✅]?[！!。.]?(?:[（(]连续\d+天[，,]今日获得\d+魔力值[）)])?$/
const SIGNED_BARE = /^(?:已签到|已簽到|已经签到|已經簽到)[！!。.]?$/
// 回执里含"签到成功/签到完成"即构成完成证据（真实站点常在其后追加连续天数与奖励，
// 早期版本要求整句精确匹配，多一个字就失效——这正是「明明签上了却显示待确认」的原因）。
const SIGNED_CONTAINS = /(?:签到|簽到)成功|打卡成功|(?:签到|簽到)完成|(?:签到|簽到)已完成/
// 句内完成回执：您今天已经签到 / 本次签到获得 N / 签到已得 N / 今天签到您获得 N 点魔力值
const SIGNED_TEXT = /(?:您|你)(?:今天|今日)(?:已(?:经)?签(?:到|过到)|已經簽到)(?:过|過|了)|(?:本次|此次)(?:签到|簽到)(?:您)?(?:获得|獲得)(?:了)?\d+(?:(?:点|點)?魔力值)?|(?:签到|簽到)已得\d+|(?:今天|今日)(?:签到|簽到)(?:您|你)?(?:获得|獲得)(?:了)?\d+(?:点|點)魔力值/
// NexusPHP 英文模板的真实回执——中文关键词匹配不到，这正是"别的插件能签、这里却不行"的主因。
const SIGNED_EN = /You have already attend, no refresh please\.|You have already attended \d+ days, Continuous \d+ days, this time you will get \d+ bonus\./i
const ACTION_LABELS = new Set(['签到', '簽到', '立即签到', '立即簽到', '每日签到', '每日簽到', '打卡', 'checkin', 'checkinnow'])

// 签到类文字不是封闭集合：「[签到得憨豆]」「每日签到领积分」都得认出来。
// 但「签到记录」「签到说明」这类是查看页面，点了反而危险，先排除。
const ACTION_NOT = /记录|記錄|历史|歷史|说明|說明|规则|規則|排行|帮助|幫助|教程|日志|日誌|详情|詳情|列表|日历|日曆|公告/
function isSigninLabel(value) {
  const label = String(value || '')
    .replace(/[\s[\]【】()（）:：·•,，.。!！?？"'“”‘’]/g, '')
    .toLowerCase()
  if (!label) return false
  if (ACTION_LABELS.has(label)) return true
  if (ACTION_NOT.test(label) || label.length > 24) return false
  return /^(?:每日|立即|今天|今日|马上|馬上)?(?:签到|簽到|打卡)/.test(label)
}

// 页面是否仍摆着「签到」按钮：有则说明签到动作还没完成（GET 没生效或需要 POST）。
export function hasSignAction(html, pageUrl) {
  // 导航栏里指向「签到页自己」的入口（典型如 NexusPHP 顶部「每日签到」→ 当前页）是导航，不是待点的动作。
  // 把它当成「按钮还在」会让已经签完的页面永远判不出完成——彩虹岛的 bakatest 就是这样被卡成待确认的。
  let selfPath = ''
  try {
    const base = pageUrl ? new URL(String(pageUrl)) : null
    selfPath = base ? base.pathname.replace(/\/+$/, '') || '/' : ''
  } catch { selfPath = '' }

  return elementLabels(html).some(item => {
    if (!(item.tag === 'input' || item.tag === 'button' || item.tag === 'a')) return false
    if (!isSigninLabel(item.label)) return false
    // 表单按钮不看 href：只要页面上真的有提交按钮，就仍然算「等用户操作」。
    if (item.tag === 'a' && selfPath) {
      const href = attrValue(item.attrs, 'href')
      if (href) {
        try {
          const target = new URL(href, pageUrl)
          const path = target.pathname.replace(/\/+$/, '') || '/'
          if (path === selfPath) return false
        } catch { /* 解析不了就保持原判定 */ }
      }
    }
    return true
  })
}

// 从页面里找出真正的「签到按钮」，模拟人点一下：可能是表单提交，也可能是一个带参数的链接。
// 只接受与签到页同站点的 https 地址，避免被页面内容引导到第三方域名。
export function findSigninAction(html, pageUrl) {
  const source = String(html || '').slice(0, MAX_HTML)
  const isAction = value => isSigninLabel(value)
  const sameSite = href => {
    try {
      const url = safeSiteURL(href, pageUrl)
      if (url.hostname !== new URL(pageUrl).hostname) return null
      return url.href
    } catch { return null }
  }
  // 指向当前页自身的「每日签到」导航不是动作：点了只会重新加载同一页。
  const samePath = href => {
    try {
      const path = new URL(href).pathname.replace(/\/+$/, '') || '/'
      const self = new URL(pageUrl).pathname.replace(/\/+$/, '') || '/'
      return path === self
    } catch { return false }
  }
  let match

  // 1) 链接式签到：<a href="attendance.php?action=sign">签到</a>
  const anchorRe = /<a\b([^>]*)>([\s\S]{0,160}?)<\/a\s*>/gi
  while ((match = anchorRe.exec(source))) {
    const label = decodeEntities(String(match[2]).replace(/<[^>]*>/g, '')).replace(/\s+/g, '').trim()
    if (!isAction(label)) continue
    const url = sameSite(attrValue(match[1], 'href'))
    if (url && !samePath(url)) return { kind: 'link', url, method: 'GET', fields: [], label }
  }

  // 2) 表单式签到：连同隐藏字段（formhash / CSRF token）一起提交，等价于点击按钮。
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi
  while ((match = formRe.exec(source))) {
    const formAttrs = match[1] || ''
    const inner = match[2] || ''
    const fields = []
    let label = ''
    let hit = false
    let tag

    const inputRe = /<input\b([^>]*)>/gi
    while ((tag = inputRe.exec(inner))) {
      const attrs = tag[1] || ''
      const type = (attrValue(attrs, 'type') || 'text').toLowerCase()
      const name = attrValue(attrs, 'name')
      const value = attrValue(attrs, 'value')
      if (type === 'submit' || type === 'image' || type === 'button') {
        if (isAction(value) || isAction(name)) {
          hit = true
          label = value || name
          if (name) fields.push({ name, value })
        }
        continue
      }
      if (!name) continue
      if (type === 'hidden' || type === 'text' || type === 'checkbox' || type === 'radio') {
        fields.push({ name, value })
      }
    }

    if (!hit) {
      const buttonRe = /<button\b([^>]*)>([\s\S]{0,160}?)<\/button\s*>/gi
      while ((tag = buttonRe.exec(inner))) {
        const attrs = tag[1] || ''
        const text = decodeEntities(String(tag[2]).replace(/<[^>]*>/g, '')).replace(/\s+/g, '').trim()
        if (!isAction(text) && !isAction(attrValue(attrs, 'value'))) continue
        hit = true
        label = text || attrValue(attrs, 'value')
        const name = attrValue(attrs, 'name')
        if (name) fields.push({ name, value: attrValue(attrs, 'value') })
      }
    }

    if (!hit) continue
    const url = sameSite(attrValue(formAttrs, 'action') || pageUrl)
    if (!url) continue
    const rawMethod = (attrValue(formAttrs, 'method') || '').toUpperCase()
    return {
      kind: 'form',
      url,
      method: rawMethod === 'GET' ? 'GET' : 'POST',
      fields: fields.filter(field => field.name),
      label,
    }
  }
  return null
}

// ===== 签到线索 =====
// 诊断用：把页面里与「签到」有关的原文和链接摊开。遇到 200 但既没回执也没按钮的站点，
// 靠这些线索判断入口到底在哪，而不是对着页面瞎猜。
const HINT_KEYWORD = /签到|簽到|打卡|已签|已打|每日签到|attend|sign\s?in|check\s?in|daily\s?(?:sign|check)/i

export function signinHints(html, pageUrl) {
  const source = String(html || '').slice(0, MAX_HTML)
  const text = visibleText(source)
  const keywords = []
  for (const raw of text.split(/[。！？!?；;\n\r|]+/)) {
    const line = raw.trim()
    if (!line || line.length > 240 || !HINT_KEYWORD.test(line)) continue
    const at = line.search(HINT_KEYWORD)
    const snippet = line.slice(Math.max(0, at - 24), at + 76).trim()
    if (snippet && !keywords.includes(snippet)) keywords.push(snippet)
    if (keywords.length >= 8) break
  }

  const links = []
  let base
  try { base = new URL(pageUrl).hostname } catch { base = '' }
  const anchorRe = /<a\b([^>]*)>([\s\S]{0,140}?)<\/a\s*>/gi
  let match
  while ((match = anchorRe.exec(source))) {
    const href = attrValue(match[1], 'href')
    const label = textOf(match[2])
    if (!HINT_KEYWORD.test(label) && !/attend|signin|sign\.php|checkin|clock|bonus/i.test(String(href || ''))) continue
    let abs = ''
    try {
      const url = safeSiteURL(href, pageUrl)
      if (!base || url.hostname === base) abs = url.href
    } catch { abs = '' }
    if (!abs) continue
    const entry = `${label || '(无文字)'} → ${abs}`
    if (!links.includes(entry)) links.push(entry)
    if (links.length >= 8) break
  }
  return { keywords, links }
}

// ===== 交互式签到障碍 =====
// 两类页面不可能靠「再发一次 GET」变成功：图形验证码、答题签到。

// 图形验证码：签到页里出现验证码图片或验证码字段。
// 登录页自带的验证码不算签到障碍——那种情况 hasLoginForm 已先一步判成 Cookie 失效。
const CAPTCHA_IMG = /<img\b[^>]*\bsrc\s*=\s*["'][^"']*(?:regimage|secimage|captcha|verifycode|verify\.php|checkcode|seccode|authcode|vcode|imagecode|randcode|showup)/i
const CAPTCHA_INPUT = /<input\b[^>]*\bname\s*=\s*["']?(?:imagestring|imagehash|captcha|verify_?code|checkcode|seccode|vcode|authcode)[\s"'>]/i

export function hasCaptcha(html) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim() || hasLoginForm(source)) return false
  return CAPTCHA_IMG.test(source) || CAPTCHA_INPUT.test(source)
}

// Cloudflare Turnstile 签到：页面里有 cf-turnstile widget 或它的回调/脚本。
// 这类站点点签到前必须由浏览器执行 JS 跑过人机验证、注入 cf-turnstile-response
// 再提交表单；纯 HTTP 请求拿不到那个 token，只有宿主渲染器能过。
// 识别出来后交给 signWithFallback 的渲染分支处理，而不是当普通按钮去点。
const TURNSTILE_MARKERS = /cf-turnstile|turnstile\/v0\/api\.js|TurnstileCallback|cf-turnstile-response|data-sitekey/i

export function hasTurnstile(html) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim() || hasLoginForm(source)) return false
  return TURNSTILE_MARKERS.test(source)
}

// 二次验证（2FA/TOTP）拦截页：NexusPHP 在未完成两步验证时，会把任何请求都替换成
// 「提交 6 位动态码」的表单——form action 指向 take2fa.php，字段名是 2fa。
// 不先过这一步，签到页永远打不开。识别出来后由 signin.js 用站点自己的
// TOTP 密钥算码并提交，密钥只在本机参与 HMAC，不外发、不进日志。
const TWO_FACTOR_MARKERS = /take2fa\.php|<input\b[^>]*\bname\s*=\s*["']?2fa["'\s>]/i

export function hasTwoFactor(html) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim()) return false
  // 有些站点（如 UHDDolby）把动态码输入框直接做进登录表单：
  // <form action="takelogin.php"> 里同时有 password 与 2fa 两个输入框。
  // 那是「登录页需要 2FA」，不是「已登录但被 take2fa.php 拦下」，判成后者会去
  // 提交一个根本没有会话承载的动态码，再把失败原因说成密钥不对——所以先排除登录表单。
  if (hasLoginForm(source)) return false
  return TWO_FACTOR_MARKERS.test(source)
}

// 登录表单里是否自带动态码输入框（说明该站登录必须过 2FA）。
// 用于把「Cookie 失效，需要重新登录（登录本身要 2FA）」讲清楚，
// 而不是笼统报「Cookie 已失效」或误报成站内二次验证拦截。
export function loginNeedsTwoFactor(html) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim()) return false
  return hasLoginForm(source) && TWO_FACTOR_MARKERS.test(source)
}

// 取出 2FA 表单的提交地址与随表单提交的普通字段。
// NexusPHP 的 take2fa.php 除了动态码，还要 type=save 与 returnto 两个隐藏域，
// 少一个就会被判无效；所以这里把表单里的非提交按钮字段整体带上。
// 只接受与页面同站点的提交目标，跨域一律丢弃。
export function parseTwoFactorForm(html, pageUrl) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim()) return null
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi
  let match
  while ((match = formRe.exec(source))) {
    const inner = match[2]
    if (!/name\s*=\s*["']?2fa["'\s>]/i.test(inner)) continue
    const action = attrValue(match[1], 'action') || 'take2fa.php'
    const abs = sameSiteHref(action, pageUrl)
    if (!abs) continue
    const fields = []
    const inputRe = /<input\b([^>]*)>/gi
    let input
    while ((input = inputRe.exec(inner))) {
      const attrs = input[1]
      const type = String(attrValue(attrs, 'type') || 'text').toLowerCase()
      if (type === 'submit' || type === 'button' || type === 'image' || type === 'file' || type === 'reset') continue
      const name = attrValue(attrs, 'name')
      if (!name || name === '2fa') continue
      fields.push({ name, value: attrValue(attrs, 'value') })
    }
    return { action: abs, fields }
  }
  // 没有可解析的 <form> 但页面明显是 2FA 页时，退回 NexusPHP 的固定提交地址与固定字段。
  if (TWO_FACTOR_MARKERS.test(source)) {
    const abs = sameSiteHref('take2fa.php', pageUrl)
    if (abs) return { action: abs, fields: [] }
  }
  return null
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

// 归一化用户填的 TOTP 密钥：去掉空格/连字符/尾部等号，统一大写。
export function normalizeTotpSecret(raw) {
  return String(raw || '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '')
}

export function isValidTotpSecret(raw) {
  const key = normalizeTotpSecret(raw)
  if (key.length < 8) return false
  for (const ch of key) if (!BASE32_ALPHABET.includes(ch)) return false
  return true
}

function base32Decode(key) {
  const out = []
  let value = 0
  let bits = 0
  for (const ch of key) {
    const index = BASE32_ALPHABET.indexOf(ch)
    if (index < 0) return null
    value = ((value << 5) | index) & 0xffff
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
      value &= (1 << bits) - 1
    }
  }
  return out.length ? Uint8Array.from(out) : null
}

// 按 RFC 6238 生成动态码（默认 6 位 / 30 秒）。密钥是用户自己在站点绑定的
// base32 secret，只在本机参与 HMAC-SHA1，算出的码只发往该站点。
export function totpCode(ctx, secret, options = {}) {
  const key = normalizeTotpSecret(secret)
  if (!key) return ''
  const bytes = base32Decode(key)
  if (!bytes) return ''
  const digits = Number(options.digits) || 6
  const period = Number(options.period) || 30
  const counter = Math.floor((Number(options.at) || Date.now()) / 1000 / period)

  const message = new Uint8Array(8)
  let rest = counter
  for (let i = 7; i >= 0; i -= 1) {
    message[i] = rest & 0xff
    rest = Math.floor(rest / 256)
  }

  const mac = ctx.crypto.hmac('sha1', bytes, message, 'bytes')
  const hash = mac instanceof Uint8Array ? mac : Uint8Array.from(mac || [])
  if (hash.length < 20) return ''
  const offset = hash[hash.length - 1] & 0x0f
  const binary = ((hash[offset] & 0x7f) << 24)
    | ((hash[offset + 1] & 0xff) << 16)
    | ((hash[offset + 2] & 0xff) << 8)
    | (hash[offset + 3] & 0xff)
  return String(binary % (10 ** digits)).padStart(digits, '0')
}

// 从签到页解析图形验证码：图片地址、可见的 hash 字段、以及签到表单的提交目标。
// 天空(HDSKY) 的套路：页面里 <img src="...regimage...&imagehash=xxx">，表单里
// <input name="imagehash" value="xxx"> + <input name="imagestring">，提交到 showup.php。
// 只接受与页面同站点的图片与提交地址，跨域一律丢弃，避免把 Cookie 或验证码带去别的域名。
export function parseCaptchaForm(html, pageUrl) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim()) return null
  let page
  try { page = new URL(pageUrl) } catch { return null }

  // 1) 验证码图片地址：优先带 captcha/regimage/verify 字样的 img
  let imageUrl = ''
  const imgRe = /<img\b([^>]*)>/gi
  let match
  while ((match = imgRe.exec(source))) {
    const src = attrValue(match[1], 'src')
    if (!src || !/(?:captcha|regimage|secimage|verifycode|verify\.php|checkcode|seccode|authcode|vcode|imagecode|randcode|showup)/i.test(src)) continue
    const abs = sameSiteHref(src, pageUrl)
    if (abs) { imageUrl = abs; break }
  }
  if (!imageUrl) return null

  // 2) 从图片 URL 或页面隐藏字段里取 imagehash
  let imagehash = ''
  try { imagehash = new URL(imageUrl).searchParams.get('imagehash') || '' } catch {}
  const hiddenRe = /<input\b([^>]*)>/gi
  while ((match = hiddenRe.exec(source))) {
    const attrs = match[1] || ''
    const name = (attrValue(attrs, 'name') || '').toLowerCase()
    if (/^(?:imagehash|hash|verify_?hash|seccode_?hash|captcha_?hash)$/.test(name)) {
      imagehash = attrValue(attrs, 'value') || imagehash
      break
    }
  }

  // 3) 提交表单：找含验证码输入框的 form，取 action / method / 隐藏字段
  let submit = null
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi
  while ((match = formRe.exec(source))) {
    const inner = match[2] || ''
    const hasCodeInput = /<input\b[^>]*\bname\s*=\s*["']?(?:imagestring|imagehash|captcha|verify_?code|checkcode|seccode|vcode|authcode)[\s"'>]/i.test(inner)
    if (!hasCodeInput) continue
    const fields = []
    const fieldRe = /<input\b([^>]*)>/gi
    let tag
    while ((tag = fieldRe.exec(inner))) {
      const attrs = tag[1] || ''
      const name = attrValue(attrs, 'name')
      if (!name) continue
      const type = (attrValue(attrs, 'type') || 'text').toLowerCase()
      if (type === 'hidden' || type === 'text') fields.push({ name, value: attrValue(attrs, 'value') })
    }
    // 把 code 字段名记下来，提交时用识别结果替换它的 value
    const codeName = fields.find(f => /^(?:imagestring|captcha|verify_?code|checkcode|seccode|vcode|authcode)$/i.test(f.name))?.name || 'imagestring'
    const action = attrValue(match[1], 'action') || pageUrl
    const target = sameSiteHref(action, pageUrl)
    if (!target) continue
    submit = {
      url: target,
      method: (attrValue(match[1], 'method') || '').toUpperCase() === 'GET' ? 'GET' : 'POST',
      fields,
      codeName,
    }
    break
  }

  return { imageUrl, imagehash, submit, pageUrl: page.href }
}

// 天空类站点：签到入口是 JS 触发的 <a id="showup">，页面本身带验证码图。
// 这类站点没有可提交的 form，需要走它自己的固定接口（见 signin.js 的 skyCaptcha）。
export function isSkyCaptchaSite(site) {
  const host = String(site?.host || '').toLowerCase().replace(/^www\./, '')
  return host === 'hdsky.my' || site?.captchaMode === true
}

function textOf(fragment) {
  return decodeEntities(String(fragment || '').replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim()
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// 从「第一个选项之前的那段文字」里切出题目：取最后一个问号所在句，去掉前面的导航/标题。
function lastQuestion(text) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim()
  if (!clean) return ''
  const tail = clean.slice(-300)
  const mark = Math.max(tail.lastIndexOf('？'), tail.lastIndexOf('?'))
  if (mark < 0) return tail
  const head = tail.slice(0, mark + 1)
  const cut = Math.max(
    head.lastIndexOf('。'), head.lastIndexOf('；'), head.lastIndexOf('！'),
    head.lastIndexOf('.'), head.lastIndexOf(';'),
  )
  const sentence = head.slice(cut + 1).trim().replace(/^["'“”‘’「」『』\s]+/, '').trim()
  return sentence.length >= 4 ? sentence : head.trim()
}

function sameSiteHref(href, pageUrl) {
  try {
    const url = safeSiteURL(href, pageUrl)
    if (url.hostname !== new URL(pageUrl).hostname) return null
    return url.href
  } catch { return null }
}

// 题干图可能挂在站点自己的图床/CDN 域名上（不是页面同域），
// 取图只读这张公开图片、不带任何 Cookie，所以这里不做同域限制。
function anySiteHref(href, pageUrl) {
  try {
    const url = new URL(String(href || '').trim(), pageUrl)
    if (!/^https?:$/.test(url.protocol)) return null
    url.hash = ''
    return url.href
  } catch { return null }
}

// 解析答题签到页：找出题目、选项（同一 radio name 且 ≥2 个）、隐藏字段与提交目标。
// 只认「多选题组 + 提交按钮」这种结构，普通签到表单不会被误认。
export function parseQuizForm(html, pageUrl) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim()) return null
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi
  let form
  while ((form = formRe.exec(source))) {
    const formAttrs = form[1] || ''
    const inner = form[2] || ''
    if (!inner.trim()) continue

    const radios = []
    const inputRe = /<input\b([^>]*)>/gi
    let tag
    while ((tag = inputRe.exec(inner))) {
      const attrs = tag[1] || ''
      if ((attrValue(attrs, 'type') || '').toLowerCase() !== 'radio') continue
      const name = attrValue(attrs, 'name')
      if (!name) continue
      radios.push({
        name,
        value: attrValue(attrs, 'value'),
        id: attrValue(attrs, 'id'),
        checked: /\bchecked\b/i.test(attrs),
        start: tag.index,
        end: tag.index + tag[0].length,
      })
    }
    if (!radios.length) continue

    // 同一 name 下至少两个选项才算一道选择题
    const groups = new Map()
    for (const radio of radios) {
      if (!groups.has(radio.name)) groups.set(radio.name, [])
      groups.get(radio.name).push(radio)
    }
    const picked = [...groups.values()].find(list => list.length >= 2)
    if (!picked) continue

    // 提交按钮：答题表单的提交是「提交」而不是「签到」
    let submitLabel = ''
    let hasSubmit = false
    const subRe = /<input\b([^>]*)>|<button\b([^>]*)>([\s\S]{0,80}?)<\/button\s*>/gi
    while ((tag = subRe.exec(inner))) {
      const attrs = tag[1] || tag[2] || ''
      const type = (attrValue(attrs, 'type') || (tag[2] ? 'submit' : '')).toLowerCase()
      if (type !== 'submit') continue
      hasSubmit = true
      submitLabel = attrValue(attrs, 'value') || textOf(tag[3] || '')
      if (submitLabel) break
    }
    if (!hasSubmit) continue

    const options = picked.map(radio => {
      let label = ''
      if (radio.id) {
        const byFor = new RegExp(
          '<label\\b[^>]*\\bfor\\s*=\\s*["\']?' + escapeRegExp(radio.id) + '["\']?[^>]*>([\\s\\S]{0,160}?)</label\\s*>',
          'i',
        ).exec(inner)
        if (byFor) label = textOf(byFor[1])
      }
      if (!label) {
        const tail = inner.slice(radio.end, radio.end + 260)
        const stop = tail.search(/<input\b|<\/td\s*>|<\/tr\s*>|<\/label\s*>|<\/li\s*>/i)
        label = textOf(stop >= 0 ? tail.slice(0, stop) : tail).slice(0, 40)
      }
      return { name: radio.name, value: radio.value, label: label || radio.value }
    })
    // 选项文字全为空说明结构不认识，不要瞎选
    if (options.filter(item => item.label && item.label !== item.value).length < 2) continue

    const fields = []
    const fieldRe = /<input\b([^>]*)>|<textarea\b([^>]*)>([\s\S]*?)<\/textarea\s*>/gi
    while ((tag = fieldRe.exec(inner))) {
      const attrs = tag[1] || tag[2] || ''
      const type = (attrValue(attrs, 'type') || (tag[2] ? 'textarea' : 'text')).toLowerCase()
      const name = attrValue(attrs, 'name')
      if (!name) continue
      if (type === 'hidden' || type === 'text' || type === 'textarea') {
        const value = type === 'textarea' ? decodeEntities(tag[3] || '').trim() : attrValue(attrs, 'value')
        fields.push({ name, value })
      }
    }

    const url = sameSiteHref(attrValue(formAttrs, 'action') || pageUrl, pageUrl)
    if (!url) continue
    const method = (attrValue(formAttrs, 'method') || '').toUpperCase() === 'GET' ? 'GET' : 'POST'
    // 有些站点的题目是「看图认人/认物」：题干就是一张图，旁边才是文字选项。
    // 只把文字喂给 AI 的话它只能回 UNKNOWN，所以这里把题干图片地址也取出来。
    const image = (() => {
      // 先看表单内选项之前的图片；找不到再往表单上方的区块找（题干图常摆在表单外面）。
      const zones = [inner.slice(0, picked[0].start), source.slice(Math.max(0, form.index - 3000), form.index)]
      for (const zone of zones) {
        const imgRe = /<img\b([^>]*)>/gi
        let img
        let found = ''
        while ((img = imgRe.exec(zone))) {
          const attrs = img[1]
          const src = attrValue(attrs, 'src') || ''
          // 题干图可能不是 src：NexusPHP 常用 pic/trans.gif 占位，
          // 真图放在 data-src/data-original 或 style 的 background:url(...) 里。
          const styleBg = /url\(\s*['"]?([^'")]+)['"]?\s*\)/i.exec(attrValue(attrs, 'style') || '')
          const real = attrValue(attrs, 'data-src') || attrValue(attrs, 'data-original') || (styleBg ? styleBg[1] : '')
          const pick = real || src
          if (!pick || /^data:/i.test(pick)) continue
          // 1×1 统计像素不是题干图，跳过。
          if (/\b(?:width|height)\s*=\s*["']?1\b/i.test(attrs)) continue
          if (PLACEHOLDER_IMG.test(pick) || (!real && PLACEHOLDER_IMG.test(src))) continue
          const abs = anySiteHref(pick, pageUrl)
          if (abs) found = abs
        }
        if (found) return found
        // 老式 NexusPHP 皮肤爱用 <td background="quiz/x.jpg"> 铺图，没有 <img>。
        const bgRe = /background\s*=\s*["']([^"']+\.(?:jpe?g|png|gif|webp))["']/gi
        let bg
        while ((bg = bgRe.exec(zone))) {
          if (PLACEHOLDER_IMG.test(bg[1])) continue
          const abs = anySiteHref(bg[1], pageUrl)
          if (abs) found = abs
        }
        if (found) return found
      }
      return ''
    })()
    // 题干说明若写在表单外，往往连着「上传量/下载量」这类账号数据：
    // 只发题目与选项是不够的，但也绝不能把账号信息送给 AI，所以表单外文字一律不取。
    const block = textOf(inner.slice(0, picked[0].start)).replace(/\s+/g, ' ').trim()
    return {
      question: lastQuestion(block),
      // 题干区块的完整文字：描述句常常在问句前面（「他是两弹元勋，请问他是谁？」），
      // 只留最后一句会把线索丢干净，AI 自然只能回「无法确定」。
      context: block.slice(-300),
      options,
      fields,
      url,
      method,
      image,
      label: submitLabel || '提交',
    }
  }
  return null
}

// 整页里的图片地址（只取 URL，不下载、不保存图片内容）。
// 用于「题目明显该配图却找不到图」时给用户/日志一个线索：题目图可能不在表单内，
// 而是摆在表单上方的独立区块里。
// NexusPHP 常拿 pic/trans.gif 当占位图（真实图片地址另放在 style/data-* 里），
// 这类图和站点小图标、等级条、表情都不是题干图，喂给 AI 只会得到一句「无法确定」。
const PLACEHOLDER_IMG = /(?:trans\.gif|spacer|blank\.gif|pixel|loading\.(?:gif|png)|smilies|emoticon|\/icons?\/|\/styles\/|level_|star_)/i
export function pageImageCandidates(html, pageUrl, limit = 6) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim()) return []
  const out = []
  const re = /<img\b([^>]*)>/gi
  let m
  while ((m = re.exec(source)) && out.length < limit) {
    const src = attrValue(m[1], 'src') || attrValue(m[1], 'data-src')
    if (!src || /^data:/i.test(src)) continue
    if (/\b(?:width|height)\s*=\s*["']?1\b/i.test(m[1])) continue
    // 站点图标/表情/等级条之类的小图没有题干价值。
    if (PLACEHOLDER_IMG.test(src)) continue
    const abs = sameSiteHref(src, pageUrl)
    if (abs && !out.includes(abs)) out.push(abs)
  }
  return out
}

// 只抽图片相关线索（img 标签属性 + CSS background 里的 url），不导出页面正文。
// 答题页把图放在 style/data-* 或 CSS 背景里时，靠这些线索才能定位真正的题干图。
export function quizImageHints(html, pageUrl, limit = 4) {
  const source = String(html || '').slice(0, MAX_HTML)
  if (!source.trim()) return []
  const out = []
  const imgRe = /<img\b([^>]*)>/gi
  let m
  while ((m = imgRe.exec(source)) && out.length < limit) {
    const attrs = m[1]
    const src = attrValue(attrs, 'src') || ''
    const style = attrValue(attrs, 'style') || ''
    const bg = /url\(\s*['"]?([^'")]+)['"]?\s*\)/i.exec(style)
    const bgUrl = bg ? bg[1] : ''
    const real = attrValue(attrs, 'data-src') || attrValue(attrs, 'data-original') || bgUrl || ''
    // 只有占位图本身、且没有任何真实地址的标签，才没有线索价值。
    if (!real && PLACEHOLDER_IMG.test(src)) continue
    const parts = []
    if (src) parts.push('src=' + src)
    if (real && real !== src) parts.push('real=' + real)
    const cls = attrValue(attrs, 'class')
    if (cls) parts.push('class=' + cls)
    const abs = anySiteHref(real || src, pageUrl) || real || src
    out.push(abs)
  }
  // 除 img 之外，老皮肤还用 <td background="..."> / CSS url(...) 铺题干图。
  const bgRe = /(?:background\s*=\s*["']([^"']+\.(?:jpe?g|png|gif|webp))["']|url\(\s*['"]?([^'")]+\.(?:jpe?g|png|gif|webp))['"]?\s*\))/gi
  let bg
  while ((bg = bgRe.exec(source)) && out.length < limit) {
    const pick = bg[1] || bg[2]
    if (!pick || PLACEHOLDER_IMG.test(pick)) continue
    const abs = anySiteHref(pick, pageUrl)
    if (abs && !out.includes(abs)) out.push(abs)
  }
  return out
}

// 题库文本：一行一条「题目关键词 = 答案」，关键词可用 | 或逗号分隔多个。
export function parseQuizBank(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'))
    .map(line => {
      const at = line.search(/=>|＝|=/)
      if (at <= 0) return null
      const rawKey = line.slice(0, at).trim()
      const answer = line.slice(at).replace(/^=>|^＝|^=/, '').trim()
      const keys = rawKey.split(/[|,，;；]/).map(item => item.trim()).filter(Boolean)
      if (!keys.length || !answer) return null
      return { keys, answer }
    })
    .filter(Boolean)
    .slice(0, 300)
}

function normKey(value) {
  return String(value || '').toLowerCase()
    .replace(/[\s\u3000]+/g, '')
    .replace(/[，。！？、,.!?：:；;“”"'‘’（）()《》〈〉【】\[\]—\-_/\\|~]/g, '')
}

// 把「答案」落到具体选项上：支持序号（1/2/3）、字母（A/B/C）与选项原文（同义/包含）。
export function pickQuizOption(options, answer) {
  const raw = String(answer || '').trim()
  if (!raw || !Array.isArray(options) || !options.length) return null
  // 纯序号优先：「3」「3.」「第3个」这类最不容易误判。
  const num = /^[#\s]*第?\s*(\d{1,2})\s*(?:[.、)）个]|选项)?\s*$/.exec(raw)
  if (num) {
    const index = Number(num[1]) - 1
    if (index >= 0 && index < options.length) return options[index]
  }
  if (/^[a-h]$/i.test(raw)) {
    const index = raw.toUpperCase().charCodeAt(0) - 65
    if (index >= 0 && index < options.length) return options[index]
  }
  const target = normKey(raw)
  if (target) {
    const exact = options.find(item => normKey(item.label) === target)
    if (exact) return exact
    const partial = options.find(item => {
      const label = normKey(item.label)
      return label && (label.includes(target) || target.includes(label))
    })
    if (partial) return partial
  }
  // 答案本身是符号（「.」「*」）：normKey 会把符号清空，按原文包含再比一次。
  if (raw.length <= 2) {
    const symbol = options.find(item => String(item.label).includes(raw))
    if (symbol) return symbol
  }
  return null
}

// 用题库匹配题目：多条命中取关键词最长的那条（更精确），答案再落到具体选项上。
export function matchQuizAnswer(quiz, bank) {
  if (!quiz || !Array.isArray(bank) || !bank.length) return null
  const question = normKey(quiz.question)
  if (!question) return null
  let best = null
  for (const rule of bank) {
    for (const key of rule.keys) {
      const token = normKey(key)
      if (token.length < 2 || !question.includes(token)) continue
      if (!best || token.length > best.token.length) best = { rule, token }
    }
  }
  if (!best) return null
  const option = pickQuizOption(quiz.options, best.rule.answer)
  return option ? { option, rule: best.rule, token: best.token } : null
}

// 把一次成功的作答落成题库行，供下次同题零成本命中。
// 关键词用题目原文，同一道题在站点上的文字是固定的；去掉会破坏「关键词 = 答案」格式的字符。
export function quizBankLine(question, answer) {
  const key = String(question || '').replace(/[\r\n=|＝]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60)
  const value = String(answer || '').replace(/[\r\n=|＝]/g, ' ').trim().slice(0, 30)
  if (normKey(key).length < 4 || !value) return ''
  return `${key} = ${value}`
}

// 交给界面与通知的题目摘要（不含任何站点凭据）。
export function quizSummary(quiz) {
  if (!quiz) return null
  return {
    question: String(quiz.question || '').slice(0, 120),
    options: (quiz.options || []).map(item => String(item.label || '').slice(0, 30)).slice(0, 8),
  }
}

// 站点是否明说「今天已经签到过」。
export function alreadySigned(html) {
  const source = String(html || '')
  if (!source.trim() || hasLoginForm(source)) return false
  const text = visibleText(source)
  const compact = text.replace(/\s+/g, '')
  if (SIGNIN_NEGATIVE.test(compact)) return false
  return ALREADY_TEXT.test(text) || ALREADY_TEXT.test(compact)
}

// 签到完成证据：只接受可见的完成回执或本次奖励；未完成的签到按钮与否定提示优先拒绝。
export function hasSigninEvidence(html) {
  const source = String(html || '')
  if (!source.trim() || hasLoginForm(source)) return false
  const text = visibleText(source)
  const compact = text.replace(/\s+/g, '')
  if (SIGNIN_NEGATIVE.test(compact)) return false
  const labels = elementLabels(source)
  // 页面上还有"签到"按钮，说明仍等用户操作，页面文案不构成完成证据。
  for (const item of labels) {
    if ((item.tag === 'input' || item.tag === 'button') && isSigninLabel(item.label)) return false
  }
  for (const item of labels) {
    if (UNSIGNED_NODE.test(item.label)) return false
  }
  for (const item of labels) {
    if (SIGNED_EXACT.test(item.label)) return true
    if (SIGNED_BARE.test(item.label)) {
      if (compact === item.label || item.tag === 'input' || item.tag === 'button') return true
      if (item.tag === 'a' && /attendance\.php/i.test(item.attrs)) return true
    }
  }
  // 控件或短文本里出现"签到成功"，即使后面还跟着连续天数与奖励也算完成。
  for (const item of labels) {
    if (item.label.length <= 60 && SIGNED_CONTAINS.test(item.label)) return true
  }
  if (SIGNED_TEXT.test(compact)) return true
  // 正文里同时出现"签到成功"与连续天数/奖励，属明确的完成回执。
  if (SIGNED_CONTAINS.test(compact) && /(?:连续|連續)\d+天|(?:获得|獲得)\d+|魔力值|积分|奖励|聲望/.test(compact)) return true
  return SIGNED_EN.test(text)
}

// 取出命中的回执原文，用于在界面上展示"站点到底说了什么"。
export function signinEvidence(html) {
  const source = String(html || '')
  const text = visibleText(source)
  const compact = text.replace(/\s+/g, '')
  const matched = SIGNED_EN.exec(text) || SIGNED_TEXT.exec(compact)
  if (matched) return String(matched[0]).slice(0, 60)
  for (const item of elementLabels(source)) {
    if (SIGNED_EXACT.test(item.label) || SIGNED_BARE.test(item.label)) return item.label.slice(0, 60)
  }
  // 含"签到成功"的整句回执，用于在界面上展示站点原话。
  if (SIGNED_CONTAINS.test(compact)) {
    const at = compact.search(SIGNED_CONTAINS)
    return compact.slice(at, at + 44)
  }
  return ''
}

// 补全签到地址：填站点根地址时按 NexusPHP 约定补 attendance.php（对齐 AutoSignIn 的 urljoin 行为）；
// 用户已填了具体路径则尊重用户的填写，不擅自改写。
export function resolveSigninURL(value) {
  const url = value instanceof URL ? new URL(value.href) : new URL(String(value))
  const path = url.pathname.replace(/\/+$/, '')
  if (!path) url.pathname = '/attendance.php'
  url.hash = ''
  return url
}

// 判定签到结果（对齐 AutoSignIn 的证据链）：
// HTTP 错误 → 空页 → Cloudflare 拦截 → 登录表单 → 用户关键词（已签/成功）→ 失败词否决
// → 站点完成回执 → 无登录态 → 未确认。绝不靠 HTTP 200 假装成功。
export function judge(response, site) {
  const raw = typeof response.body === 'string' ? response.body.slice(0, MAX_HTML) : ''
  const status = Number(response.status) || 0
  const headers = response.headers || {}
  if (status >= 400) return { status: 'failed', detail: httpFailure(status) }
  if (!raw.trim()) return { status: 'failed', detail: '站点返回空白页面' }
  if (underChallenge(raw, headers)) {
    return { status: 'failed', detail: '被 Cloudflare 拦截：需要宿主已配置渲染器（FlareSolverr 等）并在站点里开启兜底' }
  }
  if (hasLoginForm(raw)) {
    return {
      status: 'failed',
      detail: loginNeedsTwoFactor(raw)
        ? 'Cookie 已失效；该站登录需要密码 + 6 位动态码（2FA），请在浏览器登录完成后用「从 CookieCloud 同步」取回最新 Cookie'
        : 'Cookie 已失效，需重新登录后复制新 Cookie',
    }
  }
  // 被踹回登录页（可能是 JS 渲染的登录页，没有 password 输入框）：凭据没送到，别再往下判。
  if (loginRedirected(response)) {
    return { status: 'failed', detail: 'Cookie 已失效（站点跳转到登录页）' }
  }

  // 页面上还挂着 Turnstile 组件 = 人机验证还没做、表单还没提交，签到根本没发生。
  // 这类页面正文常写「签到」「连续签到」甚至成功关键词，先拦下来，别报假成功。
  if (hasTurnstile(raw) && /data-sitekey\s*=\s*["'][^"']+["']/i.test(raw)) {
    return { status: 'unconfirmed', detail: '页面仍在等人机验证（Turnstile），签到尚未完成' }
  }

  const text = visibleText(raw)
  // 用户关键词只是「页面文字命中」，不是站点回执。签到页导航、统计、说明里常含
  // 「已签到」「连续签到」「签到成功」这类字样，此时真正的签到按钮仍摆着没点。
  // 必须先排除这种「按钮还在」的情况，否则会报假成功、永不点击，站点那头什么都没发生。
  const actionPending = hasSignAction(raw, response.url || site.url)
  const already = includesAny(text, site.alreadyKeywords || [])
  if (already && !actionPending) return { status: 'already', detail: already }

  if (SIGNIN_NEGATIVE.test(text.replace(/\s+/g, ''))) {
    return { status: 'failed', detail: '站点返回签到失败提示' }
  }
  // 「您今天已经签到过了」是站点自述的当日状态，比「页面上还挂着签到入口」更可信：
  // NexusPHP 顶部导航永远有「每日签到」，用它压制 already 会让已签的站永远报待确认。
  // 它也必须排在答题回执之前：已签的答题页仍会把题目和规则摆出来。
  if (alreadySigned(raw)) {
    const hit = ALREADY_TEXT.exec(text) || ALREADY_TEXT.exec(text.replace(/\s+/g, ''))
    return { status: 'already', detail: hit ? `站点显示今日已签到：${String(hit[0]).slice(0, 40)}` : '站点显示今日已签到' }
  }
  // 答题站的完成回执是「回答正确」，不等于「签到成功」，但确实是拿到了签到结果。
  // 页面若还摆着选项（radio），说明题还没答完，此时的「回答正确」只是规则说明，不能当回执。
  // 规则段落里同样会出现这四个字（「不会却回答正确额外获得5魔力值」），句子带规则词的一律不算回执。
  const stillQuiz = /<input\b[^>]*\btype\s*=\s*["']?radio/i.test(raw)
  const quizSentence = (text.match(/[^。！!？?\n]{0,12}(?:(?:回答|答案)(?:正确|正確)|答对了|答對了)[^。！!？?\n]{0,30}/) || [''])[0]
  const quizRight = quizSentence && !/(?:额外|額外|用户|用戶|扣|规则|規則|说明|說明)/.test(quizSentence)
    ? quizSentence.trim()
    : ''
  if (quizRight && !actionPending && !stillQuiz) return { status: 'success', detail: `答题通过：${quizRight.slice(0, 40)}` }
  const success = includesAny(text, site.successKeywords || [])
  if (success && !actionPending) return { status: 'success', detail: success }

  if (hasSigninEvidence(raw)) {
    const evidence = signinEvidence(raw)
    return { status: 'success', detail: evidence || '站点返回签到完成回执' }
  }
  if (!hasLoginEvidence(raw)) return { status: 'failed', detail: '未识别到登录状态，Cookie 可能已失效' }
  if (status >= 300) return { status: 'unconfirmed', detail: `HTTP ${status}，已登录但未见到签到回执` }
  return { status: 'unconfirmed', detail: '已登录，但页面无签到完成回执' }
}

// ===== JSON 接口签到（蜂巢这类 Next.js 新框架站）=====
// 这类站点没有 HTML 签到页：页面上点「立即签到」是网页 JS 去 POST 一个 JSON 接口，
// GET 首页拿到的只是前端壳子，永远读不到回执。接口地址与请求体由用户为该站点填写，
// 必须与站点同域；Cookie 仍只发往站点自己，不碰其它域名。
export function parseJsonBody(raw) {
  const text = typeof raw === 'string' ? raw.trim() : ''
  if (!text || (text[0] !== '{' && text[0] !== '[')) return null
  try { return JSON.parse(text) } catch { return null }
}

// 取嵌套字段：'data.surface.checkedInToday' → payload.data.surface.checkedInToday
export function jsonPathGet(value, path) {
  const key = String(path || '').trim()
  if (!key) return undefined
  return key.split('.').reduce((acc, part) => (acc == null ? undefined : acc[part]), value)
}

// 按接口返回判签到结果：先看 HTTP 与业务 code，再看「今天已签到」标记。
// 站点通常返回 {code:0,message:'签到成功',data:{alreadyCheckedIn:false}}。
export function judgeJsonSignin(payload, status) {
  const httpStatus = Number(status) || 0
  const code = Number(payload?.code)
  const message = String(payload?.message || '').trim()
  if (httpStatus === 401 || code === 401) {
    return { status: 'failed', detail: '接口返回未登录：Cookie 已失效，请重新登录后用「从 CookieCloud 同步」取回' }
  }
  if (httpStatus >= 400) return { status: 'failed', detail: message || `接口返回 HTTP ${httpStatus}` }
  if (Number.isFinite(code) && code !== 0) {
    return { status: 'failed', detail: message || `接口返回错误码 ${code}` }
  }
  if (payload?.data?.alreadyCheckedIn === true) {
    return { status: 'already', detail: message || '今天已经签到过' }
  }
  return { status: 'success', detail: message || '接口返回签到成功' }
}

// 连续签到天数：从今天（或最近有记录的一天）向前累计有成功/already 记录的日期。
export function streakOf(dates, today = dayKey()) {
  const done = new Set(dates || [])
  let cursor = new Date(today + 'T12:00:00')
  // 今天还没签时，从昨天开始算，避免打断连续记录。
  if (!done.has(dayKey(cursor.getTime()))) cursor.setDate(cursor.getDate() - 1)
  let streak = 0
  for (let i = 0; i < 3660 && streak < 3660; i++) {
    if (!done.has(dayKey(cursor.getTime()))) break
    streak++
    cursor.setDate(cursor.getDate() - 1)
  }
  return streak
}

export function completedDates(entry) {
  return Array.isArray(entry?.dates) ? entry.dates : []
}
