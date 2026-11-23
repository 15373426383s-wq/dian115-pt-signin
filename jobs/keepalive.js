// M-Team（馒头）到期预警任务。
// 官方规则：未封存账号连续 40 天不登录删号（做种不算活跃）。
// 关键事实（官方 wiki + 真机验证）：M-Team 禁止第三方调用 /member/updateLastBrowse，
// 且只读 /member/profile 不会刷新 lastBrowse——也就是说接口层面根本无法替用户"保活"。
// 因此本任务不做任何写操作，改为只读监控活跃时间，临近删号线时通知用户自己登录一次。
// 红线：令牌由用户在插件页面自填、存插件私有 KV；目标域名写死 api.m-team.io；
//       只调官方只读 profile，不发往任何第三方、不读取宿主/浏览器凭据。
import { KEYS, MTEAM_API, PluginError } from './common.js'

const PROFILE_PATH = '/api/member/profile'
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
const DELETE_AFTER_DAYS = 40   // 未封存账号不登录删号线
const WARN_WITHIN_DAYS = 10    // 剩余天数 <= 10 开始提醒
const DAY_MS = 86400000

function errorText(error) {
  return String((error && error.message) || error || '').slice(0, 160)
}

// 官方 profile 成功回执：code 可能是数字 0 或字符串 "0"，message 为 SUCCESS。
function profileOK(data) {
  return Boolean(data && (Number(data.code) === 0 || data.message === 'SUCCESS'))
}

// 站点时间形如 "2026-11-22 23:39:10"，按宿主本地时区解析（宿主设为东八区）。
function parseSiteTime(value) {
  if (!value || typeof value !== 'string') return 0
  const t = Date.parse(value.trim().replace(' ', 'T'))
  return Number.isFinite(t) ? t : 0
}

// 令牌只用于写死的官方只读路径；任何情况下都不拼用户提供的 URL。
async function profileCall(ctx, apiKey) {
  const url = new URL(PROFILE_PATH, MTEAM_API)
  if (url.origin !== MTEAM_API || url.protocol !== 'https:') {
    throw new PluginError('查询目标被拒绝：仅允许 M-Team 官方 API。')
  }
  const response = await ctx.http.request({
    url: url.href,
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'User-Agent': UA,
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Ts': String(Math.floor(Date.now() / 1000)),
    },
    timeout_seconds: 30,
    max_bytes: 1024 * 1024,
  })
  const status = Number(response.status) || 0
  let data = null
  try { data = JSON.parse(String(response.body || '')) } catch { /* 非 JSON 视为异常 */ }
  return { status, data, raw: String(response.body || '').slice(0, 200) }
}

function readState(state) {
  const today = new Date().toISOString().slice(0, 10)
  return {
    lastCheck: state?.lastCheck || 0,
    lastStatus: state?.lastStatus || '',
    lastDetail: state?.lastDetail || '',
    lastUser: state?.lastUser || '',
    lastBrowse: state?.lastBrowse || '',
    daysLeft: state?.daysLeft ?? null,
    runs: Array.isArray(state?.runs) ? state.runs.slice(-20) : [],
    today,
  }
}

// 依据最近活跃时间算剩余天数与告警等级。
function evaluate(username, lastBrowseStr, now) {
  const ts = parseSiteTime(lastBrowseStr)
  if (!ts) {
    return {
      status: 'unknown', daysLeft: null, daysUsed: null,
      detail: `令牌有效，账号 ${username || '—'}，但 profile 未返回可用的活跃时间，无法估算删号剩余天数。`,
    }
  }
  const daysUsed = Math.max(0, Math.floor((now - ts) / DAY_MS))
  const daysLeft = Math.min(DELETE_AFTER_DAYS, Math.max(0, DELETE_AFTER_DAYS - daysUsed))
  const who = username || '账号'
  let status, detail
  if (daysUsed >= DELETE_AFTER_DAYS) {
    status = 'danger'
    detail = `${who} 已 ${daysUsed} 天未活跃（最近 ${lastBrowseStr}），已达到 40 天删号线，请立即登录馒头确认账号是否还在。`
  } else if (daysLeft <= WARN_WITHIN_DAYS) {
    status = 'warn'
    detail = `${who} 已 ${daysUsed} 天未活跃（最近 ${lastBrowseStr}），再过 ${daysLeft} 天可能被删号，请登录一次馒头。`
  } else {
    status = 'ok'
    detail = `${who} 最近活跃 ${lastBrowseStr}，距 40 天删号线还有 ${daysLeft} 天，暂不需要登录。`
  }
  return { status, daysLeft, daysUsed, detail }
}

export async function run(ctx, input = {}) {
  if (input.diagnose) {
    const cfg = await ctx.storage.get(KEYS.keepalive)
    const state = readState(cfg?.state)
    return {
      diagnose: {
        configured: Boolean(cfg?.apiKey),
        lastCheck: state.lastCheck,
        lastStatus: state.lastStatus,
        lastDetail: state.lastDetail,
        lastUser: state.lastUser,
        lastBrowse: state.lastBrowse,
        daysLeft: state.daysLeft,
        daysSinceCheck: state.lastCheck ? Math.floor((Date.now() - state.lastCheck) / DAY_MS) : null,
      },
    }
  }

  const cfg = await ctx.storage.get(KEYS.keepalive)
  const apiKey = String(cfg?.apiKey || '').trim()
  if (!apiKey) throw new PluginError('还没有填写馒头存取令牌，请先在「馒头到期预警」里填入 api_key。')
  if (apiKey.length > 128 || /[\r\n]/.test(apiKey)) throw new PluginError('存取令牌格式不正确。')

  await ctx.task.update({ stage: 'start', message: '馒头到期预警：读取账号状态', total: 1, done: 0, failed: 0 })

  const state = readState(cfg?.state)
  const result = { at: Date.now(), status: '', detail: '', daysLeft: null, lastBrowse: '', username: '', notified: false }

  try {
    // 只做只读查询：官方禁止第三方刷新 lastBrowse，接口层面无法代劳。
    const profile = await profileCall(ctx, apiKey)
    if (profile.status < 200 || profile.status >= 300 || !profileOK(profile.data)) {
      result.status = 'failed'
      result.detail = `令牌验证失败（HTTP ${profile.status}）：${profile.data?.message || profile.raw || '请检查 api_key 是否有效'}`
      throw new PluginError(result.detail)
    }
    const username = String(profile.data?.data?.username || '')
    const statusObj = profile.data?.data?.memberStatus || {}
    const lastBrowse = String(statusObj.lastBrowse || '')
    result.username = username
    result.lastBrowse = lastBrowse
    await ctx.task.update({ stage: 'checked', message: `令牌有效：${username || '账号'}`, done: 1, failed: 0 })

    const ev = evaluate(username, lastBrowse, result.at)
    result.status = ev.status
    result.daysLeft = ev.daysLeft
    result.detail = ev.detail
    state.lastUser = username
    state.lastBrowse = lastBrowse
    state.daysLeft = ev.daysLeft
  } catch (error) {
    if (!result.status) {
      result.status = 'failed'
      result.detail = errorText(error)
    }
  }

  state.lastCheck = result.at
  state.lastStatus = result.status
  state.lastDetail = result.detail
  state.runs.push({ at: result.at, status: result.status, detail: result.detail })
  await ctx.storage.set(KEYS.keepalive, { ...cfg, state })
  await ctx.task.update({
    stage: 'done',
    message: `馒头到期预警：${result.status}`,
    total: 1,
    done: 1,
    failed: result.status === 'failed' ? 1 : 0,
  })

  // 通知策略：验证令牌（quiet）不打扰；手动检查（force）必推；定时任务仅在告警时推。
  // 同一天同一等级只推一次，避免每日任务重复打扰。
  const today = new Date(result.at).toISOString().slice(0, 10)
  const shouldNotify = !input.quiet && (
    input.force ||
    (result.status === 'warn' || result.status === 'danger') && state.lastNotifyKey !== `pt-keepalive:${result.status}:${today}`
  )
  if (shouldNotify) {
    try {
      const receipt = await ctx.notify({
        title: result.status === 'danger' ? '馒头账号到期警告'
          : result.status === 'warn' ? '馒头账号即将到期'
            : result.status === 'failed' ? '馒头账号检查失败' : '馒头账号状态',
        body: result.detail,
        format: 'text',
        level: result.status === 'danger' || result.status === 'warn' ? 'warning' : 'success',
        dedupe_key: `pt-keepalive:${result.status}:${today}`,
      })
      result.notifyReceipt = receipt && typeof receipt === 'object' ? { accepted: receipt.accepted, error: receipt.error } : receipt
      result.notified = true
      state.lastNotifyKey = `pt-keepalive:${result.status}:${today}`
      await ctx.storage.set(KEYS.keepalive, { ...cfg, state })
    } catch (error) {
      // 通知失败不影响检查结果，但记录原因便于排查宿主通知通道。
      result.notifyError = errorText(error)
    }
  }

  return result
}

// 供诊断/预览复用：读取当前监控状态（只读）。
export async function status(ctx) {
  const cfg = await ctx.storage.get(KEYS.keepalive)
  return readState(cfg?.state)
}
