const { createClient } = require('@supabase/supabase-js')
const CryptoJS = require('crypto-js')

const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY
const AES_KEY_B64 = process.env.AES_KEY_B64
const ADMIN_SECRET = process.env.ADMIN_SECRET

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY)

function encryptBase64AES(plain) {
  const keyWords = CryptoJS.enc.Base64.parse(AES_KEY_B64)
  const encrypted = CryptoJS.AES.encrypt(plain, keyWords, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 })
  return encrypted.toString()
}

exports.handler = async function(event) {
  try {
    const secret = (event.headers && (event.headers['x-admin-secret'])) || ''
    if (secret !== ADMIN_SECRET) return { statusCode:403, body: JSON.stringify({ ok:false, reason:'forbidden' }) }
    const body = JSON.parse(event.body || '{}')
    const id = body.id
    const script = body.script
    if (!id || !script) return { statusCode:400, body: JSON.stringify({ ok:false, reason:'missing fields' }) }

    const encrypted = encryptBase64AES(script)
    const { data, error } = await supabase.from('scripts').upsert({ id, encrypted_blob: encrypted })
    if (error) return { statusCode:500, body: JSON.stringify({ ok:false, reason: String(error) }) }
    return { statusCode:200, body: JSON.stringify({ ok:true }) }
  } catch (err) {
    return { statusCode:500, body: JSON.stringify({ ok:false, reason: String(err) }) }
  }
}
