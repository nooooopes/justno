const { createClient } = require('@supabase/supabase-js')
const jwt = require('jsonwebtoken')
const CryptoJS = require('crypto-js')

const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY
const JWT_SECRET = process.env.JWT_SECRET
const AES_KEY_B64 = process.env.AES_KEY_B64

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY)

function decryptBase64AES(b64) {
  const keyWords = CryptoJS.enc.Base64.parse(AES_KEY_B64)
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(b64) })
  const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWords, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 })
  return CryptoJS.enc.Utf8.stringify(decrypted)
}

exports.handler = async function(event) {
  try {
    const auth = (event.headers && (event.headers.authorization || event.headers.Authorization)) || ''
    if (!auth.startsWith('Bearer ')) return { statusCode:401, body: JSON.stringify({ ok:false, reason:'missing token' }) }
    const token = auth.slice(7)
    let payload
    try { payload = jwt.verify(token, JWT_SECRET) } catch(e) { return { statusCode:401, body: JSON.stringify({ ok:false, reason:'invalid token' }) } }

    const pathParts = event.path.split('/')
    const scriptId = pathParts[pathParts.length - 1] || (event.queryStringParameters && event.queryStringParameters.id)
    if (!scriptId) return { statusCode:400, body: JSON.stringify({ ok:false, reason:'missing script id' }) }

    if (!payload.allowed || !payload.allowed.includes(scriptId)) {
      return { statusCode:403, body: JSON.stringify({ ok:false, reason:'not allowed' }) }
    }

    const { data, error } = await supabase.from('scripts').select('id, encrypted_blob').eq('id', scriptId).limit(1).single()
    if (error || !data) return { statusCode:404, body: JSON.stringify({ ok:false, reason:'script not found' }) }

    const plaintext = decryptBase64AES(data.encrypted_blob)
    return { statusCode:200, body: JSON.stringify({ ok:true, plaintext }) }
  } catch (err) {
    return { statusCode:500, body: JSON.stringify({ ok:false, reason: String(err) }) }
  }
}
