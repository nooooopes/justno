const { createClient } = require('@supabase/supabase-js')
const jwt = require('jsonwebtoken')

const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY
const JWT_SECRET = process.env.JWT_SECRET
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL_SECONDS || '300', 10)

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY)

exports.handler = async function(event) {
  try {
    const body = JSON.parse(event.body || '{}')
    const key = body.key
    if (!key) return { statusCode:400, body: JSON.stringify({ ok:false, reason:'missing key' }) }

    const { data, error } = await supabase
      .from('keys')
      .select('key_text, allowed, revoked')
      .eq('key_text', key)
      .limit(1)
      .single()

    if (error || !data || data.revoked) {
      return { statusCode:403, body: JSON.stringify({ ok:false, reason:'invalid or revoked key' }) }
    }

    const token = jwt.sign({ key: key, allowed: data.allowed }, JWT_SECRET, { expiresIn: TOKEN_TTL })
    return { statusCode:200, body: JSON.stringify({ ok:true, token }) }
  } catch (err) {
    return { statusCode:500, body: JSON.stringify({ ok:false, reason: String(err) }) }
  }
}
