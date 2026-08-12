const jwt = require('jsonwebtoken')
const fetch = require('node-fetch')

const ADMIN_SECRET = process.env.ADMIN_SECRET
const NETLIFY_SITE_URL = process.env.NETLIFY_SITE_URL // e.g. https://your-site.netlify.app
const TOKEN_TTL = parseInt(process.env.ADMIN_TOKEN_TTL_SECONDS || '60', 10)

exports.handler = async function(event) {
  try {
    const body = JSON.parse(event.body || '{}')
    const idToken = body.id_token
    if (!idToken) return { statusCode:400, body: JSON.stringify({ ok:false, reason:'missing id_token' }) }

    const resp = await fetch(`${NETLIFY_SITE_URL}/.netlify/identity/user`, {
      headers: { 'Authorization': `Bearer ${idToken}` }
    })
    if (!resp.ok) return { statusCode:401, body: JSON.stringify({ ok:false, reason:'invalid identity token' }) }
    const user = await resp.json()

    const roles = (user && user.app_metadata && user.app_metadata.roles) || []
    if (!Array.isArray(roles) || !roles.includes('admin')) {
      return { statusCode:403, body: JSON.stringify({ ok:false, reason:'not an admin' }) }
    }

    const token = jwt.sign({ sub: user.id, email: user.email, role: 'admin' }, ADMIN_SECRET, { expiresIn: TOKEN_TTL })
    return { statusCode:200, body: JSON.stringify({ ok:true, token }) }
  } catch (err) {
    return { statusCode:500, body: JSON.stringify({ ok:false, reason: String(err) }) }
  }
}
