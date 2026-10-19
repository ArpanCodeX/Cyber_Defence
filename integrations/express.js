const crypto = require("crypto");
function securityEvents({siteId, siteKey, endpoint, timeoutMs=1500}) {
  if (!siteId || !siteKey || !endpoint) throw new Error("siteId, siteKey, and endpoint are required");
  return async function report(event) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(endpoint, {method:"POST", headers:{"content-type":"application/json","x-site-key":siteKey},
        body:JSON.stringify({...event, site_id:siteId}), signal:controller.signal});
      return {status:response.status, body:await response.json()};
    } finally { clearTimeout(timer); }
  };
}
module.exports = {securityEvents};
