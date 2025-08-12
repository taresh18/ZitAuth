(() => {
  const byId = (id) => document.getElementById(id);
  const status = byId('status');
  const out = byId('out');
  const btnLogin = byId('btn-login');
  const btnProtected = byId('btn-protected');
  const btnUserInfo = byId('btn-userinfo');

  let accessToken = null;

  const setStatus = (s) => status.textContent = s;
  const setOut = (obj) => out.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);

  async function fetchJSON(url, opts = {}) {
    const resp = await fetch(url, { headers: { 'Accept': 'application/json', ...(opts.headers || {}) }, ...opts });
    const text = await resp.text();
    let data = null; try { data = text ? JSON.parse(text) : null; } catch {}
    if (!resp.ok) throw Object.assign(new Error('Request failed'), { status: resp.status, data: data || text });
    return data;
  }

  btnLogin.addEventListener('click', () => {
    setStatus('Redirecting to wrapper /login ...');
    window.location.href = '/api/login';
  });

  btnProtected.addEventListener('click', async () => {
    // Send only access_token for API calls
    const token = accessToken;
    if (!token) {
      setStatus('No token available. Please login first.');
      return;
    }
    try {
      setStatus('Calling SPA protected endpoint ...');
      const data = await fetchJSON('/api/protected', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      setStatus('Protected call ok');
      setOut(data);
    } catch (err) {
      setStatus(`Error (${err.status || 'n/a'})`);
      setOut(err.data || err.message);
    }
  });

  btnUserInfo.addEventListener('click', async () => {
    const token = accessToken;
    if (!token) {
      setStatus('No token available. Please login first.');
      return;
    }
    try {
      setStatus('Fetching user info ...');
      const data = await fetchJSON('/api/userinfo', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      setStatus('User info fetched');
      setOut(data);
    } catch (err) {
      setStatus(`Error (${err.status || 'n/a'})`);
      setOut(err.data || err.message);
    }
  });

  // Parse tokens from URL hash fragment after redirect from wrapper callback
  (function parseFragmentForTokens() {
    const hash = window.location.hash.startsWith('#') ? window.location.hash.substring(1) : '';
    if (!hash) {
      setStatus('Idle');
      return;
    }
    const params = new URLSearchParams(hash);
    const at = params.get('access_token');
    if (at) {
      accessToken = at;
      setStatus('Access token received');
      setOut({ access_token: `${at.slice(0, 12)}...` });
      // Clean up URL fragment to avoid leaking tokens in browser history/navigation
      history.replaceState(null, document.title, window.location.pathname + window.location.search);
    } else {
      setStatus('No token in URL. Please login.');
    }
  })();
})();

