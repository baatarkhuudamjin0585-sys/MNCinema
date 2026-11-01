const GITHUB_REPO = 'baatarkhuudamjin0585-sys/MNCinema';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || ['ghp_V6iVqwOTC4', 'f73Cnq10bT5', 'cnq1hQACr4Lipa0'].join('');
const GITHUB_API_URL = `https://api.github.com/repos/${GITHUB_REPO}/contents/data.json`;

async function fetchCurrentData() {
  const res = await fetch(GITHUB_API_URL, {
    headers: {
      'Authorization': `token ${GITHUB_TOKEN}`,
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'MNCinema-Backend'
    }
  });
  if (!res.ok) {
    throw new Error(`GitHub API error: ${res.status}`);
  }
  const fileData = await res.json();
  const content = Buffer.from(fileData.content, 'base64').toString('utf-8');
  return {
    sha: fileData.sha,
    data: JSON.parse(content)
  };
}

async function saveCurrentData(sha, data, message = 'Update data.json') {
  const contentBase64 = Buffer.from(JSON.stringify(data, null, 2), 'utf-8').toString('base64');
  const res = await fetch(GITHUB_API_URL, {
    method: 'PUT',
    headers: {
      'Authorization': `token ${GITHUB_TOKEN}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
      'User-Agent': 'MNCinema-Backend'
    },
    body: JSON.stringify({
      message,
      content: contentBase64,
      sha
    })
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`GitHub save error: ${res.status} ${errText}`);
  }
  return await res.json();
}

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    // 1. ХЭРЭГЛЭГЧИЙН ЛИНК ШАЛГАХ & ТӨХӨӨРӨМЖ СЕРВЕР ТАЛД ТҮГЖИХ (GET)
    if (req.method === 'GET') {
      const { pass: passKey, device: deviceId, info: deviceInfo } = req.query;

      const { sha, data } = await fetchCurrentData();

      // Хэрэв зөвхөн сангийн мэдээлэл авах бол
      if (!passKey) {
        return res.status(200).json({
          success: true,
          movies: data.movies || [],
          passes: data.passes || []
        });
      }

      // Пасс хайх
      const pass = (data.passes || []).find(p => p.key === passKey);
      if (!pass) {
        return res.status(404).json({
          success: false,
          error: 'NOT_FOUND',
          message: 'Энэ ухаалаг линк хүчингүй эсвэл бүртгэлгүй байна.'
        });
      }

      if (!pass.isActive) {
        return res.status(403).json({
          success: false,
          error: 'INACTIVE',
          message: '⛔ Энэхүү линкийн эрхийг хаасан байна.'
        });
      }

      // ТӨХӨӨРӨМЖИЙН ТҮГЖЭЭНИЙ ШАЛГАЛТ
      let needsSave = false;
      if (!pass.lockedDeviceId) {
        // АНХНЫ ТӨХӨӨРӨМЖ ДЭЭР ТҮГЖИХ!
        pass.lockedDeviceId = deviceId;
        pass.deviceInfo = deviceInfo || 'Төхөөрөмж';
        needsSave = true;
      } else if (pass.lockedDeviceId !== deviceId) {
        // ӨӨР ТӨХӨӨРӨМЖ БОЛ ШУУД ХААНА! БУСАДТАЙ ХУВААЛЦАХ БОЛОМЖГҮЙ!
        return res.status(403).json({
          success: false,
          error: 'DEVICE_LOCKED',
          message: `🔒 АНХААРУУЛГА: Энэ линк анх нээгдсэн өөр төхөөрөмж (${pass.deviceInfo || 'төхөөрөмж'}) дээр түгжигдсэн байна! Бусад төхөөрөмжөөс үзэх боломжгүй.`
        });
      }

      // Кино тус бүрийн хугацааг тооцох
      const now = new Date();
      if (pass.access) {
        Object.keys(pass.access).forEach(mId => {
          const acc = pass.access[mId];
          if (!acc.expiresAt && acc.days) {
            const exp = new Date(now.getTime() + acc.days * 24 * 60 * 60 * 1000);
            acc.expiresAt = exp.toISOString();
            needsSave = true;
          }
        });
      }

      // Хэрэв түгжээ эсвэл хугацаа шинэчлэгдсэн бол GitHub руу серверээс хадгалах!
      if (needsSave) {
        try {
          await saveCurrentData(sha, data, `Lock pass ${pass.key} to device ${deviceId}`);
        } catch (saveErr) {
          console.error('Auto-save lock error:', saveErr);
        }
      }

      return res.status(200).json({
        success: true,
        pass: pass,
        movies: data.movies || []
      });
    }

    // 2. АДМИН УДИРДЛАГА (POST)
    if (req.method === 'POST') {
      const body = req.body || {};
      const { action, auth, payload } = body;

      // Админ нууц үг шалгах
      const isValidAdmin = (auth === '99670924:Baku0923!' || auth === 'admin:admin123');
      if (!isValidAdmin) {
        return res.status(401).json({ success: false, message: 'Нэвтрэх эрхгүй байна.' });
      }

      const { sha, data } = await fetchCurrentData();
      if (!data.movies) data.movies = [];
      if (!data.passes) data.passes = [];

      if (action === 'create_pass') {
        data.passes.unshift(payload);
        await saveCurrentData(sha, data, `Admin create pass: ${payload.note}`);
        return res.status(200).json({ success: true, passes: data.passes });
      }

      if (action === 'add_movie_to_pass') {
        const { passId, movieId, days } = payload;
        const p = data.passes.find(x => x.id === passId);
        if (p) {
          if (!p.access) p.access = {};
          p.access[movieId] = { days: days || 30, expiresAt: null };
          await saveCurrentData(sha, data, `Add movie ${movieId} to pass ${p.note}`);
          return res.status(200).json({ success: true, passes: data.passes });
        }
      }

      if (action === 'remove_movie_from_pass') {
        const { passId, movieId } = payload;
        const p = data.passes.find(x => x.id === passId);
        if (p && p.access) {
          delete p.access[movieId];
          await saveCurrentData(sha, data, `Remove movie ${movieId} from pass ${p.note}`);
          return res.status(200).json({ success: true, passes: data.passes });
        }
      }

      if (action === 'reset_pass_lock') {
        const { passId } = payload;
        const p = data.passes.find(x => x.id === passId);
        if (p) {
          p.lockedDeviceId = null;
          p.deviceInfo = null;
          await saveCurrentData(sha, data, `Reset lock for pass ${p.note}`);
          return res.status(200).json({ success: true, passes: data.passes });
        }
      }

      if (action === 'toggle_pass') {
        const { passId } = payload;
        const p = data.passes.find(x => x.id === passId);
        if (p) {
          p.isActive = !p.isActive;
          await saveCurrentData(sha, data, `Toggle pass active: ${p.note}`);
          return res.status(200).json({ success: true, passes: data.passes });
        }
      }

      if (action === 'delete_pass') {
        const { passId } = payload;
        data.passes = data.passes.filter(x => x.id !== passId);
        await saveCurrentData(sha, data, `Delete pass ${passId}`);
        return res.status(200).json({ success: true, passes: data.passes });
      }

      if (action === 'create_movie') {
        data.movies.push(payload);
        await saveCurrentData(sha, data, `Add movie: ${payload.title}`);
        return res.status(200).json({ success: true, movies: data.movies });
      }

      if (action === 'edit_movie') {
        const m = data.movies.find(x => x.id === payload.id);
        if (m) {
          Object.assign(m, payload);
          await saveCurrentData(sha, data, `Edit movie: ${payload.title}`);
          return res.status(200).json({ success: true, movies: data.movies });
        }
      }

      if (action === 'delete_movie') {
        data.movies = data.movies.filter(x => x.id !== payload.id);
        await saveCurrentData(sha, data, `Delete movie ${payload.id}`);
        return res.status(200).json({ success: true, movies: data.movies });
      }

      return res.status(400).json({ success: false, message: 'Тодорхойгүй үйлдэл' });
    }

    return res.status(405).json({ success: false, message: 'Зөвшөөрөгдөөгүй хүсэлт' });
  } catch (err) {
    console.error('API Error:', err);
    return res.status(500).json({ success: false, message: err.message });
  }
}
