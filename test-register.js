const fetch = global.fetch || require('node-fetch');

(async () => {
  try {
    const res = await fetch('http://localhost:5000/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fullName: 'Test User',
        email: 'test.user@example.com',
        password: 'Password123',
        confirmPassword: 'Password123'
      })
    });
    const data = await res.json();
    console.log(res.status, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(err);
  }
})();