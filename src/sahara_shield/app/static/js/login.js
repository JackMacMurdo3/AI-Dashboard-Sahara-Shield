const form = document.getElementById('login-form');
const msgEl = document.getElementById('login-msg');

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const email = String(form.email.value || '').trim();
  const password = String(form.password.value || '');

  if (!email || !password) {
    msgEl.className = 'login-msg error';
    msgEl.textContent = 'Please enter both email and password.';
    return;
  }

  // lets the user know we're trying to send the provided credentials
  // to the server for authentication
  msgEl.className = 'login-msg';
  msgEl.textContent = 'Signing in...';

  try {
    const params = new URLSearchParams({ email, password }); // build query string of user-provided credentials
    // send async POST request to auth/login endpoint
    const response = await fetch('/api/v1/auth/login?' + params.toString(), {
      method: 'POST',
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || 'Invalid credentials.');
    }

    // log in succesful - redirect to root (/)
    // this should take user to the dashboard page
    msgEl.className = 'login-msg success';
    msgEl.textContent = 'Login successful. Redirecting...';
    window.location.href = '/';
  } catch (error) {
    // this happens e.g. when server takes too long to authenticate credentials and return a response
    // let the user something went wrong on the server-side
    msgEl.className = 'login-msg error';
    msgEl.textContent = 'Unable to login. Please try again later.';
  }
});
