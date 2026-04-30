const form = document.getElementById('login-form');
const errorMessage = document.getElementById('login-error');
const submitButton = document.getElementById('login-button');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorMessage.textContent = '';
  submitButton.disabled = true;

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  try {
    const query = new URLSearchParams({ email, password }); // our login endpoint expects credentials as query params
    // send http post request to our login endpoint
    const response = await fetch(`/api/v1/auth/login?${query.toString()}`, {
      method: 'POST',
      credentials: 'include',
    });

    if (!response.ok) {
      // server gave us an error after querying the api endpoint
      const payload = await response.json().catch(() => ({})); // lambda function that returns empty object if json parsing fails
      throw new Error(payload.detail || 'Login failed');
    }

    window.location.href = '/'; // login successful, redirect user to index.html
  } catch (error) {
    // should only happen if we hit the api endpoint but
    // didn't hear anything from the server
    errorMessage.textContent = error.message;
  } finally {
    // login succeeded, enable submit button
    submitButton.disabled = false;
  }
});