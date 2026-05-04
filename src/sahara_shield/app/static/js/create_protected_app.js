const createProtectedAppForm = document.getElementById('create-protected-app-form');
const statusMessage = document.getElementById('status-message');
const errorMessage = document.getElementById('error-message');

if (createProtectedAppForm) {
  createProtectedAppForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    statusMessage.textContent = '';
    errorMessage.textContent = '';

    const formData = new FormData(createProtectedAppForm);
    const params = new URLSearchParams();

    for (const [key, value] of formData.entries()) {
      params.set(key, String(value));
    }

    try {
      const response = await fetch(`/api/v1/protected_apps/me?${params.toString()}`, {
        method: 'POST',
        credentials: 'include',
      });

      if (!response.ok) {
        const errorJSON = await response.json(); // really we should expect the API to always return JSON responses
        throw new Error(errorJSON.hasOwnProperty('detail') ? `Error: ${errorJSON.detail}` : 'Failed to create protected app');
      }

      const protectedApp = await response.json();
      statusMessage.textContent = 'Protected app created successfully. Redirecting...';

      window.location.href = protectedApp?.id ? `/dashboard/${protectedApp.id}` : '/';
    } catch (error) {
      errorMessage.textContent = error instanceof Error ? error.message : String(error);
    }
  });
}