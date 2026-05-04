const createPolicyForm = document.getElementById('create-policy-form');
const errorMessage = document.getElementById('error-message');
const backLinksContainer = document.getElementById('back-links-container');

function getProtectedAppIdFromUrl() {
  const pathParts = window.location.pathname.split('/').filter(Boolean);

  // expected path format: /protected_apps/{protected_app_id}/policies/new
  if (pathParts.length >= 2 && pathParts[0] === 'protected_apps' && pathParts[2] === 'policies') {
    return parseInt(pathParts[1], 10);
  }

  return null;
}

if (createPolicyForm) {
  const protectedAppId = getProtectedAppIdFromUrl();
  const dashboardBackLink = document.createElement('a');
  dashboardBackLink.className = 'back-link';
  dashboardBackLink.textContent = '← Back to Dashboard';
  dashboardBackLink.href = `/dashboard/${protectedAppId}`;
  backLinksContainer.appendChild(dashboardBackLink);

  createPolicyForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    errorMessage.textContent = '';

    if (!protectedAppId) {
      errorMessage.textContent = 'Invalid protected app ID';
      return;
    }

    const formData = new FormData(createPolicyForm);
    const params = new URLSearchParams();

    // add protected app ID
    params.set('protected_app_id', String(protectedAppId));

    // add form fields
    for (const [key, value] of formData.entries()) {
      // handle checkbox separately
      if (key === 'active') {
        params.set(key, 'true');
      } else if (value !== '') {
        params.set(key, String(value));
      }
    }

    // ensure active is false if unchecked
    if (!formData.get('active')) {
      params.set('active', 'false');
    }

    try {
      const response = await fetch(`/api/v1/app_security_policies/me?${params.toString()}`, {
        method: 'POST',
        credentials: 'include',
      });

      if (!response.ok) {
        const errorJSON = await response.json();
        throw new Error(errorJSON.hasOwnProperty('detail') ? `Error: ${errorJSON.detail}` : 'Failed to create policy');
      }

      const policy = await response.json();
      errorMessage.textContent = '';
      
      // redirect to dashboard
      window.location.href = `/dashboard/${protectedAppId}`;
    } catch (error) {
      errorMessage.textContent = error instanceof Error ? error.message : String(error);
    }
  });
}
