const policyDetailTitle = document.getElementById('policy-detail-title');
const policyDetailSubtitle = document.getElementById('policy-detail-subtitle');
const policyDetailFields = document.getElementById('policy-detail-fields');
const errorMessage = document.getElementById('error-message');
const backLinksContainer = document.getElementById('back-links-container');

function getProtectedAppIdFromUrl() {
  const pathParts = window.location.pathname.split('/').filter(Boolean);

  if (pathParts.length >= 2 && pathParts[0] === 'dashboard') {
    return parseInt(pathParts[1], 10);
  }

  return null;
}

function getPolicyIdFromUrl() {
  const pathParts = window.location.pathname.split('/').filter(Boolean);

  if (pathParts.length >= 4 && pathParts[0] === 'dashboard' && pathParts[2] === 'policies') {
    return parseInt(pathParts[3], 10);
  }

  return null;
}

function createFieldRow(label, value) {
  const field = document.createElement('div');
  field.className = 'policy-detail-field';

  const fieldLabel = document.createElement('p');
  fieldLabel.className = 'policy-detail-label';
  fieldLabel.textContent = label;

  const fieldValue = document.createElement('p');
  fieldValue.className = 'policy-detail-value';
  fieldValue.textContent = String(value);

  field.appendChild(fieldLabel);
  field.appendChild(fieldValue);

  return field;
}

async function loadPolicyDetail() {
  try {
    errorMessage.textContent = '';

    const protectedAppId = getProtectedAppIdFromUrl();

    const dashboardBackLink = document.createElement('a');
    dashboardBackLink.className = 'back-link';
    dashboardBackLink.textContent = '← Back to Dashboard';
    dashboardBackLink.href = `/dashboard/${protectedAppId}`;
    backLinksContainer.appendChild(dashboardBackLink);

    const policyId = getPolicyIdFromUrl();

    if (!protectedAppId || !policyId) {
      throw new Error('Invalid policy or app ID');
    }

    const appResponse = await fetch(`/api/v1/protected_apps/me/${protectedAppId}`, {
      method: 'GET',
      credentials: 'include',
    });

    if (!appResponse.ok) {
      throw new Error('Failed to fetch protected app information');
    }

    const app = await appResponse.json();

    const policyResponse = await fetch(`/api/v1/app_security_policies/me/${policyId}`, {
      method: 'GET',
      credentials: 'include',
    });

    if (!policyResponse.ok) {
      throw new Error('Failed to fetch app security policy information');
    }

    const policy = await policyResponse.json();

    policyDetailTitle.textContent = policy.name || 'App Security Policy';
    policyDetailSubtitle.textContent = app.name ? `Protected app: ${app.name} (${app.url})` : '';

    policyDetailFields.innerHTML = '';

    [
      ['Policy ID', policy.id],
      ['Protected App ID', policy.protected_app_id],
      ['HTTP Method', policy.http_method],
      ['Route Pattern', policy.route_pattern],
      ['Mode', policy.mode],
      ['Analysis Engine', policy.analysis_engine_key],
      ['Decision Engine', policy.decision_engine_key],
      ['Status', policy.active ? 'Active' : 'Inactive'],
      ['Priority', policy.priority],
      ['Action Score Threshold', policy.action_score_threshold],
    ].forEach(([label, value]) => {
      policyDetailFields.appendChild(createFieldRow(label, value));
    });
  } catch (error) {
    policyDetailTitle.textContent = 'Error';
    policyDetailSubtitle.textContent = '';
    policyDetailFields.innerHTML = '';
    errorMessage.textContent = error instanceof Error ? error.message : String(error);
  }
}

loadPolicyDetail();
