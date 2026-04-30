const dashboardTitle = document.getElementById('dashboard-title');
const appSubtitle = document.getElementById('app-subtitle');
const appInfo = document.getElementById('app-info');
const errorMessage = document.getElementById('error-message');

function getProtectedAppIdFromUrl() {
  const pathParts = window.location.pathname.split('/').filter(Boolean);
  console.log(pathParts);

  if (pathParts.length >= 2 && pathParts[0] === 'dashboard') {
    return pathParts[1];
  }

  const appIdFromQuery = new URLSearchParams(window.location.search).get('app_id');
  return appIdFromQuery;
}

function createStatItem(label, value) {
  const statItem = document.createElement('div');
  statItem.className = 'stat-item';

  const statLabel = document.createElement('p');
  statLabel.className = 'stat-label';
  statLabel.textContent = label;

  const statValue = document.createElement('p');
  statValue.className = 'stat-value';
  statValue.textContent = String(value);

  statItem.appendChild(statLabel);
  statItem.appendChild(statValue);

  return statItem;
}

function renderProtectedAppInfo(app) {
  appInfo.innerHTML = '';

  const statsGrid = document.createElement('div');
  statsGrid.className = 'stats-grid';

  const liveStatus = app.live ? 'Live' : 'Offline';

  statsGrid.appendChild(createStatItem('Live', liveStatus));
  statsGrid.appendChild(
    createStatItem('App Security Policies', app.app_security_policies_count ?? 0),
  );
  statsGrid.appendChild(
    createStatItem('Flagged Requests', app.flagged_requests_count ?? 0),
  );
  statsGrid.appendChild(
    createStatItem('Security Events', app.security_events_count ?? 0),
  );

  appInfo.appendChild(statsGrid);
}

async function loadProtectedAppDashboard() {
  try {
    errorMessage.textContent = '';

    const protectedAppId = getProtectedAppIdFromUrl();

    if (!protectedAppId) {
      throw new Error('Protected app not found');
    }

    const response = await fetch(`/api/v1/protected_apps/me/${protectedAppId}`, {
      method: 'GET',
      credentials: 'include',
    });

    if (!response.ok) {
        throw new Error('Failed to fetch protected app information');
    }

    const app = await response.json();

    dashboardTitle.textContent = app.name || 'Protected App Dashboard';
    appSubtitle.textContent = app.url ? `URL: ${app.url}` : '';

    renderProtectedAppInfo(app);
  } catch (error) {
    appInfo.innerHTML = '';
    errorMessage.textContent = error instanceof Error ? error.message : String(error);
  }
}

loadProtectedAppDashboard();
