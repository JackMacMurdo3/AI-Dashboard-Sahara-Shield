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

function initializeTabs() {
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabPanels = document.querySelectorAll('.tab-panel');
  const protectedAppId = getProtectedAppIdFromUrl();

  tabButtons.forEach((button) => {
    button.addEventListener('click', async () => {
      // remove active state from all buttons and panels
      tabButtons.forEach((btn) => {
        btn.classList.remove('active');
        btn.setAttribute('aria-selected', 'false');
      });

      tabPanels.forEach((panel) => {
        panel.classList.remove('active');
        panel.setAttribute('hidden', '');
      });

      // set active state on clicked button and corresponding panel
      button.classList.add('active');
      button.setAttribute('aria-selected', 'true');

      const tabName = button.getAttribute('data-tab');
      const correspondingPanel = document.getElementById(`${tabName}-panel`);
      
      if (correspondingPanel) {
        correspondingPanel.classList.add('active');
        correspondingPanel.removeAttribute('hidden');

        // Load events summary when events tab is clicked
        if (tabName === 'events' && protectedAppId) {
          await loadSecurityEventsSummary(protectedAppId);
        }
      }
    });
  });
}

function formatMetricName(name) {
  return name.replace(/_/g, ' ');
}

function renderSummaryContainer(title, metrics) {
  const container = document.createElement('div');
  container.className = 'summary-container';

  const header = document.createElement('h3');
  header.textContent = title;
  container.appendChild(header);

  const metricsGrid = document.createElement('div');
  metricsGrid.className = 'metrics-grid';

  for (const [name, value] of Object.entries(metrics)) {
    const metricItem = document.createElement('div');
    metricItem.className = 'metric-item';

    const metricName = document.createElement('p');
    metricName.className = 'metric-name';
    metricName.textContent = formatMetricName(name);

    const metricValue = document.createElement('p');
    metricValue.className = 'metric-value';
    metricValue.textContent = String(value);

    metricItem.appendChild(metricName);
    metricItem.appendChild(metricValue);
    metricsGrid.appendChild(metricItem);
  }

  container.appendChild(metricsGrid);
  return container;
}

function renderConfidencePctStatsContainer(stats) {
  const container = document.createElement('div');
  container.className = 'summary-container';

  const header = document.createElement('h3');
  header.textContent = 'Confidence Statistics';
  container.appendChild(header);

  const statsGrid = document.createElement('div');
  statsGrid.className = 'confidence-stats';

  const meanItem = document.createElement('div');
  meanItem.className = 'confidence-stat';

  const meanLabel = document.createElement('p');
  meanLabel.className = 'confidence-label';
  meanLabel.textContent = 'Mean';
  meanItem.appendChild(meanLabel);

  const meanValue = document.createElement('p');
  meanValue.className = 'confidence-value';
  meanValue.textContent = `${stats.mean.toFixed(2)}%`;
  meanItem.appendChild(meanValue);

  statsGrid.appendChild(meanItem);

  const medianItem = document.createElement('div');
  medianItem.className = 'confidence-stat';

  const medianLabel = document.createElement('p');
  medianLabel.className = 'confidence-label';
  medianLabel.textContent = 'Median';
  medianItem.appendChild(medianLabel);

  const medianValue = document.createElement('p');
  medianValue.className = 'confidence-value';
  medianValue.textContent = `${stats.median.toFixed(2)}%`;
  medianItem.appendChild(medianValue);

  statsGrid.appendChild(medianItem);
  container.appendChild(statsGrid);

  return container;
}

async function loadSecurityEventsSummary(protectedAppId) {
  const eventsSummaryDiv = document.getElementById('events-summary');

  try {
    const response = await fetch(
      `/api/v1/security_events/me/protected_app/${protectedAppId}/summary`,
      {
        method: 'GET',
        credentials: 'include',
      }
    );

    if (!response.ok) {
      throw new Error('Failed to fetch security events summary');
    }

    const data = await response.json();

    eventsSummaryDiv.innerHTML = '';

    if (data.threat_severity_counts) {
      const severityContainer = renderSummaryContainer(
        'Threat Severity Distribution',
        data.threat_severity_counts
      );
      eventsSummaryDiv.appendChild(severityContainer);
    }

    if (data.threat_type_counts) {
      const typeContainer = renderSummaryContainer(
        'Threat Type Distribution',
        data.threat_type_counts
      );
      eventsSummaryDiv.appendChild(typeContainer);
    }

    if (data.confidence_pct_stats) {
      const confidencePctStatsContainer = renderConfidencePctStatsContainer(
        data.confidence_pct_stats
      );
      eventsSummaryDiv.appendChild(confidencePctStatsContainer);
    }
  } catch (error) {
    eventsSummaryDiv.innerHTML = '';
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error';
    errorDiv.textContent = error instanceof Error ? error.message : String(error);
    eventsSummaryDiv.appendChild(errorDiv);
  }
}

loadProtectedAppDashboard();
initializeTabs();
