const welcomeMessage = document.getElementById('welcome-message');
const appsList = document.getElementById('apps-list');
const noAppsMessage = document.getElementById('no-apps-message');
const errorMessage = document.getElementById('error-message');
const createProtectedAppButton = document.getElementById('create-protected-app-button');

if (createProtectedAppButton) {
  createProtectedAppButton.addEventListener('click', () => {
    window.location.href = '/protected_apps/new';
  });
}

async function loadDashboard() {
  try {
    errorMessage.textContent = '';

    // fetch current user info
    const userResponse = await fetch('/api/v1/users/me', {
        method: 'GET',
        credentials: 'include',
    });

    if (!userResponse.ok) {
        throw new Error('Failed to fetch user\'s information');
    }

    const user = await userResponse.json();
    welcomeMessage.textContent = `Welcome, ${user.email}!`;

    // fetch current user's protected apps
    const appsResponse = await fetch('/api/v1/protected_apps/me', {
        method: 'GET',
        credentials: 'include',
    });

    if (!appsResponse.ok) {
        throw new Error('Failed to fetch user\'s protected apps');
    }

    const apps = await appsResponse.json();

    if (apps.length === 0) {
        // user hasn't created any protected apps in the database yet
        noAppsMessage.textContent = 'You have no protected apps yet';
        appsList.innerHTML = '';
        // no apps to show so we're done here
        return;
    }

    // user has some protected apps, no need for error message
    noAppsMessage.textContent = '';
    appsList.innerHTML = '';

    apps.forEach((app) => {
        // create buttons for each of user's protected apps
        // each app will have its own dashboard
        // when clicked these will take the user there
        const button = document.createElement('button');
        button.textContent = `${app.name} (${app.url})`;
        button.addEventListener('click', () => {
        window.location.href = `/dashboard/${app.id}`;
        });
        appsList.appendChild(button);
    });
  } catch (error) {
    errorMessage.textContent = error.message;
  }
}

loadDashboard();
