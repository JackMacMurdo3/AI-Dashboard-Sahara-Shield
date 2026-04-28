const statScans = document.getElementById('stat-scans');
const statFiles = document.getElementById('stat-files');
const statClean = document.getElementById('stat-clean');
const statBad = document.getElementById('stat-bad');

function formatCount(value) {
  return new Intl.NumberFormat('en-US').format(Number(value) || 0);
}

function setStatValue(element, value) {
  if (!element) {
    return;
  }

  element.textContent = formatCount(value);
}

async function loadUserStats() {
  try {
    const response = await fetch('/api/v1/users/me', {
      credentials: 'same-origin',
      headers: {
        Accept: 'application/json',
      },
    });

    if (response.status === 401) {
      window.location.href = '/login';
      return;
    }

    if (!response.ok) {
      throw new Error('Unable to load user stats.');
    }

    const user = await response.json();

    setStatValue(statScans, user.scans_count);
    setStatValue(statFiles, user.files_scanned_count);
    setStatValue(statClean, user.clean_files_count);
    setStatValue(statBad, user.bad_files_count);
  } catch (error) {
    console.error(error);
  }
}

window.addEventListener('DOMContentLoaded', loadUserStats);
