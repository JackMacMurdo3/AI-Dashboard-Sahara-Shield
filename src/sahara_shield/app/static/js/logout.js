async function handleLogout() {
  try {
    // send a POST request to the logout API endpoint
    // if the user is logged in, their browser should have a cookie whose ID is stored in server's DB
    // sending this request will delete that cookie in the server's DB
    const response = await fetch('/api/v1/auth/logout', {
      method: 'POST',
    });

    if (!response.ok) {
      throw new Error('Logout failed'); // this should really only happen if there's a problem server-side, like a timeout
    }

    window.location.href = '/login'; // redirect back to login page
  } catch (error) {
    alert('Unable to logout: ' + (error.message || 'Unknown error. Please try again later.'));
  }
}

const logoutBtn = document.getElementById('logout-btn');
if (logoutBtn) {
  logoutBtn.addEventListener('click', handleLogout);
}
