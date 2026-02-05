/**
 * THEME TOGGLE LOGIC
 * Handles switching between Light and Dark mode.
 * Persists preference to localStorage.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Select by specific ID to avoid collisions
    const toggleSwitch = document.getElementById('theme-toggle-check');

    // Debug check
    if (!toggleSwitch) {
        console.warn('Theme toggle switch not found: #theme-toggle-check');
        // Still check for saved theme to apply it
        applySavedTheme();
        return;
    }

    // Apply saved theme on load
    applySavedTheme(toggleSwitch);

    // Event Listener
    toggleSwitch.addEventListener('change', (e) => {
        if (e.target.checked) {
            enableDarkMode();
        } else {
            enableLightMode();
        }
    });
});

function applySavedTheme(toggleSwitchElement = null) {
    const currentTheme = localStorage.getItem('theme');

    if (currentTheme === 'dark-mode') {
        enableDarkMode();
        if (toggleSwitchElement) toggleSwitchElement.checked = true;
    } else {
        // Default or Explicit Light
        enableLightMode();
        if (toggleSwitchElement) toggleSwitchElement.checked = false;
    }
}

function enableDarkMode() {
    document.body.classList.add('dark-mode');
    document.body.setAttribute('data-theme', 'dark'); // For CSS attribute selectors
    localStorage.setItem('theme', 'dark-mode');
    console.log('Switched to Dark Mode');
}

function enableLightMode() {
    document.body.classList.remove('dark-mode');
    document.body.setAttribute('data-theme', 'light');
    localStorage.setItem('theme', 'light-mode');
    console.log('Switched to Light Mode');
}
