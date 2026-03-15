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
        console.error('Theme toggle switch NOT FOUND: #theme-toggle-check');
        console.log('Available elements with theme-toggle:', document.querySelectorAll('[id*="theme"]'));
        // Still check for saved theme to apply it
        applySavedTheme();
        return;
    }

    console.log('Theme toggle switch FOUND, initializing...');

    // Apply saved theme on load
    applySavedTheme(toggleSwitch);

    // Event Listener - using both change and click for robustness
    toggleSwitch.addEventListener('change', (e) => {
        console.log('Theme toggle changed:', e.target.checked);
        if (e.target.checked) {
            enableDarkMode();
        } else {
            enableLightMode();
        }
    });
    
    // Also handle click directly in case change doesn't fire
    toggleSwitch.addEventListener('click', (e) => {
        console.log('Theme toggle clicked, checked:', e.target.checked);
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
