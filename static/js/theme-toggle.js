document.addEventListener('DOMContentLoaded', () => {
    const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');

    // Guard clause: Exit gracefully if toggle switch doesn't exist on this page
    if (!toggleSwitch) {
        // Still apply saved theme even if toggle doesn't exist
        const currentTheme = localStorage.getItem('theme');
        if (currentTheme === 'dark-mode') {
            document.body.classList.add('dark-mode');
        }
        return;
    }

    const currentTheme = localStorage.getItem('theme');

    // Apply saved theme
    if (currentTheme) {
        document.body.classList.add(currentTheme);
        if (currentTheme === 'dark-mode') {
            toggleSwitch.checked = true;
        }
    }

    // Theme switch handler
    function switchTheme(e) {
        if (e.target.checked) {
            document.body.classList.add('dark-mode');
            localStorage.setItem('theme', 'dark-mode');
        } else {
            document.body.classList.remove('dark-mode');
            localStorage.setItem('theme', 'light-mode');
        }
    }

    toggleSwitch.addEventListener('change', switchTheme);
});
