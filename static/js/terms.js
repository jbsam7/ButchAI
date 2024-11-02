function toggleMenu() {
    const header = document.querySelector('header');
    const hamburger = document.querySelector('.hamburger');
    header.classList.toggle('menu-open');
    hamburger.classList.toggle('active'); /* For animation */
}

// Allow toggling menu with keyboard (Enter key)
document.querySelector('.hamburger').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        toggleMenu();
    }
});