function toggleMenu() {
    const header = document.querySelector('header');
    header.classList.toggle('menu-open');
}

// Allow toggling menu with keyboard (Enter key)
document.querySelector('.hamburger').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        toggleMenu();
    }
});