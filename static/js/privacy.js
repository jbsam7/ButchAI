// Function to toggle the menu
function toggleMenu() {
    const header = document.querySelector('header');
    header.classList.toggle('menu-open');
}

document.addEventListener('DOMContentLoaded', function() {
    // Add click event listener for the hamburger menu
    const hamburger = document.querySelector('.hamburger');
    hamburger.addEventListener('click', toggleMenu);

    // Add keyboard event listener to toggle menu with Enter key
    hamburger.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            toggleMenu();
        }
    });
});