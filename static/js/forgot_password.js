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

// Close the menu when clicking outside
document.addEventListener('click', function(event) {
    const hamburger = document.querySelector('.hamburger');
    const navLinksLeft = document.querySelector('.nav-links-left');
    const navLinksRight = document.querySelector('.nav-links-right');
    if (!hamburger.contains(event.target) && !navLinksLeft.contains(event.target) && !navLinksRight.contains(event.target)) {
        document.querySelector('header').classList.remove('menu-open');
    }
});