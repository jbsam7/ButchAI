// Wait for the DOM to load
document.addEventListener('DOMContentLoaded', function() {
    const audio = document.getElementById('audioPlayer');
    const playPauseBtn = document.getElementById('playPauseBtn');

    // Function to update button icon
    function updateButton() {
        if (audio.paused) {
            playPauseBtn.innerHTML = '&#9658;'; // Play icon
        } else {
            playPauseBtn.innerHTML = '&#10074;&#10074;'; // Pause icon
        }
    }

    // Toggle play/pause on button click
    playPauseBtn.addEventListener('click', function() {
        if (audio.paused) {
            audio.play();
        } else {
            audio.pause();
        }
        updateButton();
    });

    // Update button icon when audio ends
    audio.addEventListener('ended', updateButton);

    // Dropdown toggle for mobile
    const dropdownToggle = document.querySelector('.dropdown-toggle');
    if (dropdownToggle) {
        dropdownToggle.addEventListener('click', function(e) {
            e.preventDefault(); // Prevent default link behavior
            const dropdown = this.parentElement;
            dropdown.classList.toggle('active');
        });
    }
});

// Remove the intro overlay after the animation ends
document.addEventListener("DOMContentLoaded", function () {
    const introOverlay = document.querySelector('.intro-overlay');
    document.body.style.overflow = 'hidden'; // Hide overflow during intro
    setTimeout(() => {
        introOverlay.style.display = 'none';
        document.body.style.overflow = 'auto'; // Allow scrolling after intro
    }, 3000); // Matches the animation duration
});



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


// Scroll event to trigger the typing animation
document.addEventListener("scroll", function() {
    const bannerText = document.querySelector('.scroll-banner-text');
    const bannerPosition = bannerText.getBoundingClientRect().top;
    const screenPosition = window.innerHeight / 1.5;

    if (bannerPosition < screenPosition && bannerText.style.visibility !== 'visible') {
        bannerText.style.visibility = 'visible';
        bannerText.style.animation = 'typingScroll 4s steps(40, end) forwards, blinkScroll 0.75s step-end infinite';
    }
});