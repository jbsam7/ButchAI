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

// Password Validation Function
function validatePassword() {
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirm_password").value;
    // Elements for feedback
    const minLength = document.getElementById("minLength");
    const uppercase = document.getElementById("uppercase");
    const lowercase = document.getElementById("lowercase");
    const number = document.getElementById("number");
    const special = document.getElementById("special");
    const match = document.getElementById("passwordMatch");

    // Minimum length (8 characters)
    if (password.length >= 8) {
        minLength.style.color = "green";
    } else {
        minLength.style.color = "red";
    }

    // At least one uppercase letter
    if (/[A-Z]/.test(password)) {
        uppercase.style.color = "green";
    } else {
        uppercase.style.color = "red";
    }

    // At least one lowercase letter
    if (/[a-z]/.test(password)) {
        lowercase.style.color = "green";
    } else {
        lowercase.style.color = "red";
    }

    // At least one number
    if (/\d/.test(password)) {
        number.style.color = "green";
    } else {
        number.style.color = "red";
    }

    // At least one special character
    if (/[@$!%*?&]/.test(password)) {
        special.style.color = "green";
    } else {
        special.style.color = "red";
    }

    // Check if passwords match
    if (password !== '' && confirmPassword !== '') {
        if (password === confirmPassword) {
            match.style.color = "green";
            match.innerText = "Passwords match";
        } else {
            match.style.color = "red";
            match.innerText = "Passwords do not match";
        }
    } else {
        match.innerText = "";
    }
}

// Dropdown toggle for mobile
document.addEventListener('DOMContentLoaded', function() {
    const dropdownToggle = document.querySelector('.dropdown-toggle');
    if (dropdownToggle) {
        dropdownToggle.addEventListener('click', function(e) {
            e.preventDefault(); // Prevent default link behavior
            const dropdown = this.parentElement;
            dropdown.classList.toggle('active');
        });
    }

    // Remove the intro overlay after the animation ends (if applicable)
    // If not using intro overlay, this can be removed
    /*
    const introOverlay = document.querySelector('.intro-overlay');
    document.body.style.overflow = 'hidden'; // Hide overflow during intro
    setTimeout(() => {
        introOverlay.style.display = 'none';
        document.body.style.overflow = 'auto'; // Allow scrolling after intro
    }, 3000); // Matches the animation duration
    */
});