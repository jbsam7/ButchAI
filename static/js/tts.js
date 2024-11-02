function toggleMenu() {
    const header = document.querySelector('header');
    header.classList.toggle('menu-open');
}

// Handle Dropdown for Mobile
document.querySelectorAll('.dropdown > a').forEach(function(dropdownToggle) {
    dropdownToggle.addEventListener('click', function(e) {
        e.preventDefault();
        this.parentElement.classList.toggle('open');
    });
});

const form = document.getElementById('uploadForm');
const loader = document.getElementById('loader');

form.addEventListener('submit', function (e) {
    e.preventDefault(); // Prevent the default form submission behavior
    loader.style.display = 'flex'; // Show loader on form submission

    const formData = new FormData(form);

    fetch(form.action, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            return response.json();  // Expecting a JSON response
        } else {
            throw new Error('Upload failed');
        }
    })
    .then(data => {
        if (data.audio_url) {
            // Clear previous link if any
            const linkContainer = document.getElementById('downloadLinkContainer');
            linkContainer.innerHTML = ''; // Clear previous links

            // Create and display the download link instead of auto-downloading
            const downloadLink = document.createElement('a');
            downloadLink.href = data.audio_url;
            downloadLink.textContent = 'Click here to download your audio file';
            downloadLink.download = true; // Optional: suggests downloading when clicked
            linkContainer.appendChild(downloadLink);
            linkContainer.style.display = 'block';
        } else {
            alert('Upload completed, but no file to download');
        }
    })
    .catch(error => {
        console.error('Error during upload:', error);
        alert('An error occurred during upload.');
    })
    .finally(() => {
        loader.style.display = 'none'; // Hide loader when done
    });
});