// Toggle between Login and Signup forms
function showSignup() {
    document.querySelector('.login-container').style.display = 'none';
    document.querySelector('.signup-container').style.display = 'block';
}

function showLogin() {
    document.querySelector('.signup-container').style.display = 'none';
    document.querySelector('.login-container').style.display = 'block';
}

// Smooth scrolling for navigation links
document.querySelectorAll('nav ul li a').forEach(link => {
    link.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});

// Basic animation for Hero section on page load
document.addEventListener('DOMContentLoaded', () => {
    const heroText = document.querySelector('.hero h1');
    heroText.style.opacity = 0;
    heroText.style.transform = 'translateY(-20px)';

    setTimeout(() => {
        heroText.style.opacity = 1;
        heroText.style.transform = 'translateY(0)';
        heroText.style.transition = 'all 0.5s ease-in-out';
    }, 500);
});

// Contact form validation
document.querySelector('.contact-form').addEventListener('submit', function(e) {
    e.preventDefault(); // Prevent form submission for validation

    const name = document.querySelector('input[name="name"]').value.trim();
    const email = document.querySelector('input[name="email"]').value.trim();
    const message = document.querySelector('textarea[name="message"]').value.trim();

    // Validation logic
    if (!name) {
        alert('Please enter your name.');
        return;
    }
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
        alert('Please enter a valid email address.');
        return;
    }
    if (!message) {
        alert('Please enter your message.');
        return;
    }

    // If validation passes
    alert('Thank you for contacting us! We will get back to you soon.');
    this.reset(); // Reset the form
});
