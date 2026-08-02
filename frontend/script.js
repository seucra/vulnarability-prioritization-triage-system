// -------------------------------
// Register
// -------------------------------

function registerUser(e) {
    e.preventDefault();

    const name = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const confirm = document.getElementById("confirm").value;
    const message = document.getElementById("message");

    message.innerHTML = "";
    message.className = "";

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const passwordRegex =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&^#()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;

    if (name.length < 3) {
        return showError("Name must be at least 3 characters.");
    }

    if (!emailRegex.test(email)) {
        return showError("Enter a valid email address.");
    }

    if (!passwordRegex.test(password)) {
        return showError(
            "Password must be 8+ characters with uppercase, lowercase, number and special character."
        );
    }

    if (password !== confirm) {
        return showError("Passwords do not match.");
    }

    let users = JSON.parse(localStorage.getItem("users")) || [];

    const exists = users.find(
        user => user.email.toLowerCase() === email.toLowerCase()
    );

    if (exists) {
        return showError("Email already registered.");
    }

    users.push({
        name,
        email,
        password
    });

    localStorage.setItem("users", JSON.stringify(users));

    message.className = "success";
    message.innerHTML = "Registration successful! Redirecting...";

    setTimeout(() => {
        window.location = "login.html";
    }, 1500);

    function showError(text) {
        message.className = "error";
        message.innerHTML = text;
    }
}

// -------------------------------
// Login
// -------------------------------

function loginUser(e) {
    e.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    const message = document.getElementById("message");

    message.innerHTML = "";
    message.className = "";

    let users = JSON.parse(localStorage.getItem("users")) || [];

    const user = users.find(
        u =>
            u.email.toLowerCase() === email.toLowerCase() &&
            u.password === password
    );

    if (!user) {
        message.className = "error";
        message.innerHTML = "Invalid email or password.";
        return;
    }

    localStorage.setItem("currentUser", JSON.stringify(user));

    window.location = "index.html";
}

// -------------------------------
// Main Page
// -------------------------------

function checkLogin() {
    const user = JSON.parse(localStorage.getItem("currentUser"));

    if (!user) {
        window.location = "login.html";
        return;
    }

    const welcome = document.getElementById("welcome");

    if (welcome) {
        welcome.innerHTML = `Welcome, <strong>${user.name}</strong>`;
    }
}

// -------------------------------
// Logout
// -------------------------------

function logout() {
    localStorage.removeItem("currentUser");
    window.location = "login.html";
}

// -------------------------------
// Show / Hide Password
// -------------------------------

function togglePassword(id) {
    const input = document.getElementById(id);

    if (input.type === "password") {
        input.type = "text";
    } else {
        input.type = "password";
    }
}
