(function () {
  function getCookie(name) {
    return document.cookie
      .split("; ")
      .find(row => row.startsWith(name + "="))
      ?.split("=")[1];
  }

  function decodeBase64Url(str) {
    // Restore padding and convert URL-safe base64
    const padded = str + "===".slice((str.length + 3) % 4);
    const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
    return atob(base64);
  }
	
	  // Wire up logout button
  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", function (e) {
      e.preventDefault();
      const host = window.location.hostname;
      window.location.href = "/auth/logout?host=" + encodeURIComponent(host);
    });
  }


  const raw = getCookie("ml_user");

  if (!raw) {
    document.getElementById("hello").textContent = "Welcome";
    document.getElementById("meta").textContent =
      "User information unavailable.";
    return;
  }

  try {
    const user = JSON.parse(decodeBase64Url(raw));

    const name =
      user.username ||
      (user.email ? user.email.split("@")[0] : "there");

    document.getElementById("hello").textContent =
      "Hello " + name;

    const meta = [];
    if (user.email) meta.push("Email: " + user.email);
    if (user.sub) meta.push("User ID: " + user.sub);
    if (user.groups && user.groups.length) {
      meta.push("Groups: " + user.groups.join(", "));
    }

    document.getElementById("meta").textContent =
      meta.join(" • ");

  } catch (e) {
    console.error("Failed to parse ml_user cookie", e);
    document.getElementById("hello").textContent = "Welcome";
    document.getElementById("meta").textContent =
      "Unable to read user details.";
  }
})();
