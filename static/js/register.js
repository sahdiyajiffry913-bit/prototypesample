// Show secret code only when role is Admin
var roleSelect = document.getElementById("role-select");
var adminWrap = document.getElementById("admin-code-wrap");
var adminInput = document.getElementById("admin-code");

function updateAdminField() {
  if (!roleSelect || !adminWrap) return;
  if (roleSelect.value === "admin") {
    adminWrap.classList.add("show");
    if (adminInput) adminInput.removeAttribute("disabled");
  } else {
    adminWrap.classList.remove("show");
    if (adminInput) {
      adminInput.value = "";
      adminInput.setAttribute("disabled", "disabled");
    }
  }
}

if (roleSelect) {
  roleSelect.addEventListener("change", updateAdminField);
  updateAdminField();
}
