document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("input[type=date]").forEach(el => {
    const today = new Date().toISOString().slice(0,10);
    el.min = today;
  });
  document.querySelectorAll(".flash").forEach(el => {
    setTimeout(() => { if (el.isConnected) el.classList.add("fade"); }, 5500);
  });
});
