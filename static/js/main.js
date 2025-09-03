function postJSON(url, data) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  }).then(r => r.json());
}

async function reserve(cell) {
  const courtId = Number(cell.dataset.court);
  const resDate = cell.dataset.date;
  const slotIndex = Number(cell.dataset.slot);
  const data = await postJSON("/api/reserve", { court_id: courtId, res_date: resDate, slot_index: slotIndex });
  if (!data.ok) alert(data.error || "예약 중 오류가 발생했습니다.");
  else location.reload();
}

async function cancelReservation(resId) {
  if (!confirm("정말 취소하시겠습니까?")) return;
  const data = await postJSON("/api/cancel", { reservation_id: Number(resId) });
  if (!data.ok) alert(data.error || "취소 중 오류가 발생했습니다.");
  else location.reload();
}

document.addEventListener("DOMContentLoaded", () => {
  // theme toggle
  const toggle = document.querySelector("#theme-toggle");
  if (toggle) {
    const setTheme = (t) => document.documentElement.setAttribute("data-theme", t);
    const saved = localStorage.getItem("theme");
    if (saved) setTheme(saved);
    toggle.addEventListener("click", () => {
      const next = (document.documentElement.getAttribute("data-theme") === "dark") ? "light" : "dark";
      setTheme(next); localStorage.setItem("theme", next);
    });
  }

  document.body.addEventListener("click", (e) => {
    const reserveBtn = e.target.closest(".reserve-btn");
    if (reserveBtn) { reserve(reserveBtn.closest(".cell")); return; }
    const cancelBtn = e.target.closest(".cancel-btn");
    if (cancelBtn) { cancelReservation(cancelBtn.dataset.resId); return; }
  });
});