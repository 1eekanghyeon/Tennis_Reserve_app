// static/js/reserve-participants.mjs
const dlg = document.querySelector("#reserve-dialog");
const btnSubmit = document.querySelector("#reserve-submit");
const btnCancel = document.querySelector("#reserve-cancel");

function openDialog(ctx) {
  dlg.dataset.courtId = String(ctx.courtId);
  dlg.dataset.slotIndex = String(ctx.slotIndex);
  dlg.dataset.date = String(ctx.date);
  if (typeof dlg.showModal === "function") dlg.showModal();
  else dlg.setAttribute("open", "open");
}
function closeDialog() {
  if (typeof dlg.close === "function") dlg.close();
  else dlg.removeAttribute("open");
}

// 새 트리거(.reserve-trigger) 클릭 시 모달 오픈
document.addEventListener("click", (e) => {
  const btn = e.target.closest(".reserve-trigger");
  if (!btn) return;
  const cell = btn.closest(".cell");
  openDialog({
    courtId: cell?.dataset.court,
    slotIndex: cell?.dataset.slot,
    date: cell?.dataset.date
  });
});

btnCancel?.addEventListener("click", closeDialog);

function setBusy(el, busy){
  if (!el) return;
  el.disabled = !!busy;
  el.style.pointerEvents = busy ? "none" : "";
  el.style.opacity = busy ? ".85" : "";
}

btnSubmit?.addEventListener("click", async () => {
  const court_id = Number(dlg.dataset.courtId);
  const slot_index = Number(dlg.dataset.slotIndex);
  const res_date = dlg.dataset.date;

  // 추가 참가자 최대 3명 수집
  const extras = [];
  dlg.querySelectorAll(".participant-rows .row").forEach((row) => {
    const name = row.querySelector(".p-name")?.value?.trim();
    if (!name) return;
    const aff = row.querySelector("input[type='radio']:checked")?.value || "student";
    extras.push({ name, affiliation: aff });
  });

  try {
    setBusy(btnSubmit, true);
    const r = await fetch("/api/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ court_id, res_date, slot_index, participants: extras })
    });
    const d = await r.json();
    if (d.ok) {
      closeDialog();
      location.reload();
    } else {
      alert(d.error || "예약 실패");
    }
  } catch (e) {
    alert(e?.message || "예약 처리 중 오류가 발생했습니다.");
  } finally {
    setBusy(btnSubmit, false);
  }
});
