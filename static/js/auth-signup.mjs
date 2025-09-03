import { initializeApp } from "https://www.gstatic.com/firebasejs/12.1.0/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, sendEmailVerification, updateProfile } from "https://www.gstatic.com/firebasejs/12.1.0/firebase-auth.js";

const app = initializeApp(window.FB_CONFIG);
const auth = getAuth(app);

const nameInput   = document.querySelector("#fb-name");
const emailInput  = document.querySelector("#fb-email");
const passInput   = document.querySelector("#fb-password");
const pass2Input  = document.querySelector("#fb-password2");
const btnSend     = document.querySelector("#fb-send-verif");
const btnComplete = document.querySelector("#fb-complete");
const help        = document.querySelector("#signup-help");

function getAff() {
  const el = document.querySelector("input[name='fb-aff']:checked");
  return el ? el.value : "student";
}
function isJnu(mail){ return mail && mail.toLowerCase().endsWith("@jnu.ac.kr"); }
function setBusy(el, busy){
  if (!el) return;
  el.disabled = !!busy;
  el.style.pointerEvents = busy ? "none" : "";
  el.style.opacity = busy ? ".85" : "";
}

// --- 인증 완료 자동 감지 ---
let pollTimer = null;

async function checkVerifiedOnce() {
  const user = auth.currentUser;
  if (!user) return false;
  await user.reload();
  if (user.emailVerified) {
    btnComplete.disabled = false;
    help.textContent = "이메일 인증이 확인되었습니다. ‘회원가입 완료’를 눌러 마무리하세요.";
    return true;
  }
  return false;
}
function startPolling() {
  stopPolling();
  // 4초 간격으로 이메일 인증 여부 체크
  pollTimer = setInterval(checkVerifiedOnce, 4000);
}
function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}
document.addEventListener("visibilitychange", async () => {
  if (!document.hidden) { await checkVerifiedOnce(); }  // 탭으로 돌아오면 즉시 재확인
});
window.addEventListener("beforeunload", stopPolling);

// --- 버튼 동작 ---
btnSend?.addEventListener("click", async () => {
  const name  = (nameInput.value || "").trim();
  const email = (emailInput.value || "").trim();
  const pass  = (passInput.value || "").trim();
  const pass2 = (pass2Input.value || "").trim();

  if (name.length < 2)  { alert("이름(실명)을 입력하세요."); return; }
  if (!isJnu(email))    { alert("@jnu.ac.kr 이메일만 허용됩니다."); return; }
  if (pass.length < 6)  { alert("비밀번호는 최소 6자입니다."); return; }
  if (pass !== pass2)   { alert("비밀번호가 서로 다릅니다."); return; }

  try {
    setBusy(btnSend, true);

    // 1) Firebase 계정 생성
    const { user } = await createUserWithEmailAndPassword(auth, email, pass);
    await updateProfile(user, { displayName: name });

    // 2) 인증메일 발송
    await sendEmailVerification(user /*, { url: location.origin + "/login" }*/);

    alert("인증메일을 보냈습니다. 메일의 링크를 누르면 이 페이지가 자동으로 인증 완료를 감지합니다.");
    help.textContent = "이메일에서 인증을 완료하면 자동으로 감지됩니다. 잠시만 기다려 주세요…";
    btnComplete.disabled = true;
    startPolling(); // 자동 감지 시작
  } catch (e) {
    alert(e?.message || "가입 중 오류가 발생했습니다.");
  } finally {
    setBusy(btnSend, false);
  }
});

btnComplete?.addEventListener("click", async () => {
  try {
    setBusy(btnComplete, true);

    // 안전망: 서버로 보내기 전에 한 번 더 실제 인증 상태 확인
    const ok = await checkVerifiedOnce();
    if (!ok) { alert("아직 이메일 인증이 완료되지 않았습니다."); return; }

    const user = auth.currentUser;
    if (!user) { alert("먼저 인증메일을 발송해 계정을 생성해 주세요."); return; }

    const idToken = await user.getIdToken(true);
    const name  = (nameInput.value || "").trim();
    const aff   = getAff();

    const r = await fetch("/auth/firebase", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken, name, affiliation: aff })
    });
    const d = await r.json();
    if (d.ok) {
      alert("회원가입이 완료되었습니다. 예약 페이지로 이동합니다.");
      window.location.href = "/reserve";
    } else {
      alert(d.error || "회원가입 완료 처리에 실패했습니다.");
    }
  } catch (e) {
    alert(e?.message || "회원가입 완료 처리 중 오류가 발생했습니다.");
  } finally {
    setBusy(btnComplete, false);
    stopPolling();
  }
});
