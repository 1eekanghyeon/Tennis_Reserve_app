import { initializeApp } from "https://www.gstatic.com/firebasejs/12.1.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword } from "https://www.gstatic.com/firebasejs/12.1.0/firebase-auth.js";

const app = initializeApp(window.FB_CONFIG);
const auth = getAuth(app);

const emailInput = document.querySelector("#fb-email");
const passInput  = document.querySelector("#fb-password");

function isJnu(mail){ return mail && mail.toLowerCase().endsWith("@jnu.ac.kr"); }

document.querySelector("#fb-login")?.addEventListener("click", async () => {
  const email = (emailInput.value || "").trim();
  const pass  = (passInput.value || "").trim();

  if (!isJnu(email)) { alert("@jnu.ac.kr 이메일만 허용됩니다."); return; }
  if (!pass) { alert("비밀번호를 입력하세요."); return; }

  try {
    const { user } = await signInWithEmailAndPassword(auth, email, pass);
    await user.reload();
    if (!user.emailVerified) { alert("이메일 인증 후 로그인 가능합니다."); return; }

    const idToken = await user.getIdToken();
    // 로그인에서는 affiliation을 보내지 않습니다(가입 때 이미 저장됨).
    const r = await fetch("/auth/firebase", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    });
    const d = await r.json();
    if (d.ok) window.location.href = "/reserve";
    else alert(d.error || "로그인 실패");
  } catch (e) {
    alert(e?.message || "로그인 실패");
  }
});
