# 전남대 여수캠 테니스 예약 — v8.2 (이름+소속, Firebase 인증)

## 실행
```
python -m venv tennis
./tennis/Scripts/activate
pip install -r requirements.txt

# 서비스 계정 키 복사
#   instance/keys/serviceAccountKey.json
# 또는 환경변수로 지정:
# $env:GOOGLE_APPLICATION_CREDENTIALS = (Resolve-Path ".\instance\keys\serviceAccountKey.json")

python app.py
# http://localhost:8000
```

## 주요 기능
- 회원가입 시 **이름 + 소속(학생/교직원)** 입력 → Firebase가 **인증메일 발송**
- 인증 완료 후 로그인 시 서버가 **ID 토큰 검증** + 이름·소속 DB 저장
- 06–22시 / 2시간 슬롯 / **하루 1건 사전 예약**, 이전 슬롯 종료 후 **바로 다음 슬롯**만 예외 허용
- **코트별 독립 예약**(UNIQUE(court_id,res_date,slot_index)), 자동 스키마 검사·마이그레이션
- 라이트/다크 테마, 애니메이션 배경/스티커, JNU 로고
