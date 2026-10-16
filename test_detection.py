from app.engine import analyze
from app.trust import full_assess, run_simulation, SCENARIOS
lv = lambda t: analyze(t)["risk_level"]
HI = ("High", "Critical")
def test_otp_theft(): assert lv("Share your verification code right now or your account will be blocked.") in HI
def test_authority(): r = full_assess("Hello, I am your college coordinator. Send your OTP immediately or your registration will be cancelled."); assert "authority" in r["summary"]["detected"] and r["risk_level"] == "Critical"
def test_emergency_money(): assert lv("Hey, I lost my phone. Please transfer ₹5,000 to this new number urgently. Do not call me.") == "Critical"
def test_secrecy_bypass(): assert lv("Skip the approval process and send the client list right now. Don't tell the team.") in HI
def test_benign_admin(): assert lv("Hi, the workshop begins at 4 PM. Please check the official event page for the meeting link.") == "Low"
def test_educational(): assert lv("Reminder: never share your OTP with anyone, including bank staff.") == "Low"
def test_ambiguous_single_signal(): assert lv("Please reply urgently when you can.") in ("Low", "Medium")
def test_conflicting_edu_plus_real_request(): assert lv("Never share your OTP. Also, send your OTP immediately or your registration will be cancelled.") in HI
def test_missing_identity_is_not_fraud(): r = full_assess("Hello there"); assert r["identity_status"] == "Verification unavailable" and r["risk_level"] == "Low"
def test_simulation_uses_engine():
    a = run_simulation("college", 3)["assessment"]; assert a["score"] == analyze(" ".join(m["text"] for m in SCENARIOS[0]["messages"]))["score"] or a["risk_level"] == "Critical"
