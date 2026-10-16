"""Labelled evaluation. Dataset is small, hand-written by the rule author: results are optimistic and NOT evidence of real-world performance."""
import sys; sys.path.insert(0, ".")
from app.engine import analyze
MAL = ["Hello, I am your college coordinator. Send your OTP immediately or your registration will be cancelled.",
 "Hey mom, new number. Need ₹10,000 transferred right now, don't tell dad.",
 "Your bank account will be blocked today. Share your password and PIN to avoid closure.",
 "I'm your manager. Buy gift cards for a client immediately and keep this between us.",
 "Install AnyDesk now so our officer can fix your account.",
 "Dear customer, your KYC expires today. Click here and enter your Aadhaar and card number.",
 "This is the HR recruiter. Pay ₹2,000 registration fee urgently to confirm your job offer.",
 "Send me your verification code immediately, I'm from the bank and your account will be suspended.",
 "Skip the approval process and wire the amount to this account right now. Do not tell finance.",
 "I'm stuck at the airport, it's an emergency. Please send ₹8,000 to this new number, don't call.",
 "Police officer here: legal action will be taken unless you pay penalty ₹5000 within 30 minutes.",
 "Kindly furnish the six digits that just arrived on your handset so we can complete the update.",
 "Congrats! You won a prize. Send bitcoin fee to claim.",
 "Your password has expired. Reply with your current password immediately."]
BEN = ["Hi, the workshop begins at 4 PM. Please check the official event page for the meeting link.",
 "Reminder: never share your OTP with anyone, including bank staff.",
 "Please submit the assignment by 5 PM today; urgent corrections are in the portal.",
 "Your OTP is 482913. Do not share it with anyone.",
 "Lunch at 1? I'll send you the location.",
 "Can you send me the meeting notes when you have time?",
 "Rent of ₹15,000 is due on the 1st, as usual. Please pay to the same account.",
 "Team, the quarterly review is urgent but routine; please join the call at 3 PM.",
 "Our bank will never ask for your password. Stay alert for phishing.",
 "I've transferred ₹500 for the movie tickets, thanks!",
 "Please bring your ID proof to the admissions office tomorrow.",
 "Hi, I'm your new manager. Looking forward to meeting the team on Monday.",
 "Don't tell anyone about the surprise party, it's for Priya!",
 "URGENT: Please reset your password using the official IT portal; we will never ask you to email it."]
def run(flag):
    tp = sum(analyze(t)["risk_level"] in flag for t in MAL); fp = sum(analyze(t)["risk_level"] in flag for t in BEN)
    fn, tn = len(MAL)-tp, len(BEN)-fp
    return tp, fp, fn, tn, tp/max(tp+fp, 1), tp/len(MAL), fp/len(BEN)
for name, flag in [("flagged = High or Critical", ("High", "Critical")), ("flagged = Medium or above", ("Medium", "High", "Critical"))]:
    tp, fp, fn, tn, p, r, f = run(flag)
    print(f"{name}: n={len(MAL)+len(BEN)} (mal={len(MAL)}, benign={len(BEN)}) TP={tp} FP={fp} FN={fn} TN={tn} precision={p:.2f} recall={r:.2f} FPR={f:.2f}")
print("Missed malicious (High+):", [t[:50] for t in MAL if analyze(t)["risk_level"] not in ("High", "Critical")])
print("False positives (High+):", [t[:50] for t in BEN if analyze(t)["risk_level"] in ("High", "Critical")])
