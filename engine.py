"""Transparent rule-based analysis. Rules and thresholds are configurable below."""
import re
from dataclasses import dataclass

@dataclass(frozen=True)
class Rule:
    id: str; kind: str; weight: int; pattern: str; why: str; action: str
    def rx(self): return re.compile(self.pattern, re.I)

RULES = [
 Rule("credential","ask",5,r"\b(otp|one[- ]time (pass(word|code)|code)|password|passcode|pin|recovery code|cvv|verification code)\b","Asks for a credential that legitimate organisations do not request by message.","Never share OTPs, passwords or codes. Contact the organisation via an official channel."),
 Rule("money","ask",3,r"(transfer|send|pay|wire|deposit)\b.{0,40}(₹|rs\.?|inr|\$|money|amount|\d{3,})|(₹|rs\.?)\s?\d[\d,]*","Requests a money transfer.","Do not pay until you confirm via a known phone number or in person."),
 Rule("giftcard","ask",4,r"\bgift ?cards?\b|\bgoogle play card\b|\bcrypto(currency)?\b|\bbitcoin\b","Requests hard-to-reverse payment (gift cards/crypto).","Treat gift-card or crypto payment requests as a strong fraud signal."),
 Rule("remote_access","ask",4,r"\b(anydesk|teamviewer|quick ?support|screen ?share|remote access|install (this|the) (app|apk))\b","Asks for remote access or app installation.","Do not install software or grant access at an unsolicited request."),
 Rule("confidential","ask",2,r"\b(aadhaar|pan card|bank details|card number|account number|id proof|confidential|client (list|data)|pricing sheet|salary data|internal documents?)\b","Requests sensitive personal or confidential information.","Share personal data only through channels you initiated and trust."),
 Rule("urgency","pressure",2,r"\b(urgent(ly)?|immediately|right now|asap|within \w+ (minutes?|hours?)|in (ten|\d+) minutes|last chance|today only|expires? (soon|today))\b","Creates time pressure to prevent verification.","Pause. Genuine requests survive a short delay for verification."),
 Rule("threat","pressure",2,r"\b(suspended|blocked|cancel(l)?ed|terminated|legal action|arrest|penalty|account (will be )?(closed|locked)|police)\b","Threatens a negative consequence.","Threats are a pressure tactic; verify with the real organisation."),
 Rule("secrecy","pressure",3,r"\b(don'?t|do not) (tell|call|inform|share (this )?with|contact)\b|\bkeep (this|it) (secret|confidential|between us)\b","Discourages you from verifying or telling others.","Verify through a known channel anyway; secrecy requests are a red flag."),
 Rule("bypass","pressure",2,r"\b(skip|bypass|no need (for|to)) (the )?(usual|normal|official|process|procedure|verification|approval)|\bnew number\b|\bwithout (approval|informing)\b","Tries to bypass normal procedure or uses an unverified new contact.","Follow the established process; confirm new contact details independently."),
 Rule("authority","context",1,r"\b(i am|this is|i'm) (your |the |from )?(college|university|coordinator|principal|manager|ceo|hr|recruiter|bank|officer|professor|dean)\b|\b(bank|rbi|income tax|customs) (official|officer|executive)\b","Claims authority or a role that cannot be confirmed from the message.","Check the claimed role via official contact details you look up yourself."),
 Rule("emotional","context",1,r"\b(lost my phone|stuck|emergency|accident|hospital|in trouble|help me|please help)\b","Uses emotional pressure or a distress story.","Call the person on their known number before acting."),
 Rule("link_login","context",1,r"https?://\S+|\bclick (this|the|on) link\b|\bclick here\b","Contains or references a link (counted only alongside other signals).","Navigate to the official site yourself instead of using the link."),
]
EDU = re.compile(r"\b(never|do not|don'?t|will never|won'?t ever)\s+(share|give|disclose|reveal)\b[^.]{0,40}\b(otp|password|pin|code)s?\b|\b(phishing awareness|awareness (tip|training)|security (tip|training))\b", re.I)
EDU_NOTE = "Credential words appear in a warning/educational context (e.g. 'never share'), so they were not treated as a request."
CONFIG = {"medium": 3, "high": 6, "critical": 10, "combo_ask_pressure": 2, "combo_ask_secrecy": 1}
LIMITS = ["Rule-based: paraphrased or non-English scams may be missed.",
          "A Low result never guarantees safety.",
          "No sender reputation, link or identity lookups are performed."]

REQ = re.compile(r"\b(send|share|give|tell|reply with|enter|forward|provide|read out)\b[^.]{0,25}\b(your|the|this)\s+(otp|password|pin|code|verification code|passcode)\b", re.I)
def _direct_request(text):
    """True if a credential is requested without a preceding negation ('never share ...')."""
    return any(not re.search(r"(never|not|n't)\s*$", text[max(0, m.start()-12):m.start()].lower()) for m in REQ.finditer(text))

def _snip(text, m, pad=35):
    s, e = max(0, m.start()-pad), min(len(text), m.end()+pad)
    return ("…" if s else "") + text[s:e].strip() + ("…" if e < len(text) else "")

def analyze(text: str, claimed_sender: str | None = None) -> dict:
    found = []
    for r in RULES:
        m = r.rx().search(text)
        if m:
            found.append({"id": r.id, "kind": r.kind, "weight": r.weight, "evidence": _snip(text, m),
                          "explanation": r.why, "action": r.action})
    edu = EDU.search(text) and not _direct_request(text)
    if edu: found = [f for f in found if f["id"] != "credential"]
    kinds = {f["kind"] for f in found}; ids = {f["id"] for f in found}
    has_ask, has_pressure = "ask" in kinds, "pressure" in kinds
    score = 0
    for f in found:
        if f["id"] == "link_login" and not (has_ask or has_pressure): f["weight"] = 0
        score += f["weight"]
    reasons = [EDU_NOTE] if edu else []
    if has_ask and has_pressure:
        score += CONFIG["combo_ask_pressure"]
        reasons.append("A sensitive request combined with pressure tactics raises risk more than either alone.")
    if has_ask and "secrecy" in ids:
        score += CONFIG["combo_ask_secrecy"]
        reasons.append("A sensitive request plus discouraging verification is a classic impersonation pattern.")
    level = ("Critical" if score >= CONFIG["critical"] else "High" if score >= CONFIG["high"]
             else "Medium" if score >= CONFIG["medium"] else "Low")
    if not found:
        reasons.append("No known manipulation indicators were detected. This does not prove the message is safe.")
    words = len(text.split())
    coverage = "limited" if words < 12 else ("substantial" if len(ids) >= 3 else "moderate")
    actions = list(dict.fromkeys(f["action"] for f in found))
    actions.append("Verify the sender through a channel you already trust before acting.")
    return {"risk_level": level, "score": score, "evidence_coverage": coverage,
            "evidence_coverage_note": "How much text/signal the rules had to work with. Not a probability of fraud.",
            "identity_status": "Verification unavailable",
            "identity_note": "TrustShield cannot verify sender identity. Use the Identity Check workflow.",
            "claimed_sender": claimed_sender, "indicators": found, "reasons": reasons,
            "recommended_actions": actions, "limitations": LIMITS}
