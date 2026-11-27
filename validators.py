"""Server-side input validation. Every field is checked against a strict
pattern or a whitelist; anything else is rejected (never "cleaned up")."""
import re

BRANCHES = ("CSE", "IT", "ECE", "EEE", "ME", "CE", "AIML")
GENDERS = ("Male", "Female", "Other", "Prefer not to say")
SEMESTERS = tuple(range(1, 9))

NAME_RE = re.compile(r"^[A-Za-z]+(?: [A-Za-z]+)*$")           # letters and single spaces
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
ROLL_RE = re.compile(r"^[A-Za-z0-9]{10,12}$")


def validate_name(v):
    if not (2 <= len(v) <= 60) or not NAME_RE.fullmatch(v):
        return "Name must be 2-60 characters: letters and spaces only."

def validate_email(v):
    if len(v) > 120 or not EMAIL_RE.fullmatch(v):
        return "Enter a valid email address."

def validate_roll(v):
    if not ROLL_RE.fullmatch(v):
        return "Roll number must be 10-12 letters or digits."

def validate_branch(v):
    if v not in BRANCHES:
        return "Choose a branch from the list."

def validate_gender(v):
    if v not in GENDERS:
        return "Choose a gender from the list."

def validate_semester(v):
    if not v.isdigit() or int(v) not in SEMESTERS:
        return "Semester must be a number from 1 to 8."

COMMON_PASSWORDS = {"password1", "password123", "12345678", "123456789", "qwerty123",
                    "iloveyou1", "admin1234", "welcome123", "letmein123", "abcd1234"}


def validate_password(v, email=""):
    if not (8 <= len(v) <= 128):
        return "Password must be 8-128 characters."
    if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)):
        return "Password must contain at least one letter and one digit."
    if v.lower() in COMMON_PASSWORDS:
        return "That password is too common. Choose something less guessable."
    if email and email.split("@")[0] and email.split("@")[0].lower() in v.lower():
        return "Password must not contain your email name."


def validate_profile(form):
    """Returns (clean_values, errors) for the editable profile fields."""
    data = {
        "name": " ".join(form.get("name", "").split()),
        "branch": form.get("branch", ""),
        "semester": form.get("semester", ""),
        "gender": form.get("gender", ""),
    }
    checks = {"name": validate_name, "branch": validate_branch,
              "semester": validate_semester, "gender": validate_gender}
    errors = {k: m for k, f in checks.items() if (m := f(data[k]))}
    return data, errors


def validate_registration(form):
    data, errors = validate_profile(form)
    data["email"] = form.get("email", "").strip().lower()
    data["roll_number"] = form.get("roll_number", "").strip().upper()
    password = form.get("password", "")
    for key, fn, val in (("email", validate_email, data["email"]),
                         ("roll_number", validate_roll, data["roll_number"]),
                         ("password", lambda x: validate_password(x, data["email"]), password)):
        if (m := fn(val)):
            errors[key] = m
    if password != form.get("confirm_password", ""):
        errors["confirm_password"] = "Passwords do not match."
    order = ["name", "email", "roll_number", "branch", "semester", "gender", "password", "confirm_password"]
    return data, password, {k: errors[k] for k in order if k in errors}


def validate_password_change(current, new, confirm, email=""):
    errors = {}
    if not current:
        errors["current_password"] = "Enter your current password."
    if (m := validate_password(new, email)):
        errors["new_password"] = m
    elif new == current:
        errors["new_password"] = "New password must be different from the current one."
    if new != confirm:
        errors["confirm_password"] = "Passwords do not match."
    return errors
