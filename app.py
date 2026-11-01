
import streamlit as st
import string
import secrets
import math
import re

# -------------------------------
# PAGE CONFIGURATION
# -------------------------------

st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔐",
    layout="wide"
)

# -------------------------------
# CUSTOM DESIGN
# -------------------------------

st.title("🔐 Password Strength Analyzer")

st.markdown(
    "### Cybersecurity | Password Security Evaluation"
)

st.write(
    "Analyze your password security and discover "
    "how to create stronger passwords."
)

st.divider()

# -------------------------------
# COMMON PASSWORD DATABASE
# -------------------------------

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "admin",
    "welcome",
    "abc123",
    "111111",
    "iloveyou",
    "letmein"
}

# -------------------------------
# PATTERN DETECTION
# -------------------------------

def check_patterns(password):

    lower = password.lower()

    patterns = [
        "1234",
        "2345",
        "3456",
        "abcd",
        "qwerty",
        "asdf"
    ]

    for pattern in patterns:
        if pattern in lower:
            return True

    if re.search(r"(.)\1{3,}", password):
        return True

    return False


# -------------------------------
# ENTROPY CALCULATION
# -------------------------------

def calculate_entropy(password):

    pool = 0

    if any(c.islower() for c in password):
        pool += 26

    if any(c.isupper() for c in password):
        pool += 26

    if any(c.isdigit() for c in password):
        pool += 10

    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)

    if pool == 0:
        return 0

    entropy = len(password) * math.log2(pool)

    return round(entropy, 2)


# -------------------------------
# PASSWORD ANALYSIS
# -------------------------------

def analyze_password(password):

    checks = {
        "At least 12 characters": len(password) >= 12,

        "Uppercase letters": any(
            c.isupper() for c in password
        ),

        "Lowercase letters": any(
            c.islower() for c in password
        ),

        "Numbers": any(
            c.isdigit() for c in password
        ),

        "Special characters": any(
            c in string.punctuation for c in password
        )
    }

    common = password.lower() in COMMON_PASSWORDS

    pattern = check_patterns(password)

    score = 0

    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15

    if checks["Uppercase letters"]:
        score += 10

    if checks["Lowercase letters"]:
        score += 10

    if checks["Numbers"]:
        score += 10

    if checks["Special characters"]:
        score += 10

    if len(password) >= 16:
        score += 10

    if len(password) >= 20:
        score += 5

    if not common:
        score += 10

    if not pattern:
        score += 10

    score = min(score, 100)

    if common or pattern or score < 40:
        strength = "Weak"

    elif score < 65:
        strength = "Medium"

    elif score < 85:
        strength = "Strong"

    else:
        strength = "Very Strong"

    entropy = calculate_entropy(password)

    return checks, score, strength, entropy, common, pattern


# -------------------------------
# SECURITY RECOMMENDATIONS
# -------------------------------

def get_recommendations(password, checks, common, pattern):

    suggestions = []

    if len(password) < 12:
        suggestions.append(
            "Increase password length to at least 12 characters."
        )

    if not checks["Uppercase letters"]:
        suggestions.append("Add uppercase letters.")

    if not checks["Lowercase letters"]:
        suggestions.append("Add lowercase letters.")

    if not checks["Numbers"]:
        suggestions.append("Include numbers.")

    if not checks["Special characters"]:
        suggestions.append("Include special characters.")

    if common:
        suggestions.append(
            "Avoid commonly used passwords."
        )

    if pattern:
        suggestions.append(
            "Avoid predictable sequences or repeated characters."
        )

    if not suggestions:
        suggestions.append(
            "Basic security checks passed. "
            "Use a unique password for every account."
        )

    return suggestions


# -------------------------------
# PASSWORD GENERATOR
# -------------------------------

def generate_password(length):

    categories = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation
    ]

    password = [
        secrets.choice(category)
        for category in categories
    ]

    all_characters = "".join(categories)

    for _ in range(length - 4):
        password.append(
            secrets.choice(all_characters)
        )

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


# -------------------------------
# MAIN DASHBOARD
# -------------------------------

tab1, tab2 = st.tabs([
    "🔍 Password Analyzer",
    "🔑 Password Generator"
])


# -------------------------------
# PASSWORD ANALYZER TAB
# -------------------------------

with tab1:

    st.subheader("Password Security Analysis")

    password = st.text_input(
        "Enter your password",
        type="password",
        placeholder="Enter password here"
    )

    if password:

        checks, score, strength, entropy, common, pattern = (
            analyze_password(password)
        )

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Security Score",
            str(score) + "/100"
        )

        col2.metric(
            "Password Strength",
            strength
        )

        col3.metric(
            "Entropy",
            str(entropy) + " bits"
        )

        st.progress(score / 100)

        st.subheader("Security Checklist")

        for label, result in checks.items():

            if result:
                st.success("✓ " + label)

            else:
                st.warning("✗ " + label)

        if common:
            st.error(
                "This password is commonly used."
            )

        if pattern:
            st.error(
                "Predictable patterns detected."
            )

        st.subheader("Security Recommendations")

        suggestions = get_recommendations(
            password,
            checks,
            common,
            pattern
        )

        for suggestion in suggestions:
            st.write("• " + suggestion)

        st.caption(
            "Entropy is a theoretical estimate based on "
            "character types and assumes random selection."
        )

    else:

        st.info(
            "Enter a password to start the security analysis."
        )


# -------------------------------
# PASSWORD GENERATOR TAB
# -------------------------------

with tab2:

    st.subheader("Secure Password Generator")

    length = st.slider(
        "Select password length",
        min_value=12,
        max_value=32,
        value=16
    )

    if st.button("Generate Secure Password"):

        new_password = generate_password(length)

        st.session_state.generated_password = new_password

    if "generated_password" in st.session_state:

        st.success("Secure password generated!")

        st.code(
            st.session_state.generated_password
        )

        st.caption(
            "Store your generated password in a trusted "
            "password manager."
        )


# -------------------------------
# FOOTER
# -------------------------------

st.divider()

st.caption(
    "Password Strength Analyzer | Python | Streamlit | Cybersecurity"
)
