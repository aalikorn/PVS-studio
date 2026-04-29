import os

class Config:
    MODE = os.getenv("MODE", "VULN")  # VULN or FIXED
    WEAK_SECRET = os.getenv("WEAK_SECRET", "weak_secret_123")
    STRONG_SECRET = os.getenv("STRONG_SECRET", "change_me_to_strong_value")
    JWT_ALGORITHMS = ["HS256"]  # allowed algorithms in FIXED mode
