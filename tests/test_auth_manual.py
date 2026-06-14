from datetime import datetime, timedelta, timezone
import jwt

from security.auth import (
    create_access_token,
    verify_token,
    SECRET_KEY,
    ALGORITHM
)

# Testing if token if valid
def test_valid_token():
    token = create_access_token({"sub": "testuser"})
    result = verify_token(token)

    print("Valid token test:", result)
    assert result == "testuser"

# Testing expiration of the token
def test_expired_token():
    token = jwt.encode(
        {
            "sub": "testuser",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    result = verify_token(token)

    print("Expired token test:", result)
    assert result is None

# Testing wrong secret
def test_invalid_signature():
    token = jwt.encode(
        {
            "sub": "testuser",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
        },
        "WRONG_SECRET",
        algorithm=ALGORITHM
    )

    result = verify_token(token)

    print("Invalid signature test:", result)
    assert result is None


if __name__ == "__main__":
    test_valid_token()
    test_expired_token()
    test_invalid_signature()

    print("\nAll tests finished")