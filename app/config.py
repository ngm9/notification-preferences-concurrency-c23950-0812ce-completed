from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    # Tokens without an exp claim never expire under JWT's default rules.
    # Set JWT_REQUIRE_EXP=true in production so expiry becomes mandatory.
    jwt_require_exp: bool = False

    class Config:
        env_file = ".env"


settings = Settings()
