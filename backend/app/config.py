import os


class Settings:
    @property
    def database_url(self) -> str:
        return os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg2://honeypot:honeypot123@postgres:5432/honeypot_db",
        )

    @property
    def jwt_secret(self) -> str:
        return os.getenv("JWT_SECRET", "change-me-in-prod")


settings = Settings()



